use std::{fmt, net::Ipv4Addr, time::Duration};

use crate::dhcp::packet::DhcpPacket;

use super::packet::{Ack, ClientPacketBuilder, Offer, ReplyContext};

const INITIAL_RETRY: Duration = Duration::from_secs(4);
const MAX_RETRY: Duration = Duration::from_secs(64);
const MAX_JITTER_MS: i64 = 1_000;
const RESTART_BACKOFF: Duration = Duration::from_secs(4);
const MIN_TIMER: Duration = Duration::from_millis(1);

pub type MonotonicTime = Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendKind {
    Broadcast,
    Unicast(Ipv4Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreReason {
    NotExpected,
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send { packet: Vec<u8>, kind: SendKind },
    WakeAt(MonotonicTime),
    LeaseAcquired(Lease),
    LeaseLost,
    CleanupNeeded(Lease),
    ReplyIgnored(IgnoreReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub prefix_len: u8,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub server_identifier: Ipv4Addr,
    pub acquired_at: MonotonicTime,
    pub renewal_at: MonotonicTime,
    pub rebinding_at: MonotonicTime,
    pub expires_at: MonotonicTime,
}

impl Lease {
    fn from_ack(ack: Ack, now: MonotonicTime) -> Self {
        Self {
            address: ack.address,
            subnet_mask: ack.subnet_mask,
            prefix_len: ack.prefix_len,
            routers: ack.routers,
            dns_servers: ack.dns_servers,
            server_identifier: ack.server_identifier,
            acquired_at: now,
            renewal_at: add(now, Duration::from_secs(ack.renewal_seconds.into())),
            rebinding_at: add(now, Duration::from_secs(ack.rebinding_seconds.into())),
            expires_at: add(now, Duration::from_secs(ack.lease_seconds.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpClientState {
    WaitingForLink,
    Init,
    InitReboot { lease: Lease },
    Selecting,
    Requesting { offer: Offer },
    Rebooting { lease: Lease },
    Bound { lease: Lease },
    Renewing { lease: Lease },
    Rebinding { lease: Lease },
    Declining { lease: Lease },
    Backoff,
    Failed { reason: String },
}

#[derive(Debug, Clone)]
pub struct DhcpClientStateMachine {
    mac: [u8; 6],
    state: DhcpClientState,
    xid: Option<u32>,
    transaction_started: Option<MonotonicTime>,
    retry: u8,
    deadline: Option<MonotonicTime>,
}

impl DhcpClientStateMachine {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            state: DhcpClientState::WaitingForLink,
            xid: None,
            transaction_started: None,
            retry: 0,
            deadline: None,
        }
    }

    pub fn state(&self) -> &DhcpClientState {
        &self.state
    }

    pub fn xid(&self) -> Option<u32> {
        self.xid
    }

    pub(crate) fn deadline(&self) -> Option<MonotonicTime> {
        self.deadline
    }

    pub fn link_ready(
        &mut self,
        now: MonotonicTime,
        xid: u32,
        remembered: Option<Lease>,
        jitter_ms: i32,
    ) -> Vec<Action> {
        self.xid = Some(xid);
        self.transaction_started = Some(now);
        self.retry = 0;
        self.state = DhcpClientState::Init;
        match remembered.filter(|lease| lease.expires_at > now) {
            Some(lease) => {
                self.state = DhcpClientState::InitReboot {
                    lease: lease.clone(),
                };
                self.state = DhcpClientState::Rebooting { lease };
                self.send_current(now, jitter_ms)
            }
            None => {
                self.state = DhcpClientState::Selecting;
                self.send_current(now, jitter_ms)
            }
        }
    }

    pub fn link_lost(&mut self) -> Vec<Action> {
        let lost = self.active_lease().is_some();
        self.state = DhcpClientState::WaitingForLink;
        self.xid = None;
        self.transaction_started = None;
        self.deadline = None;
        self.retry = 0;
        if lost {
            vec![Action::LeaseLost]
        } else {
            Vec::new()
        }
    }

    pub fn receive(&mut self, now: MonotonicTime, bytes: &[u8], jitter_ms: i32) -> Vec<Action> {
        let packet = match DhcpPacket::parse(bytes) {
            Ok(packet) => packet,
            Err(error) => return ignored(error),
        };
        let Some(xid) = self.xid else {
            return vec![Action::ReplyIgnored(IgnoreReason::NotExpected)];
        };
        let context = ReplyContext { xid, mac: self.mac };

        match self.state.clone() {
            DhcpClientState::Selecting => match context.validate_offer(&packet) {
                Ok(offer) => {
                    self.state = DhcpClientState::Requesting { offer };
                    self.retry = 0;
                    self.send_current(now, jitter_ms)
                }
                Err(error) => ignored(error),
            },
            DhcpClientState::Requesting { offer } => {
                if let Ok(ack) = context.validate_ack(
                    &packet,
                    Some(offer.server_identifier),
                    Some(offer.address),
                ) {
                    return self.bind(ack, now);
                }
                if context
                    .validate_nak(&packet, Some(offer.server_identifier))
                    .is_ok()
                {
                    return self.nak(now, jitter_ms);
                }
                ignored("reply is not a valid ACK or NAK for the selected offer")
            }
            DhcpClientState::Rebooting { lease } => {
                if let Ok(ack) = context.validate_ack(&packet, None, Some(lease.address)) {
                    return self.bind(ack, now);
                }
                if context.validate_nak(&packet, None).is_ok() {
                    return self.nak(now, jitter_ms);
                }
                ignored("reply is not a valid INIT-REBOOT ACK or NAK")
            }
            DhcpClientState::Renewing { lease } => {
                if let Ok(ack) = context.validate_ack(&packet, None, Some(lease.address)) {
                    return self.bind(ack, now);
                }
                if context.validate_nak(&packet, None).is_ok() {
                    return self.nak(now, jitter_ms);
                }
                ignored("reply is not a valid renewal ACK or NAK")
            }
            DhcpClientState::Rebinding { lease } => {
                if let Ok(ack) = context.validate_ack(&packet, None, Some(lease.address)) {
                    return self.bind(ack, now);
                }
                if context.validate_nak(&packet, None).is_ok() {
                    return self.nak(now, jitter_ms);
                }
                ignored("reply is not a valid rebinding ACK or NAK")
            }
            _ => vec![Action::ReplyIgnored(IgnoreReason::NotExpected)],
        }
    }

    pub fn timeout(&mut self, now: MonotonicTime, fresh_xid: u32, jitter_ms: i32) -> Vec<Action> {
        if self.deadline.is_some_and(|deadline| now < deadline) {
            return self.deadline.map(Action::WakeAt).into_iter().collect();
        }
        match self.state.clone() {
            DhcpClientState::Rebooting { lease } if now >= lease.expires_at => {
                self.expire_and_restart(now, fresh_xid, jitter_ms, lease)
            }
            DhcpClientState::Selecting
            | DhcpClientState::Requesting { .. }
            | DhcpClientState::Rebooting { .. } => {
                self.retry = self.retry.saturating_add(1);
                self.send_current(now, jitter_ms)
            }
            DhcpClientState::Bound { lease } if now >= lease.expires_at => {
                self.expire_and_restart(now, fresh_xid, jitter_ms, lease)
            }
            DhcpClientState::Bound { lease } if now >= lease.rebinding_at => {
                self.state = DhcpClientState::Rebinding { lease };
                self.retry = 0;
                self.xid = Some(fresh_xid);
                self.transaction_started = Some(now);
                self.send_current(now, jitter_ms)
            }
            DhcpClientState::Bound { lease } if now >= lease.renewal_at => {
                self.state = DhcpClientState::Renewing { lease };
                self.retry = 0;
                self.xid = Some(fresh_xid);
                self.transaction_started = Some(now);
                self.send_current(now, jitter_ms)
            }
            DhcpClientState::Bound { lease } => self.schedule(lease.renewal_at, now),
            DhcpClientState::Renewing { lease } if now >= lease.expires_at => {
                self.expire_and_restart(now, fresh_xid, jitter_ms, lease)
            }
            DhcpClientState::Renewing { lease } if now >= lease.rebinding_at => {
                self.state = DhcpClientState::Rebinding { lease };
                self.retry = 0;

                self.send_current(now, jitter_ms)
            }
            DhcpClientState::Renewing { .. } | DhcpClientState::Rebinding { .. } => {
                let lease = self.active_lease().cloned().expect("lease state");
                if now >= lease.expires_at {
                    self.expire_and_restart(now, fresh_xid, jitter_ms, lease)
                } else {
                    self.retry = self.retry.saturating_add(1);
                    self.send_current(now, jitter_ms)
                }
            }
            DhcpClientState::Backoff => {
                self.xid = Some(fresh_xid);
                self.transaction_started = Some(now);
                self.retry = 0;
                self.state = DhcpClientState::Init;
                self.state = DhcpClientState::Selecting;
                self.send_current(now, jitter_ms)
            }
            _ => Vec::new(),
        }
    }

    pub fn address_conflict(&mut self, now: MonotonicTime, jitter_ms: i32) -> Vec<Action> {
        let Some(lease) = self.active_lease().cloned() else {
            return Vec::new();
        };
        self.state = DhcpClientState::Declining {
            lease: lease.clone(),
        };
        let packet = self
            .builder(now)
            .decline(lease.address, lease.server_identifier);
        self.state = DhcpClientState::Backoff;
        self.deadline = Some(add(now, jittered(RESTART_BACKOFF, jitter_ms)));
        let mut actions = vec![Action::CleanupNeeded(lease)];
        if let Ok(packet) = packet {
            actions.insert(
                0,
                Action::Send {
                    packet,
                    kind: SendKind::Broadcast,
                },
            );
        }
        actions.push(Action::WakeAt(self.deadline.expect("set above")));
        actions
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state = DhcpClientState::Failed {
            reason: reason.into(),
        };
        self.deadline = None;
    }

    fn bind(&mut self, ack: Ack, now: MonotonicTime) -> Vec<Action> {
        let lease = Lease::from_ack(ack, now);
        self.state = DhcpClientState::Bound {
            lease: lease.clone(),
        };
        self.retry = 0;
        self.deadline = Some(lease.renewal_at);
        vec![
            Action::LeaseAcquired(lease.clone()),
            Action::WakeAt(lease.renewal_at),
        ]
    }

    fn nak(&mut self, now: MonotonicTime, jitter_ms: i32) -> Vec<Action> {
        let lost = self.active_lease().cloned();
        self.state = DhcpClientState::Backoff;
        self.deadline = Some(add(now, jittered(RESTART_BACKOFF, jitter_ms)));
        let mut actions = Vec::new();
        if let Some(lease) = lost {
            actions.push(Action::CleanupNeeded(lease));
        }
        actions.push(Action::LeaseLost);
        actions.push(Action::WakeAt(self.deadline.expect("set above")));
        actions
    }

    fn expire_and_restart(
        &mut self,
        now: MonotonicTime,
        fresh_xid: u32,
        jitter_ms: i32,
        lease: Lease,
    ) -> Vec<Action> {
        self.xid = Some(fresh_xid);
        self.transaction_started = Some(now);
        self.retry = 0;
        self.state = DhcpClientState::Selecting;
        let mut actions = vec![Action::CleanupNeeded(lease), Action::LeaseLost];
        actions.extend(self.send_current(now, jitter_ms));
        actions
    }

    fn send_current(&mut self, now: MonotonicTime, jitter_ms: i32) -> Vec<Action> {
        let builder = self.builder(now);
        let built = match &self.state {
            DhcpClientState::Selecting => builder.discover().map(|p| (p, SendKind::Broadcast)),
            DhcpClientState::Requesting { offer } => builder
                .selecting_request(offer.address, offer.server_identifier)
                .map(|p| (p, SendKind::Broadcast)),
            DhcpClientState::Rebooting { lease } => builder
                .init_reboot_request(lease.address)
                .map(|p| (p, SendKind::Broadcast)),
            DhcpClientState::Renewing { lease } => builder
                .renew(lease.address)
                .map(|p| (p, SendKind::Unicast(lease.server_identifier))),
            DhcpClientState::Rebinding { lease } => builder
                .rebind(lease.address)
                .map(|p| (p, SendKind::Broadcast)),
            _ => return Vec::new(),
        };
        let Ok((packet, kind)) = built else {
            self.fail("failed to build DHCP packet");
            return Vec::new();
        };
        let interval = jittered(retry_base(self.retry), jitter_ms);
        let mut deadline = add(now, interval);
        if let Some(lease) = self.active_lease() {
            let boundary = match self.state {
                DhcpClientState::Renewing { .. } => lease.rebinding_at,

                DhcpClientState::Rebinding { .. } | DhcpClientState::Rebooting { .. } => {
                    lease.expires_at
                }
                _ => deadline,
            };
            deadline = deadline.min(boundary).max(add(now, MIN_TIMER));
        }
        self.deadline = Some(deadline);
        vec![Action::Send { packet, kind }, Action::WakeAt(deadline)]
    }

    fn builder(&self, now: MonotonicTime) -> ClientPacketBuilder {
        let elapsed = now.saturating_sub(self.transaction_started.unwrap_or(now));
        ClientPacketBuilder::new(self.xid.expect("sending requires xid"), self.mac).elapsed(elapsed)
    }

    fn schedule(&mut self, target: MonotonicTime, now: MonotonicTime) -> Vec<Action> {
        let target = target.max(add(now, MIN_TIMER));
        self.deadline = Some(target);
        vec![Action::WakeAt(target)]
    }

    fn active_lease(&self) -> Option<&Lease> {
        match &self.state {
            DhcpClientState::InitReboot { lease }
            | DhcpClientState::Rebooting { lease }
            | DhcpClientState::Bound { lease }
            | DhcpClientState::Renewing { lease }
            | DhcpClientState::Rebinding { lease }
            | DhcpClientState::Declining { lease } => Some(lease),
            _ => None,
        }
    }
}

fn retry_base(retry: u8) -> Duration {
    let multiplier = 1u64 << retry.min(4);
    Duration::from_secs((INITIAL_RETRY.as_secs() * multiplier).min(MAX_RETRY.as_secs()))
}

fn jittered(base: Duration, jitter_ms: i32) -> Duration {
    let jitter = i64::from(jitter_ms).clamp(-MAX_JITTER_MS, MAX_JITTER_MS);
    if jitter < 0 {
        base.saturating_sub(Duration::from_millis(jitter.unsigned_abs()))
    } else {
        base.saturating_add(Duration::from_millis(jitter as u64))
    }
    .max(MIN_TIMER)
}

fn add(now: Duration, duration: Duration) -> Duration {
    now.checked_add(duration).unwrap_or(Duration::MAX)
}

fn ignored(error: impl fmt::Display) -> Vec<Action> {
    vec![Action::ReplyIgnored(IgnoreReason::Invalid(
        error.to_string(),
    ))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::packet::{
        finish_options, push_option, DhcpMessageType, BOOTREPLY, DHCP_FIXED_HEADER_LEN,
        DHCP_MAGIC_COOKIE, ETHERNET_HLEN, ETHERNET_HTYPE, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE,
        OPTION_REBINDING_TIME, OPTION_RENEWAL_TIME, OPTION_SERVER_IDENTIFIER, OPTION_SUBNET_MASK,
    };

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const XID: u32 = 0x1234_5678;
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn reply(xid: u32, kind: DhcpMessageType, address: Ipv4Addr, lease: Option<u32>) -> Vec<u8> {
        let mut bytes = vec![0; DHCP_FIXED_HEADER_LEN + DHCP_MAGIC_COOKIE.len()];
        bytes[0] = BOOTREPLY;
        bytes[1] = ETHERNET_HTYPE;
        bytes[2] = ETHERNET_HLEN;
        bytes[4..8].copy_from_slice(&xid.to_be_bytes());
        bytes[16..20].copy_from_slice(&address.octets());
        bytes[28..34].copy_from_slice(&MAC);
        bytes[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        push_option(&mut bytes, OPTION_MESSAGE_TYPE, &[kind.as_u8()]).unwrap();
        push_option(&mut bytes, OPTION_SERVER_IDENTIFIER, &SERVER.octets()).unwrap();
        if let Some(lease) = lease {
            push_option(&mut bytes, OPTION_SUBNET_MASK, &[255, 255, 255, 0]).unwrap();
            push_option(&mut bytes, OPTION_LEASE_TIME, &lease.to_be_bytes()).unwrap();
            let t1 = lease / 2;
            let t2 = lease * 7 / 8;
            push_option(&mut bytes, OPTION_RENEWAL_TIME, &t1.to_be_bytes()).unwrap();
            push_option(&mut bytes, OPTION_REBINDING_TIME, &t2.to_be_bytes()).unwrap();
        }
        finish_options(&mut bytes);
        bytes
    }

    fn acquire(sm: &mut DhcpClientStateMachine, now: Duration, lease: u32) -> Lease {
        sm.link_ready(now, XID, None, 0);
        sm.receive(now, &reply(XID, DhcpMessageType::Offer, ADDRESS, None), 0);
        let actions = sm.receive(
            now,
            &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(lease)),
            0,
        );
        match &actions[0] {
            Action::LeaseAcquired(lease) => lease.clone(),
            action => panic!("unexpected action: {action:?}"),
        }
    }

    fn sent(actions: &[Action]) -> (&[u8], SendKind) {
        match &actions[0] {
            Action::Send { packet, kind } => (packet, *kind),
            action => panic!("unexpected action: {action:?}"),
        }
    }

    #[test]
    fn full_lifecycle_acquires_renews_rebinds_and_expires() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut sm, Duration::ZERO, 80);
        assert_eq!(lease.renewal_at, Duration::from_secs(40));

        let actions = sm.timeout(lease.renewal_at, 99, 0);
        assert_eq!(sent(&actions).1, SendKind::Unicast(SERVER));
        assert!(matches!(sm.state(), DhcpClientState::Renewing { .. }));

        let actions = sm.timeout(lease.rebinding_at, 100, 0);
        assert_eq!(sent(&actions).1, SendKind::Broadcast);
        assert!(matches!(sm.state(), DhcpClientState::Rebinding { .. }));

        let actions = sm.timeout(lease.expires_at, 101, 0);
        assert!(matches!(actions[0], Action::CleanupNeeded(_)));
        assert!(matches!(actions[1], Action::LeaseLost));
        assert_eq!(sent(&actions[2..]).1, SendKind::Broadcast);
        assert_eq!(sm.xid(), Some(101));
        assert!(matches!(sm.state(), DhcpClientState::Selecting));
    }

    #[test]
    fn duplicate_offer_and_ack_preserve_bound_lease_deadline() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let initial = sm.link_ready(Duration::ZERO, XID, None, 0);
        assert_eq!(initial[1], Action::WakeAt(Duration::from_secs(4)));

        let offer = reply(XID, DhcpMessageType::Offer, ADDRESS, None);
        sm.receive(Duration::from_millis(100), &offer, 0);
        let request_deadline = Duration::from_millis(4_100);
        assert_eq!(sm.deadline(), Some(request_deadline));
        assert!(matches!(
            sm.receive(Duration::from_millis(200), &offer, 0)[0],
            Action::ReplyIgnored(_)
        ));
        assert_eq!(sm.deadline(), Some(request_deadline));

        let ack = reply(XID, DhcpMessageType::Ack, ADDRESS, Some(8));
        sm.receive(Duration::from_millis(300), &ack, 0);
        let renewal_deadline = Duration::from_millis(4_300);
        assert_eq!(sm.deadline(), Some(renewal_deadline));
        assert!(matches!(
            sm.receive(Duration::from_millis(400), &ack, 0)[0],
            Action::ReplyIgnored(IgnoreReason::NotExpected)
        ));
        assert_eq!(sm.deadline(), Some(renewal_deadline));

        let early = sm.timeout(request_deadline, 99, 0);
        assert_eq!(early, vec![Action::WakeAt(renewal_deadline)]);
        assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));
        let renewal = sm.timeout(renewal_deadline, 99, 0);
        assert_eq!(sent(&renewal).1, SendKind::Unicast(SERVER));
    }

    #[test]
    fn renewal_ack_replaces_schedule_and_returns_bound() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut sm, Duration::ZERO, 80);
        sm.timeout(lease.renewal_at, 99, 0);
        let actions = sm.receive(
            Duration::from_secs(41),
            &reply(99, DhcpMessageType::Ack, ADDRESS, Some(100)),
            0,
        );
        assert!(matches!(actions[0], Action::LeaseAcquired(_)));
        assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));
    }

    #[test]
    fn wrong_xid_and_wrong_state_are_explicitly_ignored() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        sm.link_ready(Duration::ZERO, XID, None, 0);
        let actions = sm.receive(
            Duration::ZERO,
            &reply(XID + 1, DhcpMessageType::Offer, ADDRESS, None),
            0,
        );
        assert!(matches!(actions[0], Action::ReplyIgnored(_)));
        assert!(matches!(sm.state(), DhcpClientState::Selecting));

        let ack = reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80));
        assert!(matches!(
            sm.receive(Duration::ZERO, &ack, 0)[0],
            Action::ReplyIgnored(_)
        ));
    }

    #[test]
    fn retries_are_bounded_jittered_and_keep_xid() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let first = sm.link_ready(Duration::ZERO, XID, None, 50_000);
        assert_eq!(first[1], Action::WakeAt(Duration::from_secs(5)));
        let mut now = Duration::from_secs(5);
        for expected in [7, 15, 31, 63, 63, 63] {
            let actions = sm.timeout(now, XID + 1, -50_000);
            let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
            assert_eq!(packet.xid, XID);
            let Action::WakeAt(next) = actions[1] else {
                panic!()
            };
            assert_eq!(next - now, Duration::from_secs(expected));
            now = next;
        }
    }

    #[test]
    fn nak_clears_lease_and_restarts_with_fresh_xid_after_backoff() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut sm, Duration::ZERO, 80);
        sm.timeout(lease.renewal_at, 99, 0);
        let actions = sm.receive(
            lease.renewal_at,
            &reply(99, DhcpMessageType::Nak, Ipv4Addr::UNSPECIFIED, None),
            0,
        );
        assert!(matches!(actions[0], Action::CleanupNeeded(_)));
        assert!(matches!(sm.state(), DhcpClientState::Backoff));
        sm.timeout(Duration::from_secs(44), 100, 0);
        assert_eq!(sm.xid(), Some(100));
        assert!(matches!(sm.state(), DhcpClientState::Selecting));
    }

    #[test]
    fn init_reboot_succeeds_or_nak_falls_back_after_backoff() {
        let mut seed = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut seed, Duration::ZERO, 80);
        let mut sm = DhcpClientStateMachine::new(MAC);
        let actions = sm.link_ready(Duration::from_secs(1), XID, Some(lease.clone()), 0);
        let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
        assert_eq!(packet.xid, XID);
        assert!(matches!(sm.state(), DhcpClientState::Rebooting { .. }));
        sm.receive(
            Duration::from_secs(2),
            &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80)),
            0,
        );
        assert!(matches!(sm.state(), DhcpClientState::Bound { .. }));

        let mut fallback = DhcpClientStateMachine::new(MAC);
        fallback.link_ready(Duration::from_secs(1), XID, Some(lease), 0);
        fallback.receive(
            Duration::from_secs(1),
            &reply(XID, DhcpMessageType::Nak, Ipv4Addr::UNSPECIFIED, None),
            0,
        );
        fallback.timeout(Duration::from_secs(5), 777, 0);
        assert_eq!(fallback.xid(), Some(777));
        assert!(matches!(fallback.state(), DhcpClientState::Selecting));
    }

    #[test]
    fn an_unanswered_init_reboot_expires_the_remembered_lease() {
        let mut seed = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut seed, Duration::ZERO, 80);

        let mut sm = DhcpClientStateMachine::new(MAC);
        let start = sm.link_ready(Duration::ZERO, XID, Some(lease.clone()), 0);

        assert_eq!(start[1], Action::WakeAt(Duration::from_secs(4)));
        let mut now = Duration::from_secs(4);
        while now < lease.expires_at {
            let actions = sm.timeout(now, 555, 0);
            let Action::WakeAt(next) = actions[actions.len() - 1] else {
                panic!("every retry schedules the next wake")
            };
            assert!(next <= lease.expires_at);
            now = next;
        }

        let expired = sm.timeout(lease.expires_at, 777, 0);
        assert!(matches!(expired[0], Action::CleanupNeeded(_)));
        assert!(matches!(expired[1], Action::LeaseLost));
        assert_eq!(sent(&expired[2..]).1, SendKind::Broadcast);
        assert_eq!(sm.xid(), Some(777));
        assert!(matches!(sm.state(), DhcpClientState::Selecting));
    }

    #[test]
    fn short_lease_deadlines_always_advance() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        let lease = acquire(&mut sm, Duration::ZERO, 3);
        assert_eq!(lease.renewal_at, Duration::from_secs(1));
        let renew = sm.timeout(lease.renewal_at, 99, -1_000);
        let Action::WakeAt(next) = renew[1] else {
            panic!()
        };
        assert!(next > lease.renewal_at);
        assert!(next <= lease.rebinding_at);
        let rebind = sm.timeout(lease.rebinding_at, 100, -1_000);
        let Action::WakeAt(next) = rebind[1] else {
            panic!()
        };
        assert!(next > lease.rebinding_at);
        assert!(next <= lease.expires_at);
    }

    #[test]
    fn link_loss_is_explicit_and_stops_timers() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        acquire(&mut sm, Duration::ZERO, 80);
        assert_eq!(sm.link_lost(), vec![Action::LeaseLost]);
        assert!(matches!(sm.state(), DhcpClientState::WaitingForLink));
        assert!(sm.timeout(Duration::from_secs(100), 9, 0).is_empty());
        assert!(matches!(
            sm.receive(
                Duration::from_secs(100),
                &reply(XID, DhcpMessageType::Ack, ADDRESS, Some(80)),
                0
            )[0],
            Action::ReplyIgnored(IgnoreReason::NotExpected)
        ));
    }

    #[test]
    fn secs_is_monotonic_and_saturates() {
        let mut sm = DhcpClientStateMachine::new(MAC);
        sm.link_ready(Duration::ZERO, XID, None, 0);
        let actions = sm.timeout(Duration::from_secs(70_000), 9, 0);
        let packet = DhcpPacket::parse(sent(&actions).0).unwrap();
        assert_eq!(packet.secs, u16::MAX);
    }
}
