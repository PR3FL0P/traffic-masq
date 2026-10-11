use std::{fmt, net::Ipv4Addr, time::Duration};

use crate::packet::DhcpPacket;

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
    hostname: Option<String>,
    state: DhcpClientState,
    xid: Option<u32>,
    transaction_started: Option<MonotonicTime>,
    retry: u8,
    deadline: Option<MonotonicTime>,
}

impl DhcpClientStateMachine {
    /// Start an inert client that waits for link readiness before producing DHCP actions.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            hostname: None,
            state: DhcpClientState::WaitingForLink,
            xid: None,
            transaction_started: None,
            retry: 0,
            deadline: None,
        }
    }

    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }

    pub fn state(&self) -> &DhcpClientState {
        &self.state
    }

    pub fn xid(&self) -> Option<u32> {
        self.xid
    }

    pub fn deadline(&self) -> Option<MonotonicTime> {
        self.deadline
    }

    /// Start acquisition with a fresh transaction ID, reusing an unexpired remembered lease
    /// through INIT-REBOOT or broadcasting discovery when no usable lease exists.
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

    /// Clear timers and transaction state; emit lease loss only when a lease was active.
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

    /// Validate a reply against the current exchange and return the resulting actions.
    /// Malformed, mismatched, or unexpected packets produce an ignored-reply action.
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

    /// Advance renewal, rebinding, expiry, or retransmission when the deadline is reached.
    /// An early call returns the existing wakeup without advancing the exchange.
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

    /// Decline an active lease, request cleanup, and schedule acquisition after backoff.
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

    /// Enter a terminal failure state and clear the scheduled deadline.
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state = DhcpClientState::Failed {
            reason: reason.into(),
        };
        self.deadline = None;
    }

    /// Accept an ACK and schedule renewal, emitting cleanup first when owned resources change.
    fn bind(&mut self, ack: Ack, now: MonotonicTime) -> Vec<Action> {
        let lease = Lease::from_ack(ack, now);
        // Renewal can change the subnet or gateways without changing the
        // client address. Release the old ownership record before applying
        // those resources: overwriting it would orphan removed routes, while
        // a changed gateway/prefix would collide with our own previous state.
        let previous = self
            .active_lease()
            .filter(|previous| {
                previous.address != lease.address
                    || previous.prefix_len != lease.prefix_len
                    || previous.routers != lease.routers
            })
            .cloned();
        self.state = DhcpClientState::Bound {
            lease: lease.clone(),
        };
        self.retry = 0;
        self.deadline = Some(lease.renewal_at);
        let mut actions = Vec::new();
        if let Some(previous) = previous {
            actions.push(Action::CleanupNeeded(previous));
        }
        actions.push(Action::LeaseAcquired(lease.clone()));
        actions.push(Action::WakeAt(lease.renewal_at));
        actions
    }

    /// Abandon the rejected lease and schedule acquisition after a bounded backoff.
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

    /// Emit cleanup and lease loss before starting discovery with a fresh transaction ID.
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

    /// Build the packet for the current state and schedule a jittered retry bounded by lease timers.
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
        let builder = ClientPacketBuilder::new(self.xid.expect("sending requires xid"), self.mac)
            .elapsed(elapsed);
        match &self.hostname {
            Some(hostname) => builder.hostname(hostname.clone()),
            None => builder,
        }
    }

    /// Schedule a wakeup no earlier than the minimum timer interval after `now`.
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

/// Compute exponential retry delay, capped at the maximum retry interval.
fn retry_base(retry: u8) -> Duration {
    let multiplier = 1u64 << retry.min(4);
    Duration::from_secs((INITIAL_RETRY.as_secs() * multiplier).min(MAX_RETRY.as_secs()))
}

/// Clamp supplied jitter and keep the resulting timer strictly positive.
fn jittered(base: Duration, jitter_ms: i32) -> Duration {
    let jitter = i64::from(jitter_ms).clamp(-MAX_JITTER_MS, MAX_JITTER_MS);
    if jitter < 0 {
        base.saturating_sub(Duration::from_millis(jitter.unsigned_abs()))
    } else {
        base.saturating_add(Duration::from_millis(jitter as u64))
    }
    .max(MIN_TIMER)
}

/// Add monotonic durations, saturating at the maximum representable duration.
fn add(now: Duration, duration: Duration) -> Duration {
    now.checked_add(duration).unwrap_or(Duration::MAX)
}

fn ignored(error: impl fmt::Display) -> Vec<Action> {
    vec![Action::ReplyIgnored(IgnoreReason::Invalid(
        error.to_string(),
    ))]
}

#[cfg(test)]
mod tests;
