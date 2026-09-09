use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpLease {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub expires_at_unix: u64,
}

impl DhcpLease {
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        self.expires_at_unix <= now_unix
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasePoolConfig {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub lease_time: Duration,
}

#[derive(Debug, Clone)]
pub struct LeaseManager {
    config: LeasePoolConfig,
    leases_by_mac: HashMap<[u8; 6], DhcpLease>,
    leases_by_ip: HashMap<Ipv4Addr, [u8; 6]>,

    // Maps a declined address to the unix timestamp it becomes offerable again.
    // Without an expiry, a spoofed DECLINE flood would poison the pool forever.
    declined: HashMap<Ipv4Addr, u64>,
}

impl LeaseManager {
    pub fn new(config: LeasePoolConfig) -> Result<Self> {
        if ipv4_to_u32(config.start) > ipv4_to_u32(config.end) {
            bail!("invalid DHCP pool: start address is greater than end address");
        }

        Ok(Self {
            config,
            leases_by_mac: HashMap::new(),
            leases_by_ip: HashMap::new(),
            declined: HashMap::new(),
        })
    }

    pub fn holds(&self, mac: [u8; 6], ip: Ipv4Addr, now_unix: u64) -> bool {
        self.leases_by_mac
            .get(&mac)
            .is_some_and(|lease| lease.ip == ip && !lease.is_expired_at(now_unix))
    }

    pub fn restore(config: LeasePoolConfig, leases: Vec<DhcpLease>, now_unix: u64) -> Result<Self> {
        let mut manager = Self::new(config)?;

        for lease in leases {
            if lease.is_expired_at(now_unix) || !manager.contains(lease.ip) {
                continue;
            }
            if manager.leases_by_mac.contains_key(&lease.mac)
                || manager.leases_by_ip.contains_key(&lease.ip)
            {
                continue;
            }

            manager.leases_by_ip.insert(lease.ip, lease.mac);
            manager.leases_by_mac.insert(lease.mac, lease);
        }

        Ok(manager)
    }

    pub fn leases(&self) -> impl Iterator<Item = &DhcpLease> {
        self.leases_by_mac.values()
    }

    pub fn snapshot(&self) -> Vec<DhcpLease> {
        let mut leases: Vec<DhcpLease> = self.leases().cloned().collect();
        leases.sort_by_key(|lease| u32::from(lease.ip));
        leases
    }

    pub fn allocate(&mut self, mac: [u8; 6], requested_ip: Option<Ipv4Addr>) -> Result<DhcpLease> {
        let now = now_unix();
        self.reclaim_expired(now);

        if let Some(existing) = self.leases_by_mac.get(&mac) {
            if !existing.is_expired_at(now) {
                return Ok(existing.clone());
            }
        }

        let ip = requested_ip
            .filter(|&requested_ip| self.is_available_for_mac(requested_ip, mac, now))
            .or_else(|| self.first_available_ip(mac, now))
            .ok_or_else(|| anyhow::anyhow!("DHCP pool is exhausted"))?;

        let lease = DhcpLease {
            mac,
            ip,
            expires_at_unix: now + self.config.lease_time.as_secs(),
        };

        self.leases_by_ip.insert(ip, mac);
        self.leases_by_mac.insert(mac, lease.clone());
        Ok(lease)
    }

    pub fn allocate_exact(&mut self, mac: [u8; 6], ip: Ipv4Addr) -> Result<DhcpLease> {
        let now = now_unix();
        self.reclaim_expired(now);

        if !self.is_available_for_mac(ip, mac, now) {
            bail!("address {ip} is not available for this client");
        }

        let lease = DhcpLease {
            mac,
            ip,
            expires_at_unix: now.saturating_add(self.config.lease_time.as_secs()),
        };
        if let Some(previous) = self.leases_by_mac.insert(mac, lease.clone()) {
            if previous.ip != ip {
                self.leases_by_ip.remove(&previous.ip);
            }
        }
        self.leases_by_ip.insert(ip, mac);
        Ok(lease)
    }

    pub fn release(&mut self, mac: [u8; 6]) -> Option<DhcpLease> {
        let lease = self.leases_by_mac.remove(&mac)?;
        self.leases_by_ip.remove(&lease.ip);
        Some(lease)
    }

    /// Only declines `ip` if `mac` is the address's current holder: a DHCPDECLINE
    /// is otherwise unauthenticated, so accepting one for any address on behalf
    /// of any MAC would let a spoofed packet evict and permanently poison an
    /// address that was never offered to the sender.
    pub fn decline(&mut self, mac: [u8; 6], ip: Ipv4Addr, now_unix: u64) {
        if !self.contains(ip) {
            return;
        }
        if self.leases_by_mac.get(&mac).map(|lease| lease.ip) != Some(ip) {
            return;
        }

        self.leases_by_ip.remove(&ip);
        self.leases_by_mac.remove(&mac);
        self.declined
            .insert(ip, now_unix + self.config.lease_time.as_secs());
    }

    pub fn is_declined(&self, ip: Ipv4Addr, now_unix: u64) -> bool {
        self.declined
            .get(&ip)
            .is_some_and(|&expires_at| expires_at > now_unix)
    }

    pub fn reclaim_expired(&mut self, now_unix: u64) {
        let expired_macs: Vec<[u8; 6]> = self
            .leases_by_mac
            .iter()
            .filter_map(|(mac, lease)| lease.is_expired_at(now_unix).then_some(*mac))
            .collect();

        for mac in expired_macs {
            self.release(mac);
        }

        self.declined
            .retain(|_, &mut expires_at| expires_at > now_unix);
    }

    fn first_available_ip(&self, mac: [u8; 6], now_unix: u64) -> Option<Ipv4Addr> {
        let start = ipv4_to_u32(self.config.start);
        let end = ipv4_to_u32(self.config.end);

        (start..=end)
            .map(u32_to_ipv4)
            .find(|ip| self.is_available_for_mac(*ip, mac, now_unix))
    }

    fn is_available_for_mac(&self, ip: Ipv4Addr, mac: [u8; 6], now_unix: u64) -> bool {
        if !self.contains(ip) || self.is_declined(ip, now_unix) {
            return false;
        }

        match self.leases_by_ip.get(&ip) {
            Some(owner) => owner == &mac,
            None => true,
        }
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip)
    }

    pub fn lease_time(&self) -> Duration {
        self.config.lease_time
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip = ipv4_to_u32(ip);
        ipv4_to_u32(self.config.start) <= ip && ip <= ipv4_to_u32(self.config.end)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ipv4(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> LeaseManager {
        LeaseManager::new(LeasePoolConfig {
            start: Ipv4Addr::new(192, 168, 10, 100),
            end: Ipv4Addr::new(192, 168, 10, 102),
            lease_time: Duration::from_secs(60),
        })
        .expect("pool should be valid")
    }

    #[test]
    fn allocates_requested_ip_when_available() {
        let mut manager = manager();
        let mac = [1, 2, 3, 4, 5, 6];
        let requested = Ipv4Addr::new(192, 168, 10, 101);

        let lease = manager.allocate(mac, Some(requested)).expect("lease");
        assert_eq!(lease.ip, requested);
    }

    #[test]
    fn returns_existing_lease_for_same_mac() {
        let mut manager = manager();
        let mac = [1, 2, 3, 4, 5, 6];

        let first = manager.allocate(mac, None).expect("first lease");
        let second = manager
            .allocate(mac, Some(Ipv4Addr::new(192, 168, 10, 102)))
            .expect("same lease");

        assert_eq!(first.ip, second.ip);
    }

    #[test]
    fn does_not_give_same_ip_to_different_macs() {
        let mut manager = manager();
        let first_mac = [1, 2, 3, 4, 5, 6];
        let second_mac = [6, 5, 4, 3, 2, 1];
        let requested = Ipv4Addr::new(192, 168, 10, 100);

        let first = manager.allocate(first_mac, Some(requested)).expect("first");
        let second = manager
            .allocate(second_mac, Some(requested))
            .expect("second");

        assert_eq!(first.ip, requested);
        assert_ne!(second.ip, requested);
    }

    #[test]
    fn reports_pool_exhaustion() {
        let mut manager = manager();

        manager.allocate([1, 0, 0, 0, 0, 1], None).expect("lease 1");
        manager.allocate([1, 0, 0, 0, 0, 2], None).expect("lease 2");
        manager.allocate([1, 0, 0, 0, 0, 3], None).expect("lease 3");

        assert!(manager.allocate([1, 0, 0, 0, 0, 4], None).is_err());
    }

    #[test]
    fn restore_discards_expired_and_out_of_pool_leases() {
        let config = LeasePoolConfig {
            start: Ipv4Addr::new(192, 168, 10, 100),
            end: Ipv4Addr::new(192, 168, 10, 102),
            lease_time: Duration::from_secs(60),
        };
        let leases = vec![
            DhcpLease {
                mac: [1, 0, 0, 0, 0, 1],
                ip: Ipv4Addr::new(192, 168, 10, 100),
                expires_at_unix: 200,
            },
            DhcpLease {
                mac: [1, 0, 0, 0, 0, 2],
                ip: Ipv4Addr::new(192, 168, 10, 101),
                expires_at_unix: 99,
            },
            DhcpLease {
                mac: [1, 0, 0, 0, 0, 3],
                ip: Ipv4Addr::new(10, 0, 0, 10),
                expires_at_unix: 200,
            },
        ];

        let manager = LeaseManager::restore(config, leases, 100).expect("restore");
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].ip, Ipv4Addr::new(192, 168, 10, 100));
    }

    #[test]
    fn decline_is_ignored_unless_the_mac_owns_the_address() {
        let mut manager = manager();
        let owner = [1, 2, 3, 4, 5, 6];
        let attacker = [6, 5, 4, 3, 2, 1];
        let owned = manager.allocate(owner, None).expect("lease").ip;

        // The attacker never held `owned`, so this must be a no-op rather than
        // evicting the real owner and poisoning the address.
        manager.decline(attacker, owned, 0);

        assert!(manager.holds(owner, owned, 0));
        assert!(!manager.is_declined(owned, 0));
    }

    #[test]
    fn declined_address_becomes_available_again_after_the_lease_time() {
        let mut manager = manager();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = manager.allocate(mac, None).expect("lease").ip;

        manager.decline(mac, ip, 0);
        assert!(manager.is_declined(ip, 0));
        assert!(manager.is_declined(ip, 59));

        // lease_time in `manager()` is 60s.
        assert!(!manager.is_declined(ip, 60));
    }

    #[test]
    fn release_frees_address() {
        let mut manager = manager();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = manager.allocate(mac, None).expect("lease").ip;

        assert!(manager.release(mac).is_some());

        let new_lease = manager
            .allocate([6, 5, 4, 3, 2, 1], Some(ip))
            .expect("lease");
        assert_eq!(new_lease.ip, ip);
    }
}
