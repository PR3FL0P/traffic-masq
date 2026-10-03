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
    /// Create an empty pool, checking only start <= end. The caller must validate
    /// subnet membership, network/broadcast/router exclusions and positive lease
    /// duration before constructing a production pool.
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

    /// Restore leases, skipping expired, out-of-range and duplicate MAC/IP entries.
    /// now_unix is wall-clock Unix seconds. Only pool ordering is checked here;
    /// the caller must validate subnet/router exclusions and positive duration.
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

    /// Reuse an unexpired lease without extending expiry, or allocate an address
    /// preferring a usable requested IP. Uses current wall-clock Unix seconds;
    /// pool exhaustion is an error. Use allocate_exact for renewal.
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

    /// Allocate or renew exactly this IP, updating expiry from current wall-clock
    /// Unix seconds even for an existing lease. Reject unavailable/out-of-pool IPs.
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

    /// Remove and return the lease assigned to this client, if present.
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

    /// Remove leases and declined-address reservations whose deadlines have passed.
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
mod tests;
