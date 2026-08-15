//! The record of which IPv4 addresses traffic-masq installed.
//!
//! "Is this address mine" used to be answered three different ways, with three
//! different failure modes: an `IFA_PROTO` tag in the kernel, a set of names in
//! memory, and the DHCP lease journal on disk. Only the last one survives both
//! a crash and a kernel that cannot hold the tag, and it is the pattern this
//! module generalises: write the intent to disk *before* touching the machine,
//! and reconcile the record against reality at startup.
//!
//! The kernel tag does not go away — it stays as *confirmation*. A claim that
//! the kernel contradicts (the address now carries someone else's tag) is
//! dropped. What changes is that the tag is no longer the only thing that can
//! answer, so on kernels older than 5.18, where `IFA_PROTO` is silently
//! dropped, releasing an interface stops being a dead end.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::netlink::{AddressOwner, Ipv4AddressInfo};
use crate::state::private_store::{PrivateJsonDirectory, PrivateStoreError};

pub const ADDRESS_CLAIM_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum OwnershipJournalError {
    #[error("unsupported address ownership schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid address ownership record: {0}")]
    InvalidRecord(String),
    #[error("address ownership journal I/O error: {0}")]
    Store(#[from] PrivateStoreError),
    #[error("invalid address ownership document: {0}")]
    Json(#[from] serde_json::Error),
}

/// Where a claim is in its life.
///
/// The two transient states exist because the journal is written before the
/// kernel is touched, which is the only order in which a crash cannot leave an
/// address on the machine that nothing remembers installing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClaimState {
    /// Written down; the address may or may not be on the link yet.
    Claiming,
    /// Confirmed on the link.
    Held,
    /// About to be removed; it may or may not still be on the link.
    Releasing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressClaim {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub state: AddressClaimState,
}

impl AddressClaim {
    fn matches(&self, address: Ipv4Addr, prefix_len: u8) -> bool {
        self.address == address && self.prefix_len == prefix_len
    }
}

/// One interface's worth of claims, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddressClaims {
    pub schema_version: u32,
    pub interface: String,
    pub claims: Vec<AddressClaim>,
}

impl InterfaceAddressClaims {
    fn validate(&self, interface: &str) -> Result<(), OwnershipJournalError> {
        if self.schema_version != ADDRESS_CLAIM_SCHEMA_VERSION {
            return Err(OwnershipJournalError::UnsupportedSchema(self.schema_version));
        }
        if self.interface != interface {
            return Err(OwnershipJournalError::InvalidRecord(
                "document/interface filename mismatch".into(),
            ));
        }
        if self.claims.iter().any(|claim| claim.prefix_len > 32) {
            return Err(OwnershipJournalError::InvalidRecord(
                "prefix length above 32".into(),
            ));
        }
        Ok(())
    }
}

/// What one interface's claims were reconciled into at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconciledClaims {
    /// Claims confirmed against the machine and kept.
    pub kept: Vec<AddressClaim>,
    /// Claims dropped, and why — for the log, which is the only place an
    /// operator can see that the daemon disowned something.
    pub dropped: Vec<(AddressClaim, String)>,
}

/// The journal of addresses this daemon installed.
///
/// The answer to "is this mine" is served from memory, because convergence asks
/// it on every pass; the disk is where the answer comes from after a restart.
/// A journal without a store is a complete journal that simply does not survive
/// one — used by tests and by tooling that never writes to the machine.
#[derive(Debug, Clone)]
pub struct AddressOwnershipJournal {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    claims: Mutex<BTreeMap<String, Vec<AddressClaim>>>,
    store: Option<PrivateJsonDirectory>,
}

impl AddressOwnershipJournal {
    /// A journal that is not written down.
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(Inner {
                claims: Mutex::new(BTreeMap::new()),
                store: None,
            }),
        }
    }

    /// Open the journal under the daemon's state directory.
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self, OwnershipJournalError> {
        let store = PrivateJsonDirectory::open(state_root, "address-ownership")?;
        let mut claims = BTreeMap::new();
        for interface in store.keys()? {
            let Some(bytes) = store.read(&interface)? else {
                continue;
            };
            let record: InterfaceAddressClaims = serde_json::from_slice(&bytes)?;
            record.validate(&interface)?;
            if !record.claims.is_empty() {
                claims.insert(interface, record.claims);
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                claims: Mutex::new(claims),
                store: Some(store),
            }),
        })
    }

    /// Whether traffic-masq installed this address.
    ///
    /// A claim in any state counts. `Claiming` and `Releasing` mean the daemon
    /// was interrupted mid-write, and in both cases the address on the link is
    /// there because of us — disowning it would leave it behind for good.
    pub async fn owns(&self, interface: &str, address: Ipv4Addr, prefix_len: u8) -> bool {
        self.inner
            .claims
            .lock()
            .await
            .get(interface)
            .is_some_and(|claims| claims.iter().any(|claim| claim.matches(address, prefix_len)))
    }

    /// Record an address as ours. Call this *before* installing it.
    pub async fn claim(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), OwnershipJournalError> {
        self.update(interface, |claims| {
            match claims
                .iter_mut()
                .find(|claim| claim.matches(address, prefix_len))
            {
                Some(existing) => existing.state = AddressClaimState::Claiming,
                None => claims.push(AddressClaim {
                    address,
                    prefix_len,
                    state: AddressClaimState::Claiming,
                }),
            }
        })
        .await
    }

    /// Confirm an address is on the link. Call this after installing it.
    pub async fn confirm(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), OwnershipJournalError> {
        self.update(interface, |claims| {
            if let Some(claim) = claims
                .iter_mut()
                .find(|claim| claim.matches(address, prefix_len))
            {
                claim.state = AddressClaimState::Held;
            }
        })
        .await
    }

    /// Mark an address as being removed. Call this *before* deleting it.
    pub async fn releasing(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), OwnershipJournalError> {
        self.update(interface, |claims| {
            if let Some(claim) = claims
                .iter_mut()
                .find(|claim| claim.matches(address, prefix_len))
            {
                claim.state = AddressClaimState::Releasing;
            }
        })
        .await
    }

    /// Give up the claim. Call this after the address is off the link.
    pub async fn release(
        &self,
        interface: &str,
        address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<(), OwnershipJournalError> {
        self.update(interface, |claims| {
            claims.retain(|claim| !claim.matches(address, prefix_len));
        })
        .await
    }

    /// Everything currently claimed on an interface.
    pub async fn claims(&self, interface: &str) -> Vec<AddressClaim> {
        self.inner
            .claims
            .lock()
            .await
            .get(interface)
            .cloned()
            .unwrap_or_default()
    }

    /// The interfaces the journal has claims for.
    pub async fn interfaces(&self) -> Vec<String> {
        self.inner.claims.lock().await.keys().cloned().collect()
    }

    /// Check what was written down against what is actually on an interface.
    ///
    /// Run once at startup, per interface with claims. A claim survives only if
    /// the address is still there and the kernel does not say it belongs to
    /// somebody else; anything else is dropped, because a journal that
    /// accumulates claims nobody can verify is worse than no journal — it would
    /// authorise deleting addresses this daemon never installed.
    pub async fn reconcile(
        &self,
        interface: &str,
        observed: &[Ipv4AddressInfo],
    ) -> Result<ReconciledClaims, OwnershipJournalError> {
        let recorded = self.claims(interface).await;
        let mut result = ReconciledClaims::default();

        for claim in recorded {
            let present = observed
                .iter()
                .find(|address| claim.matches(address.address, address.prefix_len));
            match present {
                None => result.dropped.push((
                    claim,
                    "the address is no longer on the interface".to_string(),
                )),
                Some(address) => match address.owner() {
                    // Someone else's tag beats our record: the address on the
                    // link now is not the one we installed.
                    AddressOwner::TrafficMasqDhcp | AddressOwner::Foreign(_) => result.dropped.push(
                        (claim, format!("the address is tagged {:?}", address.owner())),
                    ),
                    AddressOwner::TrafficMasqStatic | AddressOwner::Untagged => {
                        result.kept.push(AddressClaim {
                            state: AddressClaimState::Held,
                            ..claim
                        });
                    }
                },
            }
        }

        self.write(interface, result.kept.clone()).await?;
        Ok(result)
    }

    /// Change one interface's claims in memory and on disk, under one lock.
    ///
    /// The disk write happens while the lock is held. It is a small synchronous
    /// write, and letting go in between would allow two changes to land in the
    /// opposite order on disk from the order they happened in memory — leaving
    /// the file describing a state that never existed.
    async fn update(
        &self,
        interface: &str,
        change: impl FnOnce(&mut Vec<AddressClaim>),
    ) -> Result<(), OwnershipJournalError> {
        let mut claims = self.inner.claims.lock().await;
        let entry = claims.entry(interface.to_string()).or_default();
        let before = entry.clone();
        change(entry);
        if *entry == before {
            return Ok(());
        }
        let after = entry.clone();
        if after.is_empty() {
            claims.remove(interface);
        }
        self.persist(interface, &after)
    }

    async fn write(
        &self,
        interface: &str,
        claims: Vec<AddressClaim>,
    ) -> Result<(), OwnershipJournalError> {
        let mut all = self.inner.claims.lock().await;
        if claims.is_empty() {
            all.remove(interface);
        } else {
            all.insert(interface.to_string(), claims.clone());
        }
        self.persist(interface, &claims)
    }

    fn persist(
        &self,
        interface: &str,
        claims: &[AddressClaim],
    ) -> Result<(), OwnershipJournalError> {
        let Some(store) = &self.inner.store else {
            return Ok(());
        };
        if claims.is_empty() {
            store.remove(interface)?;
            return Ok(());
        }
        let record = InterfaceAddressClaims {
            schema_version: ADDRESS_CLAIM_SCHEMA_VERSION,
            interface: interface.to_string(),
            claims: claims.to_vec(),
        };
        let mut document = serde_json::to_vec_pretty(&record)?;
        document.push(b'\n');
        store.write(interface, &document)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::netlink::{AddressOwnership, TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL};

    use super::*;

    fn address(last: u8, protocol: Option<u8>) -> Ipv4AddressInfo {
        Ipv4AddressInfo {
            interface_index: 1,
            address: Ipv4Addr::new(192, 0, 2, last),
            prefix_len: 24,
            protocol,
        }
    }

    #[tokio::test]
    async fn a_claim_survives_a_restart() {
        let directory = tempdir().expect("tempdir");
        let journal = AddressOwnershipJournal::open(directory.path()).expect("journal");

        journal
            .claim("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("claim");
        journal
            .confirm("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("confirm");

        let reopened = AddressOwnershipJournal::open(directory.path()).expect("reopen");
        assert!(reopened.owns("lan0", Ipv4Addr::new(192, 0, 2, 1), 24).await);
        assert!(!reopened.owns("lan1", Ipv4Addr::new(192, 0, 2, 1), 24).await);
        assert!(!reopened.owns("lan0", Ipv4Addr::new(192, 0, 2, 2), 24).await);
    }

    /// The reason the journal is written before the kernel is touched: an
    /// address installed by a daemon that died before it could write anything
    /// down is an address nobody will ever clean up.
    #[tokio::test]
    async fn an_interrupted_claim_still_counts_as_ours() {
        let directory = tempdir().expect("tempdir");
        let journal = AddressOwnershipJournal::open(directory.path()).expect("journal");

        journal
            .claim("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("claim");

        let reopened = AddressOwnershipJournal::open(directory.path()).expect("reopen");
        assert!(reopened.owns("lan0", Ipv4Addr::new(192, 0, 2, 1), 24).await);
        assert_eq!(
            reopened.claims("lan0").await[0].state,
            AddressClaimState::Claiming
        );
    }

    #[tokio::test]
    async fn releasing_a_claim_removes_the_document() {
        let directory = tempdir().expect("tempdir");
        let journal = AddressOwnershipJournal::open(directory.path()).expect("journal");
        journal
            .claim("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("claim");

        journal
            .releasing("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("releasing");
        assert!(
            journal.owns("lan0", Ipv4Addr::new(192, 0, 2, 1), 24).await,
            "an address on its way out is still ours until it is gone"
        );

        journal
            .release("lan0", Ipv4Addr::new(192, 0, 2, 1), 24)
            .await
            .expect("release");

        assert!(!journal.owns("lan0", Ipv4Addr::new(192, 0, 2, 1), 24).await);
        assert!(AddressOwnershipJournal::open(directory.path())
            .expect("reopen")
            .interfaces()
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn startup_drops_claims_the_machine_contradicts() {
        let journal = AddressOwnershipJournal::in_memory();
        for last in [1, 2, 3, 4] {
            journal
                .claim("lan0", Ipv4Addr::new(192, 0, 2, last), 24)
                .await
                .expect("claim");
        }

        let outcome = journal
            .reconcile(
                "lan0",
                &[
                    // Still ours, tag intact.
                    address(1, AddressOwnership::Static.protocol()),
                    // No tag: a kernel that cannot hold one, or an address we
                    // installed before tagging existed. The journal is what
                    // answers now, so this stays ours.
                    address(2, None),
                    // Claimed by our own DHCP client, which keeps its own
                    // record — not this one's to delete.
                    address(3, Some(TRAFFIC_MASQ_DHCP_ADDRESS_PROTOCOL)),
                    // 192.0.2.4 is simply gone.
                ],
            )
            .await
            .expect("reconcile");

        assert_eq!(
            outcome
                .kept
                .iter()
                .map(|claim| claim.address)
                .collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
        assert_eq!(outcome.dropped.len(), 2);
        assert!(journal.owns("lan0", Ipv4Addr::new(192, 0, 2, 2), 24).await);
        assert!(!journal.owns("lan0", Ipv4Addr::new(192, 0, 2, 3), 24).await);
        assert!(!journal.owns("lan0", Ipv4Addr::new(192, 0, 2, 4), 24).await);
    }

    #[tokio::test]
    async fn a_document_from_a_future_version_is_refused_rather_than_guessed_at() {
        let directory = tempdir().expect("tempdir");
        let store = PrivateJsonDirectory::open(directory.path(), "address-ownership").expect("dir");
        store
            .write(
                "lan0",
                br#"{"schema_version":99,"interface":"lan0","claims":[]}"#,
            )
            .expect("write");

        assert!(matches!(
            AddressOwnershipJournal::open(directory.path()),
            Err(OwnershipJournalError::UnsupportedSchema(99))
        ));
    }
}
