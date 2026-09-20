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
