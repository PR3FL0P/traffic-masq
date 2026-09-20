use std::net::Ipv4Addr;

use tempfile::tempdir;

use super::*;

#[tokio::test]
async fn saves_and_loads_leases_atomically() {
    let directory = tempdir().expect("tempdir");
    let store = LeaseStore::for_interface(directory.path(), "wlan0");
    let leases = vec![DhcpLease {
        mac: [1, 2, 3, 4, 5, 6],
        ip: Ipv4Addr::new(192, 168, 10, 100),
        expires_at_unix: 123_456,
    }];

    store.save(&leases).await.expect("save");
    assert!(store.path().exists());
    assert_eq!(store.load().await.expect("load"), leases);
}

#[tokio::test]
async fn missing_lease_file_loads_as_empty() {
    let directory = tempdir().expect("tempdir");
    let store = LeaseStore::for_interface(directory.path(), "wlan0");
    assert!(store.load().await.expect("load").is_empty());
}
