use std::{
    fs,
    net::Ipv4Addr,
    os::unix::fs::{symlink, MetadataExt},
};

use tempfile::tempdir;

use super::*;
use crate::dhcp::client::lease::{DhcpClientLeaseState, DHCP_CLIENT_LEASE_SCHEMA_VERSION};

fn lease() -> DhcpClientLease {
    DhcpClientLease {
        schema_version: DHCP_CLIENT_LEASE_SCHEMA_VERSION,
        state: DhcpClientLeaseState::PendingApply,
        interface: "eth0".into(),
        interface_index: 2,
        hardware_address: vec![2, 0, 0, 0, 0, 1],
        client_identifier: vec![1, 2, 0, 0, 0, 0, 1],
        policy: None,
        server_identifier: Ipv4Addr::new(192, 0, 2, 1),
        address: Ipv4Addr::new(192, 0, 2, 20),
        prefix_len: 24,
        routers: vec![Ipv4Addr::new(192, 0, 2, 1)],
        dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        lease_seconds: 3600,
        renewal_seconds: 1800,
        rebinding_seconds: 3150,
        expires_at_unix: 10_000,
        owned_routes: vec![],
    }
}

#[test]
fn creates_private_directory_and_atomic_private_file_and_overwrites() {
    let root = tempdir().unwrap();
    let store = DhcpClientLeaseStore::new(root.path()).unwrap();
    assert_eq!(
        fs::metadata(store.directory()).unwrap().mode() & 0o777,
        0o700
    );
    let mut expected = lease();
    store.save(&expected).unwrap();
    let path = store.directory().join("eth0.json");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    expected.state = DhcpClientLeaseState::Bound;
    store.save(&expected).unwrap();
    assert_eq!(store.load("eth0").unwrap(), Some(expected));
    assert!(fs::read_dir(store.directory()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
}

#[test]
fn rejects_traversal_symlinks_and_unsupported_schema() {
    let root = tempdir().unwrap();
    let store = DhcpClientLeaseStore::new(root.path()).unwrap();
    assert!(matches!(
        store.load("../eth0"),
        Err(LeaseStoreError::InvalidInterface)
    ));
    let target = root.path().join("target");
    fs::write(&target, b"do not replace").unwrap();
    symlink(&target, store.directory().join("eth0.json")).unwrap();
    assert!(matches!(
        store.save(&lease()),
        Err(LeaseStoreError::Symlink(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"do not replace");
    fs::remove_file(store.directory().join("eth0.json")).unwrap();
    fs::write(
        store.directory().join("eth0.json"),
        br#"{"schema_version":99}"#,
    )
    .unwrap();
    assert!(matches!(
        store.load("eth0"),
        Err(LeaseStoreError::UnsupportedSchema(99))
    ));
}

#[test]
fn rejects_symlinked_store_directory() {
    let root = tempdir().unwrap();
    let elsewhere = tempdir().unwrap();
    symlink(elsewhere.path(), root.path().join("dhcp-client")).unwrap();
    assert!(matches!(
        DhcpClientLeaseStore::new(root.path()),
        Err(LeaseStoreError::Symlink(_))
    ));
}
