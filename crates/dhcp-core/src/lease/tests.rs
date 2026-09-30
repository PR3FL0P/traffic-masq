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
