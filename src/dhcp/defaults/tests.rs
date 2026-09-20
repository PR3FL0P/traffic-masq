use super::*;

#[test]
fn pools_exclude_router_network_and_broadcast_for_every_host_in_small_subnets() {
    for prefix in 24..=30 {
        let network = ipnet::Ipv4Net::new("192.168.0.0".parse().unwrap(), prefix).unwrap();
        for router in network.hosts() {
            let cidr = ipnet::Ipv4Net::new(router, prefix).unwrap();
            let (start, end) = suggest_pool(cidr).unwrap();
            assert!(start <= end);
            assert!(start > cidr.network() && end < cidr.broadcast());
            assert!(router < start || router > end);
        }
    }
}

#[test]
fn rejects_non_host_addresses_and_tiny_subnets() {
    for cidr in ["10.0.0.0/24", "10.0.0.255/24", "10.0.0.0/31", "10.0.0.1/32"] {
        assert!(suggest_pool(cidr.parse().unwrap()).is_err());
    }
}
