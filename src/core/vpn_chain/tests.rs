use super::*;

#[test]
fn relay_hop_carries_no_protected_subnets_or_killswitch() {
    let hop = VpnHopDesired {
        hop_index: 0,
        profile_name: "relay1.conf".to_string(),
        interface: "tm-wg-0".to_string(),
        upstream: "wan0".to_string(),
        reserved: VpnPolicyReservedIds::for_hop(0).expect("hop 0 reserved ids"),
        kind: VpnHopKind::Relay {
            own_route: VpnHopRoutingDesired {
                hop_interface: "tm-wg-0".to_string(),
                upstream_interface: "wan0".to_string(),
            },
        },
    };
    match hop.kind {
        VpnHopKind::Relay { own_route } => {
            assert_eq!(own_route.hop_interface, "tm-wg-0");
            assert_eq!(own_route.upstream_interface, "wan0");
        }
        VpnHopKind::Exit { .. } => panic!("expected relay hop"),
    }
}
