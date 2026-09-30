use super::*;

#[test]
fn toggle_mode_flips_between_the_only_two_modes() {
    assert_eq!(toggle_mode(VpnPolicyMode::Direct), VpnPolicyMode::Vpn);
    assert_eq!(toggle_mode(VpnPolicyMode::Vpn), VpnPolicyMode::Direct);
}

#[test]
fn vpn_policy_field_reaches_every_row_and_clamps_at_both_ends() {
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Mode),
        VpnPolicyField::Apply
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Apply),
        VpnPolicyField::ClearOverride
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::ClearOverride),
        VpnPolicyField::Reload
    );
    assert_eq!(
        next_vpn_policy_field(VpnPolicyField::Reload),
        VpnPolicyField::Reload
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Reload),
        VpnPolicyField::ClearOverride
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::ClearOverride),
        VpnPolicyField::Apply
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Apply),
        VpnPolicyField::Mode
    );
    assert_eq!(
        previous_vpn_policy_field(VpnPolicyField::Mode),
        VpnPolicyField::Mode
    );
}

#[test]
fn formats_each_mode_distinctly() {
    assert_ne!(
        format_mode(VpnPolicyMode::Direct),
        format_mode(VpnPolicyMode::Vpn)
    );
}

#[test]
fn describes_each_vpn_policy_error_detail_distinctly() {
    let messages = [
        describe_vpn_policy_error(&VpnPolicyErrorDetail::VpnDisabled),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::NoProtectedSubnets),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::TunnelUnhealthy {
            message: "no active VPN tunnel".to_string(),
        }),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::ReservedNamespaceConflict {
            message: "foreign objects occupy the reserved namespace".to_string(),
        }),
        describe_vpn_policy_error(&VpnPolicyErrorDetail::Other {
            message: "boom".to_string(),
        }),
    ];

    for (index, message) in messages.iter().enumerate() {
        assert!(!message.is_empty());
        for (other_index, other) in messages.iter().enumerate() {
            if index != other_index {
                assert_ne!(message, other, "variants must not collapse into one string");
            }
        }
    }
    assert!(messages[2].contains("no active VPN tunnel"));
    assert!(messages[3].contains("foreign objects occupy the reserved namespace"));
    assert_eq!(messages[4], "boom");
}
