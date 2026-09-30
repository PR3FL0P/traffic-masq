//! Maps typed control requests to the HTTP API.

use anyhow::{Context, Result};
use hyper::Method;
use serde::Serialize;

const API_PREFIX: &str = "/api/v1";

#[derive(Serialize)]
struct InterfaceRequestBody<'a, Interface> {
    config: &'a Interface,
    allow_management_change: bool,
}

#[derive(Serialize)]
struct TransactionRequestBody<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct VpnImportProfileRequestBody<'a> {
    name: &'a str,
    contents: &'a str,
}

#[derive(Serialize)]
struct VpnActivateRequestBody<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct VpnPolicySetModeRequestBody {
    mode: traffic_masq_protocol::VpnPolicyMode,
}

#[derive(Serialize)]
struct WifiSetPassphraseRequestBody<'a> {
    passphrase: &'a str,
}

#[derive(Serialize)]
struct ProvisionWifiAccessPointRequestBody<'a> {
    settings: &'a traffic_masq_protocol::WifiEditRequest,
    passphrase: &'a Option<String>,
    clear_passphrase: bool,
    configure_dhcp: bool,
    subnet: Option<ipnet::Ipv4Net>,
    disable_dhcp: bool,
}

pub struct RestRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub synthesize_pong: bool,
}

pub fn map_request<Interface: Serialize, Proposal: Serialize>(
    request: &traffic_masq_protocol::Request<Interface, Proposal>,
) -> Result<RestRequest> {
    use traffic_masq_protocol::Request;

    let mapped = match request {
        Request::Ping => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/status"),
            body: None,
            synthesize_pong: true,
        },
        Request::GetApiHttpsConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/access/https"),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureApiHttpsSettings { settings } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/access/https"),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ResetApiHttpsSettings => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/access/https"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetSecurityConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/security/settings"),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureSecuritySettings { settings } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/security/settings"),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ResetSecuritySettings => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/security/settings"),
            body: None,
            synthesize_pong: false,
        },
        Request::ListInterfaces => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/interfaces"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetInterfaceConfig { interface } => RestRequest {
            method: Method::GET,
            path: format!(
                "{API_PREFIX}/interfaces/{}/config",
                encode_path_segment(interface)
            ),
            body: None,
            synthesize_pong: false,
        },
        Request::DhcpStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/dhcp"),
            body: None,
            synthesize_pong: false,
        },
        Request::DhcpClientStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/dhcp-client"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetDhcpClient { interface } => RestRequest {
            method: Method::GET,
            path: dhcp_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcpClient { interface, config } => RestRequest {
            method: Method::PUT,
            path: dhcp_client_path(interface),
            body: Some(serialize_json(config)?),
            synthesize_pong: false,
        },
        Request::DisableDhcpClient { interface } => RestRequest {
            method: Method::DELETE,
            path: dhcp_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::RenewDhcpClient { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/renew", dhcp_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ReleaseDhcpClient { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/release", dhcp_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcpSettings {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: format!(
                "{API_PREFIX}/dhcp/{}/settings",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::GetDhcpConfig { interface } => RestRequest {
            method: Method::GET,
            path: dhcp_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureDhcp { interface, config } => RestRequest {
            method: Method::PUT,
            path: dhcp_path(interface),
            body: Some(serialize_json(config)?),
            synthesize_pong: false,
        },
        Request::DisableDhcp { interface } => RestRequest {
            method: Method::DELETE,
            path: dhcp_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ListLeases { interface } => RestRequest {
            method: Method::GET,
            path: format!("{}/leases", dhcp_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::DryRunInterface {
            interface,
            config,
            allow_management_change,
        } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/plan",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(&InterfaceRequestBody {
                config,
                allow_management_change: *allow_management_change,
            })?),
            synthesize_pong: false,
        },
        Request::DryRunInterfaceEdit { interface, edit } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/edit/plan",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(edit)?),
            synthesize_pong: false,
        },
        Request::ApplyInterface {
            interface,
            config,
            allow_management_change,
        } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/apply",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(&InterfaceRequestBody {
                config,
                allow_management_change: *allow_management_change,
            })?),
            synthesize_pong: false,
        },
        Request::ApplyInterfaceEdit { interface, edit } => RestRequest {
            method: Method::POST,
            path: format!(
                "{API_PREFIX}/interfaces/{}/edit/apply",
                encode_path_segment(interface)
            ),
            body: Some(serialize_json(edit)?),
            synthesize_pong: false,
        },
        Request::CommitNetworkChange { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/network-transactions/commit"),
            body: Some(serialize_json(&TransactionRequestBody { token })?),
            synthesize_pong: false,
        },
        Request::RollbackNetworkChange { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/network-transactions/rollback"),
            body: Some(serialize_json(&TransactionRequestBody { token })?),
            synthesize_pong: false,
        },
        Request::PendingNetworkChanges => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/network-transactions"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterPlan { proposal } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/plan"),
            body: Some(serialize_json(proposal)?),
            synthesize_pong: false,
        },
        Request::RouterApply { proposal } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/apply"),
            body: Some(serialize_json(proposal)?),
            synthesize_pong: false,
        },
        Request::RouterCommit { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/commit"),
            body: Some(serialize_json(&serde_json::json!({ "token": token }))?),
            synthesize_pong: false,
        },
        Request::RouterRollback { token } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/rollback"),
            body: Some(serialize_json(&serde_json::json!({ "token": token }))?),
            synthesize_pong: false,
        },
        Request::RouterPendingTransaction => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/pending"),
            body: None,
            synthesize_pong: false,
        },
        Request::ListRoutes {
            include_local_table,
        } => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/routes?include_local_table={include_local_table}"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetRouterConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/config"),
            body: None,
            synthesize_pong: false,
        },

        Request::RouterProvisioningPreview { request } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/preview"),
            body: Some(serialize_json(request)?),
            synthesize_pong: false,
        },
        Request::RouterProvisioningApply { request } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/apply"),
            body: Some(serialize_json(request)?),
            synthesize_pong: false,
        },
        Request::RouterProvisioningStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/router/provisioning/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::RouterProvisioningRepair => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/router/provisioning/repair"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnListProfiles => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn/profiles"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnImportProfile { name, contents } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/profiles"),
            body: Some(serialize_json(&VpnImportProfileRequestBody {
                name,
                contents,
            })?),
            synthesize_pong: false,
        },
        Request::VpnDeleteProfile { name } => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/vpn/profiles/{}", encode_path_segment(name)),
            body: None,
            synthesize_pong: false,
        },
        Request::GetVpnConfig => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn/config"),
            body: None,
            synthesize_pong: false,
        },
        Request::SetVpnEnabled { enabled } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/vpn/config"),
            body: Some(serialize_json(&serde_json::json!({ "enabled": enabled }))?),
            synthesize_pong: false,
        },
        Request::VpnStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnActivate { name } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/activate"),
            body: Some(serialize_json(&VpnActivateRequestBody { name })?),
            synthesize_pong: false,
        },
        Request::VpnDeactivate => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/vpn/deactivate"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnPolicyStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/vpn-policy/status"),
            body: None,
            synthesize_pong: false,
        },
        Request::VpnPolicySetMode { mode } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/vpn-policy/mode"),
            body: Some(serialize_json(&VpnPolicySetModeRequestBody {
                mode: *mode,
            })?),
            synthesize_pong: false,
        },
        Request::VpnPolicyClearMode => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/vpn-policy/mode"),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiConfig { interface } => RestRequest {
            method: Method::GET,
            path: wifi_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureWifi {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: wifi_path(interface),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ProvisionWifiAccessPoint {
            interface,
            settings,
            passphrase,
            clear_passphrase,
            configure_dhcp,
            subnet,
            disable_dhcp,
        } => RestRequest {
            method: Method::POST,
            path: format!("{}/provision", wifi_path(interface)),
            body: Some(serialize_json(&ProvisionWifiAccessPointRequestBody {
                settings,
                passphrase,
                clear_passphrase: *clear_passphrase,
                configure_dhcp: *configure_dhcp,
                subnet: *subnet,
                disable_dhcp: *disable_dhcp,
            })?),
            synthesize_pong: false,
        },
        Request::DisableWifi { interface } => RestRequest {
            method: Method::DELETE,
            path: wifi_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiSetPassphrase {
            interface,
            passphrase,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/passphrase", wifi_path(interface)),
            body: Some(serialize_json(&WifiSetPassphraseRequestBody {
                passphrase,
            })?),
            synthesize_pong: false,
        },
        Request::ListWifiStations { interface } => RestRequest {
            method: Method::GET,
            path: format!("{}/stations", wifi_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiDeauthStation { interface, mac } => RestRequest {
            method: Method::POST,
            path: format!(
                "{}/stations/{}/deauthenticate",
                wifi_path(interface),
                encode_path_segment(mac)
            ),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiReload { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/reload", wifi_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientStatus => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi-client"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiClientConfig { interface } => RestRequest {
            method: Method::GET,
            path: wifi_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::ConfigureWifiClient {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: wifi_client_path(interface),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::DisableWifiClient { interface } => RestRequest {
            method: Method::DELETE,
            path: wifi_client_path(interface),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientSetPassphrase {
            interface,
            passphrase,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/passphrase", wifi_client_path(interface)),
            body: Some(serialize_json(&WifiSetPassphraseRequestBody {
                passphrase,
            })?),
            synthesize_pong: false,
        },
        Request::WifiClientReconnect { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/reconnect", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::WifiClientScan { interface } => RestRequest {
            method: Method::POST,
            path: format!("{}/scan", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
        Request::ListWifiApProfiles => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi-ap-profiles"),
            body: None,
            synthesize_pong: false,
        },
        Request::SaveWifiApProfile { profile } => RestRequest {
            method: Method::PUT,
            path: format!("{API_PREFIX}/wifi-ap-profiles"),
            body: Some(serialize_json(profile)?),
            synthesize_pong: false,
        },
        Request::DeleteWifiApProfile { id } => RestRequest {
            method: Method::DELETE,
            path: format!("{API_PREFIX}/wifi-ap-profiles/{}", encode_path_segment(id)),
            body: None,
            synthesize_pong: false,
        },
        Request::ActivateWifiApProfile {
            interface,
            profile_id,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/profile", wifi_path(interface)),
            body: Some(serialize_json(
                &traffic_masq_protocol::WifiClientProfileActivationRequest {
                    profile_id: profile_id.clone(),
                },
            )?),
            synthesize_pong: false,
        },
        Request::ListWifiClientProfiles => RestRequest {
            method: Method::GET,
            path: format!("{API_PREFIX}/wifi-client/profiles"),
            body: None,
            synthesize_pong: false,
        },
        Request::GetWifiClientProfile { id } => RestRequest {
            method: Method::GET,
            path: wifi_client_profile_path(id),
            body: None,
            synthesize_pong: false,
        },
        Request::CreateWifiClientProfile { profile } => RestRequest {
            method: Method::POST,
            path: format!("{API_PREFIX}/wifi-client/profiles"),
            body: Some(serialize_json(profile)?),
            synthesize_pong: false,
        },
        Request::UpdateWifiClientProfile { id, profile } => RestRequest {
            method: Method::PUT,
            path: wifi_client_profile_path(id),
            body: Some(serialize_json(profile)?),
            synthesize_pong: false,
        },
        Request::DeleteWifiClientProfile { id } => RestRequest {
            method: Method::DELETE,
            path: wifi_client_profile_path(id),
            body: None,
            synthesize_pong: false,
        },
        Request::ProvisionWifiClient {
            interface,
            settings,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/provision", wifi_client_path(interface)),
            body: Some(serialize_json(settings)?),
            synthesize_pong: false,
        },
        Request::ActivateWifiClientProfile {
            interface,
            profile_id,
        } => RestRequest {
            method: Method::PUT,
            path: format!("{}/active-profile", wifi_client_path(interface)),
            body: Some(serialize_json(
                &traffic_masq_protocol::WifiClientProfileActivationRequest {
                    profile_id: profile_id.clone(),
                },
            )?),
            synthesize_pong: false,
        },
        Request::DeactivateWifiClientProfile { interface } => RestRequest {
            method: Method::DELETE,
            path: format!("{}/active-profile", wifi_client_path(interface)),
            body: None,
            synthesize_pong: false,
        },
    };

    Ok(mapped)
}

fn dhcp_path(interface: &str) -> String {
    format!("{API_PREFIX}/dhcp/{}", encode_path_segment(interface))
}

fn wifi_path(interface: &str) -> String {
    format!("{API_PREFIX}/wifi/{}", encode_path_segment(interface))
}

fn wifi_client_profile_path(id: &str) -> String {
    format!(
        "{API_PREFIX}/wifi-client/profiles/{}",
        encode_path_segment(id)
    )
}

fn dhcp_client_path(interface: &str) -> String {
    format!(
        "{API_PREFIX}/dhcp-client/{}",
        encode_path_segment(interface)
    )
}

fn wifi_client_path(interface: &str) -> String {
    format!(
        "{API_PREFIX}/wifi-client/{}",
        encode_path_segment(interface)
    )
}

fn serialize_json(value: &(impl Serialize + ?Sized)) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("failed to encode API request body")
}

/// Percent-encode a value as one URL path segment so reserved bytes cannot alter routing.
pub fn encode_path_segment(segment: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    type Request = traffic_masq_protocol::Request<serde_json::Value, serde_json::Value>;

    #[test]
    fn maps_generic_router_proposal_without_daemon_types() {
        let proposal = serde_json::json!({
            "clear_router": false,
            "set_interfaces": {},
            "remove_interfaces": []
        });
        let mapped = map_request(&Request::RouterPlan {
            proposal: proposal.clone(),
        })
        .unwrap();
        assert_eq!(mapped.method, Method::POST);
        assert_eq!(mapped.path, "/api/v1/router/plan");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&mapped.body.unwrap()).unwrap(),
            proposal
        );
    }

    #[test]
    fn encodes_interface_name_as_one_path_segment() {
        let mapped = map_request(&Request::GetInterfaceConfig {
            interface: "wan/guest".into(),
        })
        .unwrap();
        assert_eq!(mapped.path, "/api/v1/interfaces/wan%2Fguest/config");
    }
}
