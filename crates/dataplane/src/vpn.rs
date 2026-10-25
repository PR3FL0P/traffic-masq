use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    exact_owned_elements, hex_decode, hex_encode, rule_has_tokens, string_field,
    validate_interface_name, value_contains_key, value_contains_token, NftExecutor, NFT_FAMILY,
    NFT_METADATA_HEX_CHUNK_LEN,
};

const NFT_VPN_TABLE: &str = "traffic_masq_vpn";
const NFT_VPN_TABLE_COMMENT: &str = "traffic-masq:vpn:v1";
const NFT_VPN_METADATA_COMMENT_PREFIX: &str = "traffic-masq:vpn:v1:part:";

/// The mark traffic-masq sets on packets it has decided must leave via the VPN,
/// and the mask that isolates it from marks other software owns.
///
/// These live here, with the nftables backend that writes them, rather than
/// with the policy that decides when to apply them: a firewall mark is a
/// property of the dataplane. Keeping them in `core::vpn_policy` made the
/// domain layer and its driver mutually dependent for the sake of two integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FirewallMark(u32);

impl FirewallMark {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FirewallMarkMask(u32);

impl FirewallMarkMask {
    pub const fn get(self) -> u32 {
        self.0
    }
}

pub const VPN_POLICY_FWMARK: FirewallMark = FirewallMark(0x5400_0000);
pub const VPN_POLICY_FWMASK: FirewallMarkMask = FirewallMarkMask(0xff00_0000);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnPolicyFirewallDesired {
    /// Standalone policy supplies NAT; router chains use explicit forwarding NAT instead.
    #[serde(
        default = "default_masquerade_forwarded",
        skip_serializing_if = "masquerades_forwarded"
    )]
    pub masquerade_forwarded: bool,
    pub protected_subnets: Vec<Ipv4Net>,
    pub vpn_interface: String,
    pub physical_uplink: String,
    /// Also send the router's own locally generated traffic through the VPN.
    /// Absent means only forwarded LAN traffic is protected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_traffic: Option<VpnHostTrafficDesired>,
}

/// Router-originated traffic policy. Everything except the exclusions below is
/// marked for the VPN, dropped if it would leave via the physical uplink, and
/// any non-link-local IPv6 egress is blocked (IPv6 is not tunnelled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnHostTrafficDesired {
    /// Resolved WireGuard endpoints of every hop. Traffic to them must stay
    /// unmarked or the tunnel's own handshake would be routed into itself.
    pub vpn_endpoints: Vec<Ipv4Addr>,
}

impl VpnHostTrafficDesired {
    fn validate(&self) -> Result<()> {
        if self.vpn_endpoints.is_empty() {
            bail!("routing router traffic through the VPN requires at least one VPN endpoint");
        }
        for (index, endpoint) in self.vpn_endpoints.iter().enumerate() {
            if endpoint.is_unspecified()
                || endpoint.is_loopback()
                || endpoint.is_multicast()
                || endpoint.is_broadcast()
            {
                bail!("invalid VPN endpoint address: {endpoint}");
            }
            if self.vpn_endpoints[..index].contains(endpoint) {
                bail!("duplicate VPN endpoint address: {endpoint}");
            }
        }
        Ok(())
    }
}

impl VpnPolicyFirewallDesired {
    pub fn validate(&self) -> Result<()> {
        if let Some(host) = &self.host_traffic {
            host.validate()?;
        }
        if self.protected_subnets.is_empty() {
            bail!("VPN policy firewall requires at least one protected subnet");
        }
        validate_interface_name(&self.vpn_interface).context("invalid VPN interface")?;
        validate_interface_name(&self.physical_uplink)
            .context("invalid physical uplink interface")?;
        if self.vpn_interface == self.physical_uplink {
            bail!(
                "VPN interface and physical uplink interface must be different: {}",
                self.vpn_interface
            );
        }
        for (index, subnet) in self.protected_subnets.iter().enumerate() {
            if self.protected_subnets[..index].contains(subnet) {
                bail!("duplicate protected subnet: {subnet}");
            }
        }
        Ok(())
    }
}

/// Async operations retain their shared executor reservation until the blocking
/// worker finishes. Synchronous entry points require caller serialization.
pub struct VpnPolicyFirewallBackend<E> {
    pub(crate) executor: E,
    operations: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl<E> VpnPolicyFirewallBackend<E>
where
    E: NftExecutor,
{
    pub fn new(executor: E) -> Self {
        let operations = executor.operation_gate().unwrap_or_default();
        Self {
            executor,
            operations,
        }
    }

    #[cfg(feature = "test-support")]
    pub fn executor(&self) -> &E {
        &self.executor
    }

    pub async fn observe_async(self: &std::sync::Arc<Self>) -> Result<VpnFirewallObservation> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            backend.observe()
        })
        .await?
    }

    pub async fn apply_async(
        self: &std::sync::Arc<Self>,
        desired: &VpnPolicyFirewallDesired,
    ) -> Result<()> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        let desired = desired.clone();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            backend.apply(&desired)
        })
        .await?
    }

    pub async fn restore_async(
        self: &std::sync::Arc<Self>,
        snapshot: Option<&VpnPolicyFirewallDesired>,
    ) -> Result<()> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        let snapshot = snapshot.cloned();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            backend.restore(snapshot.as_ref())
        })
        .await?
    }

    pub fn observe(&self) -> Result<VpnFirewallObservation> {
        let output = self
            .executor
            .execute(&["--json", "list", "ruleset"], &[])
            .context("failed to observe VPN policy firewall ruleset")?;
        parse_owned_vpn_firewall_state(&output)
    }

    pub fn apply(&self, desired: &VpnPolicyFirewallDesired) -> Result<()> {
        desired.validate()?;
        let current = self.observe()?;
        if current.integrity == VpnFirewallIntegrity::Intact
            && current.desired.as_ref() == Some(desired)
        {
            return Ok(());
        }
        let batch = render_vpn_nftables_batch(current.desired.is_some(), Some(desired))?;
        self.executor
            .execute(&["-f", "-"], batch.as_bytes())
            .context("failed to apply atomic owned VPN policy firewall batch")?;
        Ok(())
    }

    pub fn restore(&self, snapshot: Option<&VpnPolicyFirewallDesired>) -> Result<()> {
        if let Some(desired) = snapshot {
            desired.validate()?;
        }
        let current = self.observe()?;
        if current.integrity == VpnFirewallIntegrity::Intact && current.desired.as_ref() == snapshot
        {
            return Ok(());
        }
        let batch = render_vpn_nftables_batch(current.desired.is_some(), snapshot)?;
        self.executor
            .execute(&["-f", "-"], batch.as_bytes())
            .context("failed to restore atomic owned VPN policy firewall batch")?;
        Ok(())
    }
}

fn render_vpn_nftables_batch(
    table_exists: bool,
    desired: Option<&VpnPolicyFirewallDesired>,
) -> Result<String> {
    let mut batch = String::new();
    if table_exists {
        batch.push_str("delete table inet traffic_masq_vpn\n");
    }
    let Some(desired) = desired else {
        return Ok(batch);
    };

    let metadata = hex_encode(&serde_json::to_vec(desired)?);
    let metadata_rules = metadata
        .as_bytes()
        .chunks(NFT_METADATA_HEX_CHUNK_LEN)
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "    counter comment \"{NFT_VPN_METADATA_COMMENT_PREFIX}{index:04}:{}\"\n",
                String::from_utf8_lossy(chunk)
            )
        })
        .collect::<String>();

    let subnets = desired
        .protected_subnets
        .iter()
        .map(|subnet| subnet.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mark = format!("{:#010x}", VPN_POLICY_FWMARK.get());
    let mask = format!("{:#010x}", VPN_POLICY_FWMASK.get());

    // Host traffic still needs its source translated, but must not override
    // a forwarding rule's No NAT choice. Locally generated packets have iif 0.
    let nat = if desired.masquerade_forwarded || desired.host_traffic.is_some() {
        format!(
            "    {}meta mark and {mask} == {mark} oifname \"{}\" masquerade\n",
            if desired.masquerade_forwarded {
                ""
            } else {
                "meta iif 0 "
            },
            desired.vpn_interface,
        )
    } else {
        String::new()
    };

    let (host_set, host_chains) = match &desired.host_traffic {
        None => (String::new(), String::new()),
        Some(host) => {
            let endpoints = host
                .vpn_endpoints
                .iter()
                .map(|endpoint| endpoint.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            (
                format!("  set vpn_endpoints {{ type ipv4_addr; elements = {{ {endpoints} }} }}\n"),
                format!(
                    "  chain host_mark {{\n    type route hook output priority mangle; policy accept;\n    oifname \"lo\" return\n    ip daddr @vpn_endpoints return\n    ip daddr @protected_subnets return\n    ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} return\n    udp dport {{ 67, 68 }} return\n    meta nfproto ipv4 meta mark set {mark}\n  }}\n  chain host_killswitch {{\n    type filter hook output priority filter; policy accept;\n    meta nfproto ipv4 meta mark and {mask} == {mark} oifname != \"{vpn_iface}\" drop\n    oifname != \"lo\" ip6 daddr != {{ fe80::/10, ff00::/8 }} drop\n  }}\n",
                    vpn_iface = desired.vpn_interface,
                ),
            )
        }
    };

    batch.push_str(&format!(
        "table inet {NFT_VPN_TABLE} {{\n  comment \"{NFT_VPN_TABLE_COMMENT}\"\n  chain metadata {{\n{metadata_rules}  }}\n  set protected_subnets {{ type ipv4_addr; flags interval; elements = {{ {subnets} }} }}\n{host_set}  chain vpn_mark {{\n    type filter hook prerouting priority mangle; policy accept;\n    ip saddr @protected_subnets meta mark set {mark}\n  }}\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n{nat}  }}\n  chain killswitch {{\n    type filter hook forward priority filter; policy accept;\n    meta mark and {mask} == {mark} oifname \"{uplink}\" drop\n  }}\n{host_chains}}}\n",
        uplink = desired.physical_uplink,
    ));
    Ok(batch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnFirewallIntegrity {
    Intact,
    Drifted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnFirewallObservation {
    pub desired: Option<VpnPolicyFirewallDesired>,
    pub integrity: VpnFirewallIntegrity,
}

fn parse_owned_vpn_firewall_state(output: &[u8]) -> Result<VpnFirewallObservation> {
    let ruleset: Value = serde_json::from_slice(output).context("nft returned invalid JSON")?;
    let entries = ruleset
        .get("nftables")
        .and_then(Value::as_array)
        .context("nft JSON does not contain an nftables array")?;
    for entry in entries {
        let Some(table) = entry.get("table") else {
            continue;
        };
        if table.get("family").and_then(Value::as_str) != Some(NFT_FAMILY)
            || table.get("name").and_then(Value::as_str) != Some(NFT_VPN_TABLE)
        {
            continue;
        }
        let comment = table
            .get("comment")
            .and_then(Value::as_str)
            .context("owned VPN firewall table has no traffic-masq metadata comment")?;
        if comment != NFT_VPN_TABLE_COMMENT {
            bail!("owned VPN firewall table has unsupported metadata");
        }
        let encoded = collect_vpn_metadata_chunks(entries)?;
        let desired: VpnPolicyFirewallDesired = serde_json::from_slice(&hex_decode(&encoded)?)
            .context("owned VPN firewall metadata is invalid")?;
        desired
            .validate()
            .context("owned VPN firewall metadata is unsafe")?;
        let integrity = if vpn_firewall_structure_is_intact(entries, &desired) {
            VpnFirewallIntegrity::Intact
        } else {
            VpnFirewallIntegrity::Drifted
        };
        return Ok(VpnFirewallObservation {
            desired: Some(desired),
            integrity,
        });
    }
    Ok(VpnFirewallObservation {
        desired: None,
        integrity: VpnFirewallIntegrity::Intact,
    })
}

fn collect_vpn_metadata_chunks(entries: &[Value]) -> Result<String> {
    let mut chunks = Vec::new();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        if rule.get("family").and_then(Value::as_str) != Some(NFT_FAMILY)
            || rule.get("table").and_then(Value::as_str) != Some(NFT_VPN_TABLE)
            || rule.get("chain").and_then(Value::as_str) != Some("metadata")
        {
            continue;
        }
        let Some(comment) = rule.get("comment").and_then(Value::as_str) else {
            continue;
        };
        let Some(part) = comment.strip_prefix(NFT_VPN_METADATA_COMMENT_PREFIX) else {
            continue;
        };
        let (index, chunk) = part
            .split_once(':')
            .context("owned VPN firewall metadata chunk has no index")?;
        let index = index
            .parse::<usize>()
            .context("owned VPN firewall metadata chunk index is invalid")?;
        chunks.push((index, chunk));
    }
    chunks.sort_unstable_by_key(|(index, _)| *index);
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
    {
        bail!("owned VPN firewall metadata chunks are missing or non-contiguous");
    }
    Ok(chunks.into_iter().map(|(_, chunk)| chunk).collect())
}

fn value_contains_number(value: &Value, number: u64) -> bool {
    match value {
        Value::Number(candidate) => candidate.as_u64() == Some(number),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_number(value, number)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_number(value, number)),
        _ => false,
    }
}

/// Canonical ordered expressions, including match operators and verdicts.
fn host_rule_expressions(vpn_interface: &str) -> (Vec<Value>, Vec<Value>) {
    use serde_json::json;
    let meta = |key| json!({"meta": {"key": key}});
    let payload = |protocol, field| json!({"payload": {"protocol": protocol, "field": field}});
    let condition =
        |op, left: Value, right: Value| json!({"match": {"op": op, "left": left, "right": right}});
    let ret = json!({"return": null});
    let ipv4 = condition("==", meta("nfproto"), json!("ipv4"));
    let mark = VPN_POLICY_FWMARK.get();
    let mask = VPN_POLICY_FWMASK.get();
    (
        vec![
            json!([condition("==", meta("oifname"), json!("lo")), ret]),
            json!([
                condition("==", payload("ip", "daddr"), json!("@vpn_endpoints")),
                ret
            ]),
            json!([
                condition("==", payload("ip", "daddr"), json!("@protected_subnets")),
                ret
            ]),
            json!([
                condition(
                    "==",
                    payload("ip", "daddr"),
                    json!({"set": ["224.0.0.0/4", "255.255.255.255"]})
                ),
                ret
            ]),
            json!([
                condition("==", payload("udp", "dport"), json!({"set": [67, 68]})),
                ret
            ]),
            json!([ipv4, {"mangle": {"key": meta("mark"), "value": mark}}]),
        ],
        vec![
            json!([ipv4,
                condition("==", json!({"&": [meta("mark"), mask]}), json!(mark)),
                condition("!=", meta("oifname"), json!(vpn_interface)), {"drop": null}]),
            json!([condition("!=", meta("oifname"), json!("lo")),
                condition("!=", payload("ip6", "daddr"), json!({"set": ["fe80::/10", "ff00::/8"]})), {"drop": null}]),
        ],
    )
}

/// nft emits prefixes as objects and may reorder anonymous set elements.
/// Preserve all other expression structure, especially operators and rule order.
fn normalize_expression(value: &Value) -> Value {
    // nft represents interface index zero as either a number or the string "0".
    // Normalize only this exact meta-iif comparison, keeping its operator intact.
    if let Some(condition) = value.get("match") {
        if condition.get("left") == Some(&serde_json::json!({"meta": {"key": "iif"}}))
            && condition.get("right").and_then(Value::as_str) == Some("0")
        {
            let mut normalized = value.clone();
            normalized["match"]["right"] = Value::from(0);
            return normalized;
        }
    }
    if let Some(prefix) = value.get("prefix") {
        if let (Some(address), Some(length)) = (
            prefix.get("addr").and_then(Value::as_str),
            prefix.get("len").and_then(Value::as_u64),
        ) {
            return Value::String(format!("{address}/{length}"));
        }
    }
    match value {
        Value::Array(values) => Value::Array(values.iter().map(normalize_expression).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| {
                    let mut value = normalize_expression(value);
                    if key == "set" {
                        if let Value::Array(elements) = &mut value {
                            elements.sort_by_key(Value::to_string);
                        }
                    }
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn nat_rule_expression(desired: &VpnPolicyFirewallDesired) -> Option<Value> {
    use serde_json::json;
    if !desired.masquerade_forwarded && desired.host_traffic.is_none() {
        return None;
    }
    let mut expressions = Vec::new();
    if !desired.masquerade_forwarded {
        expressions
            .push(json!({"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": 0}}));
    }
    expressions.extend([
        json!({"match": {"op": "==", "left": {"&": [{"meta": {"key": "mark"}}, VPN_POLICY_FWMASK.get()]}, "right": VPN_POLICY_FWMARK.get()}}),
        json!({"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": desired.vpn_interface}}),
        json!({"masquerade": null}),
    ]);
    Some(Value::Array(expressions))
}

fn vpn_firewall_structure_is_intact(entries: &[Value], desired: &VpnPolicyFirewallDesired) -> bool {
    let owned = |value: &Value| -> bool {
        string_field(value, "family") == Some(NFT_FAMILY)
            && string_field(value, "table") == Some(NFT_VPN_TABLE)
    };
    let chains = entries
        .iter()
        .filter_map(|entry| entry.get("chain"))
        .filter(|chain| owned(chain))
        .collect::<Vec<_>>();
    let sets = entries
        .iter()
        .filter_map(|entry| entry.get("set"))
        .filter(|set| owned(set))
        .collect::<Vec<_>>();
    let rules = entries
        .iter()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| owned(rule))
        .collect::<Vec<_>>();

    let metadata_ok = chains
        .iter()
        .any(|chain| string_field(chain, "name") == Some("metadata"));
    let mark_chain_ok = chains.iter().any(|chain| {
        string_field(chain, "name") == Some("vpn_mark")
            && string_field(chain, "type") == Some("filter")
            && string_field(chain, "hook") == Some("prerouting")
            && string_field(chain, "policy") == Some("accept")
    });
    let postrouting_chain_ok = chains.iter().any(|chain| {
        string_field(chain, "name") == Some("postrouting")
            && string_field(chain, "type") == Some("nat")
            && string_field(chain, "hook") == Some("postrouting")
            && string_field(chain, "policy") == Some("accept")
    });
    let killswitch_chain_ok = chains.iter().any(|chain| {
        string_field(chain, "name") == Some("killswitch")
            && string_field(chain, "type") == Some("filter")
            && string_field(chain, "hook") == Some("forward")
            && string_field(chain, "policy") == Some("accept")
    });
    let host = desired.host_traffic.as_ref();
    let host_chains_ok = match host {
        None => true,
        Some(_) => {
            chains.iter().any(|chain| {
                string_field(chain, "name") == Some("host_mark")
                    && chain.get("prio").and_then(Value::as_i64) == Some(-150)
                    && string_field(chain, "type") == Some("route")
                    && string_field(chain, "hook") == Some("output")
                    && string_field(chain, "policy") == Some("accept")
            }) && chains.iter().any(|chain| {
                string_field(chain, "name") == Some("host_killswitch")
                    && chain.get("prio").and_then(Value::as_i64) == Some(0)
                    && string_field(chain, "type") == Some("filter")
                    && string_field(chain, "hook") == Some("output")
                    && string_field(chain, "policy") == Some("accept")
            })
        }
    };
    let chains_ok = metadata_ok
        && mark_chain_ok
        && postrouting_chain_ok
        && killswitch_chain_ok
        && host_chains_ok
        && chains.len() == if host.is_some() { 6 } else { 4 };

    let expected_subnets = desired
        .protected_subnets
        .iter()
        .map(|subnet| subnet.to_string())
        .collect::<Vec<_>>();
    let subnets_ok = sets.len() == if host.is_some() { 2 } else { 1 }
        && sets.iter().any(|set| {
            string_field(set, "name") == Some("protected_subnets")
                && string_field(set, "type") == Some("ipv4_addr")
                && value_contains_token(set.get("flags").unwrap_or(&Value::Null), "interval")
                && exact_owned_elements(set, &expected_subnets)
        });
    let endpoints_ok = host.is_none_or(|host| {
        let expected = host
            .vpn_endpoints
            .iter()
            .map(|endpoint| endpoint.to_string())
            .collect::<Vec<_>>();
        sets.iter().any(|set| {
            string_field(set, "name") == Some("vpn_endpoints")
                && string_field(set, "type") == Some("ipv4_addr")
                && exact_owned_elements(set, &expected)
        })
    });
    let host_rules_ok = host.is_none_or(|_| {
        let host_mark = rules
            .iter()
            .filter(|rule| string_field(rule, "chain") == Some("host_mark"))
            .collect::<Vec<_>>();
        let host_kill = rules
            .iter()
            .filter(|rule| string_field(rule, "chain") == Some("host_killswitch"))
            .collect::<Vec<_>>();
        let (expected_mark, expected_kill) = host_rule_expressions(&desired.vpn_interface);
        let matches = |rules: &[&&Value], expected: &[Value]| {
            rules.len() == expected.len()
                && rules.iter().zip(expected).all(|(rule, expression)| {
                    rule.get("expr").is_some_and(|actual| {
                        normalize_expression(actual) == normalize_expression(expression)
                    })
                })
        };
        matches(&host_mark, &expected_mark) && matches(&host_kill, &expected_kill)
    });

    let mark_rules = rules
        .iter()
        .filter(|rule| string_field(rule, "chain") == Some("vpn_mark"))
        .collect::<Vec<_>>();
    let postrouting_rules = rules
        .iter()
        .filter(|rule| string_field(rule, "chain") == Some("postrouting"))
        .collect::<Vec<_>>();
    let killswitch_rules = rules
        .iter()
        .filter(|rule| string_field(rule, "chain") == Some("killswitch"))
        .collect::<Vec<_>>();

    let fw_mark = u64::from(VPN_POLICY_FWMARK.get());
    let fw_mask = u64::from(VPN_POLICY_FWMASK.get());

    let mark_ok = mark_rules.len() == 1
        && mark_rules.iter().any(|rule| {
            rule_has_tokens(rule, &["saddr", "protected_subnets"])
                && value_contains_key(rule, "mangle")
                && value_contains_number(rule, fw_mark)
        });
    let expected_nat = nat_rule_expression(desired);
    let masquerade_ok = match expected_nat {
        None => postrouting_rules.is_empty(),
        Some(expected) => {
            postrouting_rules.len() == 1
                && postrouting_rules[0]
                    .get("expr")
                    .is_some_and(|actual| normalize_expression(actual) == expected)
        }
    };
    let killswitch_ok = killswitch_rules.len() == 1
        && killswitch_rules.iter().any(|rule| {
            rule_has_tokens(rule, &["oifname", desired.physical_uplink.as_str()])
                && value_contains_key(rule, "drop")
                && value_contains_number(rule, fw_mark)
                && value_contains_number(rule, fw_mask)
        });

    chains_ok
        && subnets_ok
        && endpoints_ok
        && host_rules_ok
        && mark_ok
        && masquerade_ok
        && killswitch_ok
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[derive(Debug, Default)]
    pub struct FakeNftExecutor {
        responses: StdMutex<VecDeque<Result<Vec<u8>>>>,
        pub calls: StdMutex<Vec<(Vec<String>, Vec<u8>)>>,
    }

    impl FakeNftExecutor {
        pub fn with_responses(responses: Vec<Result<Vec<u8>>>) -> Self {
            Self {
                responses: StdMutex::new(responses.into()),
                calls: StdMutex::new(Vec::new()),
            }
        }
    }

    impl NftExecutor for FakeNftExecutor {
        fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
            self.calls.lock().expect("calls lock").push((
                arguments.iter().map(|value| (*value).to_string()).collect(),
                input.to_vec(),
            ));
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .expect("fake nft response")
        }
    }

    pub fn vpn_rule(chain: &str, expression: Value) -> Value {
        serde_json::json!({ "rule": {
            "family": NFT_FAMILY,
            "table": NFT_VPN_TABLE,
            "chain": chain,
            "expr": expression
        }})
    }

    pub fn nft_ruleset(owned: Option<&VpnPolicyFirewallDesired>) -> Vec<u8> {
        let mut entries = vec![
            serde_json::json!({
                "table": { "family": "inet", "name": "foreign", "comment": "untouched" }
            }),
            serde_json::json!({
                "table": { "family": "inet", "name": "traffic_masq", "comment": "traffic-masq:v1" }
            }),
        ];
        if let Some(desired) = owned {
            entries.push(serde_json::json!({
                "table": {
                    "family": NFT_FAMILY,
                    "name": NFT_VPN_TABLE,
                    "comment": NFT_VPN_TABLE_COMMENT
                }
            }));
            let encoded = hex_encode(&serde_json::to_vec(desired).expect("serialize desired"));
            for (index, chunk) in encoded
                .as_bytes()
                .chunks(NFT_METADATA_HEX_CHUNK_LEN)
                .enumerate()
            {
                entries.push(serde_json::json!({
                    "rule": {
                        "family": NFT_FAMILY,
                        "table": NFT_VPN_TABLE,
                        "chain": "metadata",
                        "comment": format!(
                            "{NFT_VPN_METADATA_COMMENT_PREFIX}{index:04}:{}",
                            String::from_utf8_lossy(chunk)
                        )
                    }
                }));
            }
            let fw_mark = VPN_POLICY_FWMARK.get();
            let fw_mask = VPN_POLICY_FWMASK.get();
            entries.extend([
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "metadata"
                }}),
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "vpn_mark",
                    "type": "filter", "hook": "prerouting", "prio": -150, "policy": "accept"
                }}),
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "postrouting",
                    "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"
                }}),
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "killswitch",
                    "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"
                }}),
                serde_json::json!({ "set": {
                    "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "protected_subnets",
                    "type": "ipv4_addr", "flags": ["interval"],
                    "elem": desired.protected_subnets.iter().map(|subnet| serde_json::json!({
                        "prefix": { "addr": subnet.network().to_string(), "len": subnet.prefix_len() }
                    })).collect::<Vec<_>>()
                }}),
                vpn_rule("vpn_mark", serde_json::json!([
                    { "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": "@protected_subnets" } },
                    { "mangle": { "key": { "meta": { "key": "mark" } }, "value": fw_mark } }
                ])),
                vpn_rule("killswitch", serde_json::json!([
                    { "match": { "op": "==", "left": { "&": [{ "meta": { "key": "mark" } }, fw_mask] }, "right": fw_mark } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": desired.physical_uplink } },
                    { "drop": null }
                ])),
            ]);
            if let Some(expression) = nat_rule_expression(desired) {
                entries.push(vpn_rule("postrouting", expression));
            }
            if let Some(host) = &desired.host_traffic {
                entries.extend([
                    serde_json::json!({ "chain": {
                        "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "host_mark",
                        "type": "route", "hook": "output", "prio": -150, "policy": "accept"
                    }}),
                    serde_json::json!({ "chain": {
                        "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "host_killswitch",
                        "type": "filter", "hook": "output", "prio": 0, "policy": "accept"
                    }}),
                    serde_json::json!({ "set": {
                        "family": NFT_FAMILY, "table": NFT_VPN_TABLE, "name": "vpn_endpoints",
                        "type": "ipv4_addr",
                        "elem": host.vpn_endpoints.iter().map(|endpoint| endpoint.to_string()).collect::<Vec<_>>()
                    }}),
                ]);
                let (mark_rules, kill_rules) = host_rule_expressions(&desired.vpn_interface);
                entries.extend(
                    mark_rules
                        .into_iter()
                        .map(|expression| vpn_rule("host_mark", expression)),
                );
                entries.extend(
                    kill_rules
                        .into_iter()
                        .map(|expression| vpn_rule("host_killswitch", expression)),
                );
            }
        }
        serde_json::to_vec(&serde_json::json!({ "nftables": entries })).expect("ruleset")
    }
}

fn default_masquerade_forwarded() -> bool {
    true
}

// Omit the historical default to preserve existing recovery fingerprints/metadata.
fn masquerades_forwarded(value: &bool) -> bool {
    *value
}

#[cfg(test)]
mod tests;
