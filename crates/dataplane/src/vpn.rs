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
    pub protected_subnets: Vec<Ipv4Net>,
    pub vpn_interface: String,
    pub physical_uplink: String,
}

impl VpnPolicyFirewallDesired {
    pub fn validate(&self) -> Result<()> {
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

    batch.push_str(&format!(
        "table inet {NFT_VPN_TABLE} {{\n  comment \"{NFT_VPN_TABLE_COMMENT}\"\n  chain metadata {{\n{metadata_rules}  }}\n  set protected_subnets {{ type ipv4_addr; flags interval; elements = {{ {subnets} }} }}\n  chain vpn_mark {{\n    type filter hook prerouting priority mangle; policy accept;\n    ip saddr @protected_subnets meta mark set {mark}\n  }}\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    meta mark and {mask} == {mark} oifname \"{vpn_iface}\" masquerade\n  }}\n  chain killswitch {{\n    type filter hook forward priority filter; policy accept;\n    meta mark and {mask} == {mark} oifname \"{uplink}\" drop\n  }}\n}}\n",
        vpn_iface = desired.vpn_interface,
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
    let chains_ok = metadata_ok
        && mark_chain_ok
        && postrouting_chain_ok
        && killswitch_chain_ok
        && chains.len() == 4;

    let expected_subnets = desired
        .protected_subnets
        .iter()
        .map(|subnet| subnet.to_string())
        .collect::<Vec<_>>();
    let subnets_ok = sets.len() == 1
        && sets.iter().any(|set| {
            string_field(set, "name") == Some("protected_subnets")
                && string_field(set, "type") == Some("ipv4_addr")
                && value_contains_token(set.get("flags").unwrap_or(&Value::Null), "interval")
                && exact_owned_elements(set, &expected_subnets)
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
    let masquerade_ok = postrouting_rules.len() == 1
        && postrouting_rules.iter().any(|rule| {
            rule_has_tokens(rule, &["oifname", desired.vpn_interface.as_str()])
                && value_contains_key(rule, "masquerade")
                && value_contains_number(rule, fw_mark)
                && value_contains_number(rule, fw_mask)
        });
    let killswitch_ok = killswitch_rules.len() == 1
        && killswitch_rules.iter().any(|rule| {
            rule_has_tokens(rule, &["oifname", desired.physical_uplink.as_str()])
                && value_contains_key(rule, "drop")
                && value_contains_number(rule, fw_mark)
                && value_contains_number(rule, fw_mask)
        });

    chains_ok && subnets_ok && mark_ok && masquerade_ok && killswitch_ok
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
                vpn_rule("postrouting", serde_json::json!([
                    { "match": { "op": "==", "left": { "&": [{ "meta": { "key": "mark" } }, fw_mask] }, "right": fw_mark } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": desired.vpn_interface } },
                    { "masquerade": null }
                ])),
                vpn_rule("killswitch", serde_json::json!([
                    { "match": { "op": "==", "left": { "&": [{ "meta": { "key": "mark" } }, fw_mask] }, "right": fw_mark } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": desired.physical_uplink } },
                    { "drop": null }
                ])),
            ]);
        }
        serde_json::to_vec(&serde_json::json!({ "nftables": entries })).expect("ruleset")
    }
}

#[cfg(test)]
mod tests;
