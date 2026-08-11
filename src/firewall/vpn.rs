use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    exact_owned_elements, hex_decode, hex_encode, rule_has_tokens, string_field,
    validate_interface_name, value_contains_key, value_contains_token, NftExecutor, NFT_FAMILY,
    NFT_METADATA_HEX_CHUNK_LEN,
};
use crate::core::vpn_policy::{VPN_POLICY_FWMARK, VPN_POLICY_FWMASK};

const NFT_VPN_TABLE: &str = "traffic_masq_vpn";
const NFT_VPN_TABLE_COMMENT: &str = "traffic-masq:vpn:v1";
const NFT_VPN_METADATA_COMMENT_PREFIX: &str = "traffic-masq:vpn:v1:part:";

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

pub struct VpnPolicyFirewallBackend<E> {
    pub(crate) executor: E,
}

impl<E> VpnPolicyFirewallBackend<E>
where
    E: NftExecutor,
{
    pub fn new(executor: E) -> Self {
        Self { executor }
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

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[derive(Debug, Default)]
    pub(crate) struct FakeNftExecutor {
        responses: StdMutex<VecDeque<Result<Vec<u8>>>>,
        pub(crate) calls: StdMutex<Vec<(Vec<String>, Vec<u8>)>>,
    }

    impl FakeNftExecutor {
        pub(crate) fn with_responses(responses: Vec<Result<Vec<u8>>>) -> Self {
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

    pub(crate) fn vpn_rule(chain: &str, expression: Value) -> Value {
        serde_json::json!({ "rule": {
            "family": NFT_FAMILY,
            "table": NFT_VPN_TABLE,
            "chain": chain,
            "expr": expression
        }})
    }

    pub(crate) fn nft_ruleset(owned: Option<&VpnPolicyFirewallDesired>) -> Vec<u8> {
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
mod tests {
    use super::test_support::{nft_ruleset, FakeNftExecutor};
    use super::*;

    fn desired() -> VpnPolicyFirewallDesired {
        VpnPolicyFirewallDesired {
            protected_subnets: vec![
                "192.168.10.0/24".parse().expect("subnet"),
                "192.168.20.0/24".parse().expect("subnet"),
            ],
            vpn_interface: "tm-wg0".to_string(),
            physical_uplink: "eth0".to_string(),
        }
    }

    fn owned_entries(ruleset: &mut Value) -> &mut Vec<Value> {
        ruleset
            .get_mut("nftables")
            .and_then(Value::as_array_mut)
            .expect("nftables entries")
    }

    fn nft_ruleset_value(desired: &VpnPolicyFirewallDesired) -> Value {
        serde_json::from_slice(&nft_ruleset(Some(desired))).expect("ruleset JSON")
    }

    #[test]
    fn desired_validation_rejects_invalid_topologies() {
        let mut candidate = desired();
        candidate.protected_subnets.clear();
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one protected subnet"));

        let mut candidate = desired();
        candidate.vpn_interface = candidate.physical_uplink.clone();
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("different"));

        let mut candidate = desired();
        candidate.protected_subnets[1] = candidate.protected_subnets[0];
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        let mut candidate = desired();
        candidate.physical_uplink = "bad/name".to_string();
        let error = candidate.validate().expect_err("invalid name must fail");
        assert!(format!("{error:#}").contains("unsupported"));
    }

    #[test]
    fn nft_render_contains_marking_nat_and_killswitch() {
        let rendered = render_vpn_nftables_batch(false, Some(&desired())).expect("render");

        assert!(rendered.contains("table inet traffic_masq_vpn"));
        assert!(rendered.contains("comment \"traffic-masq:vpn:v1\""));
        assert!(rendered.contains(
            "set protected_subnets { type ipv4_addr; flags interval; elements = { 192.168.10.0/24, 192.168.20.0/24 } }"
        ));
        assert!(rendered.contains("ip saddr @protected_subnets meta mark set 0x54000000"));
        assert!(rendered
            .contains("meta mark and 0xff000000 == 0x54000000 oifname \"tm-wg0\" masquerade"));
        assert!(rendered.contains("meta mark and 0xff000000 == 0x54000000 oifname \"eth0\" drop"));
    }

    #[test]
    fn nft_apply_is_idempotent_and_preserves_foreign_tables() {
        let wanted = desired();
        let executor = FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(Some(&wanted)))]);
        let backend = VpnPolicyFirewallBackend::new(executor);

        backend.apply(&wanted).expect("idempotent apply");

        let calls = backend.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, ["--json", "list", "ruleset"]);
    }

    #[test]
    fn nft_apply_replaces_only_owned_vpn_table_in_one_atomic_batch() {
        let executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(Some(&VpnPolicyFirewallDesired {
                protected_subnets: vec!["10.0.0.0/24".parse().expect("subnet")],
                vpn_interface: "tm-wg0".to_string(),
                physical_uplink: "old0".to_string(),
            }))),
            Ok(Vec::new()),
        ]);
        let backend = VpnPolicyFirewallBackend::new(executor);

        backend.apply(&desired()).expect("apply");

        let calls = backend.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, ["-f", "-"]);
        let batch = String::from_utf8(calls[1].1.clone()).expect("UTF-8 batch");
        assert!(batch.starts_with("delete table inet traffic_masq_vpn\n"));
        assert!(!batch.contains("foreign"));
        assert!(!batch.contains("\"traffic_masq\""));
        assert_eq!(batch.matches("table inet traffic_masq_vpn").count(), 2);
    }

    #[test]
    fn nft_restore_recreates_snapshot_or_removes_owned_table() {
        let snapshot = desired();
        let executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(None)),
            Ok(Vec::new()),
            Ok(nft_ruleset(Some(&snapshot))),
            Ok(Vec::new()),
        ]);
        let backend = VpnPolicyFirewallBackend::new(executor);

        backend.restore(Some(&snapshot)).expect("restore snapshot");
        backend.restore(None).expect("remove owned state");

        let calls = backend.executor.calls.lock().expect("calls lock");
        let create = String::from_utf8(calls[1].1.clone()).expect("create batch");
        let remove = String::from_utf8(calls[3].1.clone()).expect("remove batch");
        assert!(create.starts_with("table inet traffic_masq_vpn"));
        assert_eq!(remove, "delete table inet traffic_masq_vpn\n");
    }

    #[test]
    fn nft_observe_reports_intact_rendered_structure() {
        let wanted = desired();
        let backend = VpnPolicyFirewallBackend::new(FakeNftExecutor::with_responses(vec![Ok(
            nft_ruleset(Some(&wanted)),
        )]));

        let observed = backend.observe().expect("observe intact structure");

        assert_eq!(observed.desired, Some(wanted));
        assert_eq!(observed.integrity, VpnFirewallIntegrity::Intact);
    }

    #[test]
    fn nft_observe_rejects_owned_table_without_valid_metadata() {
        let malformed = serde_json::to_vec(&serde_json::json!({
            "nftables": [{
                "table": { "family": NFT_FAMILY, "name": NFT_VPN_TABLE, "comment": "foreign" }
            }]
        }))
        .expect("ruleset");
        let backend =
            VpnPolicyFirewallBackend::new(FakeNftExecutor::with_responses(vec![Ok(malformed)]));

        let error = backend.observe().expect_err("metadata must be required");

        assert!(error.to_string().contains("unsupported metadata"));
    }

    #[test]
    fn nft_observe_detects_missing_or_changed_owned_objects_and_rules() {
        let wanted = desired();
        let mut drifted_rulesets = Vec::new();

        let mut missing_chain = nft_ruleset_value(&wanted);
        owned_entries(&mut missing_chain).retain(|entry| {
            entry
                .get("chain")
                .and_then(|chain| chain.get("name"))
                .and_then(Value::as_str)
                != Some("killswitch")
        });
        drifted_rulesets.push(missing_chain);

        let mut changed_chain = nft_ruleset_value(&wanted);
        let killswitch = owned_entries(&mut changed_chain)
            .iter_mut()
            .find(|entry| {
                entry
                    .get("chain")
                    .and_then(|chain| chain.get("name"))
                    .and_then(Value::as_str)
                    == Some("killswitch")
            })
            .and_then(|entry| entry.get_mut("chain"))
            .expect("killswitch chain");
        killswitch["policy"] = Value::String("drop".to_string());
        drifted_rulesets.push(changed_chain);

        let mut missing_set = nft_ruleset_value(&wanted);
        owned_entries(&mut missing_set).retain(|entry| {
            entry
                .get("set")
                .and_then(|set| set.get("name"))
                .and_then(Value::as_str)
                != Some("protected_subnets")
        });
        drifted_rulesets.push(missing_set);

        let mut changed_set = nft_ruleset_value(&wanted);
        let subnets = owned_entries(&mut changed_set)
            .iter_mut()
            .find(|entry| {
                entry
                    .get("set")
                    .and_then(|set| set.get("name"))
                    .and_then(Value::as_str)
                    == Some("protected_subnets")
            })
            .and_then(|entry| entry.get_mut("set"))
            .expect("protected subnets set");
        subnets["elem"] = serde_json::json!([{ "prefix": { "addr": "10.9.9.0", "len": 24 } }]);
        drifted_rulesets.push(changed_set);

        let mut missing_rule = nft_ruleset_value(&wanted);
        owned_entries(&mut missing_rule).retain(|entry| {
            entry
                .get("rule")
                .and_then(|rule| rule.get("chain"))
                .and_then(Value::as_str)
                != Some("postrouting")
        });
        drifted_rulesets.push(missing_rule);

        let mut changed_rule = nft_ruleset_value(&wanted);
        let postrouting = owned_entries(&mut changed_rule)
            .iter_mut()
            .find(|entry| {
                entry
                    .get("rule")
                    .and_then(|rule| rule.get("chain"))
                    .and_then(Value::as_str)
                    == Some("postrouting")
            })
            .and_then(|entry| entry.get_mut("rule"))
            .expect("postrouting rule");
        postrouting["expr"] = serde_json::json!([{ "accept": null }]);
        drifted_rulesets.push(changed_rule);

        for ruleset in drifted_rulesets {
            let observed = parse_owned_vpn_firewall_state(
                &serde_json::to_vec(&ruleset).expect("serialize drifted ruleset"),
            )
            .expect("valid metadata must remain observable");
            assert_eq!(observed.desired.as_ref(), Some(&wanted));
            assert_eq!(observed.integrity, VpnFirewallIntegrity::Drifted);
        }
    }
}
