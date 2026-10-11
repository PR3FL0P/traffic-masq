//! IPv4 forwarding, NAT, and firewall policies.
//!
//! Rules are marked with traffic-masq identifiers, so reconciliation changes
//! only daemon-owned rules and can restore the original state snapshot.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

use traffic_masq_netlink::NetworkProvider;

mod view;
pub mod vpn;

const IPV4_FORWARDING_PATH: &str = "/proc/sys/net/ipv4/ip_forward";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "traffic_masq";
const NFT_TABLE_COMMENT: &str = "traffic-masq:v1";
const NFT_LEGACY_COMMENT_PREFIX: &str = "traffic-masq:v1:";
const NFT_METADATA_COMMENT_PREFIX: &str = "traffic-masq:v1:part:";
const NFT_METADATA_HEX_CHUNK_LEN: usize = 96;

pub trait Ipv4ForwardingIo: Send + Sync {
    fn read(&self) -> Result<Vec<u8>>;
    fn write(&self, value: &[u8]) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcSysIpv4ForwardingIo;

impl Ipv4ForwardingIo for ProcSysIpv4ForwardingIo {
    fn read(&self) -> Result<Vec<u8>> {
        fs::read(IPV4_FORWARDING_PATH)
            .with_context(|| format!("failed to read {IPV4_FORWARDING_PATH}"))
    }

    fn write(&self, value: &[u8]) -> Result<()> {
        fs::write(IPV4_FORWARDING_PATH, value)
            .with_context(|| format!("failed to write {IPV4_FORWARDING_PATH}"))
    }
}

#[derive(Debug)]
pub struct Ipv4ForwardingBackend<I> {
    io: I,
}

impl<I> Ipv4ForwardingBackend<I>
where
    I: Ipv4ForwardingIo,
{
    pub fn new(io: I) -> Self {
        Self { io }
    }

    pub fn observe(&self) -> Result<bool> {
        parse_ipv4_forwarding(&self.io.read()?)
    }

    pub fn enable(&self) -> Result<()> {
        self.set(true)
    }

    pub fn restore(&self, snapshot: bool) -> Result<()> {
        self.set(snapshot)
    }

    fn set(&self, enabled: bool) -> Result<()> {
        if self.observe()? == enabled {
            return Ok(());
        }

        let value = if enabled { b"1\n" } else { b"0\n" };
        self.io.write(value).with_context(|| {
            format!(
                "failed to set IPv4 forwarding to {}",
                if enabled { 1 } else { 0 }
            )
        })
    }
}

fn parse_ipv4_forwarding(value: &[u8]) -> Result<bool> {
    match value {
        b"0" | b"0\n" => Ok(false),
        b"1" | b"1\n" => Ok(true),
        _ => bail!(
            "invalid IPv4 forwarding value: expected 0 or 1 with an optional trailing newline"
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNetwork {
    pub interface: String,
    pub subnet: Ipv4Net,
}

/// A directional permission to forward IPv4 traffic between existing interfaces.
/// Routing selects the egress; this rule does not create routes or VPN tunnels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subnet: Option<Ipv4Net>,
    pub from: String,
    pub to: String,
    #[serde(default = "default_true")]
    pub masquerade: bool,
}

fn default_true() -> bool {
    true
}

impl traffic_masq_protocol::ForwardingRule for ForwardingConfig {
    fn source_subnet(&self) -> Option<Ipv4Net> {
        self.source_subnet
    }

    fn ingress_interface(&self) -> &str {
        &self.from
    }

    fn egress_interface(&self) -> &str {
        &self.to
    }
}

fn validate_interface_name(name: &str) -> Result<()> {
    traffic_masq_protocol::validate_interface_name(name).map_err(anyhow::Error::msg)
}

fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneDesired {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding: Option<Vec<ForwardingConfig>>,
    pub uplink: String,
    pub outputs: Vec<OutputNetwork>,
}

impl RouterDataplaneDesired {
    /// Canonical directional permissions, also for legacy sharing metadata.
    pub fn forwarding_rules(&self) -> Vec<ForwardingConfig> {
        self.forwarding.clone().unwrap_or_else(|| {
            self.outputs
                .iter()
                .map(|output| ForwardingConfig {
                    source_subnet: Some(output.subnet.trunc()),
                    from: output.interface.clone(),
                    to: self.uplink.clone(),
                    masquerade: true,
                })
                .collect()
        })
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(rules) = &self.forwarding {
            if !self.uplink.is_empty() || !self.outputs.is_empty() {
                bail!("explicit forwarding cannot contain legacy dataplane fields");
            }
            return traffic_masq_protocol::validate_forwarding(rules).map_err(anyhow::Error::msg);
        }
        validate_interface_name(&self.uplink).context("invalid uplink interface")?;
        if self.outputs.is_empty() {
            bail!("router dataplane requires at least one output network");
        }

        for (index, output) in self.outputs.iter().enumerate() {
            validate_interface_name(&output.interface)
                .with_context(|| format!("invalid output interface {}", output.interface))?;
            if output.interface == self.uplink {
                bail!(
                    "uplink and output interface must be different: {}",
                    self.uplink
                );
            }

            for other in self.outputs.iter().skip(index + 1) {
                if output.interface == other.interface {
                    bail!("duplicate output interface: {}", output.interface);
                }
                if networks_overlap(output.subnet, other.subnet) {
                    bail!(
                        "output networks overlap: {} ({}) and {} ({})",
                        output.interface,
                        output.subnet,
                        other.interface,
                        other.subnet
                    );
                }
            }
        }

        Ok(())
    }
}

// Intersect committed permissions with proven applied permissions. Preserve
// the original metadata when nothing was removed, including legacy format.
fn retained_firewall(
    current: Option<&RouterDataplaneDesired>,
    target: &RouterDataplaneTarget,
) -> Option<RouterDataplaneDesired> {
    let current = current?;
    let permitted = match target {
        RouterDataplaneTarget::Disabled => return None,
        RouterDataplaneTarget::Enabled(desired) => desired.forwarding_rules(),
    };
    let existing = current.forwarding_rules();
    let retained: Vec<_> = existing
        .iter()
        .filter(|rule| permitted.contains(rule))
        .cloned()
        .collect();
    if retained.len() == existing.len() {
        return Some(current.clone());
    }
    if retained.is_empty() {
        return None;
    }
    Some(RouterDataplaneDesired {
        forwarding: Some(retained),
        uplink: String::new(),
        outputs: Vec::new(),
    })
}

pub trait NftExecutor: Send + Sync + 'static {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>>;

    /// Share admission across backends that operate on the same ruleset.
    /// A reservation is transferred into the blocking worker, so cancellation
    /// cannot allow a later observation or rollback to overtake an old write.
    fn operation_gate(&self) -> Option<std::sync::Arc<tokio::sync::Mutex<()>>> {
        None
    }
}

impl NftExecutor for std::sync::Arc<dyn NftExecutor> {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        (**self).execute(arguments, input)
    }

    fn operation_gate(&self) -> Option<std::sync::Arc<tokio::sync::Mutex<()>>> {
        (**self).operation_gate()
    }
}

/// Synchronous entry points require caller serialization. Async entry points
/// keep operation admission inside their blocking workers, including on cancellation.
#[derive(Debug)]
pub struct NftablesBackend<E> {
    executor: E,
    operations: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl<E> NftablesBackend<E>
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

    pub async fn observe_async(self: &std::sync::Arc<Self>) -> Result<OwnedFirewallObservation> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            backend.observe()
        })
        .await?
    }

    /// Run the synchronous backend on the blocking pool. Dropping/timing out this
    /// future does not stop work already running. The worker retains admission
    /// until it finishes; subsequent observation and compensation wait for it.
    pub async fn apply_async(
        self: &std::sync::Arc<Self>,
        desired: &RouterDataplaneDesired,
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

    /// Run the synchronous backend on the blocking pool. Dropping/timing out this
    /// future does not stop work already running. The worker retains admission
    /// until it finishes, including when the caller's recovery budget expires.
    pub async fn restore_async(
        self: &std::sync::Arc<Self>,
        snapshot: Option<&RouterDataplaneDesired>,
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

    pub async fn cleanup_removed_async(
        self: &std::sync::Arc<Self>,
        target: &RouterDataplaneTarget,
    ) -> Result<()> {
        let reservation = self.operations.clone().lock_owned().await;
        let backend = self.clone();
        let target = target.clone();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            backend.cleanup_removed(&target)
        })
        .await?
    }

    pub fn observe(&self) -> Result<OwnedFirewallObservation> {
        let output = self
            .executor
            .execute(&["--json", "list", "ruleset"], &[])
            .context("failed to observe nftables ruleset")?;
        parse_owned_nftables_state(&output)
    }

    /// Validate and replace the daemon-owned nftables rules for the requested router configuration.
    pub fn apply(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        desired.validate()?;
        let current = self.observe()?;
        if current.integrity == OwnedFirewallIntegrity::Intact
            && current.desired.as_ref() == Some(desired)
        {
            return Ok(());
        }
        let batch = render_nftables_batch(current.desired.is_some(), Some(desired))?;
        self.executor
            .execute(&["-f", "-"], batch.as_bytes())
            .context("failed to apply atomic owned nftables batch")?;
        Ok(())
    }

    /// Retire permissions absent from committed intent. This never grants a
    /// new permission, repairs drift, or requires the referenced devices.
    pub fn cleanup_removed(&self, target: &RouterDataplaneTarget) -> Result<()> {
        if let RouterDataplaneTarget::Enabled(desired) = target {
            desired.validate()?;
        }
        let current = self.observe()?;
        let retained = retained_firewall(current.desired.as_ref(), target);
        if retained == current.desired {
            return Ok(());
        }
        anyhow::ensure!(
            current.integrity == OwnedFirewallIntegrity::Intact,
            "cannot retire firewall permissions: owned structure is drifted; inspect `sudo nft list table inet traffic_masq` and the recorded ownership metadata; reconfigure the competing firewall writer manually; rule drift alone does not identify its author"
        );
        let batch = render_nftables_batch(current.desired.is_some(), retained.as_ref())?;
        self.executor
            .execute(&["-f", "-"], batch.as_bytes())
            .context("failed to retire removed owned firewall permissions")?;
        Ok(())
    }

    pub fn restore(&self, snapshot: Option<&RouterDataplaneDesired>) -> Result<()> {
        if let Some(desired) = snapshot {
            desired.validate()?;
        }
        let current = self.observe()?;
        if current.integrity == OwnedFirewallIntegrity::Intact
            && current.desired.as_ref() == snapshot
        {
            return Ok(());
        }
        let batch = render_nftables_batch(current.desired.is_some(), snapshot)?;
        self.executor
            .execute(&["-f", "-"], batch.as_bytes())
            .context("failed to restore atomic owned nftables batch")?;
        Ok(())
    }
}

fn render_nftables_batch(
    table_exists: bool,
    desired: Option<&RouterDataplaneDesired>,
) -> Result<String> {
    let mut batch = String::new();
    if table_exists {
        batch.push_str("delete table inet traffic_masq\n");
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
                "    counter comment \"{NFT_METADATA_COMMENT_PREFIX}{index:04}:{}\"\n",
                String::from_utf8_lossy(chunk)
            )
        })
        .collect::<String>();
    if let Some(rules) = &desired.forwarding {
        let mut forward = String::new();
        let mut nat = String::new();
        for rule in rules {
            let source = rule
                .source_subnet
                .map_or(String::new(), |subnet| format!(" ip saddr {subnet}"));
            let destination = rule
                .source_subnet
                .map_or(String::new(), |subnet| format!(" ip daddr {subnet}"));
            forward.push_str(&format!(
                "    meta nfproto ipv4 iifname \"{}\" oifname \"{}\"{source} accept\n",
                rule.from, rule.to
            ));
            forward.push_str(&format!("    meta nfproto ipv4 iifname \"{}\" oifname \"{}\"{destination} ct state established,related accept\n", rule.to, rule.from));
            if rule.masquerade {
                nat.push_str(&format!(
                    "    meta nfproto ipv4 iifname \"{}\" oifname \"{}\"{source} masquerade\n",
                    rule.from, rule.to
                ));
            }
        }
        // All permissions precede drops, including intentionally bidirectional links.
        let ingress: std::collections::BTreeSet<_> = rules.iter().map(|rule| &rule.from).collect();
        for interface in ingress {
            forward.push_str(&format!("    meta nfproto ipv4 iifname \"{interface}\" drop\n    meta nfproto ipv4 oifname \"{interface}\" drop\n"));
        }
        batch.push_str(&format!("table inet {NFT_TABLE} {{\n  comment \"{NFT_TABLE_COMMENT}\"\n  chain metadata {{\n{metadata_rules}  }}\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n{forward}  }}\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n{nat}  }}\n}}\n"));
        return Ok(batch);
    }
    let output_ifaces = desired
        .outputs
        .iter()
        .map(|output| format!("\"{}\"", output.interface))
        .collect::<Vec<_>>()
        .join(", ");
    let output_subnets = desired
        .outputs
        .iter()
        .map(|output| output.subnet.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    batch.push_str(&format!(
        "table inet {NFT_TABLE} {{\n  comment \"{NFT_TABLE_COMMENT}\"\n  chain metadata {{\n{metadata_rules}  }}\n  set output_ifaces {{ type ifname; elements = {{ {output_ifaces} }} }}\n  set output_subnets {{ type ipv4_addr; flags interval; elements = {{ {output_subnets} }} }}\n  chain forward {{\n    type filter hook forward priority filter; policy accept;\n    iifname @output_ifaces oifname \"{}\" accept\n    iifname \"{}\" oifname @output_ifaces ct state established,related accept\n    iifname \"{}\" oifname @output_ifaces drop\n  }}\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    ip saddr @output_subnets oifname \"{}\" masquerade\n  }}\n}}\n",
        desired.uplink, desired.uplink, desired.uplink, desired.uplink
    ));
    Ok(batch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedFirewallIntegrity {
    Intact,
    Drifted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedFirewallObservation {
    pub desired: Option<RouterDataplaneDesired>,
    pub integrity: OwnedFirewallIntegrity,
}

fn parse_owned_nftables_state(output: &[u8]) -> Result<OwnedFirewallObservation> {
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
            || table.get("name").and_then(Value::as_str) != Some(NFT_TABLE)
        {
            continue;
        }
        let comment = table
            .get("comment")
            .and_then(Value::as_str)
            .context("owned nftables table has no traffic-masq metadata comment; inspect `sudo nft list table inet traffic_masq` and identify/reconfigure the table owner manually before retrying")?;
        let (encoded, chunked_metadata) = if let Some(legacy) =
            comment.strip_prefix(NFT_LEGACY_COMMENT_PREFIX)
        {
            (legacy.to_string(), false)
        } else if comment == NFT_TABLE_COMMENT {
            (collect_metadata_chunks(entries)?, true)
        } else {
            bail!("owned nftables table has unsupported metadata; inspect `sudo nft list table inet traffic_masq`; verify the table owner and reconfigure its service manually before retrying; traffic-masq will not overwrite an unverified table");
        };
        let desired: RouterDataplaneDesired = serde_json::from_slice(&hex_decode(&encoded)?)
            .context("owned nftables metadata is invalid")?;
        desired
            .validate()
            .context("owned nftables metadata is unsafe")?;
        let integrity = if owned_nftables_structure_is_intact(entries, &desired, chunked_metadata) {
            OwnedFirewallIntegrity::Intact
        } else {
            OwnedFirewallIntegrity::Drifted
        };
        return Ok(OwnedFirewallObservation {
            desired: Some(desired),
            integrity,
        });
    }
    Ok(OwnedFirewallObservation {
        desired: None,
        integrity: OwnedFirewallIntegrity::Intact,
    })
}

fn collect_metadata_chunks(entries: &[Value]) -> Result<String> {
    let mut chunks = Vec::new();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        if rule.get("family").and_then(Value::as_str) != Some(NFT_FAMILY)
            || rule.get("table").and_then(Value::as_str) != Some(NFT_TABLE)
            || rule.get("chain").and_then(Value::as_str) != Some("metadata")
        {
            continue;
        }
        let Some(comment) = rule.get("comment").and_then(Value::as_str) else {
            continue;
        };
        let Some(part) = comment.strip_prefix(NFT_METADATA_COMMENT_PREFIX) else {
            continue;
        };
        let (index, chunk) = part
            .split_once(':')
            .context("owned nftables metadata chunk has no index")?;
        let index = index
            .parse::<usize>()
            .context("owned nftables metadata chunk index is invalid")?;
        chunks.push((index, chunk));
    }
    chunks.sort_unstable_by_key(|(index, _)| *index);
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
    {
        bail!("owned nftables metadata chunks are missing or non-contiguous");
    }
    Ok(chunks.into_iter().map(|(_, chunk)| chunk).collect())
}

fn owned_nftables_structure_is_intact(
    entries: &[Value],
    desired: &RouterDataplaneDesired,
    require_metadata_chain: bool,
) -> bool {
    let chains = entries
        .iter()
        .filter_map(|entry| entry.get("chain"))
        .filter(|chain| owned_object(chain))
        .collect::<Vec<_>>();
    let sets = entries
        .iter()
        .filter_map(|entry| entry.get("set"))
        .filter(|set| owned_object(set))
        .collect::<Vec<_>>();
    let rules = entries
        .iter()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| owned_object(rule))
        .collect::<Vec<_>>();

    let metadata_ok = !require_metadata_chain
        || chains
            .iter()
            .any(|chain| object_name(chain) == Some("metadata"));
    let forward_chain_ok = chains.iter().any(|chain| {
        object_name(chain) == Some("forward")
            && string_field(chain, "type") == Some("filter")
            && string_field(chain, "hook") == Some("forward")
            && string_field(chain, "policy") == Some("accept")
    });
    let postrouting_chain_ok = chains.iter().any(|chain| {
        object_name(chain) == Some("postrouting")
            && string_field(chain, "type") == Some("nat")
            && string_field(chain, "hook") == Some("postrouting")
            && string_field(chain, "policy") == Some("accept")
    });
    let allowed_chain_count = if require_metadata_chain { 3 } else { 2 };
    let chains_ok = metadata_ok
        && forward_chain_ok
        && postrouting_chain_ok
        && chains.len() == allowed_chain_count;

    if let Some(connections) = &desired.forwarding {
        return chains_ok && sets.is_empty() && forwarding_structure_is_intact(&rules, connections);
    }

    let expected_ifaces = desired
        .outputs
        .iter()
        .map(|output| output.interface.as_str())
        .collect::<Vec<_>>();
    let expected_subnets = desired
        .outputs
        .iter()
        .map(|output| output.subnet.to_string())
        .collect::<Vec<_>>();
    let ifaces_ok = sets.iter().any(|set| {
        object_name(set) == Some("output_ifaces")
            && string_field(set, "type") == Some("ifname")
            && exact_string_elements(set, &expected_ifaces)
    });
    let subnets_ok = sets.iter().any(|set| {
        object_name(set) == Some("output_subnets")
            && string_field(set, "type") == Some("ipv4_addr")
            && value_contains_token(set.get("flags").unwrap_or(&Value::Null), "interval")
            && exact_owned_elements(set, &expected_subnets)
    });
    let sets_ok = ifaces_ok && subnets_ok && sets.len() == 2;

    let forward_rules = rules
        .iter()
        .filter(|rule| string_field(rule, "chain") == Some("forward"))
        .collect::<Vec<_>>();
    let postrouting_rules = rules
        .iter()
        .filter(|rule| string_field(rule, "chain") == Some("postrouting"))
        .collect::<Vec<_>>();
    let outbound = forward_rules.iter().any(|rule| {
        rule_has_tokens(
            rule,
            &["iifname", "output_ifaces", "oifname", &desired.uplink],
        ) && value_contains_key(rule, "accept")
            && !value_contains_key(rule, "ct")
    });
    let established = forward_rules.iter().any(|rule| {
        rule_has_tokens(
            rule,
            &[
                "iifname",
                &desired.uplink,
                "oifname",
                "output_ifaces",
                "state",
                "established",
                "related",
            ],
        ) && value_contains_key(rule, "ct")
            && value_contains_key(rule, "accept")
    });
    let blocked_new = forward_rules.iter().any(|rule| {
        rule_has_tokens(
            rule,
            &["iifname", &desired.uplink, "oifname", "output_ifaces"],
        ) && value_contains_key(rule, "drop")
    });
    let masquerade = postrouting_rules.iter().any(|rule| {
        rule_has_tokens(
            rule,
            &["ip", "saddr", "output_subnets", "oifname", &desired.uplink],
        ) && value_contains_key(rule, "masquerade")
    });
    let policy_rules_ok = outbound
        && established
        && blocked_new
        && masquerade
        && forward_rules.len() == 3
        && postrouting_rules.len() == 1;

    chains_ok && sets_ok && policy_rules_ok
}

// Compare ordered expressions, including exact direction and verdict. Metadata
// alone must never make missing or reordered forwarding rules look healthy.
fn forwarding_structure_is_intact(rules: &[&Value], connections: &[ForwardingConfig]) -> bool {
    use serde_json::json;
    let matched = |key: &str, value: &str| json!({"match": {"op": "==", "left": {"meta": {"key": key}}, "right": value}});
    let prefix = || vec![matched("nfproto", "ipv4")];
    let mut forward = Vec::new();
    let mut nat = Vec::new();
    for connection in connections {
        // An ip payload match already constrains the family; nft may elide
        // the redundant nfproto expression from its normalized JSON.
        let scoped_prefix = || {
            if connection.source_subnet.is_some() {
                Vec::new()
            } else {
                prefix()
            }
        };
        let mut outbound = scoped_prefix();
        outbound.extend([
            matched("iifname", &connection.from),
            matched("oifname", &connection.to),
        ]);
        let subnet_match = |field: &str, subnet: ipnet::Ipv4Net| {
            let right = if subnet.prefix_len() == 32 {
                json!(subnet.addr().to_string())
            } else {
                json!({"prefix": {"addr": subnet.network().to_string(), "len": subnet.prefix_len()}})
            };
            json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": field}}, "right": right}})
        };
        if let Some(subnet) = connection.source_subnet {
            outbound.push(subnet_match("saddr", subnet));
        }
        let mut translated = outbound.clone();
        outbound.push(json!({"accept": null}));
        forward.push(json!(outbound));
        let mut inbound = scoped_prefix();
        inbound.extend([
            matched("iifname", &connection.to),
            matched("oifname", &connection.from),
        ]);
        if let Some(subnet) = connection.source_subnet {
            inbound.push(subnet_match("daddr", subnet));
        }
        inbound.extend([
            json!({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}),
            json!({"accept": null}),
        ]);
        forward.push(json!(inbound));
        if connection.masquerade {
            translated.push(json!({"masquerade": null}));
            nat.push(json!(translated));
        }
    }
    let ingress: std::collections::BTreeSet<_> =
        connections.iter().map(|rule| &rule.from).collect();
    for interface in ingress {
        for key in ["iifname", "oifname"] {
            let mut drop = prefix();
            drop.extend([matched(key, interface), json!({"drop": null})]);
            forward.push(json!(drop));
        }
    }
    let expressions = |chain: &str| {
        rules
            .iter()
            .filter(|rule| string_field(rule, "chain") == Some(chain))
            .map(|rule| {
                let mut expr = rule.get("expr").cloned().unwrap_or(Value::Null);
                // nft versions encode a state list as either an array or an anonymous set.
                if let Some(items) = expr.as_array_mut() {
                    if items.iter().any(|item| {
                        item.pointer("/match/left/payload/protocol")
                            .and_then(Value::as_str)
                            == Some("ip")
                    }) {
                        items.retain(|item| item != &matched("nfproto", "ipv4"));
                    }
                    for item in items {
                        if let Some(right) = item.pointer_mut("/match/right") {
                            if let Some(states) = right.get("set").and_then(Value::as_array) {
                                *right = Value::Array(states.clone());
                            }
                        }
                    }
                }
                expr
            })
            .collect::<Vec<_>>()
    };
    expressions("forward") == forward && expressions("postrouting") == nat
}

fn owned_object(value: &Value) -> bool {
    string_field(value, "family") == Some(NFT_FAMILY)
        && string_field(value, "table") == Some(NFT_TABLE)
}

fn object_name(value: &Value) -> Option<&str> {
    string_field(value, "name")
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn exact_string_elements(value: &Value, expected: &[&str]) -> bool {
    let Some(elements) = value.get("elem").and_then(Value::as_array) else {
        return false;
    };
    let mut actual = elements
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn exact_owned_elements(value: &Value, expected: &[String]) -> bool {
    let Some(elements) = value.get("elem").and_then(Value::as_array) else {
        return false;
    };
    let mut actual = elements
        .iter()
        .filter_map(nft_element_as_string)
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn nft_element_as_string(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    let prefix = value.get("prefix")?;
    let address = prefix.get("addr")?.as_str()?;
    let length = prefix.get("len")?.as_u64()?;
    Some(format!("{address}/{length}"))
}

fn rule_has_tokens(rule: &Value, tokens: &[&str]) -> bool {
    let expression = rule.get("expr").unwrap_or(&Value::Null);
    tokens
        .iter()
        .all(|token| value_contains_token(expression, token))
}

fn value_contains_token(value: &Value, token: &str) -> bool {
    match value {
        Value::String(value) => value.trim_start_matches('@') == token,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_token(value, token)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key == token || value_contains_token(value, token)),
        _ => false,
    }
}

fn value_contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Array(values) => values.iter().any(|value| value_contains_key(value, key)),
        Value::Object(values) => {
            values.contains_key(key) || values.values().any(|value| value_contains_key(value, key))
        }
        _ => false,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid hexadecimal nftables metadata");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneSnapshot {
    pub ipv4_forwarding: bool,
    pub owned: Option<RouterDataplaneDesired>,
    #[serde(default = "owned_firewall_intact_by_default")]
    pub owned_firewall_integrity: OwnedFirewallIntegrity,
}

fn owned_firewall_intact_by_default() -> OwnedFirewallIntegrity {
    OwnedFirewallIntegrity::Intact
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "desired", rename_all = "snake_case")]
pub enum RouterDataplaneTarget {
    Enabled(RouterDataplaneDesired),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplanePlan {
    pub snapshot: RouterDataplaneSnapshot,
    pub target: RouterDataplaneTarget,
    pub requires_apply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterDataplaneDrift {
    ForwardingDisabled,
    OwnedFirewallMissing,
    OwnedFirewallMismatch { observed: RouterDataplaneDesired },
    OwnedFirewallStructureDrift,
    OwnedFirewallUnexpected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneHealth {
    pub observed: RouterDataplaneSnapshot,
    pub drift: Vec<RouterDataplaneDrift>,
}

impl RouterDataplaneHealth {
    pub fn is_healthy(&self) -> bool {
        self.drift.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterDataplaneOperation {
    Apply,
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterDataplaneOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneEvent {
    pub operation: RouterDataplaneOperation,
    pub outcome: RouterDataplaneOutcome,
    pub error: Option<String>,
}

pub trait RouterDataplaneEventSink: Send + Sync {
    fn emit(&self, event: RouterDataplaneEvent);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRouterDataplaneEventSink;

impl RouterDataplaneEventSink for NoopRouterDataplaneEventSink {
    fn emit(&self, _event: RouterDataplaneEvent) {}
}

#[async_trait]
/// Owned firewall and global IPv4 forwarding adapter. Caller serializes
/// mutations and snapshots before apply; hooks may return Err after partial
/// changes. Preserve unrelated firewall objects and refuse foreign replacements.
/// Async blocking backend work may outlive cancellation; retain recovery proof.
pub trait RouterDataplaneProvider: Send + Sync {
    /// Observe forwarding and owned firewall metadata/integrity without changing them.
    /// An observation error is not an empty or disabled snapshot.
    async fn observe(&self) -> Result<RouterDataplaneSnapshot>;
    /// Install owned firewall policy before enabling IPv4 forwarding. May partially
    /// apply on error; the caller must restore its captured snapshot.
    /// Repeated application must still verify owned table identity.
    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()>;
    /// Remove only owned firewall state. The production adapter leaves global IPv4
    /// forwarding unchanged; this is not restoration of the original sysctl value.
    async fn disable_owned(&self) -> Result<()>;
    /// Restore captured global forwarding and owned firewall state while preserving
    /// foreign objects. Attempt both components; failure may leave a partial restore,
    /// requiring retry with the original snapshot.
    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()>;
    /// Remove obsolete owned forwarding paths without additions or service activation.
    /// The default implementation only verifies no removal is needed, otherwise errors.
    /// Use under the mutation gate and retain proof if cleanup fails.
    async fn cleanup_removed(&self, target: &RouterDataplaneTarget) -> Result<()> {
        let observed = self.observe().await?;
        anyhow::ensure!(
            retained_firewall(observed.owned.as_ref(), target) == observed.owned,
            "removal-only firewall cleanup is unavailable"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("router dataplane {role} interface {interface} does not exist")]
pub struct RouterDataplaneInterfaceMissing {
    pub role: String,
    pub interface: String,
}

pub fn missing_router_dataplane_interface(
    error: &anyhow::Error,
) -> Option<&RouterDataplaneInterfaceMissing> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<RouterDataplaneInterfaceMissing>())
}

#[derive(Debug)]
pub struct LinuxRouterDataplaneProvider<F, N, L> {
    forwarding: Ipv4ForwardingBackend<F>,
    nftables: std::sync::Arc<NftablesBackend<N>>,
    network: L,
}

impl<F, N, L> LinuxRouterDataplaneProvider<F, N, L>
where
    F: Ipv4ForwardingIo,
    N: NftExecutor,
    L: NetworkProvider,
{
    pub fn new(
        forwarding: Ipv4ForwardingBackend<F>,
        nftables: NftablesBackend<N>,
        network: L,
    ) -> Self {
        Self {
            forwarding,
            nftables: std::sync::Arc::new(nftables),
            network,
        }
    }

    async fn preflight_interfaces(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        let interfaces = self
            .network
            .list_interfaces()
            .await
            .context("failed to observe interfaces for router dataplane preflight")?
            .into_iter()
            .map(|interface| (interface.name, interface.is_up))
            .collect::<HashMap<_, _>>();

        if let Some(rules) = &desired.forwarding {
            for rule in rules {
                validate_active_interface(&interfaces, &rule.from, "ingress")?;
                validate_active_interface(&interfaces, &rule.to, "egress")?;
            }
            return Ok(());
        }
        validate_active_interface(&interfaces, &desired.uplink, "uplink")?;
        for output in &desired.outputs {
            validate_active_interface(&interfaces, &output.interface, "output")?;
        }
        Ok(())
    }
}

#[async_trait]
impl<F, N, L> RouterDataplaneProvider for LinuxRouterDataplaneProvider<F, N, L>
where
    F: Ipv4ForwardingIo,
    N: NftExecutor,
    L: NetworkProvider,
{
    async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
        let firewall = self.nftables.observe_async().await?;
        Ok(RouterDataplaneSnapshot {
            ipv4_forwarding: self.forwarding.observe()?,
            owned: firewall.desired,
            owned_firewall_integrity: firewall.integrity,
        })
    }

    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        self.preflight_interfaces(desired).await?;
        self.nftables
            .apply_async(desired)
            .await
            .context("failed to activate owned firewall policy before enabling forwarding")?;
        self.forwarding
            .enable()
            .context("owned firewall policy is active but enabling IPv4 forwarding failed")
    }

    async fn disable_owned(&self) -> Result<()> {
        self.nftables
            .restore_async(None)
            .await
            .context("failed to remove owned firewall state")
    }

    async fn cleanup_removed(&self, target: &RouterDataplaneTarget) -> Result<()> {
        self.nftables.cleanup_removed_async(target).await
    }

    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        let (firewall_result, forwarding_result) = if snapshot.ipv4_forwarding {
            let firewall = self
                .nftables
                .restore_async(snapshot.owned.as_ref())
                .await
                .context("failed to restore owned firewall state");
            let forwarding = self
                .forwarding
                .restore(true)
                .context("failed to restore IPv4 forwarding state");
            (firewall, forwarding)
        } else {
            let forwarding = self
                .forwarding
                .restore(false)
                .context("failed to restore IPv4 forwarding state");
            let firewall = self
                .nftables
                .restore_async(snapshot.owned.as_ref())
                .await
                .context("failed to restore owned firewall state");
            (firewall, forwarding)
        };

        match (firewall_result, forwarding_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(firewall), Ok(())) => Err(firewall),
            (Ok(()), Err(forwarding)) => Err(forwarding),
            (Err(firewall), Err(forwarding)) => Err(anyhow::anyhow!(
                "dataplane restore had multiple failures: firewall: {firewall:#}; forwarding: {forwarding:#}"
            )),
        }
    }
}

#[derive(Debug)]
pub struct RouterDataplaneManager<P, E = NoopRouterDataplaneEventSink> {
    provider: P,
    events: E,
}

impl<P> RouterDataplaneManager<P, NoopRouterDataplaneEventSink>
where
    P: RouterDataplaneProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            events: NoopRouterDataplaneEventSink,
        }
    }
}

impl<P, E> RouterDataplaneManager<P, E>
where
    P: RouterDataplaneProvider,
    E: RouterDataplaneEventSink,
{
    pub fn with_event_sink(provider: P, events: E) -> Self {
        Self { provider, events }
    }

    /// Preview enabled router forwarding and firewall state without applying it.
    pub async fn plan(&self, desired: RouterDataplaneDesired) -> Result<RouterDataplanePlan> {
        self.plan_target(RouterDataplaneTarget::Enabled(desired))
            .await
    }

    pub async fn cleanup_removed(&self, target: &RouterDataplaneTarget) -> Result<()> {
        self.provider.cleanup_removed(target).await
    }

    pub async fn snapshot(&self) -> Result<RouterDataplaneSnapshot> {
        self.provider.observe().await
    }

    /// Observe current state and determine whether the enabled or disabled target needs changes.
    pub async fn plan_target(&self, target: RouterDataplaneTarget) -> Result<RouterDataplanePlan> {
        if let RouterDataplaneTarget::Enabled(desired) = &target {
            desired.validate()?;
        }
        let snapshot = self.provider.observe().await?;
        let requires_apply = match &target {
            RouterDataplaneTarget::Enabled(desired) => {
                !snapshot.ipv4_forwarding
                    || snapshot.owned.as_ref() != Some(desired)
                    || snapshot.owned_firewall_integrity == OwnedFirewallIntegrity::Drifted
            }
            RouterDataplaneTarget::Disabled => snapshot.owned.is_some(),
        };
        Ok(RouterDataplanePlan {
            snapshot,
            target,
            requires_apply,
        })
    }

    pub async fn health(&self, desired: &RouterDataplaneDesired) -> Result<RouterDataplaneHealth> {
        self.health_target(&RouterDataplaneTarget::Enabled(desired.clone()))
            .await
    }

    /// Compare observed forwarding and owned firewall structure with the requested target.
    pub async fn health_target(
        &self,
        target: &RouterDataplaneTarget,
    ) -> Result<RouterDataplaneHealth> {
        if let RouterDataplaneTarget::Enabled(desired) = target {
            desired.validate()?;
        }
        let observed = self.provider.observe().await?;
        let mut drift = Vec::new();
        match target {
            RouterDataplaneTarget::Disabled => {
                if observed.owned.is_some() {
                    drift.push(RouterDataplaneDrift::OwnedFirewallUnexpected);
                }
            }
            RouterDataplaneTarget::Enabled(desired) => {
                if !observed.ipv4_forwarding {
                    drift.push(RouterDataplaneDrift::ForwardingDisabled);
                }
                match observed.owned.as_ref() {
                    None => drift.push(RouterDataplaneDrift::OwnedFirewallMissing),
                    Some(owned) if owned != desired => {
                        drift.push(RouterDataplaneDrift::OwnedFirewallMismatch {
                            observed: owned.clone(),
                        });
                    }
                    Some(_) => {}
                }
                if observed.owned.is_some()
                    && observed.owned_firewall_integrity == OwnedFirewallIntegrity::Drifted
                {
                    drift.push(RouterDataplaneDrift::OwnedFirewallStructureDrift);
                }
            }
        }
        Ok(RouterDataplaneHealth { observed, drift })
    }

    /// Apply the planned firewall target and attempt snapshot restoration on failure.
    /// Return the prior snapshot on success; include restoration errors when compensation fails.
    pub async fn apply(&self, plan: &RouterDataplanePlan) -> Result<RouterDataplaneSnapshot> {
        if let RouterDataplaneTarget::Enabled(desired) = &plan.target {
            desired.validate()?;
        }
        if !plan.requires_apply {
            self.emit_success(RouterDataplaneOperation::Apply);
            return Ok(plan.snapshot.clone());
        }

        let apply_result = match &plan.target {
            RouterDataplaneTarget::Enabled(desired) => self.provider.apply_owned(desired).await,
            RouterDataplaneTarget::Disabled => self.provider.disable_owned().await,
        };
        if let Err(apply_error) = apply_result {
            let error = if let Err(restore_error) =
                self.provider.restore_owned(&plan.snapshot).await
            {
                anyhow::anyhow!(
                    "dataplane apply failed: {apply_error:#}; snapshot restore also failed: {restore_error:#}"
                )
            } else {
                apply_error.context("dataplane apply failed; original snapshot restored")
            };
            self.emit_failure(RouterDataplaneOperation::Apply, &error);
            return Err(error);
        }

        self.emit_success(RouterDataplaneOperation::Apply);
        Ok(plan.snapshot.clone())
    }

    /// Restore captured forwarding and owned firewall state, emitting the operation result.
    pub async fn rollback(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        match self.provider.restore_owned(snapshot).await {
            Ok(()) => {
                self.emit_success(RouterDataplaneOperation::Rollback);
                Ok(())
            }
            Err(error) => {
                let error = error.context("dataplane rollback failed");
                self.emit_failure(RouterDataplaneOperation::Rollback, &error);
                Err(error)
            }
        }
    }

    fn emit_success(&self, operation: RouterDataplaneOperation) {
        self.events.emit(RouterDataplaneEvent {
            operation,
            outcome: RouterDataplaneOutcome::Succeeded,
            error: None,
        });
    }

    fn emit_failure(&self, operation: RouterDataplaneOperation, error: &anyhow::Error) {
        self.events.emit(RouterDataplaneEvent {
            operation,
            outcome: RouterDataplaneOutcome::Failed,
            error: Some(format!("{error:#}")),
        });
    }
}

fn validate_active_interface(
    interfaces: &HashMap<String, bool>,
    name: &str,
    role: &str,
) -> Result<()> {
    match interfaces.get(name) {
        None => Err(RouterDataplaneInterfaceMissing {
            role: role.to_string(),
            interface: name.to_string(),
        }
        .into()),
        Some(false) => bail!("router dataplane {role} interface {name} is down"),
        Some(true) => Ok(()),
    }
}

#[cfg(test)]
mod tests;
