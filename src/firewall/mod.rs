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

use crate::config::{networks_overlap, validate_interface_name};
use crate::netlink::NetworkProvider;
use std::io::Write;
use std::process::{Command, Stdio};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDataplaneDesired {
    pub uplink: String,
    pub outputs: Vec<OutputNetwork>,
}

impl RouterDataplaneDesired {
    pub fn validate(&self) -> Result<()> {
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

pub trait NftExecutor: Send + Sync {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>>;
}

impl NftExecutor for std::sync::Arc<dyn NftExecutor> {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        (**self).execute(arguments, input)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NftCommandExecutor;

impl NftExecutor for NftCommandExecutor {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let mut child = Command::new("nft")
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start nft")?;
        child
            .stdin
            .take()
            .context("nft stdin was not available")?
            .write_all(input)
            .context("failed to write nft batch")?;
        let output = child.wait_with_output().context("failed to wait for nft")?;
        if !output.status.success() {
            bail!(
                "nft exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }
}

#[derive(Debug)]
pub struct NftablesBackend<E> {
    executor: E,
}

impl<E> NftablesBackend<E>
where
    E: NftExecutor,
{
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn observe(&self) -> Result<OwnedFirewallObservation> {
        let output = self
            .executor
            .execute(&["--json", "list", "ruleset"], &[])
            .context("failed to observe nftables ruleset")?;
        parse_owned_nftables_state(&output)
    }

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
            .context("owned nftables table has no traffic-masq metadata comment")?;
        let (encoded, chunked_metadata) =
            if let Some(legacy) = comment.strip_prefix(NFT_LEGACY_COMMENT_PREFIX) {
                (legacy.to_string(), false)
            } else if comment == NFT_TABLE_COMMENT {
                (collect_metadata_chunks(entries)?, true)
            } else {
                bail!("owned nftables table has unsupported metadata");
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
pub trait RouterDataplaneProvider: Send + Sync {
    async fn observe(&self) -> Result<RouterDataplaneSnapshot>;
    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()>;
    async fn disable_owned(&self) -> Result<()>;
    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()>;
}

#[derive(Debug)]
pub struct LinuxRouterDataplaneProvider<F, N, L> {
    forwarding: Ipv4ForwardingBackend<F>,
    nftables: NftablesBackend<N>,
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
            nftables,
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
        let firewall = self.nftables.observe()?;
        Ok(RouterDataplaneSnapshot {
            ipv4_forwarding: self.forwarding.observe()?,
            owned: firewall.desired,
            owned_firewall_integrity: firewall.integrity,
        })
    }

    async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
        self.preflight_interfaces(desired).await?;
        self.nftables
            .apply(desired)
            .context("failed to activate owned firewall policy before enabling forwarding")?;
        self.forwarding
            .enable()
            .context("owned firewall policy is active but enabling IPv4 forwarding failed")
    }

    async fn disable_owned(&self) -> Result<()> {
        self.nftables
            .restore(None)
            .context("failed to remove owned firewall state")
    }

    async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
        let (firewall_result, forwarding_result) = if snapshot.ipv4_forwarding {
            let firewall = self
                .nftables
                .restore(snapshot.owned.as_ref())
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
                .restore(snapshot.owned.as_ref())
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

    pub async fn plan(&self, desired: RouterDataplaneDesired) -> Result<RouterDataplanePlan> {
        self.plan_target(RouterDataplaneTarget::Enabled(desired))
            .await
    }

    pub async fn snapshot(&self) -> Result<RouterDataplaneSnapshot> {
        self.provider.observe().await
    }

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
        None => bail!("router dataplane {role} interface {name} does not exist"),
        Some(false) => bail!("router dataplane {role} interface {name} is down"),
        Some(true) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::netlink::AddressOwnership;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Mutex;

    use super::*;
    use crate::netlink::{Ipv4AddressInfo, NetworkInterface};

    #[derive(Debug, Clone)]
    struct FakeNetworkProvider {
        interfaces: Vec<NetworkInterface>,
    }

    impl FakeNetworkProvider {
        fn all_up() -> Self {
            Self {
                interfaces: vec![
                    NetworkInterface {
                        is_wireless: false,
                        index: 1,
                        name: "eth0".to_string(),
                        is_up: true,
                        rx_bytes: 0,
                        tx_bytes: 0,
                    },
                    NetworkInterface {
                        is_wireless: false,
                        index: 2,
                        name: "lan0".to_string(),
                        is_up: true,
                        rx_bytes: 0,
                        tx_bytes: 0,
                    },
                    NetworkInterface {
                        is_wireless: false,
                        index: 3,
                        name: "lan1".to_string(),
                        is_up: true,
                        rx_bytes: 0,
                        tx_bytes: 0,
                    },
                ],
            }
        }
    }

    #[async_trait]
    impl NetworkProvider for FakeNetworkProvider {
        async fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
            Ok(self.interfaces.clone())
        }

        async fn list_ipv4_addresses(&self, _interface: &str) -> Result<Vec<Ipv4AddressInfo>> {
            unreachable!("not used by dataplane preflight")
        }

        async fn set_link_up(&self, _name: &str) -> Result<()> {
            unreachable!("not used")
        }
        async fn set_link_down(&self, _name: &str) -> Result<()> {
            unreachable!("not used")
        }
        async fn add_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
            _ownership: AddressOwnership,
        ) -> Result<()> {
            unreachable!("not used")
        }
        async fn delete_ipv4_address(
            &self,
            _interface: &str,
            _address: Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            unreachable!("not used")
        }
    }

    #[derive(Debug)]
    struct FakeForwardingIo {
        value: StdMutex<Vec<u8>>,
        writes: StdMutex<Vec<Vec<u8>>>,
        fail_write: AtomicBool,
        trace: Option<Arc<StdMutex<Vec<&'static str>>>>,
    }

    impl FakeForwardingIo {
        fn new(value: &[u8]) -> Self {
            Self {
                value: StdMutex::new(value.to_vec()),
                writes: StdMutex::new(Vec::new()),
                fail_write: AtomicBool::new(false),
                trace: None,
            }
        }

        fn with_trace(mut self, trace: Arc<StdMutex<Vec<&'static str>>>) -> Self {
            self.trace = Some(trace);
            self
        }
    }

    impl Ipv4ForwardingIo for FakeForwardingIo {
        fn read(&self) -> Result<Vec<u8>> {
            Ok(self.value.lock().expect("value lock").clone())
        }

        fn write(&self, value: &[u8]) -> Result<()> {
            if let Some(trace) = &self.trace {
                trace.lock().expect("trace lock").push("forwarding");
            }
            if self.fail_write.load(Ordering::SeqCst) {
                bail!("injected write failure");
            }
            self.writes
                .lock()
                .expect("writes lock")
                .push(value.to_vec());
            *self.value.lock().expect("value lock") = value.to_vec();
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeNftExecutor {
        responses: StdMutex<VecDeque<Result<Vec<u8>>>>,
        calls: StdMutex<Vec<(Vec<String>, Vec<u8>)>>,
        trace: Option<Arc<StdMutex<Vec<&'static str>>>>,
    }

    impl FakeNftExecutor {
        fn with_responses(responses: Vec<Result<Vec<u8>>>) -> Self {
            Self {
                responses: StdMutex::new(responses.into()),
                calls: StdMutex::new(Vec::new()),
                trace: None,
            }
        }

        fn with_trace(mut self, trace: Arc<StdMutex<Vec<&'static str>>>) -> Self {
            self.trace = Some(trace);
            self
        }
    }

    impl NftExecutor for FakeNftExecutor {
        fn execute(&self, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
            if arguments == ["-f", "-"] {
                if let Some(trace) = &self.trace {
                    trace.lock().expect("trace lock").push("firewall");
                }
            }
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

    struct FakeProvider {
        state: Mutex<RouterDataplaneSnapshot>,
        foreign_state: Mutex<Vec<String>>,
        apply_calls: AtomicUsize,
        restore_calls: AtomicUsize,
        fail_after_partial_apply: AtomicBool,
        fail_restore: AtomicBool,
    }

    impl FakeProvider {
        fn new(snapshot: RouterDataplaneSnapshot) -> Self {
            Self {
                state: Mutex::new(snapshot),
                foreign_state: Mutex::new(vec!["foreign-table".to_string()]),
                apply_calls: AtomicUsize::new(0),
                restore_calls: AtomicUsize::new(0),
                fail_after_partial_apply: AtomicBool::new(false),
                fail_restore: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl RouterDataplaneProvider for FakeProvider {
        async fn observe(&self) -> Result<RouterDataplaneSnapshot> {
            Ok(self.state.lock().await.clone())
        }

        async fn apply_owned(&self, desired: &RouterDataplaneDesired) -> Result<()> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().await = RouterDataplaneSnapshot {
                ipv4_forwarding: true,
                owned: Some(desired.clone()),
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            };
            if self.fail_after_partial_apply.load(Ordering::SeqCst) {
                bail!("injected apply failure");
            }
            Ok(())
        }

        async fn disable_owned(&self) -> Result<()> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().await;
            state.owned = None;
            state.owned_firewall_integrity = OwnedFirewallIntegrity::Intact;
            Ok(())
        }

        async fn restore_owned(&self, snapshot: &RouterDataplaneSnapshot) -> Result<()> {
            self.restore_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_restore.load(Ordering::SeqCst) {
                bail!("injected restore failure");
            }
            *self.state.lock().await = snapshot.clone();
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingEventSink {
        events: StdMutex<Vec<RouterDataplaneEvent>>,
    }

    impl RouterDataplaneEventSink for RecordingEventSink {
        fn emit(&self, event: RouterDataplaneEvent) {
            self.events.lock().expect("events lock").push(event);
        }
    }

    #[test]
    fn forwarding_observes_zero_and_one_with_optional_newline() {
        for (raw, expected) in [
            (&b"0"[..], false),
            (&b"0\n"[..], false),
            (&b"1"[..], true),
            (&b"1\n"[..], true),
        ] {
            let backend = Ipv4ForwardingBackend::new(FakeForwardingIo::new(raw));
            assert_eq!(backend.observe().expect("valid forwarding value"), expected);
        }
    }

    #[test]
    fn forwarding_enable_is_idempotent() {
        let backend = Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"1\n"));

        backend.enable().expect("first enable");
        backend.enable().expect("second enable");

        assert!(backend.io.writes.lock().expect("writes lock").is_empty());
    }

    #[test]
    fn forwarding_rejects_malformed_input() {
        for raw in [
            &b""[..],
            &b"2\n"[..],
            &b"true\n"[..],
            &b" 1\n"[..],
            &b"1\n\n"[..],
        ] {
            let backend = Ipv4ForwardingBackend::new(FakeForwardingIo::new(raw));
            assert!(backend
                .observe()
                .expect_err("malformed value must fail")
                .to_string()
                .contains("expected 0 or 1"));
        }
    }

    #[test]
    fn forwarding_reports_write_failure_without_changing_state() {
        let io = FakeForwardingIo::new(b"0\n");
        io.fail_write.store(true, Ordering::SeqCst);
        let backend = Ipv4ForwardingBackend::new(io);

        let error = backend.enable().expect_err("write must fail");

        assert!(format!("{error:#}").contains("injected write failure"));
        assert!(!backend.observe().expect("original state"));
    }

    #[test]
    fn forwarding_restores_exact_original_snapshot() {
        for original in [false, true] {
            let initial = if original { &b"1\n"[..] } else { &b"0\n"[..] };
            let backend = Ipv4ForwardingBackend::new(FakeForwardingIo::new(initial));
            let snapshot = backend.observe().expect("snapshot");

            backend.enable().expect("enable");
            backend.restore(snapshot).expect("restore");

            assert_eq!(backend.observe().expect("restored state"), original);
            let expected_writes = if original {
                Vec::<Vec<u8>>::new()
            } else {
                vec![b"1\n".to_vec(), b"0\n".to_vec()]
            };
            assert_eq!(
                *backend.io.writes.lock().expect("writes lock"),
                expected_writes
            );
        }
    }

    fn desired() -> RouterDataplaneDesired {
        RouterDataplaneDesired {
            uplink: "eth0".to_string(),
            outputs: vec![
                OutputNetwork {
                    interface: "lan0".to_string(),
                    subnet: "192.168.10.0/24".parse().expect("subnet"),
                },
                OutputNetwork {
                    interface: "lan1".to_string(),
                    subnet: "192.168.20.0/24".parse().expect("subnet"),
                },
            ],
        }
    }

    fn nft_ruleset(owned: Option<&RouterDataplaneDesired>) -> Vec<u8> {
        let mut entries = vec![serde_json::json!({
            "table": { "family": "inet", "name": "foreign", "comment": "untouched" }
        })];
        if let Some(desired) = owned {
            entries.push(serde_json::json!({
                "table": {
                    "family": NFT_FAMILY,
                    "name": NFT_TABLE,
                    "comment": NFT_TABLE_COMMENT
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
                        "table": NFT_TABLE,
                        "chain": "metadata",
                        "comment": format!(
                            "{NFT_METADATA_COMMENT_PREFIX}{index:04}:{}",
                            String::from_utf8_lossy(chunk)
                        )
                    }
                }));
            }
            entries.extend([
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_TABLE, "name": "metadata"
                }}),
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_TABLE, "name": "forward",
                    "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"
                }}),
                serde_json::json!({ "chain": {
                    "family": NFT_FAMILY, "table": NFT_TABLE, "name": "postrouting",
                    "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"
                }}),
                serde_json::json!({ "set": {
                    "family": NFT_FAMILY, "table": NFT_TABLE, "name": "output_ifaces",
                    "type": "ifname",
                    "elem": desired.outputs.iter().map(|output| output.interface.clone()).collect::<Vec<_>>()
                }}),
                serde_json::json!({ "set": {
                    "family": NFT_FAMILY, "table": NFT_TABLE, "name": "output_subnets",
                    "type": "ipv4_addr", "flags": ["interval"],
                    "elem": desired.outputs.iter().map(|output| output.subnet.to_string()).collect::<Vec<_>>()
                }}),
                policy_rule("forward", serde_json::json!([
                    { "match": { "left": { "meta": { "key": "iifname" } }, "right": "@output_ifaces" } },
                    { "match": { "left": { "meta": { "key": "oifname" } }, "right": desired.uplink } },
                    { "accept": null }
                ])),
                policy_rule("forward", serde_json::json!([
                    { "match": { "left": { "meta": { "key": "iifname" } }, "right": desired.uplink } },
                    { "match": { "left": { "meta": { "key": "oifname" } }, "right": "@output_ifaces" } },
                    { "match": { "left": { "ct": { "key": "state" } }, "right": { "set": ["established", "related"] } } },
                    { "accept": null }
                ])),
                policy_rule("forward", serde_json::json!([
                    { "match": { "left": { "meta": { "key": "iifname" } }, "right": desired.uplink } },
                    { "match": { "left": { "meta": { "key": "oifname" } }, "right": "@output_ifaces" } },
                    { "drop": null }
                ])),
                policy_rule("postrouting", serde_json::json!([
                    { "match": { "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": "@output_subnets" } },
                    { "match": { "left": { "meta": { "key": "oifname" } }, "right": desired.uplink } },
                    { "masquerade": null }
                ])),
            ]);
        }
        serde_json::to_vec(&serde_json::json!({ "nftables": entries })).expect("ruleset")
    }

    fn policy_rule(chain: &str, expression: Value) -> Value {
        serde_json::json!({ "rule": {
            "family": NFT_FAMILY,
            "table": NFT_TABLE,
            "chain": chain,
            "expr": expression
        }})
    }

    #[test]
    fn nft_render_contains_owned_policy_and_scoped_masquerade() {
        let rendered = render_nftables_batch(false, Some(&desired())).expect("render");

        assert!(rendered.contains("table inet traffic_masq"));
        assert!(rendered.contains("comment \"traffic-masq:v1\""));
        assert!(rendered.contains("chain metadata"));
        assert!(rendered
            .lines()
            .filter_map(|line| line.split_once("comment \"").map(|(_, value)| value))
            .all(|comment| comment.trim_end_matches('"').len() <= 128));
        assert!(rendered.contains("iifname @output_ifaces oifname \"eth0\" accept"));
        assert!(rendered.contains(
            "iifname \"eth0\" oifname @output_ifaces ct state established,related accept"
        ));
        assert!(rendered.contains("iifname \"eth0\" oifname @output_ifaces drop"));
        assert!(rendered.contains("ip saddr @output_subnets oifname \"eth0\" masquerade"));
        assert!(rendered.contains("192.168.10.0/24, 192.168.20.0/24"));
    }

    #[test]
    fn nft_apply_is_idempotent_and_preserves_foreign_tables() {
        let wanted = desired();
        let executor = FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(Some(&wanted)))]);
        let backend = NftablesBackend::new(executor);

        backend.apply(&wanted).expect("idempotent apply");

        let calls = backend.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, ["--json", "list", "ruleset"]);
    }

    #[test]
    fn nft_apply_replaces_only_owned_table_in_one_atomic_batch() {
        let executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(Some(&RouterDataplaneDesired {
                uplink: "old0".to_string(),
                outputs: vec![OutputNetwork {
                    interface: "lan9".to_string(),
                    subnet: "10.0.0.0/24".parse().expect("subnet"),
                }],
            }))),
            Ok(Vec::new()),
        ]);
        let backend = NftablesBackend::new(executor);

        backend.apply(&desired()).expect("apply");

        let calls = backend.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, ["-f", "-"]);
        let batch = String::from_utf8(calls[1].1.clone()).expect("UTF-8 batch");
        assert!(batch.starts_with("delete table inet traffic_masq\n"));
        assert!(!batch.contains("foreign"));
        assert_eq!(batch.matches("table inet traffic_masq").count(), 2);
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
        let backend = NftablesBackend::new(executor);

        backend.restore(Some(&snapshot)).expect("restore snapshot");
        backend.restore(None).expect("remove owned state");

        let calls = backend.executor.calls.lock().expect("calls lock");
        let create = String::from_utf8(calls[1].1.clone()).expect("create batch");
        let remove = String::from_utf8(calls[3].1.clone()).expect("remove batch");
        assert!(create.starts_with("table inet traffic_masq"));
        assert_eq!(remove, "delete table inet traffic_masq\n");
    }

    #[test]
    fn nft_atomic_batch_failure_is_reported_without_retry() {
        let executor = FakeNftExecutor::with_responses(vec![
            Ok(nft_ruleset(None)),
            Err(anyhow::anyhow!("injected atomic failure")),
        ]);
        let backend = NftablesBackend::new(executor);

        let error = backend.apply(&desired()).expect_err("batch must fail");

        assert!(format!("{error:#}").contains("injected atomic failure"));
        assert_eq!(backend.executor.calls.lock().expect("calls lock").len(), 2);
    }

    #[test]
    fn nft_observe_reports_intact_rendered_structure() {
        let wanted = desired();
        let backend = NftablesBackend::new(FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(
            Some(&wanted),
        ))]));

        let observed = backend.observe().expect("observe intact structure");

        assert_eq!(observed.desired, Some(wanted));
        assert_eq!(observed.integrity, OwnedFirewallIntegrity::Intact);
    }

    #[test]
    fn nft_observe_preserves_legacy_metadata_compatibility() {
        let wanted = desired();
        let mut ruleset = nft_ruleset_value(&wanted);
        let encoded = hex_encode(&serde_json::to_vec(&wanted).expect("serialize desired"));
        let entries = owned_entries(&mut ruleset);
        entries
            .iter_mut()
            .find(|entry| {
                entry
                    .get("table")
                    .and_then(|table| table.get("name"))
                    .and_then(Value::as_str)
                    == Some(NFT_TABLE)
            })
            .and_then(|entry| entry.get_mut("table"))
            .expect("owned table")["comment"] =
            Value::String(format!("{NFT_LEGACY_COMMENT_PREFIX}{encoded}"));
        entries.retain(|entry| {
            let metadata_chain = entry
                .get("chain")
                .and_then(|chain| chain.get("name"))
                .and_then(Value::as_str)
                == Some("metadata");
            let metadata_rule = entry
                .get("rule")
                .and_then(|rule| rule.get("chain"))
                .and_then(Value::as_str)
                == Some("metadata");
            !metadata_chain && !metadata_rule
        });

        let observed = parse_owned_nftables_state(
            &serde_json::to_vec(&ruleset).expect("serialize legacy ruleset"),
        )
        .expect("legacy metadata");

        assert_eq!(observed.desired, Some(wanted));
        assert_eq!(observed.integrity, OwnedFirewallIntegrity::Intact);
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
                != Some("forward")
        });
        drifted_rulesets.push(missing_chain);

        let mut changed_chain = nft_ruleset_value(&wanted);
        let forward = owned_entries(&mut changed_chain)
            .iter_mut()
            .find(|entry| {
                entry
                    .get("chain")
                    .and_then(|chain| chain.get("name"))
                    .and_then(Value::as_str)
                    == Some("forward")
            })
            .and_then(|entry| entry.get_mut("chain"))
            .expect("forward chain");
        forward["policy"] = Value::String("drop".to_string());
        drifted_rulesets.push(changed_chain);

        let mut missing_set = nft_ruleset_value(&wanted);
        owned_entries(&mut missing_set).retain(|entry| {
            entry
                .get("set")
                .and_then(|set| set.get("name"))
                .and_then(Value::as_str)
                != Some("output_ifaces")
        });
        drifted_rulesets.push(missing_set);

        let mut changed_set = nft_ruleset_value(&wanted);
        let output_ifaces = owned_entries(&mut changed_set)
            .iter_mut()
            .find(|entry| {
                entry
                    .get("set")
                    .and_then(|set| set.get("name"))
                    .and_then(Value::as_str)
                    == Some("output_ifaces")
            })
            .and_then(|entry| entry.get_mut("set"))
            .expect("output interfaces set");
        output_ifaces["elem"] = serde_json::json!(["lan9"]);
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
            let observed = parse_owned_nftables_state(
                &serde_json::to_vec(&ruleset).expect("serialize drifted ruleset"),
            )
            .expect("valid metadata must remain observable");
            assert_eq!(observed.desired.as_ref(), Some(&wanted));
            assert_eq!(observed.integrity, OwnedFirewallIntegrity::Drifted);
        }
    }

    fn nft_ruleset_value(desired: &RouterDataplaneDesired) -> Value {
        serde_json::from_slice(&nft_ruleset(Some(desired))).expect("ruleset JSON")
    }

    fn owned_entries(ruleset: &mut Value) -> &mut Vec<Value> {
        ruleset
            .get_mut("nftables")
            .and_then(Value::as_array_mut)
            .expect("nftables entries")
    }

    #[test]
    fn nft_observe_rejects_owned_table_without_valid_metadata() {
        let malformed = serde_json::to_vec(&serde_json::json!({
            "nftables": [{
                "table": { "family": NFT_FAMILY, "name": NFT_TABLE, "comment": "foreign" }
            }]
        }))
        .expect("ruleset");
        let backend = NftablesBackend::new(FakeNftExecutor::with_responses(vec![Ok(malformed)]));

        let error = backend.observe().expect_err("metadata must be required");

        assert!(error.to_string().contains("unsupported metadata"));
    }

    fn empty_snapshot() -> RouterDataplaneSnapshot {
        RouterDataplaneSnapshot {
            ipv4_forwarding: false,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        }
    }

    #[test]
    fn desired_validation_rejects_invalid_topologies() {
        let mut candidate = desired();
        candidate.outputs.clear();
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one"));

        let mut candidate = desired();
        candidate.outputs[0].interface = candidate.uplink.clone();
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("different"));

        let mut candidate = desired();
        candidate.outputs[1].subnet = "192.168.10.128/25".parse().expect("subnet");
        assert!(candidate
            .validate()
            .unwrap_err()
            .to_string()
            .contains("overlap"));

        let mut candidate = desired();
        candidate.uplink = "bad/name".to_string();
        let error = candidate.validate().expect_err("invalid name must fail");
        assert!(format!("{error:#}").contains("unsupported"));
    }

    #[tokio::test]
    async fn linux_provider_observes_and_coordinates_forwarding_with_owned_firewall() {
        let wanted = desired();
        let provider = LinuxRouterDataplaneProvider::new(
            Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"0\n")),
            NftablesBackend::new(FakeNftExecutor::with_responses(vec![
                Ok(nft_ruleset(None)),
                Ok(nft_ruleset(None)),
                Ok(Vec::new()),
                Ok(nft_ruleset(Some(&wanted))),
                Ok(Vec::new()),
            ])),
            FakeNetworkProvider::all_up(),
        );
        let snapshot = provider.observe().await.expect("observe");
        assert_eq!(snapshot, empty_snapshot());

        provider.apply_owned(&wanted).await.expect("apply");
        assert!(provider.forwarding.observe().expect("forwarding enabled"));

        provider.restore_owned(&snapshot).await.expect("restore");
        assert!(!provider.forwarding.observe().expect("forwarding restored"));
        let calls = provider.nftables.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 5);
        assert!(String::from_utf8(calls[4].1.clone())
            .expect("restore batch")
            .starts_with("delete table inet traffic_masq"));
    }

    #[tokio::test]
    async fn linux_provider_disable_removes_owned_firewall_without_writing_forwarding() {
        let wanted = desired();
        let provider = LinuxRouterDataplaneProvider::new(
            Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"1\n")),
            NftablesBackend::new(FakeNftExecutor::with_responses(vec![
                Ok(nft_ruleset(Some(&wanted))),
                Ok(Vec::new()),
            ])),
            FakeNetworkProvider::all_up(),
        );

        provider.disable_owned().await.expect("disable owned state");

        assert!(provider.forwarding.observe().expect("forwarding preserved"));
        assert!(provider
            .forwarding
            .io
            .writes
            .lock()
            .expect("writes lock")
            .is_empty());
        let calls = provider.nftables.executor.calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 2);
        assert!(String::from_utf8(calls[1].1.clone())
            .expect("disable batch")
            .starts_with("delete table inet traffic_masq"));
    }

    #[tokio::test]
    async fn linux_provider_activates_firewall_before_enabling_forwarding() {
        let trace = Arc::new(StdMutex::new(Vec::new()));
        let provider = LinuxRouterDataplaneProvider::new(
            Ipv4ForwardingBackend::new(
                FakeForwardingIo::new(b"0\n").with_trace(Arc::clone(&trace)),
            ),
            NftablesBackend::new(
                FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None)), Ok(Vec::new())])
                    .with_trace(Arc::clone(&trace)),
            ),
            FakeNetworkProvider::all_up(),
        );

        provider.apply_owned(&desired()).await.expect("safe apply");

        assert_eq!(
            *trace.lock().expect("trace lock"),
            ["firewall", "forwarding"]
        );
    }

    #[tokio::test]
    async fn linux_provider_restore_orders_operations_for_target_forwarding_state() {
        for (target_forwarding, expected) in [
            (false, ["forwarding", "firewall"]),
            (true, ["firewall", "forwarding"]),
        ] {
            let trace = Arc::new(StdMutex::new(Vec::new()));
            let initial = if target_forwarding { b"0\n" } else { b"1\n" };
            let provider = LinuxRouterDataplaneProvider::new(
                Ipv4ForwardingBackend::new(
                    FakeForwardingIo::new(initial).with_trace(Arc::clone(&trace)),
                ),
                NftablesBackend::new(
                    FakeNftExecutor::with_responses(vec![
                        Ok(nft_ruleset(Some(&desired()))),
                        Ok(Vec::new()),
                    ])
                    .with_trace(Arc::clone(&trace)),
                ),
                FakeNetworkProvider::all_up(),
            );
            let snapshot = RouterDataplaneSnapshot {
                ipv4_forwarding: target_forwarding,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            };

            provider
                .restore_owned(&snapshot)
                .await
                .expect("safe restore");

            assert_eq!(*trace.lock().expect("trace lock"), expected);
        }
    }

    #[tokio::test]
    async fn linux_provider_restore_attempts_both_resources_and_combines_failures() {
        for (fail_firewall, fail_forwarding) in [(true, false), (false, true), (true, true)] {
            let forwarding = FakeForwardingIo::new(b"1\n");
            forwarding
                .fail_write
                .store(fail_forwarding, Ordering::SeqCst);
            let nft_result = if fail_firewall {
                Err(anyhow::anyhow!("injected nft restore failure"))
            } else {
                Ok(Vec::new())
            };
            let provider = LinuxRouterDataplaneProvider::new(
                Ipv4ForwardingBackend::new(forwarding),
                NftablesBackend::new(FakeNftExecutor::with_responses(vec![
                    Ok(nft_ruleset(Some(&desired()))),
                    nft_result,
                ])),
                FakeNetworkProvider::all_up(),
            );

            let error = provider
                .restore_owned(&empty_snapshot())
                .await
                .expect_err("injected restore failure");
            let message = format!("{error:#}");

            assert_eq!(
                provider
                    .nftables
                    .executor
                    .calls
                    .lock()
                    .expect("calls lock")
                    .len(),
                2,
                "firewall restore must always be attempted"
            );
            assert_eq!(
                provider
                    .forwarding
                    .io
                    .writes
                    .lock()
                    .expect("writes lock")
                    .len(),
                usize::from(!fail_forwarding),
                "forwarding restore must always be attempted"
            );
            if fail_firewall {
                assert!(
                    message.contains("injected nft restore failure"),
                    "{message}"
                );
            }
            if fail_forwarding {
                assert!(message.contains("injected write failure"), "{message}");
            }
            if fail_firewall && fail_forwarding {
                assert!(message.contains("multiple failures"), "{message}");
            }
        }
    }

    #[tokio::test]
    async fn linux_provider_preflight_rejects_missing_or_down_interfaces_without_mutations() {
        for (name, role, remove) in [
            ("eth0", "uplink", true),
            ("eth0", "uplink", false),
            ("lan0", "output", true),
            ("lan0", "output", false),
        ] {
            let mut network = FakeNetworkProvider::all_up();
            if remove {
                network
                    .interfaces
                    .retain(|interface| interface.name != name);
            } else {
                network
                    .interfaces
                    .iter_mut()
                    .find(|interface| interface.name == name)
                    .expect("test interface")
                    .is_up = false;
            }
            let provider = LinuxRouterDataplaneProvider::new(
                Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"0\n")),
                NftablesBackend::new(FakeNftExecutor::default()),
                network,
            );

            let error = provider
                .apply_owned(&desired())
                .await
                .expect_err("preflight must fail");

            let message = format!("{error:#}");
            assert!(message.contains(name), "{message}");
            assert!(message.contains(role), "{message}");
            assert!(
                message.contains(if remove { "does not exist" } else { "is down" }),
                "{message}"
            );
            assert!(!provider.forwarding.observe().expect("forwarding unchanged"));
            assert!(provider
                .forwarding
                .io
                .writes
                .lock()
                .expect("writes lock")
                .is_empty());
            assert!(provider
                .nftables
                .executor
                .calls
                .lock()
                .expect("calls lock")
                .is_empty());
        }
    }

    #[tokio::test]
    async fn linux_provider_preflight_accepts_active_uplink_and_outputs() {
        let wanted = desired();
        let provider = LinuxRouterDataplaneProvider::new(
            Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"0\n")),
            NftablesBackend::new(FakeNftExecutor::with_responses(vec![
                Ok(nft_ruleset(None)),
                Ok(Vec::new()),
            ])),
            FakeNetworkProvider::all_up(),
        );

        provider
            .apply_owned(&wanted)
            .await
            .expect("active interfaces");

        assert!(provider.forwarding.observe().expect("forwarding enabled"));
        assert_eq!(
            provider
                .nftables
                .executor
                .calls
                .lock()
                .expect("calls lock")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn health_reports_healthy_state_and_forwarding_or_firewall_drift() {
        let wanted = desired();
        let healthy = RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
            ipv4_forwarding: true,
            owned: Some(wanted.clone()),
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        }))
        .health(&wanted)
        .await
        .expect("healthy status");
        assert!(healthy.is_healthy());
        assert!(healthy.drift.is_empty());

        let forwarding_drift =
            RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
                ipv4_forwarding: false,
                owned: Some(wanted.clone()),
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            }))
            .health(&wanted)
            .await
            .expect("forwarding drift");
        assert_eq!(
            forwarding_drift.drift,
            vec![RouterDataplaneDrift::ForwardingDisabled]
        );

        let missing_firewall =
            RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
                ipv4_forwarding: true,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            }))
            .health(&wanted)
            .await
            .expect("missing firewall drift");
        assert_eq!(
            missing_firewall.drift,
            vec![RouterDataplaneDrift::OwnedFirewallMissing]
        );

        let mut other = wanted.clone();
        other.uplink = "other0".to_string();
        let mismatched_firewall =
            RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
                ipv4_forwarding: true,
                owned: Some(other.clone()),
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            }))
            .health(&wanted)
            .await
            .expect("mismatched firewall drift");
        assert_eq!(
            mismatched_firewall.drift,
            vec![RouterDataplaneDrift::OwnedFirewallMismatch { observed: other }]
        );
    }

    #[tokio::test]
    async fn structure_drift_is_unhealthy_and_requires_reapply() {
        let wanted = desired();
        let manager = RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
            ipv4_forwarding: true,
            owned: Some(wanted.clone()),
            owned_firewall_integrity: OwnedFirewallIntegrity::Drifted,
        }));

        let health = manager.health(&wanted).await.expect("health");
        let plan = manager.plan(wanted).await.expect("plan");

        assert_eq!(
            health.drift,
            vec![RouterDataplaneDrift::OwnedFirewallStructureDrift]
        );
        assert!(plan.requires_apply);
    }

    #[tokio::test]
    async fn event_sink_records_apply_and_rollback_success_and_failures() {
        let successful = RouterDataplaneManager::with_event_sink(
            FakeProvider::new(empty_snapshot()),
            RecordingEventSink::default(),
        );
        let plan = successful.plan(desired()).await.expect("plan");
        let snapshot = successful.apply(&plan).await.expect("apply");
        successful.rollback(&snapshot).await.expect("rollback");
        assert_eq!(
            *successful.events.events.lock().expect("events lock"),
            vec![
                RouterDataplaneEvent {
                    operation: RouterDataplaneOperation::Apply,
                    outcome: RouterDataplaneOutcome::Succeeded,
                    error: None,
                },
                RouterDataplaneEvent {
                    operation: RouterDataplaneOperation::Rollback,
                    outcome: RouterDataplaneOutcome::Succeeded,
                    error: None,
                },
            ]
        );

        let apply_failure = FakeProvider::new(empty_snapshot());
        apply_failure
            .fail_after_partial_apply
            .store(true, Ordering::SeqCst);
        let failed_apply =
            RouterDataplaneManager::with_event_sink(apply_failure, RecordingEventSink::default());
        let plan = failed_apply.plan(desired()).await.expect("plan");
        failed_apply.apply(&plan).await.expect_err("apply failure");
        let events = failed_apply.events.events.lock().expect("events lock");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, RouterDataplaneOperation::Apply);
        assert_eq!(events[0].outcome, RouterDataplaneOutcome::Failed);
        assert!(events[0]
            .error
            .as_deref()
            .expect("failure context")
            .contains("original snapshot restored"));
        drop(events);

        let rollback_failure = FakeProvider::new(empty_snapshot());
        rollback_failure.fail_restore.store(true, Ordering::SeqCst);
        let failed_rollback = RouterDataplaneManager::with_event_sink(
            rollback_failure,
            RecordingEventSink::default(),
        );
        failed_rollback
            .rollback(&empty_snapshot())
            .await
            .expect_err("rollback failure");
        let events = failed_rollback.events.events.lock().expect("events lock");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, RouterDataplaneOperation::Rollback);
        assert_eq!(events[0].outcome, RouterDataplaneOutcome::Failed);
        assert!(events[0]
            .error
            .as_deref()
            .expect("failure context")
            .contains("injected restore failure"));
    }

    #[tokio::test]
    async fn plan_describes_required_and_idempotent_apply() {
        let manager = RouterDataplaneManager::new(FakeProvider::new(empty_snapshot()));
        let first = manager.plan(desired()).await.expect("first plan");
        assert!(first.requires_apply);
        manager.apply(&first).await.expect("first apply");

        let second = manager.plan(desired()).await.expect("second plan");
        assert!(!second.requires_apply);
        manager.apply(&second).await.expect("idempotent apply");
        assert_eq!(manager.provider.apply_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_partial_apply_restores_original_snapshot() {
        let initial = empty_snapshot();
        let provider = FakeProvider::new(initial.clone());
        provider
            .fail_after_partial_apply
            .store(true, Ordering::SeqCst);
        let manager = RouterDataplaneManager::new(provider);
        let plan = manager.plan(desired()).await.expect("plan");

        let error = manager.apply(&plan).await.expect_err("apply must fail");
        assert!(error.to_string().contains("original snapshot restored"));
        assert_eq!(manager.provider.observe().await.expect("state"), initial);
        assert_eq!(manager.provider.restore_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rollback_restores_snapshot() {
        let initial = RouterDataplaneSnapshot {
            ipv4_forwarding: true,
            owned: None,
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        };
        let manager = RouterDataplaneManager::new(FakeProvider::new(initial.clone()));
        let plan = manager.plan(desired()).await.expect("plan");
        let snapshot = manager.apply(&plan).await.expect("apply");
        manager.rollback(&snapshot).await.expect("rollback");
        assert_eq!(manager.provider.observe().await.expect("state"), initial);
    }

    #[tokio::test]
    async fn enabled_to_disabled_removes_only_owned_firewall() {
        let initial = RouterDataplaneSnapshot {
            ipv4_forwarding: true,
            owned: Some(desired()),
            owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
        };
        let manager = RouterDataplaneManager::new(FakeProvider::new(initial));
        let plan = manager
            .plan_target(RouterDataplaneTarget::Disabled)
            .await
            .expect("disable plan");
        assert!(plan.requires_apply);
        manager.apply(&plan).await.expect("disable owned state");

        let observed = manager.provider.observe().await.expect("state");
        assert!(observed.ipv4_forwarding);
        assert!(observed.owned.is_none());
        assert_eq!(
            *manager.provider.foreign_state.lock().await,
            vec!["foreign-table".to_string()]
        );
    }

    #[tokio::test]
    async fn disabled_target_is_noop_and_preserves_foreign_forwarding_state() {
        for forwarding in [false, true] {
            let initial = RouterDataplaneSnapshot {
                ipv4_forwarding: forwarding,
                owned: None,
                owned_firewall_integrity: OwnedFirewallIntegrity::Intact,
            };
            let manager = RouterDataplaneManager::new(FakeProvider::new(initial.clone()));
            let plan = manager
                .plan_target(RouterDataplaneTarget::Disabled)
                .await
                .expect("disabled plan");
            assert!(!plan.requires_apply);
            manager.apply(&plan).await.expect("no-op apply");
            assert_eq!(manager.provider.observe().await.expect("state"), initial);
            assert_eq!(manager.provider.apply_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn disabled_health_reports_remaining_owned_firewall_only() {
        let manager = RouterDataplaneManager::new(FakeProvider::new(RouterDataplaneSnapshot {
            ipv4_forwarding: false,
            owned: Some(desired()),
            owned_firewall_integrity: OwnedFirewallIntegrity::Drifted,
        }));
        let health = manager
            .health_target(&RouterDataplaneTarget::Disabled)
            .await
            .expect("health");
        assert_eq!(
            health.drift,
            vec![RouterDataplaneDrift::OwnedFirewallUnexpected]
        );
    }

    #[tokio::test]
    async fn owned_operations_preserve_foreign_state() {
        let manager = RouterDataplaneManager::new(FakeProvider::new(empty_snapshot()));
        let plan = manager.plan(desired()).await.expect("plan");
        let snapshot = manager.apply(&plan).await.expect("apply");
        manager.rollback(&snapshot).await.expect("rollback");

        assert_eq!(
            *manager.provider.foreign_state.lock().await,
            vec!["foreign-table".to_string()]
        );
    }
}
