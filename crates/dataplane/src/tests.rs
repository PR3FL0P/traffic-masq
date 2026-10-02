use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use traffic_masq_netlink::AddressOwnership;

use tokio::sync::Mutex;

use super::*;
use traffic_masq_netlink::{Ipv4AddressInfo, NetworkInterface};

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
        forwarding: None,
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
    assert!(rendered
        .contains("iifname \"eth0\" oifname @output_ifaces ct state established,related accept"));
    assert!(rendered.contains("iifname \"eth0\" oifname @output_ifaces drop"));
    assert!(rendered.contains("ip saddr @output_subnets oifname \"eth0\" masquerade"));
    assert!(rendered.contains("192.168.10.0/24, 192.168.20.0/24"));
}

fn forwarding_desired() -> RouterDataplaneDesired {
    RouterDataplaneDesired {
        forwarding: Some(vec![
            ForwardingConfig {
                from: "lan0".to_string(),
                to: "wan0".to_string(),
                masquerade: true,
                source_subnet: Some("192.168.10.0/24".parse().expect("subnet")),
            },
            ForwardingConfig {
                from: "lan1".to_string(),
                to: "wg0".to_string(),
                masquerade: false,
                source_subnet: None,
            },
        ]),
        uplink: String::new(),
        outputs: Vec::new(),
    }
}

#[test]
fn nft_render_forwarding_batch_contains_rules_and_drops() {
    let wanted = forwarding_desired();
    let rendered = render_nftables_batch(false, Some(&wanted)).expect("render");

    assert!(rendered.contains("table inet traffic_masq"));
    assert!(rendered.contains("chain forward"));
    assert!(rendered.contains("chain postrouting"));
    assert!(rendered.contains(
        "meta nfproto ipv4 iifname \"lan0\" oifname \"wan0\" ip saddr 192.168.10.0/24 accept"
    ));
    assert!(rendered.contains("meta nfproto ipv4 iifname \"wan0\" oifname \"lan0\" ip daddr 192.168.10.0/24 ct state established,related accept"));
    assert!(rendered.contains(
        "meta nfproto ipv4 iifname \"lan0\" oifname \"wan0\" ip saddr 192.168.10.0/24 masquerade"
    ));
    assert!(rendered.contains("meta nfproto ipv4 iifname \"lan1\" oifname \"wg0\" accept"));
    assert!(rendered.contains(
        "meta nfproto ipv4 iifname \"wg0\" oifname \"lan1\" ct state established,related accept"
    ));
    assert!(!rendered.contains("meta nfproto ipv4 iifname \"lan1\" oifname \"wg0\" masquerade"));
    assert!(rendered.contains("meta nfproto ipv4 iifname \"lan0\" drop"));
    assert!(rendered.contains("meta nfproto ipv4 oifname \"lan0\" drop"));
    assert!(rendered.contains("meta nfproto ipv4 iifname \"lan1\" drop"));
    assert!(rendered.contains("meta nfproto ipv4 oifname \"lan1\" drop"));
    assert!(!rendered.contains("set output_ifaces"));
    assert!(!rendered.contains("set output_subnets"));
}

#[test]
fn nft_forwarding_structure_intact_and_detects_drift() {
    let wanted = forwarding_desired();
    let connections = wanted.forwarding.as_ref().unwrap();

    let make_rules = || {
        vec![
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "lan0" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "wan0" } },
                    { "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": { "prefix": { "addr": "192.168.10.0", "len": 24 } } } },
                    { "accept": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "wan0" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "lan0" } },
                    { "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "daddr" } }, "right": { "prefix": { "addr": "192.168.10.0", "len": 24 } } } },
                    { "match": { "op": "in", "left": { "ct": { "key": "state" } }, "right": ["established", "related"] } },
                    { "accept": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "lan1" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "wg0" } },
                    { "accept": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "wg0" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "lan1" } },
                    { "match": { "op": "in", "left": { "ct": { "key": "state" } }, "right": ["established", "related"] } },
                    { "accept": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "lan0" } },
                    { "drop": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "lan0" } },
                    { "drop": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "lan1" } },
                    { "drop": null }
                ]
            }),
            serde_json::json!({
                "chain": "forward",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "nfproto" } }, "right": "ipv4" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "lan1" } },
                    { "drop": null }
                ]
            }),
            serde_json::json!({
                "chain": "postrouting",
                "expr": [
                    { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": "lan0" } },
                    { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": "wan0" } },
                    { "match": { "op": "==", "left": { "payload": { "protocol": "ip", "field": "saddr" } }, "right": { "prefix": { "addr": "192.168.10.0", "len": 24 } } } },
                    { "masquerade": null }
                ]
            }),
        ]
    };

    let rules = make_rules();
    let rule_refs: Vec<&Value> = rules.iter().collect();
    assert!(
        forwarding_structure_is_intact(&rule_refs, connections),
        "expected canonical forwarding AST to be intact"
    );

    // Missing drop rule reports drift
    let tampered = make_rules()[..rules.len() - 2].to_vec();
    let tampered_refs: Vec<&Value> = tampered.iter().collect();
    assert!(
        !forwarding_structure_is_intact(&tampered_refs, connections),
        "missing drop rule must report drift"
    );
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
            forwarding: None,
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
        Ipv4ForwardingBackend::new(FakeForwardingIo::new(b"0\n").with_trace(Arc::clone(&trace))),
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
        if remove {
            let missing = missing_router_dataplane_interface(&error)
                .expect("missing interface error must stay machine-readable");
            assert_eq!(missing.interface, name);
            assert_eq!(missing.role, role);
        } else {
            assert!(missing_router_dataplane_interface(&error).is_none());
        }
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
    {
        let events = failed_apply.events.events.lock().expect("events lock");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, RouterDataplaneOperation::Apply);
        assert_eq!(events[0].outcome, RouterDataplaneOutcome::Failed);
        assert!(events[0]
            .error
            .as_deref()
            .expect("failure context")
            .contains("original snapshot restored"));
    }

    let rollback_failure = FakeProvider::new(empty_snapshot());
    rollback_failure.fail_restore.store(true, Ordering::SeqCst);
    let failed_rollback =
        RouterDataplaneManager::with_event_sink(rollback_failure, RecordingEventSink::default());
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

#[test]
fn cleanup_removed_firewall_retains_only_existing_permissions_without_devices() {
    let applied = desired();
    let mut rules = applied.forwarding_rules();
    rules.remove(1);
    rules.push(ForwardingConfig {
        from: "new0".into(),
        to: "new1".into(),
        source_subnet: None,
        masquerade: true,
    });
    let target = RouterDataplaneTarget::Enabled(RouterDataplaneDesired {
        forwarding: Some(rules),
        uplink: String::new(),
        outputs: vec![],
    });
    let backend = NftablesBackend::new(FakeNftExecutor::with_responses(vec![
        Ok(nft_ruleset(Some(&applied))),
        Ok(vec![]),
    ]));
    backend.cleanup_removed(&target).unwrap();
    let calls = backend.executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    let batch = std::str::from_utf8(&calls[1].1).unwrap();
    assert!(batch.contains("delete table inet traffic_masq"));
    assert!(batch.contains("iifname \"lan0\" oifname \"eth0\""));
    assert!(!batch.contains("lan1"));
    assert!(!batch.contains("new0"));
    assert!(!batch.contains("foreign"));
}

#[test]
fn cleanup_removed_firewall_never_recreates_retired_permissions() {
    let current = forwarding_desired();
    let first = current.forwarding.as_ref().unwrap()[0].clone();
    let mut saved = current.clone();
    saved.forwarding.as_mut().unwrap().remove(0);
    let retained = retained_firewall(
        Some(&current),
        &RouterDataplaneTarget::Enabled(saved.clone()),
    )
    .unwrap();
    assert!(!retained.forwarding_rules().contains(&first));
    assert_eq!(
        retained_firewall(Some(&retained), &RouterDataplaneTarget::Enabled(current)),
        Some(retained.clone())
    );
    saved.forwarding = Some(vec![]);
    assert!(retained_firewall(Some(&retained), &RouterDataplaneTarget::Enabled(saved)).is_none());
    let backend =
        NftablesBackend::new(FakeNftExecutor::with_responses(vec![Ok(nft_ruleset(None))]));
    backend
        .cleanup_removed(&RouterDataplaneTarget::Disabled)
        .unwrap();
    assert_eq!(backend.executor.calls.lock().unwrap().len(), 1);
}

#[test]
fn cleanup_removed_firewall_refuses_drifted_or_unproven_ownership() {
    let mut drifted = nft_ruleset_value(&desired());
    owned_entries(&mut drifted)
        .retain(|entry| entry.pointer("/rule/chain").and_then(Value::as_str) != Some("forward"));
    for observed in [
        serde_json::to_vec(&drifted).unwrap(),
        serde_json::to_vec(&serde_json::json!({
            "nftables": [{"table": {"family": NFT_FAMILY, "name": NFT_TABLE, "comment": "foreign"}}]
        }))
        .unwrap(),
    ] {
        let backend = NftablesBackend::new(FakeNftExecutor::with_responses(vec![Ok(observed)]));
        assert!(backend
            .cleanup_removed(&RouterDataplaneTarget::Disabled)
            .is_err());
        assert_eq!(backend.executor.calls.lock().unwrap().len(), 1);
    }
}
