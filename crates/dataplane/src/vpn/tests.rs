use super::test_support::{nft_ruleset, FakeNftExecutor};
use super::*;

#[tokio::test]
async fn rebuilt_vpn_backend_waits_for_a_cancelled_apply_worker() {
    use crate::tests::SuspendedNftExecutor;
    use std::sync::Arc;
    let (executor, started, release) = SuspendedNftExecutor::new(nft_ruleset(Some(&desired())));
    let backend = Arc::new(VpnPolicyFirewallBackend::new(
        executor.clone() as Arc<dyn NftExecutor>
    ));
    let applying = tokio::spawn(async move { backend.apply_async(&desired()).await });
    started.await.unwrap();
    applying.abort();
    let _ = applying.await;
    // Production VPN chain operations rebuild this backend for each hop.
    let recovery = Arc::new(VpnPolicyFirewallBackend::new(
        executor.clone() as Arc<dyn NftExecutor>
    ));
    let mut restoring = {
        let recovery = recovery.clone();
        tokio::spawn(async move { recovery.restore_async(None).await })
    };
    let early = tokio::time::timeout(std::time::Duration::from_millis(20), &mut restoring).await;
    let completed_early = early.is_ok();
    release.send(()).unwrap();
    match early {
        Ok(result) => result,
        Err(_) => restoring.await,
    }
    .unwrap()
    .unwrap();
    assert!(
        !completed_early,
        "a rebuilt backend must wait for the old worker"
    );
    assert_eq!(executor.writes(), ["apply", "restore"]);
    assert!(recovery.observe_async().await.unwrap().desired.is_none());
}

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
    assert!(
        rendered.contains("meta mark and 0xff000000 == 0x54000000 oifname \"tm-wg0\" masquerade")
    );
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
