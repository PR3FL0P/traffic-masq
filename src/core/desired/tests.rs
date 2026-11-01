use std::time::Duration;

use tempfile::tempdir;

use crate::config::InterfaceRole;

use super::*;

fn interface(address: &str) -> InterfaceConfig {
    InterfaceConfig {
        wifi_concurrent: false,
        randomize_mac: false,
        mac_address: None,
        role: InterfaceRole::Output,
        managed: true,
        ipv4: Some(address.parse().expect("network")),
        dhcp: None,
        dhcp_client: None,
        wifi: None,
        wifi_client: None,
    }
}

async fn desired_state() -> (DesiredNetworkState, tempfile::TempDir) {
    let directory = tempdir().expect("tempdir");
    let mut base = AppConfig::default();
    base.network
        .interfaces
        .insert("lan0".to_string(), interface("192.168.10.1/24"));
    let overrides = RuntimeOverrideManager::load(directory.path(), &base)
        .await
        .expect("overrides");
    (DesiredNetworkState::new(base, overrides), directory)
}

async fn lan0_address(state: &DesiredNetworkState) -> String {
    state
        .effective()
        .await
        .expect("effective")
        .network
        .interfaces["lan0"]
        .ipv4
        .expect("ipv4")
        .to_string()
}

#[tokio::test]
async fn changes_during_a_pass_are_retained_until_the_next_wait() {
    let (state, _dir) = desired_state().await;
    // A pass has read the old snapshot and is busy applying it.
    assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
    state
        .propose("pending", "lan0", interface("10.1.1.1/24"), false)
        .await;
    tokio::time::timeout(Duration::from_secs(1), state.changed())
        .await
        .unwrap();
    assert_eq!(lan0_address(&state).await, "10.1.1.1/24");
    state.withdraw("pending").await;
    tokio::time::timeout(Duration::from_secs(1), state.changed())
        .await
        .unwrap();
    assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
    state
        .overrides
        .set_interface("lan0".into(), interface("172.16.0.1/24"), false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), state.changed())
        .await
        .unwrap();
    assert_eq!(lan0_address(&state).await, "172.16.0.1/24");
}

#[tokio::test]
async fn pass_result_is_retained_before_a_waiter_subscribes() {
    let (state, _dir) = desired_state().await;
    state.report_result(7, Err(anyhow::anyhow!("netlink unavailable")));
    let pass = tokio::time::timeout(Duration::from_secs(1), state.pass_covering(7))
        .await
        .unwrap();
    assert_eq!(pass.error.as_deref(), Some("netlink unavailable"));
    state.report_pass(8, BTreeMap::new());
    let pass = tokio::time::timeout(Duration::from_secs(1), state.pass_covering(8))
        .await
        .unwrap();
    assert!(pass.error.is_none());
}

#[tokio::test]
async fn converger_failure_wakes_a_waiter_without_a_new_pass() {
    let (state, _dir) = desired_state().await;
    state.attach_converger();

    let waiter = {
        let state = state.clone();
        tokio::spawn(async move { state.pass_covering(1).await })
    };
    tokio::task::yield_now().await;
    state.fail_converger("rtnetlink notification stream closed");

    let pass = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("failed converger should wake the waiter")
        .expect("waiter task");
    assert_eq!(
        pass.error.as_deref(),
        Some("network converger failed: rtnetlink notification stream closed")
    );
}

#[tokio::test]
async fn converger_failure_is_sticky_across_stop() {
    let (state, _dir) = desired_state().await;
    state.attach_converger();
    state.fail_converger("notifications closed");
    state.stop_converger();
    assert_eq!(
        state.converger_state(),
        ConvergerState::Failed("notifications closed".into())
    );
}

#[tokio::test]
async fn without_a_proposal_the_committed_configuration_is_what_counts() {
    let (state, _dir) = desired_state().await;
    assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
}

#[tokio::test]
async fn a_proposal_becomes_what_the_machine_is_converged_towards() {
    let (state, _dir) = desired_state().await;

    state
        .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
        .await;

    assert_eq!(lan0_address(&state).await, "10.1.1.1/24");
    assert!(state.is_tentative("lan0").await);
}

/// Abandoning a change is dropping the layer. There is no undo step,
/// because the committed layer never stopped describing the old state.
#[tokio::test]
async fn withdrawing_a_proposal_restores_the_committed_configuration() {
    let (state, _dir) = desired_state().await;
    state
        .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
        .await;

    let released = state.withdraw("token-1").await;

    assert_eq!(released, vec!["lan0".to_string()]);
    assert_eq!(lan0_address(&state).await, "192.168.10.1/24");
    assert!(!state.is_tentative("lan0").await);
}

#[tokio::test]
async fn a_transaction_cannot_withdraw_what_another_one_proposed() {
    let (state, _dir) = desired_state().await;
    state
        .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
        .await;

    assert!(state.withdraw("token-2").await.is_empty());
    assert_eq!(lan0_address(&state).await, "10.1.1.1/24");
}

#[tokio::test]
async fn proposing_wakes_whoever_is_converging() {
    let (state, _dir) = desired_state().await;
    let waiter = {
        let state = state.clone();
        tokio::spawn(async move { state.changed().await })
    };
    tokio::task::yield_now().await;

    state
        .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
        .await;

    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("a proposal must wake the converger")
        .expect("waiter task");
}

/// Both layers feed one wait, so a committed change is not missed just
/// because the converger happened to be waiting for a tentative one.
#[tokio::test]
async fn a_committed_change_wakes_the_same_wait() {
    let (state, _dir) = desired_state().await;
    let waiter = {
        let state = state.clone();
        tokio::spawn(async move { state.changed().await })
    };
    tokio::task::yield_now().await;

    state
        .overrides
        .set_interface("lan0".to_string(), interface("172.16.0.1/24"), false)
        .await
        .expect("commit");

    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("a committed change must wake the converger")
        .expect("waiter task");
    assert_eq!(lan0_address(&state).await, "172.16.0.1/24");
}

/// The layer on top wins while it exists: a transaction that has been
/// applied but not confirmed is what the machine should currently look like.
#[tokio::test]
async fn a_proposal_outranks_the_committed_configuration() {
    let (state, _dir) = desired_state().await;
    state
        .overrides
        .set_interface("lan0".to_string(), interface("172.16.0.1/24"), false)
        .await
        .expect("commit");
    state
        .propose("token-1", "lan0", interface("10.1.1.1/24"), false)
        .await;

    assert_eq!(lan0_address(&state).await, "10.1.1.1/24");

    state.withdraw("token-1").await;
    assert_eq!(lan0_address(&state).await, "172.16.0.1/24");
}

#[tokio::test]
async fn interface_completion_is_independent_and_cannot_acknowledge_a_newer_intent() {
    let (state, _dir) = desired_state().await;
    state.attach_converger();
    state
        .propose("first", "lan0", interface("10.0.0.1/24"), false)
        .await;
    let first = state.interface_revision("lan0");
    state.report_interface_result("lan0", first, &Ok(()));
    tokio::time::timeout(
        Duration::from_millis(100),
        state.interface_pass_covering("lan0", first),
    )
    .await
    .expect("another interface's unfinished pass must not block this one");
    state
        .propose("second", "lan0", interface("10.1.0.1/24"), false)
        .await;
    let second = state.interface_revision("lan0");
    state.report_interface_result("lan0", first, &Ok(()));
    state.report_interface_result("other0", second, &Ok(()));
    assert!(tokio::time::timeout(
        Duration::from_millis(20),
        state.interface_pass_covering("lan0", second)
    )
    .await
    .is_err());
    state.report_interface_result("lan0", second, &Err(anyhow::anyhow!("DHCP unavailable")));
    let result = state.interface_pass_covering("lan0", second).await;
    assert!(result.failures["lan0"].contains("DHCP unavailable"));
    // A slow old worker cannot replace the newer interface receipt.
    state.report_interface_result("lan0", first, &Ok(()));
    assert_eq!(state.interface_pass_covering("lan0", second).await, result);
}

#[tokio::test]
async fn effective_read_does_not_mix_old_overrides_with_a_withdrawn_proposal() {
    let (state, _dir) = desired_state().await;
    let candidate = interface("10.7.0.1/24");
    state
        .propose("commit", "lan0", candidate.clone(), false)
        .await;
    let mut tentative = state.tentative.lock().await;
    let mut reader = tokio::spawn({
        let state = state.clone();
        async move { state.effective().await.unwrap() }
    });
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut reader)
        .await
        .is_err());
    state
        .commit_interface("commit", "lan0".into(), candidate.clone(), false)
        .await
        .unwrap();
    // This is withdraw's map mutation, held at the exact interleaving where a
    // reader that had already cloned old overrides would lose the candidate.
    tentative.remove("lan0");
    drop(tentative);
    assert_eq!(reader.await.unwrap().network.interfaces["lan0"], candidate);
}
