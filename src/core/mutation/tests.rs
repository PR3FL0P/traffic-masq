use super::*;
use std::sync::Arc;

#[tokio::test]
async fn interface_mutations_serialize_per_interface_only() {
    let locks = InterfaceMutationLocks::default();
    let eth0 = locks.lock("eth0").await;

    let blocked = tokio::spawn({
        let locks = locks.clone();
        async move { locks.lock("eth0").await }
    });
    tokio::task::yield_now().await;
    assert!(!blocked.is_finished());

    let wlan0 = tokio::time::timeout(std::time::Duration::from_secs(1), locks.lock("wlan0"))
        .await
        .expect("different interfaces must not block each other");
    drop(wlan0);
    drop(eth0);
    drop(blocked.await.unwrap());
}

#[tokio::test]
async fn autonomous_runtime_writer_excludes_convergence() {
    let gate = Arc::new(NetworkMutationGate::default());
    let writer = gate.execute().await;
    let convergence = tokio::spawn({
        let gate = gate.clone();
        async move {
            let _guard = gate.read().await;
        }
    });
    tokio::task::yield_now().await;
    assert!(!convergence.is_finished());
    drop(writer);
    convergence.await.unwrap();
}

#[tokio::test]
async fn queued_mutation_does_not_block_transaction_convergence() {
    let gate = Arc::new(NetworkMutationGate::default());
    let transaction = gate.admit().await;
    let writer = tokio::spawn({
        let gate = gate.clone();
        async move {
            let _guard = gate.write().await;
        }
    });
    tokio::task::yield_now().await;
    let worker = tokio::time::timeout(std::time::Duration::from_secs(1), gate.read())
        .await
        .expect("convergence must progress while another request waits");
    assert!(!writer.is_finished());
    drop(worker);
    drop(transaction);
    writer.await.unwrap();
}

#[tokio::test]
async fn compensation_joins_convergence_ahead_of_a_queued_global_writer() {
    let gate = Arc::new(NetworkMutationGate::default());
    let pass = gate.converge().await;
    let writer = tokio::spawn({
        let gate = gate.clone();
        async move {
            let _guard = gate.execute().await;
        }
    });
    tokio::task::yield_now().await;
    assert!(!writer.is_finished());
    let rollback = tokio::time::timeout(std::time::Duration::from_millis(100), gate.participate())
        .await
        .expect("compensation must not wait behind a writer blocked by its own converger");
    drop(pass);
    assert!(
        !writer.is_finished(),
        "global writes still exclude compensation"
    );
    drop(rollback);
    tokio::time::timeout(std::time::Duration::from_secs(1), writer)
        .await
        .unwrap()
        .unwrap();
}
