use super::*;
use std::{future::Future, pin::Pin, task::Poll};

async fn assert_pending(future: Pin<&mut impl Future>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn complete<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(1), future)
        .await
        .expect("lock acquisition must finish after its blocker is released")
}

#[tokio::test]
async fn interface_mutations_serialize_per_interface_only() {
    let locks = InterfaceMutationLocks::default();
    let eth0 = locks.lock("eth0").await;

    let blocked = locks.lock("eth0");
    tokio::pin!(blocked);
    assert_pending(blocked.as_mut()).await;

    let wlan0 = tokio::time::timeout(std::time::Duration::from_secs(1), locks.lock("wlan0"))
        .await
        .expect("different interfaces must not block each other");
    drop(wlan0);
    drop(eth0);
    drop(complete(blocked).await);
}

#[tokio::test]
async fn autonomous_runtime_writer_excludes_convergence() {
    let gate = NetworkMutationGate::default();
    let writer = gate.execute().await;
    let convergence = gate.read();
    tokio::pin!(convergence);
    assert_pending(convergence.as_mut()).await;
    drop(writer);
    drop(complete(convergence).await);
}

#[tokio::test]
async fn queued_mutation_does_not_block_transaction_convergence() {
    let gate = NetworkMutationGate::default();
    let transaction = gate.admit().await;
    let writer = gate.write();
    tokio::pin!(writer);
    assert_pending(writer.as_mut()).await;
    let worker = tokio::time::timeout(std::time::Duration::from_secs(1), gate.read())
        .await
        .expect("convergence must progress while another request waits");
    assert_pending(writer.as_mut()).await;
    drop(worker);
    drop(transaction);
    drop(complete(writer).await);
}

#[tokio::test]
async fn compensation_joins_convergence_ahead_of_a_queued_global_writer() {
    let gate = NetworkMutationGate::default();
    let pass = gate.converge().await;
    let writer = gate.execute();
    tokio::pin!(writer);
    assert_pending(writer.as_mut()).await;
    let rollback = tokio::time::timeout(std::time::Duration::from_secs(1), gate.participate())
        .await
        .expect("compensation must not wait behind a writer blocked by its own converger");
    drop(pass);
    assert_pending(writer.as_mut()).await;
    drop(rollback);
    drop(complete(writer).await);
}
