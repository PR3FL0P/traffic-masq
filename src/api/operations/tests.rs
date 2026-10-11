use super::*;

#[tokio::test]
async fn cancelled_caller_does_not_cancel_operation_and_shutdown_waits() {
    let operations = Operations::default();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let caller = {
        let operations = operations.clone();
        tokio::spawn(async move {
            operations
                .run(async move {
                    started_tx.send(()).unwrap();
                    finish_rx.await.unwrap();
                    done_tx.send(()).unwrap();
                })
                .await
        })
    };
    started_rx.await.unwrap();
    caller.abort();
    let _ = caller.await;
    let shutdown = {
        let operations = operations.clone();
        tokio::spawn(async move { operations.close().await })
    };
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    finish_tx.send(()).unwrap();
    shutdown.await.unwrap();
    done_rx.await.unwrap();
    assert!(operations.run(async {}).await.is_err());
}

#[tokio::test]
async fn saturated_executor_rejects_more_work() {
    let operations = Operations::default();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut callers = JoinSet::new();
    for _ in 0..MAX_OPERATIONS {
        let operations = operations.clone();
        let gate = gate.clone();
        let started = started_tx.clone();
        callers.spawn(async move {
            operations
                .run(async move {
                    started.send(()).unwrap();
                    let _permit = gate.acquire().await.unwrap();
                })
                .await
                .unwrap();
        });
    }
    for _ in 0..MAX_OPERATIONS {
        started_rx.recv().await.unwrap();
    }
    assert!(operations
        .run(async {})
        .await
        .unwrap_err()
        .to_string()
        .contains("busy"));
    gate.add_permits(MAX_OPERATIONS);
    while let Some(result) = callers.join_next().await {
        result.unwrap();
    }
    operations.close().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_stalled_operations_after_the_drain_deadline() {
    let operations = Operations::default();
    let (started_tx, started_rx) = oneshot::channel();
    let caller = tokio::spawn({
        let operations = operations.clone();
        async move {
            operations
                .run(async move {
                    started_tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                })
                .await
        }
    });
    started_rx.await.unwrap();
    tokio::time::timeout(
        SHUTDOWN_DRAIN_TIMEOUT + std::time::Duration::from_secs(1),
        operations.close(),
    )
    .await
    .unwrap();
    assert!(caller.await.unwrap().is_err());
    operations.close().await;
    assert!(operations.run(async {}).await.is_err());
}
