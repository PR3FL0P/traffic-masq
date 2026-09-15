use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

const MAX_OPERATIONS: usize = 128;

#[derive(Clone, Default)]
pub(crate) struct Operations(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    closed: bool,
    tasks: JoinSet<()>,
}

impl Operations {
    /// Accepted operations outlive their callers. Closing the service waits
    /// for them before network shutdown begins.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        operation: impl Future<Output = T> + Send + 'static,
    ) -> Result<T> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self.0.lock().await;
            while let Some(result) = state.tasks.try_join_next() {
                if let Err(error) = result {
                    tracing::error!(%error, "control operation failed");
                }
            }
            if state.closed {
                bail!("control service is stopping");
            }
            if state.tasks.len() >= MAX_OPERATIONS {
                bail!("control service is busy; retry later");
            }
            state.tasks.spawn(async move {
                let _ = sender.send(operation.await);
            });
        }
        receiver.await.context("control operation failed")
    }

    pub(crate) async fn close(&self) {
        let mut state = self.0.lock().await;
        state.closed = true;
        while let Some(result) = state.tasks.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error, "control operation failed during shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
}
