use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinSet;

const MAX_OPERATIONS: usize = 128;
const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

    /// Stop admission and drain accepted tasks up to the shutdown deadline.
    /// Stalled tasks are cancelled; mutation guards retain their recovery proof.
    pub(crate) async fn close(&self) {
        let mut state = self.0.lock().await;
        state.closed = true;
        let drain = async {
            while let Some(result) = state.tasks.join_next().await {
                if let Err(error) = result {
                    tracing::error!(%error, "control operation failed during shutdown");
                }
            }
        };
        if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::warn!(remaining = state.tasks.len(), "control shutdown deadline reached; cancelling stalled operations and retaining recovery journals");
            state.tasks.abort_all();
            while let Some(result) = state.tasks.join_next().await {
                if let Err(error) = result {
                    if !error.is_cancelled() {
                        tracing::error!(%error, "control operation failed during shutdown");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
