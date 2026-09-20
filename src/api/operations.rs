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

    /// Stop accepting operations and wait for every accepted task to finish.
    /// Log task panics while continuing to drain the remaining operations.
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
mod tests;
