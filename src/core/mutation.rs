//! Admission and runtime execution are separate: a transaction may wait for
//! convergence while keeping other requests out, without locking its worker out.
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Default)]
pub struct NetworkMutationGate {
    admission: Mutex<()>,
    runtime: RwLock<()>,
}

impl NetworkMutationGate {
    pub async fn admit(&self) -> MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Background convergence/liveness, which never acquire admission.
    pub async fn read(&self) -> RwLockReadGuard<'_, ()> {
        self.runtime.read().await
    }

    /// A caller that already holds admission may exclude background writers.
    pub async fn execute(&self) -> RwLockWriteGuard<'_, ()> {
        self.runtime.write().await
    }

    pub async fn write(&self) -> (MutexGuard<'_, ()>, RwLockWriteGuard<'_, ()>) {
        let admission = self.admit().await;
        let runtime = self.execute().await;
        (admission, runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn queued_mutation_does_not_block_transaction_convergence() {
        let gate = Arc::new(NetworkMutationGate::default());
        let transaction = gate.admit().await;
        let writer = tokio::spawn({
            let gate = gate.clone();
            async move { let _guard = gate.write().await; }
        });
        tokio::task::yield_now().await;
        let worker = tokio::time::timeout(std::time::Duration::from_secs(1), gate.read())
            .await.expect("convergence must progress while another request waits");
        assert!(!writer.is_finished());
        drop(worker);
        drop(transaction);
        writer.await.unwrap();
    }
}
