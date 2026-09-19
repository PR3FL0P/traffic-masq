//! Admission and runtime execution are separate: a transaction may wait for
//! convergence while keeping other requests out, without locking its worker out.
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use tokio::sync::{
    Mutex, MutexGuard, OwnedMutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

#[derive(Clone, Default)]
pub struct InterfaceMutationLocks {
    locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl InterfaceMutationLocks {
    /// Process-wide per-interface serialization for kernel address ownership.
    ///
    /// Interface managers and the embedded DHCP client use separate runtime
    /// objects (and sometimes separate netlink sockets) but mutate the same
    /// kernel resources. A shared registry keeps those writers serialized
    /// without involving the control-plane mutation gate, which DHCP callbacks
    /// cannot safely acquire while router apply is waiting for lease readiness.
    pub fn global() -> Self {
        static GLOBAL: OnceLock<InterfaceMutationLocks> = OnceLock::new();
        GLOBAL.get_or_init(Self::default).clone()
    }

    pub async fn lock(&self, interface: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(interface.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

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
    async fn interface_mutations_serialize_per_interface_only() {
        let locks = InterfaceMutationLocks::default();
        let eth0 = locks.lock("eth0").await;

        let blocked = tokio::spawn({
            let locks = locks.clone();
            async move { locks.lock("eth0").await }
        });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());

        let wlan0 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            locks.lock("wlan0"),
        )
        .await
        .expect("different interfaces must not block each other");
        drop(wlan0);
        drop(eth0);
        drop(blocked.await.unwrap());
    }

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
