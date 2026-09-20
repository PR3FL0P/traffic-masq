//! Admission and runtime execution are separate: a transaction may wait for
//! convergence while keeping other requests out, without locking its worker out.
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

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

    /// Serialize mutations of one interface until the returned guard is dropped.
    /// Other interfaces can acquire their own locks independently.
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
    /// Reserve admission for one control operation without preventing background convergence.
    pub async fn admit(&self) -> MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Desired-state/background audits that are safe to run concurrently.
    pub async fn read(&self) -> RwLockReadGuard<'_, ()> {
        self.runtime.read().await
    }

    /// Exclude concurrent runtime writers. Callers may already hold admission,
    /// or may be autonomous background writers such as process liveness repair.
    pub async fn execute(&self) -> RwLockWriteGuard<'_, ()> {
        self.runtime.write().await
    }

    /// Acquire admission before exclusive runtime access, returning both guards.
    /// This order lets convergence progress while another mutation waits for admission.
    pub async fn write(&self) -> (MutexGuard<'_, ()>, RwLockWriteGuard<'_, ()>) {
        let admission = self.admit().await;
        let runtime = self.execute().await;
        (admission, runtime)
    }
}

#[cfg(test)]
mod tests;
