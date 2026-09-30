//! Action values carried in router recovery notices.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    InspectRecoveryState,
    RepairStorageAccess,
    RepairStorageAndRestart,
    RestoreCoherentBackup,
    RetryRollback,
    AwaitCleanup,
    UseCompatibleDaemon,
}

impl RecoveryAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InspectRecoveryState => "inspect_recovery_state",
            Self::RepairStorageAccess => "repair_storage_access",
            Self::RepairStorageAndRestart => "repair_storage_and_restart",
            Self::RestoreCoherentBackup => "restore_coherent_backup",
            Self::RetryRollback => "retry_rollback",
            Self::AwaitCleanup => "await_cleanup",
            Self::UseCompatibleDaemon => "use_compatible_daemon",
        }
    }

    pub const fn guidance(self) -> &'static str {
        match self {
            Self::InspectRecoveryState => {
                "preserve recovery metadata and inspect the nested recovery diagnostic before changing state"
            }
            Self::RepairStorageAndRestart => {
                "repair storage access, then restart the daemon to resolve persisted commit proof; preserve the complete state directory"
            }
            Self::RepairStorageAccess => {
                "preserve recovery metadata and repair the reported path type permissions or storage access"
            }
            Self::RestoreCoherentBackup => {
                "restore the complete state directory from one coherent backup and do not replace a journal alone"
            }
            Self::RetryRollback => {
                "repair the reported runtime failure and retry rollback without deleting the journal"
            }
            Self::AwaitCleanup => {
                "preserve recovered state, repair storage access if needed, and wait for automatic journal cleanup"
            }
            Self::UseCompatibleDaemon => {
                "use a daemon that supports the reported journal schema or restore one coherent state backup"
            }
        }
    }
}

impl std::str::FromStr for RecoveryAction {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "inspect_recovery_state" => Self::InspectRecoveryState,
            "repair_storage_access" => Self::RepairStorageAccess,
            "repair_storage_and_restart" => Self::RepairStorageAndRestart,
            "restore_coherent_backup" => Self::RestoreCoherentBackup,
            "retry_rollback" => Self::RetryRollback,
            "await_cleanup" | "retry_cleanup" => Self::AwaitCleanup,
            "use_compatible_daemon" => Self::UseCompatibleDaemon,
            _ => return Err(()),
        })
    }
}

impl std::fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
