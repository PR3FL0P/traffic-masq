use super::*;

impl NetworkTransactionManager {
    /// Restore the committed state after staging or convergence fails. The
    /// caller retains operation reservations and the cancellation guard until
    /// compensation has either completed or registered explicit recovery.
    pub(super) async fn compensate_failed_apply(
        &self,
        pending: PendingTransaction,
        error: anyhow::Error,
        cancellation: &mut ApplyRecoveryGuard,
    ) -> Result<PendingNetworkChange> {
        let PendingTransaction {
            info,
            target,
            allow_management_change,
            snapshot,
            previous_config,
            secret,
            ..
        } = pending;
        let token = info.token;
        let interface = info.interface.as_str();
        let config = &target;
        let desired = self.desired();
        let gate = self.runtime_gate();
        let running_network_managers = if config.wifi_client.is_some() {
            crate::wifi::process::find_competing_network_managers().await
        } else {
            Vec::new()
        };
        tracing::warn!(%interface, %token, error = %format!("{error:#}"), ?running_network_managers, "interface change failed; restoring previous configuration");
        let path = self.journal_path(interface);
        let rollback = self
            .recovery()
            .run(&path, false, async {
                self.recovery().check_rollback_scope(
                    desired.state_dir(),
                    Some(interface),
                    &path,
                )?;
                let execution = match &gate {
                    Some(gate) => Some(gate.participate().await),
                    None => None,
                };
                let lane = desired.runtime_locks.lock(interface).await;
                // Persistence in another scope may have become uncertain
                // while compensation waited for its runtime reservation/lane.
                self.recovery().check_commit(desired.state_dir())?;
                let credential_update = desired.credential_updates.clone().read_owned().await;
                let secret = secret.clone();
                let root = desired.state_dir().to_path_buf();
                let name = interface.to_owned();
                let (lane, credential_update, execution, secret_restored) =
                    tokio::task::spawn_blocking(move || {
                        let result = match secret {
                            Some(secret) => secret.restore(&root, &name),
                            None => Ok(()),
                        };
                        (lane, credential_update, execution, result)
                    })
                    .await?;
                desired
                    .restore(&token, snapshot.clone(), previous_config.clone())
                    .await;
                drop(credential_update);
                drop(lane);
                drop(execution);
                let restoration = match secret_restored {
                    Ok(()) => self.await_convergence(&desired, interface).await,
                    Err(error) => Err(error),
                };
                match restoration {
                    Ok(()) => self.clear_journal(interface).await,
                    Err(error) => Err(error),
                }
            })
            .await;
        if let Err(rollback_error) = rollback {
            // The requested state is no longer desired, but until a fresh
            // convergence pass proves the committed state was restored the
            // transaction must stay visible and block overlapping network
            // mutations. The token is rollback-only: a failed candidate
            // must never become committable merely because compensation
            // also failed.
            let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
            let info = PendingNetworkChange {
                recovery_progress: None,
                token: token.clone(),
                interface: interface.to_string(),
                rollback_timeout_seconds,
                expires_at_unix: current_unix_time().saturating_add(rollback_timeout_seconds),
                phase: if self.recovery().stopped(&path) {
                    NetworkChangePhase::RecoveryRequired
                } else {
                    NetworkChangePhase::RollbackRequired
                },
                last_error: Some(format!("apply: {error:#}; rollback: {rollback_error:#}")),
            };
            self.inner.pending.lock().await.insert(
                token.clone(),
                PendingTransaction {
                    info,
                    confirmation_deadline: None,
                    target: config.clone(),
                    allow_management_change,
                    snapshot: snapshot.clone(),
                    previous_config: previous_config.clone(),
                    secret: secret.clone(),
                },
            );
            self.spawn_timer(token.clone(), false);
            cancellation.armed = false;
            bail!(
                "network change failed to converge: {error}; rollback also failed: {rollback_error}; recovery remains pending as token {token}"
            );
        }
        desired.withdraw(&token).await;
        self.inner.pending.lock().await.remove(&token);
        cancellation.armed = false;
        Err(error)
    }

    /// Start the confirmation window only after convergence succeeds.
    pub(super) async fn await_confirmation(
        &self,
        mut pending: PendingTransaction,
        cancellation: &mut ApplyRecoveryGuard,
    ) -> PendingNetworkChange {
        let rollback_timeout_seconds = self.inner.rollback_timeout.as_secs();
        pending.info.expires_at_unix = current_unix_time().saturating_add(rollback_timeout_seconds);
        pending.info.phase = NetworkChangePhase::AwaitingCommit;
        pending.confirmation_deadline =
            Some(tokio::time::Instant::now() + self.inner.rollback_timeout);
        let info = pending.info.clone();
        let managed = pending.target.managed;
        self.inner
            .pending
            .lock()
            .await
            .insert(info.token.clone(), pending);
        tracing::info!(
            interface = %info.interface,
            token = %info.token,
            rollback_timeout_seconds,
            managed,
            "network change converged; awaiting commit before the rollback timer fires"
        );
        self.spawn_rollback_timer(info.token.clone());
        cancellation.armed = false;
        info
    }
}
