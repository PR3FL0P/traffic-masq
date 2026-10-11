//! Scanning through owned sessions and temporary supplicant processes.
//! Temporary scans retain their own launch proof and compensate before returning.

use super::{
    ClientSupervisorError, CtrlSocketNode, OwnedWpaCtrlIdentity, OwnedWpaCtrlSession,
    WifiClientSupervisor,
};
use crate::wifi::client::ctrl::{CtrlError, WpaSupplicantEvent, WpaSupplicantScanResult};
use crate::wifi::client::render::{render_scan_config, scan_config_path};
use crate::wifi::lifecycle::{save_launch_intent, save_spawned_record, write_private_config};
use crate::wifi::process::ProcessError;
use crate::wifi::record::{WifiProcessKind, WifiRecordStore};
use crate::wifi::render::WifiDigest;
use std::path::Path;
use std::time::Duration;

const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

impl WifiClientSupervisor {
    async fn remove_ctrl_node_if_same(
        &self,
        interface: &str,
        ctrl_path: &Path,
        trusted: Option<CtrlSocketNode>,
    ) -> Result<(), ClientSupervisorError> {
        let Some(trusted) = trusted else {
            return Ok(());
        };

        match tokio::fs::symlink_metadata(ctrl_path).await {
            Ok(metadata) if CtrlSocketNode::from_metadata(&metadata) == trusted => {
                tokio::fs::remove_file(ctrl_path).await.map_err(|error| {
                    ClientSupervisorError::Configuration(anyhow::Error::from(error).context(
                        format!(
                            "failed to remove stale owned wpa_supplicant control socket {}",
                            ctrl_path.display()
                        ),
                    ))
                })?;
                Ok(())
            }
            Ok(_) => Err(ClientSupervisorError::NotOwned {
                interface: interface.to_string(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ClientSupervisorError::Configuration(
                anyhow::Error::from(error).context(format!(
                    "failed to inspect wpa_supplicant control socket {}",
                    ctrl_path.display()
                )),
            )),
        }
    }

    /// Scan through an available supplicant, starting a temporary process when necessary.
    /// Validate the interface name and serialize scanning with configuration changes.
    pub async fn scan(
        &self,
        interface: &str,
    ) -> Result<Vec<WpaSupplicantScanResult>, ClientSupervisorError> {
        crate::config::validate_interface_name(interface)?;
        let _operation = self.inner.operation_lock.read().await;
        let _interface_operation = self.inner.interface_operations.lock(interface).await;
        let ctrl_path = self.ctrl_path(interface);

        let task = self.inner.tasks.lock().await.get(interface).cloned();
        if let Some(task) = task {
            let session = self.owned_ctrl_session(&task).await?;
            return self.perform_scan(&session, interface).await;
        }

        // A pathname alone does not establish ownership. Never unlink or use
        // an unrecorded supplicant socket, even if it does not answer PING.
        match tokio::fs::symlink_metadata(&ctrl_path).await {
            Ok(_) => {
                return Err(ClientSupervisorError::NotOwned {
                    interface: interface.into(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(anyhow::Error::from(error).into()),
        }
        let scan_config_path = scan_config_path(&self.inner.runtime_dir, interface);
        let scan_config = render_scan_config(&self.inner.runtime_dir);
        write_private_config(&scan_config_path, &scan_config)
            .await
            .map_err(anyhow::Error::from)?;

        let store =
            WifiRecordStore::for_scan(&self.inner.records_dir, &self.inner.runtime_dir, interface);
        let config_digest = WifiDigest::of(&[scan_config.as_bytes()]);
        let key_digest = WifiDigest::of(&[]);
        let launch_boot_id = self
            .inner
            .process
            .boot_id()
            .await?
            .ok_or(ProcessError::BootIdUnavailable)?;
        save_launch_intent(
            &store,
            launch_boot_id,
            &self.inner.wpa_supplicant_binary,
            &ctrl_path,
            &scan_config_path,
            config_digest,
            key_digest,
            "",
        )
        .await?;

        let pid = match self
            .inner
            .process
            .spawn_wifi_client(
                &self.inner.wpa_supplicant_binary,
                interface,
                &scan_config_path,
            )
            .await
        {
            Ok(pid) => pid,
            Err(err) => {
                let cleanup = store.clear().await;
                let _ = tokio::fs::remove_file(&scan_config_path).await;
                if let Err(cleanup) = cleanup {
                    return Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "Wi-Fi scan spawn failed: {err}; launch-intent cleanup also failed: {cleanup}; recovery required"
                    )));
                }
                return Err(ClientSupervisorError::from(err));
            }
        };

        tracing::info!(%interface, pid, purpose = "scan", "temporary wpa_supplicant started");
        let spawned_record = async {
            let process_start_ticks = self
                .inner
                .process
                .process_start_ticks(pid)
                .await?
                .ok_or(ProcessError::IdentityChanged { pid })?;
            let boot_id = self
                .inner
                .process
                .boot_id()
                .await?
                .ok_or(ProcessError::BootIdUnavailable)?;
            save_spawned_record(
                &store,
                pid,
                process_start_ticks,
                boot_id,
                &self.inner.wpa_supplicant_binary,
                &ctrl_path,
                &scan_config_path,
                config_digest,
                key_digest,
                "",
            )
            .await
            .map_err(ClientSupervisorError::from)
        }
        .await;
        let record = match spawned_record {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(%interface, pid, error = %format!("{error:#}"), "failed to record temporary wpa_supplicant ownership; stopping process");
                return match self.graceful_stop(pid).await {
                    Ok(()) => {
                        let cleanup = store.clear().await;
                        let _ = tokio::fs::remove_file(&scan_config_path).await;
                        // No durable spawned record exists, so there is no
                        // ownership-bound node identity to authorize unlink.
                        // Leave any surviving pathname untouched.
                        match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                                "failed to persist Wi-Fi scan ownership: {error}; process stopped but ownership cleanup failed: {cleanup}; recovery required"
                            ))),
                        }
                    }
                    Err(stop) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                        "failed to persist Wi-Fi scan ownership: {error}; stopping ephemeral supplicant also failed: {stop}; recovery required"
                    ))),
                };
            }
        };

        let ready = self
            .wait_for_ready(
                OwnedWpaCtrlIdentity {
                    interface: interface.to_string(),
                    kind: WifiProcessKind::Scan,
                    record,
                    require_current_record: true,
                },
                self.inner.ctrl_timeout,
            )
            .await;
        let (scan_result, trusted_ctrl_node) = match ready {
            Ok(session) => match session.capture_ctrl_node().await {
                Ok(node) => (self.perform_scan(&session, interface).await, Some(node)),
                Err(error) => (Err(error), None),
            },
            Err(error) => (Err(error), None),
        };

        match &scan_result {
            Ok(results) => {
                tracing::info!(%interface, pid, networks = results.len(), reason = "scan completed", "stopping temporary wpa_supplicant")
            }
            Err(error) => {
                let running_network_managers =
                    crate::wifi::process::find_competing_network_managers().await;
                tracing::warn!(%interface, pid, error = %format!("{error:#}"), ?running_network_managers, reason = "scan failed", "stopping temporary wpa_supplicant");
            }
        }
        match self.graceful_stop(pid).await {
            Ok(()) => {
                let clear_result = store.clear().await;
                let _ = tokio::fs::remove_file(&scan_config_path).await;
                let ctrl_cleanup = self
                    .remove_ctrl_node_if_same(interface, &ctrl_path, trusted_ctrl_node)
                    .await;
                let cleanup_result = match (clear_result, ctrl_cleanup) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(error), Ok(())) => Err(ClientSupervisorError::from(error)),
                    (Ok(()), Err(error)) => Err(error),
                    (Err(record_error), Err(ctrl_error)) => {
                        Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                            "ownership record cleanup failed: {record_error}; control-socket cleanup also failed: {ctrl_error}; recovery required"
                        )))
                    }
                };

                match (scan_result, cleanup_result) {
                    (Ok(results), Ok(())) => Ok(results),
                    (Err(error), Ok(())) => Err(error),
                    (Ok(_), Err(cleanup)) => Err(cleanup),
                    (Err(error), Err(cleanup)) => Err(ClientSupervisorError::Configuration(
                        anyhow::anyhow!(
                            "Wi-Fi scan failed: {error}; ownership cleanup also failed: {cleanup}; recovery required"
                        ),
                    )),
                }
            }
            Err(stop) => match scan_result {
                Ok(_) => Err(stop),
                Err(error) => Err(ClientSupervisorError::Configuration(anyhow::anyhow!(
                    "Wi-Fi scan failed: {error}; stopping ephemeral supplicant also failed: {stop}; recovery required"
                ))),
            },
        }
    }

    async fn perform_scan(
        &self,
        session: &OwnedWpaCtrlSession,
        interface: &str,
    ) -> Result<Vec<WpaSupplicantScanResult>, ClientSupervisorError> {
        let (events, mut receiver) = session.attach_events().await?;
        if let Err(error) = session.client.scan().await {
            events.close().await;
            return match error {
                CtrlError::Failed => Err(ClientSupervisorError::ScanBusy {
                    interface: interface.to_string(),
                }),
                error => Err(error.into()),
            };
        }

        let completed = tokio::time::timeout(SCAN_TIMEOUT, async {
            loop {
                match receiver.recv().await {
                    Ok(WpaSupplicantEvent::ScanResults) => return true,
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        events.close().await;

        if !completed {
            return Err(ClientSupervisorError::ScanTimeout {
                interface: interface.to_string(),
                timeout: SCAN_TIMEOUT,
            });
        }
        Ok(session.client.scan_results().await?)
    }
}
