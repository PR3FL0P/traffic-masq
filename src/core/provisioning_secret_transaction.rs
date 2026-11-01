use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;
use zeroize::{Zeroize, Zeroizing};

use crate::atomic_file::{self, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::{PassphraseStore, WifiCredentialRole};

const JOURNAL_VERSION: u32 = 2;
const JOURNAL_FILE: &str = "router-provisioning-secrets.json";

#[derive(Clone)]
pub struct ProvisioningSecretTransactionStore {
    recovery: crate::core::recovery::RecoveryState,
    journal: PathBuf,
    state_dir: PathBuf,
}

#[derive(Deserialize)]
struct ProvisioningSecretJournalHeader {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningSecretJournal {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    previous: BTreeMap<String, Option<String>>,
    roles: BTreeMap<String, WifiCredentialRole>,
}

impl Drop for ProvisioningSecretJournal {
    fn drop(&mut self) {
        for secret in self.previous.values_mut().flatten() {
            secret.zeroize();
        }
    }
}

impl ProvisioningSecretTransactionStore {
    pub fn in_state_dir(
        state_dir: impl AsRef<Path>,
        recovery: crate::core::recovery::RecoveryState,
    ) -> Self {
        let wifi_dir = state_dir.as_ref().join("wifi");
        Self {
            recovery,
            journal: wifi_dir.join(JOURNAL_FILE),
            state_dir: state_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn stage(
        &self,
        previous: BTreeMap<String, (WifiCredentialRole, Option<WifiPassphrase>)>,
    ) -> Result<()> {
        if previous.is_empty() {
            return Ok(());
        }
        if self.load().await?.is_some() {
            bail!("an unresolved router provisioning secret transaction already exists");
        }

        let roles = previous
            .iter()
            .map(|(interface, (role, _))| (interface.clone(), *role))
            .collect();
        let previous = previous
            .into_iter()
            .map(|(interface, (_, secret))| {
                (interface, secret.map(|secret| secret.expose().to_owned()))
            })
            .collect();
        self.save(&ProvisioningSecretJournal {
            version: JOURNAL_VERSION,
            token: None,
            previous,
            roles,
        })
        .await
    }

    /// Return whether secret recovery still blocks new network mutations.
    ///
    /// A journal bound to the already-committed router token is only stale
    /// cleanup metadata: retry its removal here so a transient unlink/fsync
    /// failure after commit cannot wedge the live daemon indefinitely. Never
    /// restore an uncommitted journal from this check; rollback owns that path.
    pub async fn unresolved_after_committed_cleanup(
        &self,
        committed_token: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .load_uncommitted_for_recovery(committed_token)
            .await?
            .is_some())
    }

    pub async fn bind_token(&self, token: &str) -> Result<()> {
        let Some(mut journal) = self.load().await? else {
            return Ok(());
        };
        match journal.token.as_deref() {
            Some(existing) if existing == token => return Ok(()),
            Some(existing) => {
                bail!("provisioning secret journal belongs to transaction {existing}, not {token}")
            }
            None => {}
        }
        journal.token = Some(token.to_owned());
        self.save(&journal).await
    }

    /// Restore the prior credentials while retaining the journal. `None` is
    /// valid only for a staged journal; a token also accepts an unbound journal
    /// when binding failed after the router transaction began.
    pub async fn restore(&self, token: Option<&str>) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        Self::check_token(&journal, token)?;
        self.restore_only(&journal).await?;
        Ok(true)
    }

    /// Retire a journal only after every runtime consumer has been restored,
    /// or after the router commit has durably recorded its token.
    pub async fn finish(&self, token: Option<&str>) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        Self::check_token(&journal, token)?;
        self.clear().await?;
        Ok(true)
    }

    fn check_token(journal: &ProvisioningSecretJournal, token: Option<&str>) -> Result<()> {
        match (journal.token.as_deref(), token) {
            (Some(existing), Some(token)) if existing == token => Ok(()),
            (None, _) => Ok(()),
            (Some(_), Some(token)) => {
                bail!("provisioning secret journal does not belong to transaction {token}")
            }
            (Some(_), None) => {
                bail!("refusing to access a token-bound provisioning secret journal without its token")
            }
        }
    }

    /// Resolve a journal left by a process crash before Wi-Fi supervisors start.
    /// A token already recorded as committed owns the staged secrets; every other
    /// journal represents an uncommitted transaction and must be restored.
    pub async fn recover(&self, committed_token: Option<&str>) -> Result<bool> {
        let Some(journal) = self.load_uncommitted_for_recovery(committed_token).await? else {
            return Ok(false);
        };
        self.restore_and_clear(journal).await?;
        Ok(true)
    }

    async fn restore_and_clear(&self, journal: ProvisioningSecretJournal) -> Result<()> {
        self.restore_only(&journal).await?;
        self.clear().await
    }

    async fn restore_only(&self, journal: &ProvisioningSecretJournal) -> Result<()> {
        let mut failures = Vec::new();
        for (interface, previous) in &journal.previous {
            let passphrases = PassphraseStore::for_role(&self.state_dir, journal.roles[interface]);
            let result = match previous {
                Some(raw) => match WifiPassphrase::new(raw.clone()) {
                    Ok(secret) => passphrases.set(interface, &secret),
                    Err(error) => {
                        failures.push(crate::core::recovery_control::failure(
                            crate::core::recovery_control::FailureKind::Incompatible,
                            format!("{interface}: invalid journaled passphrase: {error}"),
                        ));
                        continue;
                    }
                },
                None => passphrases.clear(interface),
            };
            if let Err(error) = result {
                failures.push(anyhow::Error::new(error).context(interface.clone()));
            }
        }

        crate::core::recovery_control::aggregate(
            failures,
            "failed to restore router provisioning secrets",
        )
    }

    async fn load(&self) -> Result<Option<ProvisioningSecretJournal>> {
        let Some(bytes) = self.load_pending_bytes().await? else {
            return Ok(None);
        };
        self.decode(&bytes).map(Some)
    }

    /// Return only recovery metadata that can still require rollback. A journal
    /// proven committed by the durable router token is retired before full-schema
    /// decoding. This deliberately does not infer a token from malformed JSON.
    async fn load_uncommitted_for_recovery(
        &self,
        committed_token: Option<&str>,
    ) -> Result<Option<ProvisioningSecretJournal>> {
        let Some(bytes) = self.load_pending_bytes().await? else {
            return Ok(None);
        };
        let committed = serde_json::from_slice::<ProvisioningSecretJournalHeader>(&bytes)
            .ok()
            .and_then(|header| header.token)
            .is_some_and(|token| Some(token.as_str()) == committed_token);
        if committed {
            tracing::warn!(
                journal = %self.journal.display(),
                operation = "retire_committed_provisioning_journal",
                invariant = "committed_token_proof",
                metadata_safe_to_remove = true,
                "retiring provisioning recovery metadata proven obsolete by committed router token"
            );
            self.clear().await?;
            return Ok(None);
        }
        self.decode(&bytes).map(Some)
    }

    async fn load_pending_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        // Merely checking for crash-recovery state must not create or chmod the
        // runtime state directory. This matters for read-only/test setups and
        // also avoids turning every network API request into a filesystem
        // mutation when no provisioning journal exists. Security validation is
        // still performed before reading an existing journal.
        match fs::symlink_metadata(&self.journal).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect provisioning secret journal {}",
                        self.journal.display()
                    )
                })
            }
        }

        let parent = self
            .journal
            .parent()
            .context("provisioning secret journal path has no parent")?;
        atomic_file::ensure_private_dir(parent, PRIVATE_DIR_MODE).with_context(|| {
            format!(
                "failed to secure provisioning state directory {}",
                parent.display()
            )
        })?;
        atomic_file::reject_symlink(&self.journal).with_context(|| {
            format!(
                "refusing unsafe provisioning secret journal {}",
                self.journal.display()
            )
        })?;
        let bytes = Zeroizing::new(match fs::read(&self.journal).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read provisioning secret journal {}",
                        self.journal.display()
                    )
                })
            }
        });
        if self.recovery.completed(&self.journal, &bytes).await? {
            self.recovery.retire(&self.journal).await?;
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    fn decode(&self, bytes: &[u8]) -> Result<ProvisioningSecretJournal> {
        let diagnostic = || {
            crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::ValidProvisioningSecretSnapshot,
                "decode",
                crate::core::recovery::RecoveryAction::RestoreCoherentBackup,
            )
            .journal(self.journal.clone())
            .object("router-provisioning-secrets")
            .detail("backup_scope", "complete_state_directory")
            .detail("do_not_edit_journal", true)
        };
        #[derive(Deserialize)]
        struct Schema {
            version: u32,
        }
        let schema: Schema = serde_json::from_slice(bytes).with_context(diagnostic)?;
        if schema.version != JOURNAL_VERSION {
            let diagnostic = crate::core::recovery::RecoveryDiagnostic::fatal(
                crate::core::recovery::StartupRecoveryCode::SupportedProvisioningSecretSchema,
                "decode",
                crate::core::recovery::RecoveryAction::UseCompatibleDaemon,
            )
            .journal(self.journal.clone())
            .object("router-provisioning-secrets")
            .detail("journal_schema", schema.version)
            .detail("supported_schemas", "2")
            .detail("fallback_action", "restore_coherent_backup");
            return Err(anyhow::anyhow!(
                "unsupported provisioning secret journal version {}",
                schema.version
            )
            .context(diagnostic));
        }
        let journal: ProvisioningSecretJournal =
            serde_json::from_slice(bytes).with_context(diagnostic)?;
        if !journal.previous.keys().eq(journal.roles.keys()) {
            return Err(
                anyhow::anyhow!("invalid role provenance in provisioning secret journal")
                    .context(diagnostic()),
            );
        }
        Ok(journal)
    }

    async fn save(&self, journal: &ProvisioningSecretJournal) -> Result<()> {
        self.recovery.before_write(&self.journal).await?;
        let parent = self
            .journal
            .parent()
            .context("provisioning secret journal path has no parent")?;
        atomic_file::ensure_private_dir(parent, PRIVATE_DIR_MODE).with_context(|| {
            format!(
                "failed to secure provisioning state directory {}",
                parent.display()
            )
        })?;
        let mut bytes = Zeroizing::new(serde_json::to_vec_pretty(journal)?);
        bytes.push(b'\n');
        atomic_file::replace_preserving_on_error_async(&self.journal, &bytes, PRIVATE_FILE_MODE)
            .await
            .with_context(|| {
                format!(
                    "failed to persist provisioning secret journal {}",
                    self.journal.display()
                )
            })
    }

    async fn clear(&self) -> Result<()> {
        self.recovery.retire(&self.journal).await
    }
}

#[cfg(test)]
mod tests;
