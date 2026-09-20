use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;
use zeroize::{Zeroize, Zeroizing};

use crate::atomic_file::{self, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE};
use crate::wifi::secret::WifiPassphrase;
use crate::wifi::store::PassphraseStore;

const JOURNAL_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "router-provisioning-secrets.json";

#[derive(Clone)]
pub struct ProvisioningSecretTransactionStore {
    journal: PathBuf,
    passphrases: PassphraseStore,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningSecretJournal {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    previous: BTreeMap<String, Option<String>>,
}

impl Drop for ProvisioningSecretJournal {
    fn drop(&mut self) {
        for secret in self.previous.values_mut().flatten() {
            secret.zeroize();
        }
    }
}

impl ProvisioningSecretTransactionStore {
    pub fn in_state_dir(state_dir: impl AsRef<Path>) -> Self {
        let wifi_dir = state_dir.as_ref().join("wifi");
        Self {
            journal: wifi_dir.join(JOURNAL_FILE),
            passphrases: PassphraseStore::new(wifi_dir.join("psk")),
        }
    }

    pub async fn stage(&self, previous: BTreeMap<String, Option<WifiPassphrase>>) -> Result<()> {
        if previous.is_empty() {
            return Ok(());
        }
        if self.load().await?.is_some() {
            bail!("an unresolved router provisioning secret transaction already exists");
        }

        let previous = previous
            .into_iter()
            .map(|(interface, secret)| (interface, secret.map(|secret| secret.expose().to_owned())))
            .collect();
        self.save(&ProvisioningSecretJournal {
            version: JOURNAL_VERSION,
            token: None,
            previous,
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
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.as_deref().is_some() && journal.token.as_deref() == committed_token {
            self.clear().await?;
            return Ok(false);
        }
        Ok(true)
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

    pub async fn restore_staged(&self) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.is_some() {
            bail!(
                "refusing to restore a token-bound provisioning secret journal without its token"
            );
        }
        self.restore_and_clear(journal).await?;
        Ok(true)
    }

    /// Restore staged secrets but retain the journal until the caller has
    /// re-converged every runtime consumer of those secrets.  This keeps new
    /// network mutations fail-closed if hostapd/wpa_supplicant restoration
    /// fails after the files themselves were restored.
    pub async fn restore_staged_for_reconvergence(&self) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.is_some() {
            bail!(
                "refusing to restore a token-bound provisioning secret journal without its token"
            );
        }
        self.restore_only(&journal).await?;
        Ok(true)
    }

    pub async fn restore_for_token(&self, token: &str) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.as_deref() != Some(token) {
            bail!("provisioning secret journal does not belong to transaction {token}");
        }
        self.restore_and_clear(journal).await?;
        Ok(true)
    }

    /// Restore an uncommitted journal after the router coordinator has
    /// successfully rolled back. `None` is accepted because an apply failure
    /// can enter RollbackFailed before the provisioning journal is bound to the
    /// router token; the coordinator token still serializes that recovery.
    pub async fn restore_for_token_or_unbound(&self, token: &str) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal
            .token
            .as_deref()
            .is_some_and(|existing| existing != token)
        {
            bail!("provisioning secret journal does not belong to transaction {token}");
        }
        self.restore_and_clear(journal).await?;
        Ok(true)
    }

    /// Token-aware variant used after router rollback when runtime consumers
    /// still need a second convergence pass before recovery can be declared
    /// complete.
    pub async fn restore_for_token_or_unbound_for_reconvergence(
        &self,
        token: &str,
    ) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal
            .token
            .as_deref()
            .is_some_and(|existing| existing != token)
        {
            bail!("provisioning secret journal does not belong to transaction {token}");
        }
        self.restore_only(&journal).await?;
        Ok(true)
    }

    pub async fn complete_reconvergence(&self) -> Result<()> {
        self.clear().await
    }

    pub async fn discard_for_token(&self, token: &str) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.as_deref() != Some(token) {
            bail!("provisioning secret journal does not belong to transaction {token}");
        }
        self.clear().await?;
        Ok(true)
    }

    /// Resolve a journal left by a process crash before Wi-Fi supervisors start.
    /// A token already recorded as committed owns the staged secrets; every other
    /// journal represents an uncommitted transaction and must be restored.
    pub async fn recover(&self, committed_token: Option<&str>) -> Result<bool> {
        let Some(journal) = self.load().await? else {
            return Ok(false);
        };
        if journal.token.as_deref().is_some() && journal.token.as_deref() == committed_token {
            self.clear().await?;
            return Ok(false);
        }
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
            let result = match previous {
                Some(raw) => match WifiPassphrase::new(raw.clone()) {
                    Ok(secret) => self.passphrases.set(interface, &secret),
                    Err(error) => {
                        failures.push(format!(
                            "{interface}: invalid journaled passphrase: {error}"
                        ));
                        continue;
                    }
                },
                None => self.passphrases.clear(interface),
            };
            if let Err(error) = result {
                failures.push(format!("{interface}: {error}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to restore router provisioning secrets: {}",
                failures.join("; ")
            )
        }
    }

    async fn load(&self) -> Result<Option<ProvisioningSecretJournal>> {
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
        let journal: ProvisioningSecretJournal =
            serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "failed to parse provisioning secret journal {}",
                    self.journal.display()
                )
            })?;
        if journal.version != JOURNAL_VERSION {
            bail!(
                "unsupported provisioning secret journal version {} in {}",
                journal.version,
                self.journal.display()
            );
        }
        Ok(Some(journal))
    }

    async fn save(&self, journal: &ProvisioningSecretJournal) -> Result<()> {
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
        atomic_file::remove_preserving_on_error_async(&self.journal, PRIVATE_FILE_MODE)
            .await
            .with_context(|| {
                format!(
                    "failed to remove provisioning secret journal {}",
                    self.journal.display()
                )
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
