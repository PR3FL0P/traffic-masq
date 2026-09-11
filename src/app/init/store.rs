//! Receipt and artifact ownership, serialized mutation and recovery.
use super::render::{INIT_SCRIPT, RUNIT_DIR, UNIT};
use super::{absolute_path, Backend, CommandRunner, CommandSpec, Registration, RECEIPT};
use crate::atomic_file;
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

/// Filesystem root is injectable for tests; production always uses `/`.
#[derive(Debug, Clone)]
pub struct ServiceStore {
    pub(super) root: PathBuf,
}
impl ServiceStore {
    pub fn host() -> Self {
        Self { root: "/".into() }
    }
    pub(super) fn path(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(
            path.as_ref()
                .strip_prefix("/")
                .expect("absolute service path"),
        )
    }
    pub fn lock_mutation(&self) -> Result<fs::File> {
        let path = self.path("/etc/traffic-masq/service-install.lock");
        regular_or_missing(&path)?;
        fs::create_dir_all(path.parent().unwrap())?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.try_lock_exclusive()
            .context("another installation or uninstallation is in progress")?;
        Ok(file)
    }
    pub fn ensure_unchanged(&self, expected: Option<&Registration>) -> Result<()> {
        if self.load()?.as_ref() != expected {
            bail!("service registration changed after preflight; rerun installation");
        }
        Ok(())
    }
    pub fn load(&self) -> Result<Option<Registration>> {
        let path = self.path(RECEIPT);
        regular_or_missing(&path)?;
        let content = match fs::read(&path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let registration: Registration =
            serde_json::from_slice(&content).context("invalid init service receipt")?;
        registration.validate()?;
        Ok(Some(registration))
    }
    pub fn matching(&self, config: Option<&Path>) -> Result<Option<Registration>> {
        let Some(registration) = self.load()? else {
            return Ok(None);
        };
        if config.map(absolute_path).transpose()?.as_ref() != Some(&registration.config) {
            return Ok(None);
        }
        Ok(Some(registration))
    }
    pub(super) fn save(&self, registration: &Registration) -> Result<()> {
        let path = self.path(RECEIPT);
        regular_or_missing(&path)?;
        fs::create_dir_all(path.parent().unwrap())?;
        atomic_file::replace(&path, &serde_json::to_vec_pretty(registration)?, 0o600)?;
        Ok(())
    }
    /// Exact previous contents, not a magic comment, establish ownership.
    pub(super) fn validate_files(
        &self,
        desired: &Registration,
        previous: Option<&Registration>,
    ) -> Result<()> {
        regular_or_missing(&self.path(RECEIPT))?;
        for file in &desired.files {
            let path = self.path(&file.path);
            regular_or_missing(&path)?;
            match fs::read(&path) {
                Ok(bytes) => {
                    let owned = previous.is_some_and(|p| {
                        p.files
                            .iter()
                            .chain(&p.previous_files)
                            .any(|old| old.path == file.path && old.content.as_bytes() == bytes)
                    });
                    if !owned {
                        bail!(
                            "refusing to replace unowned or edited service file {}",
                            path.display()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(link) = desired.runit_link() {
            let path = self.path(&link);
            match fs::symlink_metadata(&path) {
                Ok(_)
                    if previous.and_then(Registration::runit_link).as_ref() == Some(&link)
                        && fs::read_link(&path).ok().as_deref() == Some(Path::new(RUNIT_DIR)) => {}
                Ok(_) => bail!(
                    "refusing to replace unowned runit activation path {}",
                    path.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub(super) fn runit_supervisor_running(&self) -> Result<bool> {
        let lock = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path(format!("{RUNIT_DIR}/supervise/lock")))
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        match lock.try_lock_exclusive() {
            Ok(()) => {
                FileExt::unlock(&lock)?;
                Ok(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
    pub fn validate_owned(&self, registration: &Registration) -> Result<()> {
        self.validate_files(registration, Some(registration))
    }
    pub async fn disable(
        &self,
        registration: &Registration,
        runner: &impl CommandRunner,
    ) -> Result<()> {
        self.validate_owned(registration)?;
        if let Some(link) = registration.runit_link() {
            remove_if_present(&self.path(link))?;
        }
        let native_file = match registration.backend {
            Backend::Systemd => UNIT,
            Backend::Openrc | Backend::Sysv => INIT_SCRIPT,
            Backend::Runit => RUNIT_DIR,
        };
        // Nothing was enabled if installation stopped before its native file was written.
        if self.path(native_file).exists() {
            for command in registration.disable_commands() {
                runner.run(&command).await?;
            }
        }
        Ok(())
    }
    pub async fn stop(
        &self,
        registration: &Registration,
        runner: &impl CommandRunner,
        timeout: Duration,
    ) -> Result<()> {
        self.validate_owned(registration)?;
        // A partially installed service may have a receipt but no native file yet.
        let exists = match registration.backend {
            Backend::Systemd => self.path(UNIT).exists(),
            Backend::Openrc | Backend::Sysv => self.path(INIT_SCRIPT).exists(),
            Backend::Runit => self.runit_supervisor_running()?,
        };
        if exists {
            runner.run(&registration.action("stop", timeout)).await?;
        }
        Ok(())
    }
    pub async fn remove(
        &self,
        registration: &Registration,
        runner: &impl CommandRunner,
    ) -> Result<()> {
        self.validate_owned(registration)?;
        if registration.backend == Backend::Runit && self.runit_supervisor_running()? {
            runner
                .run(&registration.action("shutdown", Duration::from_secs(60)))
                .await?;
        }
        for file in registration.files.iter().rev() {
            remove_if_present(&self.path(&file.path))?;
        }
        if registration.backend == Backend::Systemd {
            runner
                .run(&CommandSpec::new("systemctl", &["daemon-reload"]))
                .await?;
        }
        remove_if_present(&self.path(RECEIPT))?;
        // runsv owns supervise/; never recursively delete that runtime state.
        if registration.backend == Backend::Runit {
            let _ = fs::remove_dir(self.path(RUNIT_DIR));
        }
        Ok(())
    }
}

fn regular_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => bail!(
            "service file {} must be a regular file, not a symlink",
            path.display()
        ),
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut parent = path.parent();
    while let Some(path) = parent {
        match fs::symlink_metadata(path) {
            Ok(m)
                if m.file_type().is_symlink()
                    && path == Path::new("/etc/init.d")
                    && fs::canonicalize(path).ok().as_deref()
                        == Some(Path::new("/etc/rc.d/init.d")) => {}
            Ok(m) if !m.is_dir() || m.file_type().is_symlink() => bail!(
                "service file has a non-directory or symlinked parent {}",
                path.display()
            ),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        parent = path.parent();
    }
    Ok(())
}
fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
