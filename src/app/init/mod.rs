//! Init integration: discovery -> immutable plan -> owned files -> native actions.
//! A private receipt allows retries and removal without adopting foreign services.
mod command;
mod host;
mod render;
mod store;
pub use command::{CommandRunner, CommandSpec, NativeRunner};
pub use host::HostFacts;
pub use store::ServiceStore;
#[cfg(test)]
mod tests;

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use super::service::{self, ServiceStatus};
use crate::atomic_file;
use crate::config::AppConfig;
use render::{INIT_SCRIPT, RUNIT_DIR};

const RECEIPT: &str = "/etc/traffic-masq/service-install.json";
const NAME: &str = "traffic-masqd";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InitSystem {
    Auto,
    None,
    Systemd,
    Openrc,
    Runit,
    Sysv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Systemd,
    Openrc,
    Runit,
    Sysv,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Systemd => "systemd",
            Self::Openrc => "OpenRC",
            Self::Runit => "runit",
            Self::Sysv => "SysVinit",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SysvTool {
    UpdateRcD,
    Chkconfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Artifact {
    path: PathBuf,
    content: String,
    mode: u32,
}
impl Artifact {
    fn new(path: impl Into<PathBuf>, content: String, mode: u32) -> Self {
        Self {
            path: path.into(),
            content,
            mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    version: u32,
    pub backend: Backend,
    pub daemon: PathBuf,
    pub config: PathBuf,
    runit_service_dir: Option<PathBuf>,
    sysv_tool: Option<SysvTool>,
    files: Vec<Artifact>,
    #[serde(default)]
    previous_files: Vec<Artifact>,
}

#[derive(Debug)]
pub struct InitPlan {
    pub previous: Option<Registration>,
    pub desired: Option<Registration>,
}
impl InitPlan {
    pub fn build(
        store: &ServiceStore,
        host: &HostFacts,
        selection: InitSystem,
        daemon: &Path,
        config: &Path,
        runit_service_dir: Option<&Path>,
        start: bool,
    ) -> Result<Self> {
        let previous = store.load()?;
        let daemon = absolute_path(daemon)?;
        let config = absolute_path(config)?;
        if let Some(old) = &previous {
            if old.daemon != daemon || old.config != config {
                bail!("an init service is already registered for {} with configuration {}; uninstall that registration before changing prefix or configuration path", old.daemon.display(), old.config.display());
            }
            store.validate_owned(old)?;
            old.require_tools(host)?;
        }
        let backend = match selection {
            InitSystem::Auto => previous
                .as_ref()
                .map(|p| p.backend)
                .or_else(|| host.detect()),
            InitSystem::None => None,
            InitSystem::Systemd => Some(Backend::Systemd),
            InitSystem::Openrc => Some(Backend::Openrc),
            InitSystem::Runit => Some(Backend::Runit),
            InitSystem::Sysv => Some(Backend::Sysv),
        };
        let desired = if let Some(backend) = backend {
            if previous.as_ref().is_some_and(|p| p.backend != backend) {
                bail!("changing init systems requires uninstalling the previous registration first (configuration and state are preserved)");
            }
            let mut registration = Registration {
                version: 1,
                backend,
                daemon,
                config,
                runit_service_dir: None,
                sysv_tool: None,
                files: vec![],
                previous_files: vec![],
            };
            match backend {
                Backend::Systemd => host.require("systemctl")?,
                Backend::Openrc => {
                    host.require("rc-service")?;
                    host.require("rc-update")?;
                    host.require("/sbin/openrc-run")?;
                }
                Backend::Runit => {
                    host.require("sv")?;
                    let dir = runit_service_dir.map(PathBuf::from)
                        .or_else(|| previous.as_ref().and_then(|p| p.runit_service_dir.clone()))
                        .or_else(|| host.runit_dirs.first().cloned())
                        .context("runit requires an existing scan directory; pass --runit-service-dir PATH")?;
                    let dir = absolute_path(&dir)?;
                    if !store.path(&dir).is_dir() {
                        bail!("runit scan directory {} does not exist", dir.display());
                    }
                    if previous
                        .as_ref()
                        .is_some_and(|p| p.runit_service_dir.as_ref() != Some(&dir))
                    {
                        bail!("uninstall the existing registration before changing the runit scan directory");
                    }
                    if !start {
                        bail!("runit starts services when enabled; use --start with runit autostart, or --init-system none");
                    }
                    registration.runit_service_dir = Some(dir);
                }
                Backend::Sysv => {
                    registration.sysv_tool = Some(
                        if let Some(tool) = previous.as_ref().and_then(|p| p.sysv_tool) {
                            tool
                        } else if host.commands.contains("update-rc.d") {
                            SysvTool::UpdateRcD
                        } else {
                            host.require("chkconfig")?;
                            SysvTool::Chkconfig
                        },
                    );
                }
            }
            registration.files = render::artifacts(&registration);
            if registration.backend == Backend::Runit
                && store.path(format!("{RUNIT_DIR}/down")).exists()
            {
                bail!("runit service has an administrator-provided down file; remove it before enabling boot autostart");
            }
            if previous.is_none() && registration.backend == Backend::Systemd {
                for path in [
                    "/usr/lib/systemd/system/traffic-masqd.service",
                    "/lib/systemd/system/traffic-masqd.service",
                ] {
                    if store.path(path).exists() {
                        bail!("a vendor service already exists at {path}; refusing to shadow it");
                    }
                }
            }
            store.validate_files(&registration, previous.as_ref())?;
            Some(registration)
        } else {
            None
        };
        if runit_service_dir.is_some()
            && desired.as_ref().is_none_or(|p| p.backend != Backend::Runit)
        {
            bail!("--runit-service-dir requires runit init integration");
        }
        Ok(Self { previous, desired })
    }
    pub fn print(&self) {
        match &self.desired {
            None if self.previous.is_some() => {
                println!("  Boot autostart: remove the recorded service registration");
                self.previous.as_ref().unwrap().print_removal();
            }
            None => {
                println!("  Boot autostart: none (disabled or no supported running init detected)")
            }
            Some(registration) => {
                println!(
                    "  Boot autostart: {} (receipt: {RECEIPT})",
                    registration.backend
                );
                for file in &registration.files {
                    println!(
                        "  Service file: {} (mode {:o})\n{}",
                        file.path.display(),
                        file.mode,
                        file.content
                    );
                }
                if let Some(link) = registration.runit_link() {
                    println!(
                        "  Enable link: {} -> {RUNIT_DIR} (starts immediately)",
                        link.display()
                    );
                }
                for command in registration.enable_commands() {
                    println!("  Enable command: {command}");
                }
            }
        }
    }
    /// Run after binaries/config/password are ready, while the installer holds
    /// the daemon lock. The receipt is written first so partial installs recover.
    pub async fn apply(&self, store: &ServiceStore, runner: &impl CommandRunner) -> Result<()> {
        match &self.desired {
            Some(registration) => {
                store.validate_files(registration, self.previous.as_ref())?;
                let mut pending = registration.clone();
                if let Some(previous) = &self.previous {
                    pending.previous_files = previous
                        .files
                        .iter()
                        .chain(&previous.previous_files)
                        .cloned()
                        .collect();
                }
                store.save(&pending)?;
                for file in &registration.files {
                    let path = store.path(&file.path);
                    fs::create_dir_all(path.parent().unwrap())?;
                    atomic_file::replace(&path, file.content.as_bytes(), file.mode)?;
                }
                // Enabling runit is deferred until the process lock is released.
                for command in registration.enable_commands() {
                    runner.run(&command).await?;
                }
                store.save(registration)?;
            }
            None => {
                if let Some(old) = &self.previous {
                    store.disable(old, runner).await?;
                    store.remove(old, runner).await?;
                }
            }
        }
        Ok(())
    }
    pub fn activate_runit(&self, store: &ServiceStore) -> Result<()> {
        if let Some(registration) = &self.desired {
            if let Some(link) = registration.runit_link() {
                store.validate_owned(registration)?;
                let link = store.path(link);
                if fs::symlink_metadata(&link).is_err() {
                    std::os::unix::fs::symlink(RUNIT_DIR, link)?;
                }
            }
        }
        Ok(())
    }
}

impl Registration {
    fn require_tools(&self, host: &HostFacts) -> Result<()> {
        match self.backend {
            Backend::Systemd => host.require("systemctl"),
            Backend::Openrc => {
                host.require("rc-service")?;
                host.require("rc-update")
            }
            Backend::Runit => host.require("sv"),
            Backend::Sysv => host.require(match self.sysv_tool.context("missing SysV tool")? {
                SysvTool::UpdateRcD => "update-rc.d",
                SysvTool::Chkconfig => "chkconfig",
            }),
        }
    }
    pub fn print_removal(&self) {
        for command in self.disable_commands() {
            println!("  Disable command: {command}");
        }
        println!(
            "  Stop command: {}",
            self.action("stop", Duration::from_secs(60))
        );
        for file in &self.files {
            println!("  Remove owned service file: {}", file.path.display());
        }
        if let Some(link) = self.runit_link() {
            println!("  Remove owned activation link: {}", link.display());
        }
        println!("  Remove receipt: {RECEIPT}");
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported init receipt version {}", self.version);
        }
        for path in [&self.daemon, &self.config] {
            if !path.is_absolute() || absolute_path(path)? != *path {
                bail!("non-canonical path in init receipt");
            }
        }
        if self.backend == Backend::Runit {
            let directory = self
                .runit_service_dir
                .as_deref()
                .context("runit receipt lacks scan directory")?;
            if !directory.is_absolute() || absolute_path(directory)? != directory {
                bail!("non-canonical runit directory in receipt");
            }
        } else if self.runit_service_dir.is_some() {
            bail!("invalid runit directory in receipt");
        }
        if (self.backend == Backend::Sysv) != self.sysv_tool.is_some() {
            bail!("invalid SysV tool in receipt");
        }
        // Only known artifact paths are ever touched, even with a malformed receipt.
        let expected = render::artifacts(self);
        if self.previous_files.iter().any(|file| {
            !expected
                .iter()
                .any(|f| f.path == file.path && f.mode == file.mode)
        }) {
            bail!("unexpected previous artifact paths in init receipt");
        }
        if self.files.len() != expected.len()
            || self
                .files
                .iter()
                .zip(expected)
                .any(|(file, expected)| file.path != expected.path || file.mode != expected.mode)
        {
            bail!("unexpected artifact paths in init receipt");
        }
        Ok(())
    }
    fn runit_link(&self) -> Option<PathBuf> {
        self.runit_service_dir.as_ref().map(|p| p.join(NAME))
    }
    fn enable_commands(&self) -> Vec<CommandSpec> {
        match self.backend {
            Backend::Systemd => vec![
                CommandSpec::new("systemctl", &["daemon-reload"]),
                CommandSpec::new("systemctl", &["enable", "traffic-masqd.service"]),
            ],
            Backend::Openrc => vec![CommandSpec::new("rc-update", &["add", NAME, "default"])],
            Backend::Runit => vec![],
            Backend::Sysv => match self.sysv_tool.unwrap() {
                SysvTool::UpdateRcD => vec![
                    CommandSpec::new("update-rc.d", &[NAME, "defaults"]),
                    CommandSpec::new("update-rc.d", &[NAME, "enable"]),
                ],
                SysvTool::Chkconfig => vec![
                    CommandSpec::new("chkconfig", &["--add", NAME]),
                    CommandSpec::new("chkconfig", &[NAME, "on"]),
                ],
            },
        }
    }
    fn disable_commands(&self) -> Vec<CommandSpec> {
        match self.backend {
            Backend::Systemd => vec![CommandSpec::new(
                "systemctl",
                &["disable", "traffic-masqd.service"],
            )],
            Backend::Openrc => vec![CommandSpec::new("rc-update", &["--all", "del", NAME])],
            Backend::Runit => vec![],
            Backend::Sysv => match self.sysv_tool.unwrap() {
                SysvTool::UpdateRcD => {
                    vec![CommandSpec::new("update-rc.d", &["-f", NAME, "remove"])]
                }
                SysvTool::Chkconfig => vec![CommandSpec::new("chkconfig", &["--del", NAME])],
            },
        }
    }
    fn action(&self, action: &str, timeout: Duration) -> CommandSpec {
        let mut command = match self.backend {
            Backend::Systemd => CommandSpec::new("systemctl", &[action, "traffic-masqd.service"]),
            Backend::Openrc if action == "stop" => {
                CommandSpec::new("rc-service", &["--ifstarted", NAME, action])
            }
            Backend::Openrc => CommandSpec::new("rc-service", &[NAME, action]),
            Backend::Sysv => CommandSpec::new(INIT_SCRIPT, &[action]),
            Backend::Runit => CommandSpec::new(
                "sv",
                &[
                    "-w",
                    &timeout.as_secs().max(1).to_string(),
                    action,
                    RUNIT_DIR,
                ],
            ),
        };
        command.timeout = timeout + Duration::from_secs(5);
        command
    }
}

pub async fn start(
    registration: &Registration,
    config: &AppConfig,
    timeout: Duration,
) -> Result<u32> {
    ServiceStore::host().validate_owned(registration)?;
    let deadline = tokio::time::Instant::now() + timeout;
    if registration.backend == Backend::Runit {
        while !ServiceStore::host().runit_supervisor_running()? {
            if tokio::time::Instant::now() >= deadline {
                bail!("runit did not discover traffic-masqd; check that runsvdir watches the selected scan directory");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    NativeRunner
        .run(&registration.action("start", timeout))
        .await?;
    loop {
        if let ServiceStatus::Ready { pid: Some(pid) } = service::status(config).await? {
            return Ok(pid);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("{} accepted start but traffic-masqd API did not become ready; inspect the native service and daemon logs", registration.backend);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let text = absolute
        .to_str()
        .context("service paths must be valid UTF-8")?;
    if text.chars().any(char::is_control) {
        bail!("service paths cannot contain control characters");
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => (),
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized == Path::new("/") {
        bail!("service path cannot be the filesystem root");
    }
    Ok(normalized)
}
