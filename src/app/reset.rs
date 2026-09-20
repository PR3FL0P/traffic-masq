//! Destructive reset of traffic-masq configuration and persistent state.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use nix::unistd::Uid;

use crate::app::init::{NativeRunner, ServiceStore};
use crate::app::process::ProcessGuard;
use crate::app::service::{self, ServiceStatus};
use crate::atomic_file;
use crate::config::{AppConfig, ResolvedConfig, ShutdownPolicy};

use super::shutdown_control;

#[derive(Debug, Clone, Args)]
pub struct ResetArgs {
    /// Print what would be reset without changing anything
    #[arg(long)]
    pub dry_run: bool,

    /// Reset without an interactive confirmation
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Maximum time to wait for the daemon to stop
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,

    /// Allow reset while the daemon is already stopped
    ///
    /// Use only after a reboot, or when you otherwise know no traffic-masq-owned
    /// kernel state needs recovery. Without this flag reset requires a healthy,
    /// running daemon so restoration can be acknowledged before journals are removed.
    #[arg(long)]
    pub force_offline: bool,
}

#[derive(Debug)]
struct ResetPlan {
    config_path: Option<PathBuf>,
    current: AppConfig,
    reset: AppConfig,
    directories: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl ResetPlan {
    fn build(resolved: &ResolvedConfig) -> Result<Self> {
        let current = resolved.config.clone();
        let reset = reset_config(&current);

        let mut directories = Vec::new();
        push_directory(&mut directories, current.runtime.state_dir.clone())?;
        push_directory(&mut directories, current.dhcp.leases_dir.clone())?;
        push_directory(&mut directories, current.vpn.wireguard_config_dir.clone())?;

        let mut files = Vec::new();
        if !covered_by_directory(&current.auth.database_path, &directories) {
            files.push(current.auth.database_path.clone());
            files.push(sqlite_sidecar(&current.auth.database_path, "-wal"));
            files.push(sqlite_sidecar(&current.auth.database_path, "-shm"));
        }
        for file in &files {
            validate_removable_file(file)?;
        }

        let config_path = match resolved.source.path() {
            Some(path) if path.is_absolute() => Some(path.to_path_buf()),
            Some(path) => Some(std::env::current_dir()?.join(path)),
            None => None,
        };
        if let Some(path) = &config_path {
            validate_config_target(path)?;
        }

        Ok(Self {
            config_path,
            current,
            reset,
            directories,
            files,
        })
    }

    fn print(&self) {
        println!("traffic-masq reset plan:");
        println!("  Stop traffic-masqd if it is running");
        match &self.config_path {
            Some(path) => println!(
                "  Replace configuration with safe defaults: {}",
                path.display()
            ),
            None => println!("  Configuration already comes from built-in safe defaults"),
        }
        for path in &self.directories {
            println!("  Clear persistent state directory: {}", path.display());
        }
        for path in &self.files {
            println!(
                "  Remove persistent state file if present: {}",
                path.display()
            );
        }
        println!(
            "  Preserve logs: {}",
            self.current.runtime.log_dir.display()
        );
        println!("  Preserve installed binaries and init-service registration");
        println!("  Leave the daemon stopped after reset");
    }

    fn apply(&self) -> Result<()> {
        for directory in &self.directories {
            clear_directory(directory)?;
        }
        for file in &self.files {
            remove_regular_file(file)?;
        }
        if let Some(path) = &self.config_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to recreate configuration directory {}",
                        parent.display()
                    )
                })?;
            }
            let contents = toml::to_string_pretty(&self.reset)?;
            atomic_file::replace(path, contents.as_bytes(), 0o640)
                .with_context(|| format!("failed to reset configuration {}", path.display()))?;
        }
        Ok(())
    }
}

/// Resolve configuration and execute the requested device reset through the host registration store.
pub async fn run(args: ResetArgs, config_override: Option<PathBuf>) -> Result<()> {
    if !args.dry_run && !Uid::effective().is_root() {
        bail!("traffic-masqd reset must be run as root");
    }
    run_with_store(args, config_override, ServiceStore::host()).await
}

pub(crate) async fn run_with_store(
    args: ResetArgs,
    config_override: Option<PathBuf>,
    store: ServiceStore,
) -> Result<()> {
    if args.timeout_seconds == 0 {
        bail!("reset timeout must be greater than zero");
    }

    let resolved = ResolvedConfig::load(config_override)?;
    let plan = ResetPlan::build(&resolved)?;
    plan.print();
    if args.dry_run {
        println!("Dry run completed; no changes were made.");
        return Ok(());
    }

    if !args.yes {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("non-interactive reset requires --yes; use --dry-run to inspect the plan");
        }
        print!("Reset all traffic-masq settings and persistent state? [y/N] ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Reset cancelled; no changes were made.");
            return Ok(());
        }
    }

    let timeout = Duration::from_secs(args.timeout_seconds);
    let _service_lock = store.lock_mutation()?;
    let status = service::status(&resolved.config).await?;

    let mut offline_guard = None;
    let restore_request = match status {
        ServiceStatus::Ready { pid: Some(pid) } => Some(
            shutdown_control::request_restore_interfaces(
                &resolved.config.runtime.pid_path,
                pid,
                timeout,
            )
            .context("failed to request restoration before reset")?,
        ),
        ServiceStatus::Ready { pid: None } => {
            bail!("daemon is ready but its PID file is missing; refusing destructive reset")
        }
        ServiceStatus::StartingOrUnhealthy { pid } => {
            bail!(
                "daemon is running but not ready{}; refusing reset because restoration cannot be acknowledged safely",
                pid.map_or_else(String::new, |pid| format!(" (PID {pid})"))
            )
        }
        ServiceStatus::Stopped if !args.force_offline => {
            bail!(
                "daemon is stopped; safe reset requires a running, ready daemon so owned network state can be restored and acknowledged. After a reboot, rerun with --force-offline if you intentionally want an offline reset"
            )
        }
        ServiceStatus::Stopped => {
            eprintln!(
                "WARNING: performing offline reset without daemon restoration acknowledgement; use this only after reboot or when live traffic-masq-owned kernel state is known to be clean"
            );
            offline_guard = Some(
                ProcessGuard::acquire(&resolved.config.runtime.pid_path)
                    .context("daemon started during offline reset; settings were not reset")?,
            );
            None
        }
    };

    if let Some(registration) = store.matching(resolved.source.path())? {
        store
            .stop(&registration, &NativeRunner, timeout)
            .await
            .context("init service failed to stop; settings were not reset")?;
    }
    if restore_request.is_some() {
        service::stop(&resolved.config, timeout)
            .await
            .context("daemon shutdown failed; settings were not reset")?;
    }

    let _running_guard = if offline_guard.is_none() {
        Some(
            ProcessGuard::acquire(&resolved.config.runtime.pid_path)
                .context("daemon restarted during reset; settings were not reset")?,
        )
    } else {
        None
    };

    if let Some(request) = restore_request {
        request.verify_and_cleanup().context(
            "daemon did not prove successful restoration; recovery state was preserved and reset was aborted",
        )?;
    }

    plan.apply()?;

    println!("traffic-masq settings and persistent state were reset.");
    println!("Logs were preserved. The daemon remains stopped.");
    Ok(())
}

fn reset_config(current: &AppConfig) -> AppConfig {
    let mut reset = AppConfig::default();

    // Preserve installation/runtime locations. A reset should remove user intent,
    // not silently move the daemon to a different state/socket/log directory.
    reset.runtime.state_dir = current.runtime.state_dir.clone();
    reset.runtime.log_dir = current.runtime.log_dir.clone();
    reset.runtime.socket_path = current.runtime.socket_path.clone();
    reset.runtime.pid_path = current.runtime.pid_path.clone();
    reset.runtime.socket_group = current.runtime.socket_group.clone();
    reset.runtime.shutdown_policy = ShutdownPolicy::PreserveInterfaces;
    reset.dhcp.leases_dir = current.dhcp.leases_dir.clone();
    reset.vpn.wireguard_config_dir = current.vpn.wireguard_config_dir.clone();
    reset.auth.database_path = current.auth.database_path.clone();

    reset
}

fn push_directory(directories: &mut Vec<PathBuf>, path: PathBuf) -> Result<()> {
    validate_destructive_directory(&path)?;
    if directories.iter().any(|parent| path.starts_with(parent)) {
        return Ok(());
    }
    directories.retain(|nested| !nested.starts_with(&path));
    directories.push(path);
    directories.sort();
    Ok(())
}

fn covered_by_directory(path: &Path, directories: &[PathBuf]) -> bool {
    directories
        .iter()
        .any(|directory| path.starts_with(directory))
}

/// Reject directory targets that are unsafe for recursive reset cleanup.
fn validate_destructive_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "refusing to clear non-absolute state directory {}",
            path.display()
        );
    }
    let normal = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    if normal < 3
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!(
            "refusing to clear unsafe state directory {}",
            path.display()
        );
    }
    reject_symlink_ancestors(path)?;
    Ok(())
}

/// Reject reset paths containing existing symlink components before destructive filesystem work.
fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "refusing to reset through symbolic link {}",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()))
            }
        }
    }
    Ok(())
}

fn validate_config_target(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "refusing to reset non-absolute configuration path {}",
            path.display()
        );
    }
    reject_symlink_ancestors(path)
}

fn validate_removable_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "refusing to remove non-absolute state file {}",
            path.display()
        );
    }
    reject_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "refusing to remove non-regular state file {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn clear_directory(path: &Path) -> Result<()> {
    validate_destructive_directory(path)?;
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    };

    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            fs::remove_dir_all(&entry_path)
                .with_context(|| format!("failed to remove {}", entry_path.display()))?;
        } else {
            fs::remove_file(&entry_path)
                .with_context(|| format!("failed to remove {}", entry_path.display()))?;
        }
    }
    Ok(())
}

fn remove_regular_file(path: &Path) -> Result<()> {
    validate_removable_file(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests;
