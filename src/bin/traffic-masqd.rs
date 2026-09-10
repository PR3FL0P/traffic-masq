use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use nix::unistd::Uid;
use traffic_masq::app::installer::{self, InstallArgs, UninstallArgs};
use traffic_masq::app::service::{self, ServiceStatus};
use traffic_masq::app::{reset_device_password, run_daemon};
use traffic_masq::config::{AppConfig, ResolvedConfig, DEFAULT_CONFIG_PATH};
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(name = "traffic-masqd", about = "traffic-masq privileged daemon")]
struct Args {
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install both binaries and prepare safe local configuration
    Install(InstallArgs),

    /// Stop the daemon and remove installed files, preserving configuration and state
    Uninstall(UninstallArgs),

    /// Run the daemon in the foreground
    ///
    /// Keeps the process attached to the current terminal. Logs and startup
    /// errors remain visible, and Ctrl+C stops the daemon. This mode is best
    /// suited to development and diagnostics.
    Run,

    /// Start the daemon as a background process
    ///
    /// Detaches the daemon from the terminal, writes its PID under /run, and
    /// sends logs to the configured log directory. Use `traffic-masqd status`
    /// to inspect it and `traffic-masqd stop` to stop it.
    Start {
        #[arg(
            long,
            default_value_t = 10,
            help = "Seconds to wait for the background daemon to become ready"
        )]
        timeout_seconds: u64,
    },

    /// Stop the background daemon and wait for it to exit
    Stop {
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },

    /// Show whether the daemon is running and responding
    Status,

    /// Read daemon log output
    Logs {
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
        #[arg(short, long)]
        follow: bool,
    },

    /// Manage daemon authentication
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Inspect, validate, or initialize daemon configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Set or reset the shared device password while the daemon is stopped
    SetPassword,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the selected configuration file path
    Path,

    /// Print the effective configuration
    Show,

    /// Validate the selected configuration
    Validate,

    /// Create a safe initial configuration file
    Init {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let command = args.command.unwrap_or(Command::Run);
    if let Command::Install(install_args) = &command {
        return installer::run(install_args.clone(), args.config).await;
    }
    if let Command::Uninstall(uninstall_args) = &command {
        return installer::uninstall(uninstall_args.clone(), args.config).await;
    }
    if let Command::Config {
        command: ConfigCommand::Init { path, force },
    } = &command
    {
        require_root()?;
        let path = path
            .clone()
            .or(args.config.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        return init_config(&path, *force);
    }

    let resolved = ResolvedConfig::load(args.config)?;
    let config = &resolved.config;
    match command {
        Command::Install(_) | Command::Uninstall(_) => {
            unreachable!("install handled before configuration resolution")
        }
        Command::Config { command } => match command {
            ConfigCommand::Path => {
                println!("{}", resolved.source);
                Ok(())
            }
            ConfigCommand::Show => {
                println!("# source: {}", resolved.source);
                print!("{}", toml::to_string_pretty(config)?);
                Ok(())
            }
            ConfigCommand::Validate => {
                println!("configuration is valid: {}", resolved.source);
                Ok(())
            }
            ConfigCommand::Init { .. } => unreachable!("init handled before resolution"),
        },
        Command::Run => {
            require_root()?;
            eprintln!("Using configuration: {}", resolved.source);
            if resolved.source.is_built_in() {
                eprintln!("Safe mode: no interfaces are configured or managed.");
            }
            run_daemon(resolved.config).await
        }
        Command::Start { timeout_seconds } => {
            require_root()?;
            if timeout_seconds == 0 {
                bail!("start timeout must be greater than zero");
            }
            let pid = service::start(
                config,
                resolved.source.path(),
                Duration::from_secs(timeout_seconds),
            )
            .await?;
            println!(
                "traffic-masqd started (PID {pid}); config: {}",
                resolved.source
            );
            Ok(())
        }
        Command::Stop { timeout_seconds } => {
            require_root()?;
            if timeout_seconds == 0 {
                bail!("stop timeout must be greater than zero");
            }
            if service::stop(config, Duration::from_secs(timeout_seconds)).await? {
                println!("traffic-masqd stopped");
            } else {
                println!("traffic-masqd is already stopped");
            }
            Ok(())
        }
        Command::Status => {
            require_root()?;
            println!("Configuration: {}", resolved.source);
            match service::status(config).await? {
                ServiceStatus::Ready { pid } => {
                    println!("traffic-masqd is running and ready{}", format_pid(pid));
                    Ok(())
                }
                ServiceStatus::StartingOrUnhealthy { pid } => {
                    println!(
                        "traffic-masqd process is running but API is not ready{}",
                        format_pid(pid)
                    );
                    std::process::exit(1);
                }
                ServiceStatus::Stopped => {
                    println!("traffic-masqd is stopped");
                    std::process::exit(3);
                }
            }
        }
        Command::Logs { lines, follow } => {
            require_root()?;
            service::print_logs(config, lines, follow).await
        }
        Command::Auth {
            command: AuthCommand::SetPassword,
        } => {
            require_root()?;
            set_password(config).await
        }
    }
}

fn init_config(path: &Path, force: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).mode(0o640);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("failed to create {}: {error}", path.display()))?;
    let contents = toml::to_string_pretty(&AppConfig::default())?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    println!("created safe configuration at {}", path.display());
    println!("No interfaces are managed until you add them to this file.");
    Ok(())
}

fn require_root() -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("traffic-masqd administration commands must be run as root");
    }
    Ok(())
}

fn format_pid(pid: Option<u32>) -> String {
    pid.map_or_else(String::new, |pid| format!(" (PID {pid})"))
}

async fn set_password(config: &AppConfig) -> Result<()> {
    let mut password = rpassword::prompt_password("New device password: ")?;
    let mut repeated = rpassword::prompt_password("Repeat device password: ")?;
    if password != repeated {
        password.zeroize();
        repeated.zeroize();
        bail!("passwords do not match");
    }
    let result = reset_device_password(config, &password).await;
    password.zeroize();
    repeated.zeroize();
    result?;
    println!("device password updated; all active sessions were revoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn uninstall_cli_accepts_custom_paths_and_preview() {
        use clap::Parser;
        let args = super::Args::try_parse_from([
            "traffic-masqd",
            "--config",
            "/tmp/config.toml",
            "uninstall",
            "--prefix",
            "/opt/traffic-masq",
            "--dry-run",
            "--yes",
        ])
        .unwrap();
        let Some(super::Command::Uninstall(options)) = args.command else {
            panic!("wrong command")
        };
        assert!(options.dry_run && options.yes);
        assert_eq!(
            options.prefix,
            std::path::PathBuf::from("/opt/traffic-masq")
        );
    }

    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn init_creates_a_private_valid_safe_config_and_refuses_overwrite() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        init_config(&path, false).expect("initialize");

        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o640
        );
        let config = AppConfig::load(&path).expect("load initialized config");
        config.validate().expect("valid initialized config");
        assert!(config.network.interfaces.is_empty());
        assert!(init_config(&path, false).is_err());
        init_config(&path, true).expect("explicit overwrite");
    }
}
