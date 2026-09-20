use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use nix::unistd::{chown, Gid, Group, Uid, User};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use zeroize::Zeroize;

use crate::app::init::{self, InitPlan, InitSystem, NativeRunner, ServiceStore};
use crate::app::service::{self, ServiceStatus};
use crate::atomic_file;
use crate::auth::{AuthService, MINIMUM_PASSWORD_CHARACTERS};
use crate::config::{AppConfig, CONFIG_ENV, DEFAULT_CONFIG_PATH};

use super::process::ProcessGuard;

const ACCESS_GROUP: &str = "traffic-masq";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DependencyPreset {
    Router,
    WifiAp,
    WifiClient,
    Wireguard,
}

#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Never prompt; all ambiguous choices must be supplied explicitly
    #[arg(long)]
    pub non_interactive: bool,
    /// Existing local user to add to the traffic-masq access group
    #[arg(long, conflicts_with = "skip_user_access")]
    pub user: Option<String>,
    /// Do not grant a local user access to the TUI
    #[arg(long)]
    pub skip_user_access: bool,
    /// Dependency checks to perform (does not activate network features)
    #[arg(long, value_delimiter = ',', default_value = "router")]
    pub dependency_presets: Vec<DependencyPreset>,
    /// Install missing dependencies selected by --dependency-presets
    #[arg(long)]
    pub install_deps: bool,
    /// Read the initial device password from this file
    #[arg(long, value_name = "PATH", conflicts_with = "defer_password")]
    pub password_file: Option<PathBuf>,
    /// Leave first-time device password setup for later
    #[arg(long)]
    pub defer_password: bool,
    /// Start the daemon after installation and wait until its API is ready
    #[arg(long)]
    pub start: bool,
    /// Boot service integration; auto detects the running init, none removes our registration
    #[arg(long, value_enum, default_value = "auto")]
    pub init_system: InitSystem,
    /// Existing runit scan directory, when its location cannot be detected
    #[arg(long, value_name = "PATH")]
    pub runit_service_dir: Option<PathBuf>,
    /// Binary installation prefix
    #[arg(long, default_value = "/usr/local")]
    pub prefix: PathBuf,
    /// Print the complete plan without changing the machine
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct UninstallArgs {
    /// Binary installation prefix used during install
    #[arg(long, default_value = "/usr/local")]
    pub prefix: PathBuf,
    /// Show what would be removed without stopping the daemon or changing files
    #[arg(long)]
    pub dry_run: bool,
    /// Apply the removal plan without an interactive prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Maximum time to wait for graceful daemon shutdown
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
}

/// Resolve the owned installation and remove it according to the supplied uninstall options.
pub async fn uninstall(args: UninstallArgs, config_override: Option<PathBuf>) -> Result<()> {
    uninstall_with_store(args, config_override, ServiceStore::host()).await
}

pub(crate) async fn uninstall_with_store(
    args: UninstallArgs,
    config_override: Option<PathBuf>,
    store: ServiceStore,
) -> Result<()> {
    let files = uninstall_files(&args.prefix)?;
    let resolved = crate::config::ResolvedConfig::load(config_override)?;
    let registration = store.load()?;
    if let Some(registration) = &registration {
        if registration.daemon != init::absolute_path(&args.prefix.join("sbin/traffic-masqd"))?
            || Some(&registration.config)
                != resolved
                    .source
                    .path()
                    .map(init::absolute_path)
                    .transpose()?
                    .as_ref()
        {
            bail!("installed init service uses {} and {}; pass its --prefix and --config to uninstall", registration.daemon.display(), registration.config.display());
        }
        store.validate_owned(registration)?;
        println!(
            "Disable and remove recorded {} boot service before removing binaries",
            registration.backend
        );
        registration.print_removal();
    }
    println!(
        "Stop traffic-masqd using configuration: {}",
        resolved.source
    );
    for path in &files {
        println!("Remove if present: {}", path.display());
    }
    println!(
        "Preserve configuration, passwords, state, logs, access group and dependency packages."
    );
    if args.dry_run {
        println!("Dry run completed; no changes were made.");
        return Ok(());
    }
    if !Uid::effective().is_root() {
        bail!("traffic-masqd uninstall must be run as root");
    }
    if !args.yes {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            bail!("non-interactive removal requires --yes; use --dry-run to inspect the plan");
        }
        if !prompt_yes_no("Apply this removal plan?", false)? {
            println!("Uninstallation cancelled; no changes were made.");
            return Ok(());
        }
    }
    let _installation_lock = store.lock_mutation()?;
    store.ensure_unchanged(registration.as_ref())?;
    if let Some(registration) = &registration {
        store.disable(registration, &NativeRunner).await?;
        store
            .stop(
                registration,
                &NativeRunner,
                Duration::from_secs(args.timeout_seconds),
            )
            .await?;
    }
    service::stop(&resolved.config, Duration::from_secs(args.timeout_seconds))
        .await
        .context("daemon shutdown failed; installed files were not removed")?;
    let _guard = ProcessGuard::acquire(&resolved.config.runtime.pid_path)
        .context("daemon restarted during uninstallation; installed files were not removed")?;
    if let Some(registration) = &registration {
        store.remove(registration, &NativeRunner).await?;
    }
    remove_uninstall_files(&files)?;
    println!("traffic-masq uninstalled. Configuration, passwords, state and logs were preserved.");
    Ok(())
}

fn uninstall_files(prefix: &Path) -> Result<Vec<PathBuf>> {
    validate_prefix(prefix)?;
    let files: Vec<_> = [
        "bin/traffic-masq",
        "share/doc/traffic-masq/README.md",
        "share/doc/traffic-masq/config.example.toml",
        "sbin/traffic-masqd",
    ]
    .iter()
    .map(|name| prefix.join(name))
    .collect();
    for path in &files {
        validate_destination(path, "uninstall target")?;
    }
    Ok(files)
}

fn remove_uninstall_files(files: &[PathBuf]) -> Result<()> {
    // Recheck the complete plan before removing any file. Never recurse into directories.
    for path in files {
        validate_destination(path, "uninstall target")?;
    }
    for path in files {
        match fs::remove_file(path) {
            Ok(()) => println!("Removed {}", path.display()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error).with_context(|| format!("failed to remove {}; earlier files may already have been removed; rerun uninstall to finish", path.display())),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Apt,
    Dnf,
    Pacman,
}

#[derive(Debug)]
struct DependencyPlan {
    missing: Vec<&'static str>,
    command: Option<Vec<OsString>>,
    automatic_safe: bool,
    diagnostics: Vec<String>,
}

struct InstallPlan {
    user: Option<String>,
    presets: BTreeSet<DependencyPreset>,
    install_deps: bool,
    password: Option<zeroize::Zeroizing<String>>,
    start: bool,
    config_path: PathBuf,
    daemon_source: PathBuf,
    tui_source: PathBuf,
    daemon_destination: PathBuf,
    tui_destination: PathBuf,
    config: AppConfig,
    config_exists: bool,
    auth_initialized: bool,
    dependencies: DependencyPlan,
    init: InitPlan,
}

/// Resolve installation choices, validate the installation plan, and apply it when requested.
pub async fn run(mut args: InstallArgs, config_override: Option<PathBuf>) -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("traffic-masqd install must be run as root");
    }
    if !args.non_interactive && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        bail!("interactive installation requires a terminal; use --non-interactive and provide all required choices");
    }

    let mut config_path = config_override
        .or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    loop {
        let password = if args.non_interactive {
            validate_unattended(&args)?;
            None
        } else {
            interactive_choices(&mut args, &mut config_path).await?
        };
        let mut plan = match build_plan(&args, config_path.clone(), password).await {
            Ok(plan) => plan,
            Err(error) if !args.non_interactive => {
                eprintln!("Preflight failed: {error:#}");
                if prompt_yes_no("Edit installation choices and retry?", false)? {
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        print_plan(&plan);
        if args.dry_run {
            plan.password.zeroize();
            println!("Dry run completed; no changes were made.");
            return Ok(());
        }
        if !args.non_interactive && !prompt_yes_no("Apply this installation plan?", true)? {
            plan.password.zeroize();
            if prompt_yes_no("Edit installation choices?", false)? {
                continue;
            }
            println!("Installation cancelled; no changes were made.");
            return Ok(());
        }
        return apply_plan(&mut plan).await;
    }
}

fn validate_unattended(args: &InstallArgs) -> Result<()> {
    if args.user.is_none() && !args.skip_user_access {
        bail!("non-interactive installation requires either --user USER or --skip-user-access");
    }
    if args.password_file.is_none() && !args.defer_password {
        bail!(
            "non-interactive installation requires either --password-file PATH or --defer-password"
        );
    }
    Ok(())
}

async fn interactive_choices(
    args: &mut InstallArgs,
    config_path: &mut PathBuf,
) -> Result<Option<zeroize::Zeroizing<String>>> {
    println!("traffic-masq installation\n");
    let suggested = args
        .user
        .clone()
        .or_else(|| std::env::var("SUDO_USER").ok())
        .filter(|u| u != "root")
        .filter(|u| User::from_name(u).ok().flatten().is_some());
    if !args.skip_user_access {
        let label = match &suggested {
            Some(u) => format!("User allowed to access the TUI [{u}] (enter '-' to skip): "),
            None => "User allowed to access the TUI [- = root-only access]: ".into(),
        };
        loop {
            let answer = prompt(&label)?;
            if answer == "-" || (answer.is_empty() && suggested.is_none()) {
                args.user = None;
                break;
            }
            let candidate = if answer.is_empty() {
                suggested.clone()
            } else {
                Some(answer)
            };
            if let Some(name) = candidate {
                if User::from_name(&name)?.is_some_and(|u| !u.uid.is_root()) {
                    args.user = Some(name);
                    break;
                }
            }
            println!("Enter an existing non-root user, or '-' to explicitly skip access setup.");
        }
        args.skip_user_access = args.user.is_none();
    }

    println!("\nDependency presets select checks and packages only; they do not enable network features.");
    let defaults = args.dependency_presets.clone();
    args.dependency_presets.clear();
    for (preset, label) in [
        (DependencyPreset::Router, "Routing / NAT"),
        (DependencyPreset::WifiAp, "Wi-Fi access point"),
        (DependencyPreset::WifiClient, "Wi-Fi client"),
        (DependencyPreset::Wireguard, "WireGuard VPN"),
    ] {
        if prompt_yes_no(&format!("Select {label}?"), defaults.contains(&preset))? {
            args.dependency_presets.push(preset);
        }
    }
    args.install_deps = prompt_yes_no("Install missing dependencies?", true)?;
    args.start = prompt_yes_no("Start the daemon after installation?", true)?;
    if args.init_system != InitSystem::None
        && !prompt_yes_no(
            "Enable daemon autostart at boot (detect init system)?",
            true,
        )?
    {
        args.init_system = InitSystem::None;
    }
    if prompt_yes_no("Advanced settings?", false)? {
        let prefix = prompt(&format!("Binary prefix [{}]: ", args.prefix.display()))?;
        if !prefix.is_empty() {
            args.prefix = PathBuf::from(prefix);
        }
        let path = prompt(&format!("Configuration path [{}]: ", config_path.display()))?;
        if !path.is_empty() {
            *config_path = PathBuf::from(path);
        }
    }
    let config = if config_path.exists() {
        AppConfig::load(config_path)?
    } else {
        AppConfig::default()
    };
    let dependencies =
        dependency_plan(&args.dependency_presets.iter().copied().collect(), &config)?;
    if args.install_deps
        && !dependencies.missing.is_empty()
        && (!dependencies.automatic_safe || dependencies.command.is_none())
    {
        println!("Automatic dependency installation is unavailable. Install {} manually; package hooks may start competing services.", dependencies.missing.join(", "));
        if !prompt_yes_no("Continue installation without installing packages?", false)? {
            bail!("Installation cancelled; no changes were made");
        }
        args.install_deps = false;
    }
    if read_auth_initialized(&config).await? {
        println!("Existing device password will be preserved.");
        return Ok(None);
    }
    if args.password_file.is_some() || args.defer_password {
        return Ok(None);
    }
    if !prompt_yes_no(
        "Set the device password now (otherwise initialize via sudo traffic-masq)?",
        false,
    )? {
        args.defer_password = true;
        return Ok(None);
    }
    loop {
        let first = zeroize::Zeroizing::new(rpassword::prompt_password("New device password: ")?);
        let second =
            zeroize::Zeroizing::new(rpassword::prompt_password("Repeat device password: ")?);
        if first != second {
            println!("Passwords do not match; try again.");
            continue;
        }
        if let Err(error) = validate_password(&first) {
            println!("{error}; try again.");
            continue;
        }
        return Ok(Some(first));
    }
}

async fn build_plan(
    args: &InstallArgs,
    config_path: PathBuf,
    interactive_password: Option<zeroize::Zeroizing<String>>,
) -> Result<InstallPlan> {
    validate_prefix(&args.prefix)?;
    let config_path = init::absolute_path(&config_path)?;
    let user = match &args.user {
        Some(name) => {
            let found =
                User::from_name(name).with_context(|| format!("failed to look up user {name}"))?;
            match found {
                Some(user) if !user.uid.is_root() => Some(name.clone()),
                Some(_) => {
                    bail!("root cannot be granted TUI access; use --skip-user-access to skip")
                }
                None => bail!("local user {name} does not exist"),
            }
        }
        None => None,
    };
    if Group::from_name(ACCESS_GROUP)?.is_none() && !command_exists("groupadd") {
        bail!("the access group does not exist and groupadd was not found in PATH");
    }
    if user.is_some() && !command_exists("usermod") {
        bail!("--user requires usermod, but it was not found in PATH");
    }
    let executable =
        std::env::current_exe().context("failed to resolve the installer executable")?;
    let (daemon_source, tui_source) = locate_binaries(&executable)?;
    validate_regular_executable(&daemon_source)?;
    validate_regular_executable(&tui_source)?;
    let daemon_destination = args.prefix.join("sbin/traffic-masqd");
    let tui_destination = args.prefix.join("bin/traffic-masq");
    validate_destination(&daemon_destination, "daemon destination")?;
    validate_destination(&tui_destination, "TUI destination")?;

    validate_destination(&config_path, "configuration destination")?;
    let config_exists = config_path.exists();
    let mut config = if config_exists {
        AppConfig::load(&config_path)?
    } else {
        AppConfig::default()
    };
    match config.runtime.socket_group.as_deref() {
        Some(ACCESS_GROUP) => {}
        Some(other) => bail!("{} already configures runtime.socket_group = {other:?}; refusing to overwrite it with {ACCESS_GROUP:?}", config_path.display()),
        None => config.runtime.socket_group = Some(ACCESS_GROUP.into()),
    }
    config.validate()?;
    super::runtime::validate_socket_directory(&config.runtime.socket_path)?;
    if service::status(&config).await? != ServiceStatus::Stopped {
        bail!("traffic-masqd is running or starting; stop it first with `traffic-masqd --config {} stop`", config_path.display());
    }

    let auth_initialized = read_auth_initialized(&config).await?;
    let presets = args.dependency_presets.iter().copied().collect();
    let dependencies = dependency_plan(&presets, &config)?;
    if args.install_deps && !dependencies.missing.is_empty() {
        if dependencies.command.is_none() {
            bail!("missing dependencies cannot be installed automatically: no supported package manager was found; install {} manually", dependencies.missing.join(", "));
        }
        if !dependencies.automatic_safe {
            bail!("automatic installation is unavailable for the selected Wi-Fi packages because package hooks may start competing services; install {} manually, then rerun without --install-deps", dependencies.missing.join(", "));
        }
    }
    let password = if auth_initialized {
        None
    } else if args.password_file.is_some() {
        read_password(args)?
    } else {
        interactive_password
    };
    if let Some(value) = &password {
        if let Err(error) = validate_password(value) {
            let mut password = password;
            password.zeroize();
            return Err(error);
        }
    }
    let init = InitPlan::build(
        &ServiceStore::host(),
        &init::HostFacts::discover(),
        args.init_system,
        &daemon_destination,
        &config_path,
        args.runit_service_dir.as_deref(),
        args.start,
    )?;
    Ok(InstallPlan {
        user,
        presets,
        install_deps: args.install_deps,
        password,
        start: args.start,
        config_path,
        daemon_source,
        tui_source,
        daemon_destination,
        tui_destination,
        config,
        config_exists,
        auth_initialized,
        dependencies,
        init,
    })
}

async fn read_auth_initialized(config: &AppConfig) -> Result<bool> {
    if !config.auth.database_path.exists() {
        return Ok(false);
    }
    let options = SqliteConnectOptions::new()
        .filename(&config.auth.database_path)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| {
            format!(
                "failed to inspect existing authentication database {}",
                config.auth.database_path.display()
            )
        })?;
    let has_users: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
    )
    .fetch_one(&pool)
    .await?;
    if has_users == 0 {
        return Ok(false);
    }
    let initialized: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = 'device' AND enabled = 1)",
    )
    .fetch_one(&pool)
    .await?;
    Ok(initialized != 0)
}

fn read_password(args: &InstallArgs) -> Result<Option<zeroize::Zeroizing<String>>> {
    if let Some(path) = &args.password_file {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect password file {}", path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!(
                "password file {} must be a regular, non-symlink file",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "password file {} must not be accessible by group or other users",
                path.display()
            );
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        let mut password = zeroize::Zeroizing::new(String::new());
        file.read_to_string(&mut password)?;
        while password.ends_with(['\n', '\r']) {
            password.pop();
        }
        return Ok(Some(password));
    }
    Ok(None)
}

fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MINIMUM_PASSWORD_CHARACTERS {
        bail!("password must contain at least {MINIMUM_PASSWORD_CHARACTERS} characters");
    }
    Ok(())
}

fn locate_binaries(current: &Path) -> Result<(PathBuf, PathBuf)> {
    let parent = current
        .parent()
        .context("installer executable has no parent directory")?;
    let sibling = parent.join("traffic-masq");
    if sibling.is_file() {
        return Ok((current.to_path_buf(), sibling));
    }
    let adjacent_bin = parent.parent().map(|p| p.join("bin/traffic-masq"));
    if let Some(path) = adjacent_bin.filter(|p| p.is_file()) {
        return Ok((current.to_path_buf(), path));
    }
    bail!("could not find traffic-masq next to {} or in the adjacent bin directory; use a release archive containing both binaries", current.display())
}

fn validate_regular_executable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("missing source binary {}", path.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        bail!("{} is not a regular executable file", path.display());
    }
    Ok(())
}

fn validate_destination(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            bail!(
                "{label} {} must be a regular, non-symlink file when it exists",
                path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {label} {}", path.display()))
        }
    }
    let mut ancestor = path.parent();
    while let Some(candidate) = ancestor {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("{label} has a symlinked parent: {}", candidate.display())
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "{label} has a non-directory parent: {}",
                    candidate.display()
                )
            }
            Ok(_) => ancestor = candidate.parent(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => ancestor = candidate.parent(),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_prefix(prefix: &Path) -> Result<()> {
    if !prefix.is_absolute() {
        bail!("--prefix must be an absolute path");
    }
    if prefix
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        bail!("--prefix must not contain '..' components");
    }
    Ok(())
}

fn dependency_plan(
    presets: &BTreeSet<DependencyPreset>,
    config: &AppConfig,
) -> Result<DependencyPlan> {
    let mut missing = Vec::new();
    let mut diagnostics = Vec::new();
    if presets.contains(&DependencyPreset::Router) {
        match Command::new("nft")
            .args(["--json", "list", "ruleset"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(_) => {
                diagnostics.push(
                    "nft was found, but the JSON ruleset check failed; JSON support or kernel nftables availability is inconclusive"
                        .into(),
                );
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push("nftables"),
            Err(e) => return Err(e.into()),
        }
        diagnostics.push(kernel_probe(
            "/proc/net/netfilter",
            "Kernel nftables support",
        ));
    }
    if presets.contains(&DependencyPreset::WifiAp) && !is_executable(&config.wifi.hostapd_binary) {
        missing.push("hostapd");
    }
    if presets.contains(&DependencyPreset::WifiClient)
        && !is_executable(&config.wifi_client.wpa_supplicant_binary)
    {
        missing.push("wpa_supplicant");
    }
    if presets.contains(&DependencyPreset::Wireguard) {
        diagnostics.push(kernel_probe(
            "/sys/module/wireguard",
            "Kernel WireGuard support",
        ));
    }
    missing.sort_unstable();
    missing.dedup();
    let manager = detect_package_manager();
    let command = manager.map(|m| package_command(m, &missing));
    let wifi_missing = missing
        .iter()
        .any(|p| *p == "hostapd" || *p == "wpa_supplicant");
    let automatic_safe = !(manager == Some(PackageManager::Apt) && wifi_missing);
    Ok(DependencyPlan {
        missing,
        command,
        automatic_safe,
        diagnostics,
    })
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
fn kernel_probe(path: &str, label: &str) -> String {
    if Path::new(path).exists() {
        format!("{label}: detected")
    } else {
        format!("{label}: inconclusive (module may be loadable)")
    }
}
fn detect_package_manager() -> Option<PackageManager> {
    [
        ("apt-get", PackageManager::Apt),
        ("dnf", PackageManager::Dnf),
        ("pacman", PackageManager::Pacman),
    ]
    .into_iter()
    .find_map(|(b, m)| command_exists(b).then_some(m))
}
fn command_exists(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| is_executable(&p.join(binary))))
        .unwrap_or(false)
}
fn package_command(manager: PackageManager, packages: &[&str]) -> Vec<OsString> {
    let mut out: Vec<OsString> = match manager {
        PackageManager::Apt => ["apt-get", "install", "--no-install-recommends", "-y"]
            .into_iter()
            .map(Into::into)
            .collect(),
        PackageManager::Dnf => ["dnf", "install", "-y"]
            .into_iter()
            .map(Into::into)
            .collect(),
        PackageManager::Pacman => ["pacman", "-S", "--needed", "--noconfirm"]
            .into_iter()
            .map(Into::into)
            .collect(),
    };
    out.extend(packages.iter().map(|package| {
        OsString::from(match (manager, *package) {
            (PackageManager::Apt, "wpa_supplicant") => "wpasupplicant",
            _ => package,
        })
    }));
    out
}

fn print_plan(plan: &InstallPlan) {
    println!("\nInstallation plan:");
    println!(
        "  Install missing packages: {}",
        if plan.install_deps {
            "yes"
        } else {
            "no (manual setup)"
        }
    );
    println!(
        "  Daemon: {} <- {}",
        plan.daemon_destination.display(),
        plan.daemon_source.display()
    );
    println!(
        "  TUI: {} <- {}",
        plan.tui_destination.display(),
        plan.tui_source.display()
    );
    println!(
        "  Config: {} ({})",
        plan.config_path.display(),
        if plan.config_exists {
            "preserve existing settings"
        } else {
            "create safe defaults with no managed interfaces"
        }
    );
    println!(
        "  State: {} (preserved)",
        plan.config.runtime.state_dir.display()
    );
    println!(
        "  Runtime: {}",
        plan.config
            .runtime
            .socket_path
            .parent()
            .unwrap_or(Path::new("/run/traffic-masq"))
            .display()
    );
    println!("  Logs: {}", plan.config.runtime.log_dir.display());
    println!(
        "  TUI access: {}",
        plan.user
            .as_deref()
            .map(|u| format!("user {u}, group {ACCESS_GROUP}"))
            .unwrap_or_else(|| "no user selected".into())
    );
    println!(
        "  Dependency presets: {}",
        plan.presets
            .iter()
            .map(|p| p.to_possible_value().unwrap().get_name().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Missing dependencies: {}",
        if plan.dependencies.missing.is_empty() {
            "none".into()
        } else {
            plan.dependencies.missing.join(", ")
        }
    );
    if let Some(command) = &plan.dependencies.command {
        if !plan.dependencies.missing.is_empty() {
            println!(
                "  Package command: {}",
                command
                    .iter()
                    .map(|v| v.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }
    for diagnostic in &plan.dependencies.diagnostics {
        println!("  {diagnostic}");
    }
    println!(
        "  Password: {}",
        if plan.auth_initialized {
            "preserve existing credential"
        } else if plan.password.is_some() {
            "initialize (value hidden)"
        } else {
            "defer setup"
        }
    );
    println!(
        "  Start now: {}",
        if plan.start {
            "yes; an existing desired configuration may resume convergence"
        } else {
            "no"
        }
    );
    plan.init.print();
}

async fn apply_plan(plan: &mut InstallPlan) -> Result<()> {
    let mut completed = Vec::new();
    let result = apply_plan_inner(plan, &mut completed).await;
    plan.password.zeroize();
    result.with_context(|| format!("Completed steps: {}. The failed step may have partially changed the system. Persistent state and packages were not removed. Correct the reported error and rerun the installer with the same configuration {} (stop the daemon first if running).", if completed.is_empty() { "none".into() } else { completed.join(", ") }, shell_path(&plan.config_path)))
}

async fn apply_plan_inner(plan: &mut InstallPlan, completed: &mut Vec<&'static str>) -> Result<()> {
    let store = ServiceStore::host();
    let _installation_lock = store.lock_mutation()?;
    store.ensure_unchanged(plan.init.previous.as_ref())?;
    if let Some(previous) = &plan.init.previous {
        store
            .stop(previous, &NativeRunner, Duration::from_secs(60))
            .await?;
        completed.push("previous init service quiesced");
    }
    let install_guard = ProcessGuard::acquire(&plan.config.runtime.pid_path)
        .context("traffic-masqd started after installation preflight; stop it and retry")?;
    if plan.install_deps && !plan.dependencies.missing.is_empty() {
        let command = plan
            .dependencies
            .command
            .as_ref()
            .expect("preflight command");
        let status = Command::new(&command[0])
            .args(&command[1..])
            .status()
            .context("failed to start package manager")?;
        if !status.success() {
            bail!("package installation failed with status {status}; completed package actions were not rolled back. Fix the package-manager error and rerun the installer");
        }
        completed.push("package manager completed");
        let remaining = dependency_plan(&plan.presets, &plan.config)?;
        if !remaining.missing.is_empty() {
            bail!("package manager completed, but these dependencies are still unavailable: {}. Package changes were not rolled back; fix the dependency paths or packages and rerun", remaining.missing.join(", "));
        }
    }
    let access_gid = ensure_group()?;
    completed.push("access group ready");
    install_binary(&plan.daemon_source, &plan.daemon_destination)?;
    completed.push("daemon binary installed");
    install_binary(&plan.tui_source, &plan.tui_destination)?;
    completed.push("TUI binary installed");
    write_config(plan)?;
    completed.push("configuration prepared");
    prepare_directories(&plan.config, access_gid)?;
    completed.push("directories prepared");
    if let Some(user) = &plan.user {
        add_user_to_group(user)?;
        completed.push("user access granted");
    }
    if !plan.auth_initialized {
        if let Some(password) = &plan.password {
            let auth = AuthService::open(&plan.config.auth).await?;
            auth.initialize_device_password(password).await?;
            completed.push("device password initialized");
        }
    }
    plan.init.apply(&store, &NativeRunner).await?;
    completed.push("boot service registration prepared");
    drop(install_guard);
    plan.init.activate_runit(&store)?;
    println!("Installation completed.");
    if let Some(user) = &plan.user {
        println!("{user} was added to {ACCESS_GROUP}. Sign out and back in before running the TUI; the current shell does not acquire the new group automatically.");
    }
    if !plan.auth_initialized && plan.password.is_none() {
        println!("Device password setup was deferred. While stopped, run: sudo {} --config {} auth set-password", shell_path(&plan.daemon_destination), shell_path(&plan.config_path));
        println!(
            "Or start the daemon and initialize through: sudo {} --socket {}",
            shell_path(&plan.tui_destination),
            shell_path(&plan.config.runtime.socket_path)
        );
    }
    if plan.start {
        let started = if let Some(registration) = &plan.init.desired {
            init::start(registration, &plan.config, Duration::from_secs(10)).await
        } else {
            service::start_executable(
                &plan.daemon_destination,
                &plan.config,
                Some(&plan.config_path),
                Duration::from_secs(10),
            )
            .await
        };
        match started {
            Ok(_) => println!("Daemon started and ready."),
            Err(error) => bail!("installation completed, but daemon startup failed: {error}. Inspect diagnostics with: sudo {} --config {} logs", shell_path(&plan.daemon_destination), shell_path(&plan.config_path)),
        }
    }
    if let Some(registration) = &plan.init.desired {
        println!("Boot autostart enabled via {}.", registration.backend);
    } else {
        println!("No boot service is registered.");
    }
    Ok(())
}

fn shell_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn ensure_group() -> Result<Gid> {
    if let Some(group) = Group::from_name(ACCESS_GROUP)? {
        return Ok(group.gid);
    }
    let status = Command::new("groupadd")
        .args(["--system", ACCESS_GROUP])
        .status()
        .context("failed to run groupadd")?;
    if !status.success() {
        bail!("groupadd failed with status {status}");
    }
    Group::from_name(ACCESS_GROUP)?
        .map(|g| g.gid)
        .context("access group was not visible after groupadd")
}

fn install_binary(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }
    let parent = destination
        .parent()
        .context("binary destination has no parent")?;
    fs::create_dir_all(parent)?;
    let bytes = fs::read(source).with_context(|| format!("failed to read {}", source.display()))?;
    atomic_file::replace(destination, &bytes, 0o755)
        .with_context(|| format!("failed to install {}", destination.display()))?;
    if Uid::effective().is_root() {
        chown(destination, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))?;
    }
    Ok(())
}

fn write_config(plan: &InstallPlan) -> Result<()> {
    let parent = plan
        .config_path
        .parent()
        .context("config path has no parent")?;
    fs::create_dir_all(parent)?;
    let serialized = toml::to_string_pretty(&plan.config)?;
    if !plan.config_exists
        || AppConfig::load(&plan.config_path)?
            .runtime
            .socket_group
            .is_none()
    {
        atomic_file::replace(&plan.config_path, serialized.as_bytes(), 0o640)?;
    } else {
        fs::set_permissions(&plan.config_path, fs::Permissions::from_mode(0o640))?;
    }
    chown(
        &plan.config_path,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )?;
    Ok(())
}

fn prepare_directories(config: &AppConfig, access_gid: Gid) -> Result<()> {
    atomic_file::ensure_private_dir(&config.runtime.state_dir, 0o700)
        .map_err(anyhow::Error::new)?;
    fs::create_dir_all(&config.runtime.log_dir)?;
    fs::set_permissions(&config.runtime.log_dir, fs::Permissions::from_mode(0o750))?;
    chown(
        &config.runtime.log_dir,
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(0)),
    )?;
    super::runtime::prepare_socket_directory(&config.runtime.socket_path, Some(access_gid))?;
    Ok(())
}

fn add_user_to_group(user: &str) -> Result<()> {
    let status = Command::new("usermod")
        .args(["-aG", ACCESS_GROUP, user])
        .status()
        .context("failed to run usermod")?;
    if !status.success() {
        bail!("usermod failed with status {status}");
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    read_input(&mut io::stdin().lock())
}

fn read_input(reader: &mut impl io::BufRead) -> Result<String> {
    let mut value = String::new();
    if reader.read_line(&mut value)? == 0 {
        bail!("Input closed; installation cancelled without accepting a default");
    }
    Ok(value.trim().to_owned())
}
fn prompt_yes_no(label: &str, default: bool) -> Result<bool> {
    let suffix = if default { " [Y/n] " } else { " [y/N] " };
    loop {
        match prompt(&format!("{label}{suffix}"))?
            .to_ascii_lowercase()
            .as_str()
        {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer yes or no."),
        }
    }
}

#[cfg(test)]
mod tests;
