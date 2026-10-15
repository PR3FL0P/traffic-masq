#[tokio::test]
async fn uninstall_dry_run_preserves_files_and_does_not_create_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let files = uninstall_files(dir.path()).unwrap();
    fs::create_dir_all(files[0].parent().unwrap()).unwrap();
    fs::write(&files[0], "installed").unwrap();
    let mut config = AppConfig::default();
    config.runtime.pid_path = dir.path().join("runtime/daemon.pid");
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    uninstall_with_store(
        UninstallArgs {
            prefix: dir.path().to_path_buf(),
            dry_run: true,
            yes: true,
            timeout_seconds: 1,
        },
        Some(config_path.clone()),
        ServiceStore::with_root(dir.path()),
    )
    .await
    .unwrap();
    assert_eq!(fs::read_to_string(&files[0]).unwrap(), "installed");
    assert!(config_path.exists());
    assert!(!dir.path().join("runtime").exists());
}

#[test]
fn uninstall_removes_only_named_files_and_is_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    let files = uninstall_files(dir.path()).unwrap();
    for path in &files {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "installed").unwrap();
    }
    let preserved = dir.path().join("share/doc/traffic-masq/custom.txt");
    fs::write(&preserved, "keep").unwrap();
    remove_uninstall_files(&files).unwrap();
    remove_uninstall_files(&files).unwrap();
    assert!(files.iter().all(|path| !path.exists()));
    assert_eq!(fs::read_to_string(preserved).unwrap(), "keep");
}

#[test]
fn uninstall_rejects_directory_or_symlink_before_removing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let files = uninstall_files(dir.path()).unwrap();
    fs::create_dir_all(files[0].parent().unwrap()).unwrap();
    fs::write(&files[0], "keep until preflight passes").unwrap();
    fs::create_dir_all(&files[3]).unwrap();
    assert!(remove_uninstall_files(&files).is_err());
    assert!(files[0].exists());
    fs::remove_dir(&files[3]).unwrap();
    std::os::unix::fs::symlink(&files[0], &files[3]).unwrap();
    assert!(uninstall_files(dir.path()).is_err());
    assert!(files[0].exists());
    assert!(uninstall_files(Path::new("relative")).is_err());
}

use super::*;
use clap::Parser;
use tempfile::tempdir;

#[test]
fn destination_rejects_symlinks_above_existing_parent() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("real/bin")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    assert!(validate_destination(&dir.path().join("link/bin/tool"), "binary").is_err());
    assert!(validate_destination(&dir.path().join("real/bin/tool"), "binary").is_ok());
    assert!(validate_prefix(Path::new("/opt/../usr")).is_err());
}

#[test]
fn dependency_executable_requires_execute_permissions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tool");
    fs::write(&path, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!is_executable(&path));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(is_executable(&path));
    assert!(!is_executable(dir.path()));
}

#[test]
fn eof_is_not_an_empty_default_answer() {
    assert!(read_input(&mut io::Cursor::new(b"")).is_err());
    assert_eq!(read_input(&mut io::Cursor::new(b"\n")).unwrap(), "");
    assert_eq!(read_input(&mut io::Cursor::new(b"yes\n")).unwrap(), "yes");
}

#[test]
fn displayed_paths_quote_shell_metacharacters() {
    assert_eq!(
        shell_path(Path::new("/opt/a'b $(touch nope)")),
        "'/opt/a'\\''b $(touch nope)'"
    );
}

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    install: InstallArgs,
}

#[test]
fn unattended_defaults_keep_package_installation_and_startup_opt_in() {
    let cli = TestCli::try_parse_from([
        "test",
        "--non-interactive",
        "--skip-user-access",
        "--defer-password",
    ])
    .unwrap();
    assert_eq!(
        cli.install.dependency_presets,
        vec![DependencyPreset::Router]
    );
    assert_eq!(cli.install.prefix, PathBuf::from("/usr/local"));
    assert!(!cli.install.install_deps);
    assert!(!cli.install.start);
}

#[tokio::test]
async fn auth_preflight_does_not_create_a_missing_database() {
    let dir = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.auth.database_path = dir.path().join("auth.sqlite3");
    assert!(!read_auth_initialized(&config).await.unwrap());
    assert!(!config.auth.database_path.exists());
}

#[test]
fn unattended_requires_explicit_user_and_password_choices() {
    let args = InstallArgs {
        non_interactive: true,
        user: None,
        skip_user_access: false,
        dependency_presets: vec![DependencyPreset::Router],
        install_deps: false,
        password_file: None,
        defer_password: false,
        start: false,
        init_system: InitSystem::None,
        runit_service_dir: None,
        prefix: "/usr/local".into(),
        dry_run: false,
    };
    assert!(validate_unattended(&args)
        .unwrap_err()
        .to_string()
        .contains("--skip-user-access"));
}

#[test]
fn package_commands_are_argument_vectors() {
    assert_eq!(
        package_command(PackageManager::Apt, &["nftables"]),
        vec![
            "apt-get",
            "install",
            "--no-install-recommends",
            "-y",
            "nftables"
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>()
    );
}

#[test]
fn binary_install_is_atomic_and_preserves_source() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source");
    let destination = dir.path().join("bin/tool");
    fs::write(&source, b"binary").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    install_binary(&source, &destination).unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"binary");
    assert_eq!(fs::read(&destination).unwrap(), b"binary");
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn preset_selection_accepts_lists_deduplicates_and_rejects_mistakes() {
    assert_eq!(
        parse_dependency_presets(" router, wifi-ap,router ").unwrap(),
        vec![DependencyPreset::Router, DependencyPreset::WifiAp]
    );
    assert!(parse_dependency_presets("none").unwrap().is_empty());
    assert!(parse_dependency_presets("router,typo").is_err());
    assert!(parse_dependency_presets("router,").is_err());
    assert!(parse_dependency_presets("none,router").is_err());
}
