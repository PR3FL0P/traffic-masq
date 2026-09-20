#[test]
fn reset_cli_accepts_preview_and_non_interactive_confirmation() {
    use clap::Parser;
    let args = super::Args::try_parse_from([
        "traffic-masqd",
        "--config",
        "/tmp/config.toml",
        "reset",
        "--dry-run",
        "--yes",
        "--timeout-seconds",
        "12",
        "--force-offline",
    ])
    .unwrap();
    let Some(super::Command::Reset(options)) = args.command else {
        panic!("wrong command")
    };
    assert!(options.dry_run && options.yes && options.force_offline);
    assert_eq!(options.timeout_seconds, 12);
}

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
