use super::*;
use tempfile::tempdir;

#[test]
fn reset_config_removes_user_intent_but_preserves_installation_paths() {
    let mut current = AppConfig::default();
    current.runtime.state_dir = "/srv/traffic-masq/state".into();
    current.runtime.log_dir = "/srv/traffic-masq/log".into();
    current.runtime.socket_group = Some("traffic-masq".into());
    current.vpn.enabled = true;

    let reset = reset_config(&current);
    assert!(!reset.router.is_active());
    assert!(!reset.vpn.enabled);
    assert!(reset.network.interfaces.is_empty());
    assert_eq!(reset.runtime.state_dir, current.runtime.state_dir);
    assert_eq!(reset.runtime.log_dir, current.runtime.log_dir);
    assert_eq!(reset.runtime.socket_group, current.runtime.socket_group);
    reset.validate().expect("reset config must be valid");
}

#[test]
fn clear_directory_removes_contents_but_keeps_root() {
    let root = tempdir().expect("tempdir");
    let state = root.path().join("traffic-masq/state");
    fs::create_dir_all(state.join("nested")).unwrap();
    fs::write(state.join("nested/value"), b"x").unwrap();
    fs::write(state.join("record"), b"y").unwrap();

    clear_directory(&state).expect("clear state");
    assert!(state.is_dir());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
}

#[test]
fn destructive_directory_rejects_shallow_or_relative_paths() {
    assert!(validate_destructive_directory(Path::new("relative/state")).is_err());
    assert!(validate_destructive_directory(Path::new("/")).is_err());
    assert!(validate_destructive_directory(Path::new("/var")).is_err());
    assert!(validate_destructive_directory(Path::new("/var/lib")).is_err());
    assert!(validate_destructive_directory(Path::new("/var/lib/traffic-masq")).is_ok());
}

fn offline_fixture() -> (tempfile::TempDir, PathBuf, AppConfig) {
    let root = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.runtime.state_dir = root.path().join("state");
    config.runtime.log_dir = root.path().join("logs");
    config.runtime.socket_path = root.path().join("run/traffic-masqd.sock");
    config.runtime.pid_path = root.path().join("run/traffic-masqd.pid");
    config.dhcp.leases_dir = config.runtime.state_dir.join("dhcp/leases");
    config.vpn.wireguard_config_dir = config.runtime.state_dir.join("vpn/wireguard");
    config.auth.database_path = config.runtime.state_dir.join("auth.sqlite3");
    config.vpn.enabled = true;
    config.validate().unwrap();

    fs::create_dir_all(config.runtime.state_dir.join("owned")).unwrap();
    fs::write(config.runtime.state_dir.join("owned/journal.json"), b"{}").unwrap();
    fs::create_dir_all(config.runtime.log_dir.clone()).unwrap();

    let config_path = root.path().join("config.toml");
    fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    (root, config_path, config)
}

#[tokio::test]
async fn offline_reset_requires_explicit_force_and_then_clears_state() {
    let (root, config_path, original) = offline_fixture();
    let store = ServiceStore::with_root(root.path().join("service-root"));
    let args = ResetArgs {
        dry_run: false,
        yes: true,
        timeout_seconds: 1,
        force_offline: false,
    };
    let error = run_with_store(args, Some(config_path.clone()), store.clone())
        .await
        .expect_err("stopped daemon must require explicit offline force");
    assert!(error.to_string().contains("--force-offline"));
    assert!(original
        .runtime
        .state_dir
        .join("owned/journal.json")
        .exists());

    let args = ResetArgs {
        dry_run: false,
        yes: true,
        timeout_seconds: 1,
        force_offline: true,
    };
    run_with_store(args, Some(config_path.clone()), store)
        .await
        .expect("forced offline reset");

    let reset = AppConfig::load(&config_path).unwrap();
    assert!(!reset.router.is_active());
    assert!(!reset.vpn.enabled);
    assert_eq!(reset.runtime.state_dir, original.runtime.state_dir);
    assert!(reset.runtime.state_dir.is_dir());
    assert_eq!(fs::read_dir(&reset.runtime.state_dir).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn destructive_directory_rejects_symlinked_parent() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let real = root.path().join("real/state");
    fs::create_dir_all(&real).unwrap();
    let linked = root.path().join("linked");
    symlink(root.path().join("real"), &linked).unwrap();
    assert!(validate_destructive_directory(&linked.join("state")).is_err());
}
