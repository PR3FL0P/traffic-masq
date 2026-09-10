use super::render::UNIT;
use super::*;
use async_trait::async_trait;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

#[derive(Default)]
struct Recorder {
    commands: Mutex<Vec<CommandSpec>>,
    fail_at: Option<usize>,
}
#[async_trait]
impl CommandRunner for Recorder {
    async fn run(&self, command: &CommandSpec) -> Result<()> {
        let mut commands = self.commands.lock().unwrap();
        commands.push(command.clone());
        if self.fail_at == Some(commands.len()) {
            bail!("injected native failure");
        }
        Ok(())
    }
}
fn host() -> HostFacts {
    HostFacts {
        commands: [
            "systemctl",
            "rc-update",
            "rc-service",
            "/sbin/openrc-run",
            "update-rc.d",
            "chkconfig",
            "sv",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        ..HostFacts::default()
    }
}
fn store() -> (tempfile::TempDir, ServiceStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ServiceStore {
        root: dir.path().to_owned(),
    };
    (dir, store)
}
fn plan(store: &ServiceStore, selection: InitSystem) -> InitPlan {
    fs::create_dir_all(store.path("/var/service")).unwrap();
    let mut facts = host();
    facts.runit_dirs.push("/var/service".into());
    InitPlan::build(
        store,
        &facts,
        selection,
        Path::new("/opt/traffic-masq/sbin/traffic-masqd"),
        Path::new("/etc/custom/traffic.toml"),
        None,
        true,
    )
    .unwrap()
}

#[test]
fn detection_uses_running_init_evidence_not_installed_commands() {
    let mut facts = host();
    assert_eq!(facts.detect(), None);
    facts.pid1 = "systemd".into();
    assert_eq!(facts.detect(), None);
    facts.systemd_running = true;
    assert_eq!(facts.detect(), Some(Backend::Systemd));
    facts.systemd_running = false;
    facts.pid1 = "init".into();
    facts.openrc_running = true;
    assert_eq!(facts.detect(), Some(Backend::Openrc));
    facts.openrc_running = false;
    assert_eq!(facts.detect(), Some(Backend::Sysv));
    facts.pid1 = "runit".into();
    assert_eq!(facts.detect(), Some(Backend::Runit));
    facts.pid1 = "s6-svscan".into();
    assert_eq!(facts.detect(), None);
}

#[test]
fn planning_and_printing_never_create_receipts_or_native_files() {
    let (_dir, store) = store();
    for selection in [
        InitSystem::Auto,
        InitSystem::None,
        InitSystem::Systemd,
        InitSystem::Openrc,
        InitSystem::Sysv,
    ] {
        let p = InitPlan::build(
            &store,
            &host(),
            selection,
            Path::new("/usr/local/sbin/traffic-masqd"),
            Path::new("/etc/traffic-masq/config.toml"),
            None,
            false,
        )
        .unwrap();
        p.print();
        assert!(fs::read_dir(&store.root).unwrap().next().is_none());
    }
}

#[tokio::test]
async fn each_backend_installs_repeats_disables_and_removes_only_owned_files() {
    for selection in [
        InitSystem::Systemd,
        InitSystem::Openrc,
        InitSystem::Runit,
        InitSystem::Sysv,
    ] {
        let (_dir, store) = store();
        let recorder = Recorder::default();
        let p = plan(&store, selection);
        p.apply(&store, &recorder).await.unwrap();
        p.activate_runit(&store).unwrap();
        let registration = store.load().unwrap().unwrap();
        for file in &registration.files {
            assert_eq!(
                fs::read_to_string(store.path(&file.path)).unwrap(),
                file.content
            );
            assert_eq!(
                fs::metadata(store.path(&file.path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                file.mode
            );
        }
        assert_eq!(
            fs::metadata(store.path(RECEIPT))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let keep = store.path("/etc/traffic-masq/config.toml");
        fs::write(&keep, "keep configuration").unwrap();
        let upgrade = plan(&store, selection);
        upgrade.apply(&store, &recorder).await.unwrap();
        upgrade.activate_runit(&store).unwrap();
        store.disable(&registration, &recorder).await.unwrap();
        store
            .stop(&registration, &recorder, Duration::from_secs(60))
            .await
            .unwrap();
        store.remove(&registration, &recorder).await.unwrap();
        assert!(store.load().unwrap().is_none());
        assert_eq!(fs::read_to_string(&keep).unwrap(), "keep configuration");
        assert!(registration
            .files
            .iter()
            .all(|f| !store.path(&f.path).exists()));
        if let Some(link) = registration.runit_link() {
            assert!(fs::symlink_metadata(store.path(link)).is_err());
        }
    }
}

#[tokio::test]
async fn native_enable_failure_leaves_a_receipt_for_retry() {
    let (_dir, store) = store();
    let p = plan(&store, InitSystem::Systemd);
    let failing = Recorder {
        fail_at: Some(2),
        ..Recorder::default()
    };
    assert!(p.apply(&store, &failing).await.is_err());
    assert!(store.load().unwrap().is_some());
    plan(&store, InitSystem::Systemd)
        .apply(&store, &Recorder::default())
        .await
        .unwrap();
}

#[tokio::test]
async fn interrupted_upgrade_accepts_old_and_new_exact_contents_but_not_user_edits() {
    let (_dir, store) = store();
    let p = plan(&store, InitSystem::Systemd);
    p.apply(&store, &Recorder::default()).await.unwrap();
    let old = store.load().unwrap().unwrap();
    let mut pending = old.clone();
    pending.previous_files = old.files.clone();
    pending.files[0].content.push_str("# new release\n");
    store.save(&pending).unwrap();
    // Receipt is new, launcher is still old: recover without losing ownership.
    let retry = plan(&store, InitSystem::Systemd);
    retry.apply(&store, &Recorder::default()).await.unwrap();
    assert!(store.load().unwrap().unwrap().previous_files.is_empty());
    fs::write(store.path(UNIT), "administrator override").unwrap();
    assert!(store.validate_owned(&old).is_err());
}

#[test]
fn foreign_files_symlinks_and_conflicting_registration_are_rejected() {
    let (_dir, store) = store();
    let p = plan(&store, InitSystem::Systemd);
    fs::create_dir_all(store.path("/etc/systemd/system")).unwrap();
    fs::write(store.path(UNIT), "foreign unit").unwrap();
    assert!(store
        .validate_files(p.desired.as_ref().unwrap(), None)
        .is_err());
    fs::remove_file(store.path(UNIT)).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", store.path(UNIT)).unwrap();
    assert!(store
        .validate_files(p.desired.as_ref().unwrap(), None)
        .is_err());
    fs::remove_file(store.path(UNIT)).unwrap();
    store.save(p.desired.as_ref().unwrap()).unwrap();
    assert!(InitPlan::build(
        &store,
        &host(),
        InitSystem::Auto,
        Path::new("/other/sbin/traffic-masqd"),
        Path::new("/etc/custom/traffic.toml"),
        None,
        true
    )
    .is_err());
    assert!(InitPlan::build(
        &store,
        &host(),
        InitSystem::Openrc,
        Path::new("/opt/traffic-masq/sbin/traffic-masqd"),
        Path::new("/etc/custom/traffic.toml"),
        None,
        true
    )
    .is_err());
}

#[tokio::test]
async fn opting_out_removes_the_registered_service() {
    let (_dir, store) = store();
    plan(&store, InitSystem::Systemd)
        .apply(&store, &Recorder::default())
        .await
        .unwrap();
    let p = plan(&store, InitSystem::None);
    assert!(p.desired.is_none());
    assert!(p.previous.is_some());
    p.apply(&store, &Recorder::default()).await.unwrap();
    assert!(store.load().unwrap().is_none());
}

#[test]
fn runit_requires_start_and_an_existing_scan_directory() {
    let (_dir, store) = store();
    let daemon = Path::new("/usr/local/sbin/traffic-masqd");
    let config = Path::new("/etc/traffic-masq/config.toml");
    assert!(InitPlan::build(
        &store,
        &host(),
        InitSystem::Runit,
        daemon,
        config,
        None,
        true
    )
    .is_err());
    fs::create_dir_all(store.path("/service")).unwrap();
    let error = InitPlan::build(
        &store,
        &host(),
        InitSystem::Runit,
        daemon,
        config,
        Some(Path::new("/service")),
        false,
    )
    .unwrap_err();
    assert!(error.to_string().contains("--start"));
}

#[test]
fn receipt_paths_and_control_characters_cannot_inject_files_or_commands() {
    let (_dir, store) = store();
    let mut registration = plan(&store, InitSystem::Systemd).desired.unwrap();
    registration.files[0].path = "/etc/passwd".into();
    assert!(registration.validate().is_err());
    assert!(absolute_path(Path::new("/etc/config\nExecStart=oops")).is_err());
    assert!(absolute_path(Path::new("/etc/config\0bad")).is_err());
}

#[test]
fn launcher_preserves_arbitrary_quoted_paths_as_single_arguments() {
    let (dir, store) = store();
    let mut registration = plan(&store, InitSystem::Systemd).desired.unwrap();
    registration.daemon = dir.path().join("daemon ' $ ` with spaces");
    registration.config = dir.path().join("config ' $ ` with spaces.toml");
    fs::write(&registration.daemon, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&registration.daemon, fs::Permissions::from_mode(0o755)).unwrap();
    let launcher = render::artifacts(&registration).remove(0);
    let path = dir.path().join("launcher");
    fs::write(&path, launcher.content).unwrap();
    let output = std::process::Command::new("/bin/sh")
        .arg(path)
        .arg("run")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("--config\n{}\nrun\n", registration.config.display())
    );
}

#[test]
fn native_scripts_are_valid_shell_and_supervisors_run_foreground() {
    let (dir, store) = store();
    for selection in [
        InitSystem::Systemd,
        InitSystem::Openrc,
        InitSystem::Runit,
        InitSystem::Sysv,
    ] {
        let registration = plan(&store, selection).desired.unwrap();
        for (index, file) in registration.files.iter().enumerate() {
            if file.content.starts_with("#!") {
                let path = dir.path().join(format!("script{index}"));
                fs::write(&path, &file.content).unwrap();
                assert!(std::process::Command::new("/bin/sh")
                    .arg("-n")
                    .arg(path)
                    .status()
                    .unwrap()
                    .success());
            }
        }
        if registration.backend == Backend::Systemd {
            assert!(registration.files[1]
                .content
                .contains("ExecStart=/etc/traffic-masq/service-run run"));
            assert!(registration.files[1].content.contains("KillMode=process"));
        }
    }
}

#[test]
fn mutation_lock_serializes_install_and_uninstall_without_touching_daemon_pid() {
    let (_dir, store) = store();
    let first = store.lock_mutation().unwrap();
    assert!(store.lock_mutation().is_err());
    drop(first);
    assert!(store.lock_mutation().is_ok());
    assert!(!store.path("/run").exists());
}

#[tokio::test]
async fn native_runner_propagates_failure_and_timeout() {
    assert!(NativeRunner
        .run(&CommandSpec::new("/bin/false", &[]))
        .await
        .is_err());
    let mut command = CommandSpec::new("/bin/sleep", &["10"]);
    command.timeout = Duration::from_millis(20);
    assert!(NativeRunner
        .run(&command)
        .await
        .unwrap_err()
        .to_string()
        .contains("timed out"));
}

#[tokio::test]
#[ignore = "requires installed runsv and sv; runs only a temporary sleep service"]
async fn real_runit_stops_service_and_supervisor_before_removing_files() {
    struct RootedRunner(ServiceStore);
    #[async_trait]
    impl CommandRunner for RootedRunner {
        async fn run(&self, command: &CommandSpec) -> Result<()> {
            assert_eq!(command.program, "sv");
            let mut command = command.clone();
            for arg in &mut command.args {
                if arg == RUNIT_DIR {
                    *arg = self.0.path(RUNIT_DIR).to_string_lossy().into_owned();
                }
            }
            NativeRunner.run(&command).await
        }
    }
    let (_dir, store) = store();
    let mut p = plan(&store, InitSystem::Runit);
    // Substitute only the workload: exercise actual runsv, sv, locking and removal.
    let registration = p.desired.as_mut().unwrap();
    registration.files[1].content = "#!/bin/sh\nexec /bin/sleep 300\n".into();
    registration.files[2].content = "#!/bin/sh\nexit 0\n".into();
    p.apply(&store, &Recorder::default()).await.unwrap();
    let registration = p.desired.as_ref().unwrap();
    let mut supervisor = tokio::process::Command::new("runsv")
        .arg(store.path(RUNIT_DIR))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !store.runit_supervisor_running().unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("runsv did not acquire its lock")?;
        let runner = RootedRunner(store.clone());
        runner
            .run(&registration.action("start", Duration::from_secs(5)))
            .await?;
        store.disable(registration, &runner).await?;
        store
            .stop(registration, &runner, Duration::from_secs(5))
            .await?;
        store.remove(registration, &runner).await?;
        tokio::time::timeout(Duration::from_secs(5), supervisor.wait()).await??;
        assert!(store.load()?.is_none());
        assert!(!store.runit_supervisor_running()?);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        // Clean up the temporary workload even when the assertion path fails.
        let runner = RootedRunner(store.clone());
        let _ = runner
            .run(&registration.action("shutdown", Duration::from_secs(5)))
            .await;
    }
    result.unwrap();
}
