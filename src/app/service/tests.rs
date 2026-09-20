use tempfile::tempdir;

use crate::app::process::ProcessGuard;

use super::*;

#[tokio::test]
async fn status_distinguishes_stopped_from_locked_but_unready() {
    let directory = tempdir().expect("tempdir");
    let mut config = AppConfig::default();
    config.runtime.pid_path = directory.path().join("traffic-masqd.pid");
    config.runtime.socket_path = directory.path().join("traffic-masqd.sock");

    assert_eq!(
        status(&config).await.expect("stopped status"),
        ServiceStatus::Stopped
    );
    let guard = ProcessGuard::acquire(&config.runtime.pid_path).expect("process guard");
    assert_eq!(
        status(&config).await.expect("unready status"),
        ServiceStatus::StartingOrUnhealthy {
            pid: Some(std::process::id())
        }
    );
    drop(guard);
    assert_eq!(
        status(&config).await.expect("stopped status"),
        ServiceStatus::Stopped
    );
}

#[test]
fn prints_and_selects_latest_rolling_log() {
    let directory = tempdir().expect("tempdir");
    let older = directory.path().join("traffic-masqd.log.2026-01-01");
    let latest = directory.path().join("traffic-masqd.log.2026-01-02");
    fs::write(&older, "old\n").expect("older log");
    std::thread::sleep(Duration::from_millis(10));
    fs::write(&latest, "one\ntwo\nthree\n").expect("latest log");
    assert_eq!(latest_log_path(directory.path()).expect("latest"), latest);
}
