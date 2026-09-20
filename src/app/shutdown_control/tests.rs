use super::*;
use tempfile::tempdir;

#[test]
fn request_is_process_bound_and_requires_matching_acknowledgement() {
    let directory = tempdir().unwrap();
    let pid_path = directory.path().join("traffic-masqd.pid");
    fs::write(&pid_path, std::process::id().to_string()).unwrap();

    let handle =
        request_restore_interfaces(&pid_path, std::process::id(), Duration::from_secs(1)).unwrap();
    let request = request_for_current_process(&pid_path)
        .unwrap()
        .expect("request");
    assert!(request.restores_interfaces());
    acknowledge(&pid_path, &request).unwrap();
    handle.verify_and_cleanup().unwrap();
    assert!(!request_path(&pid_path).exists());
    assert!(!acknowledgement_path(&pid_path).exists());
}

#[test]
fn missing_acknowledgement_preserves_request_for_diagnosis() {
    let directory = tempdir().unwrap();
    let pid_path = directory.path().join("traffic-masqd.pid");
    fs::write(&pid_path, std::process::id().to_string()).unwrap();

    let handle =
        request_restore_interfaces(&pid_path, std::process::id(), Duration::from_secs(1)).unwrap();
    assert!(handle.verify_and_cleanup().is_err());
    assert!(request_path(&pid_path).exists());
}

#[test]
fn request_for_another_process_is_ignored() {
    let directory = tempdir().unwrap();
    let pid_path = directory.path().join("traffic-masqd.pid");
    fs::write(&pid_path, std::process::id().to_string()).unwrap();
    let other_pid = std::process::id().saturating_add(1);
    let _handle = request_restore_interfaces(&pid_path, other_pid, Duration::from_secs(1)).unwrap();
    assert!(request_for_current_process(&pid_path).unwrap().is_none());
}
