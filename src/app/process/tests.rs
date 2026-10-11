use tempfile::tempdir;

use super::*;

#[test]
fn releasing_owner_unlocks_even_while_a_duplicate_descriptor_exists() {
    let directory = tempdir().unwrap();
    let pid_path = directory.path().join("traffic-masqd.pid");
    let owner = ProcessGuard::acquire(&pid_path).unwrap();
    // dup and fork share the open file description that owns the flock.
    let inherited = owner._lock.try_clone().unwrap();
    assert!(process_lock_is_held(&pid_path).unwrap());
    drop(owner);
    assert!(!pid_path.exists());
    assert!(!process_lock_is_held(&pid_path).unwrap());
    let next_owner = ProcessGuard::acquire(&pid_path).unwrap();
    drop(inherited);
    assert!(process_lock_is_held(&pid_path).unwrap());
    drop(next_owner);
}

#[test]
fn prevents_second_owner_and_cleans_only_pid_file() {
    let directory = tempdir().expect("tempdir");
    let pid_path = directory.path().join("traffic-masqd.pid");
    let lock_path = lock_path_for(&pid_path);

    let first = ProcessGuard::acquire(&pid_path).expect("first owner");
    assert!(pid_path.exists());
    assert!(lock_path.exists());
    let error = ProcessGuard::acquire(&pid_path)
        .err()
        .expect("lock conflict");
    let message = format!("{error:#}");
    assert!(message.contains(&format!("kernel lock holder PID {}", std::process::id())));
    assert!(message.contains("Do not delete the lock file"));
    assert!(error.downcast_ref::<std::io::Error>().is_some());

    drop(first);
    assert!(!pid_path.exists());
    assert!(lock_path.exists());

    ProcessGuard::acquire(&pid_path).expect("lock released after owner exit");
}
