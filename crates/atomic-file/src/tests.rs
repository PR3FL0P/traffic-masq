use super::*;
use tempfile::tempdir;

#[test]
fn replace_writes_private_contents() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("document.json");

    replace(&path, b"first", PRIVATE_FILE_MODE).expect("write");

    assert_eq!(fs::read(&path).expect("read"), b"first");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
}

#[test]
fn replace_overwrites_without_widening_permissions() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("document.json");

    replace(&path, b"first", PRIVATE_FILE_MODE).expect("first write");
    replace(&path, b"second", PRIVATE_FILE_MODE).expect("second write");

    assert_eq!(fs::read(&path).expect("read"), b"second");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
}

#[test]
fn replace_leaves_no_temporary_behind() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("document.json");

    replace(&path, b"contents", PRIVATE_FILE_MODE).expect("write");

    let leftovers: Vec<_> = fs::read_dir(directory.path())
        .expect("read_dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp") || name.contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "left temporaries behind: {leftovers:?}"
    );
}

#[test]
fn replace_refuses_to_follow_a_symlinked_target() {
    let directory = tempdir().expect("tempdir");
    let outside = directory.path().join("outside");
    fs::write(&outside, b"original").expect("seed");
    let link = directory.path().join("document.json");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");

    let error = replace(&link, b"attacker", PRIVATE_FILE_MODE).expect_err("must refuse");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        fs::read(&outside).expect("read"),
        b"original",
        "the symlink target must not have been written through"
    );
}

#[tokio::test]
async fn replace_async_matches_the_blocking_version() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("document.json");

    replace_async(&path, b"async", PRIVATE_FILE_MODE)
        .await
        .expect("write");

    assert_eq!(fs::read(&path).expect("read"), b"async");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
}

#[test]
fn ensure_private_dir_creates_and_tightens() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("store");

    ensure_private_dir(&target, PRIVATE_DIR_MODE).expect("create");

    let mode = fs::metadata(&target)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, PRIVATE_DIR_MODE);
}

#[test]
fn private_directory_creation_requires_durable_parents_even_after_a_failed_attempt() {
    let directory = tempdir().unwrap();
    let parent = directory.path().join("wifi");
    let target = parent.join("credentials");
    directory_sync_faults()
        .lock()
        .unwrap()
        .insert(parent.clone());
    assert!(matches!(
        ensure_private_dir(&target, PRIVATE_DIR_MODE),
        Err(PrivateDirError::Io(_))
    ));
    assert!(
        target.is_dir(),
        "a failed sync can leave the new tree present"
    );
    // Neither the leaf's existence nor a successful sync of its immediate
    // parent proves that the parent itself survived the previous attempt.
    directory_sync_faults()
        .lock()
        .unwrap()
        .insert(directory.path().to_owned());
    assert!(matches!(
        ensure_private_dir(&target, PRIVATE_DIR_MODE),
        Err(PrivateDirError::Io(_))
    ));
    ensure_private_dir(&target, PRIVATE_DIR_MODE).unwrap();
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        PRIVATE_DIR_MODE
    );
}

#[tokio::test]
async fn durable_directory_creation_preserves_existing_permissions_and_propagates_sync_errors() {
    let directory = tempdir().unwrap();
    let parent = directory.path().join("state");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
    let target = parent.join("nested/store");
    directory_sync_faults()
        .lock()
        .unwrap()
        .insert(parent.clone());
    assert!(create_dir_all_durable_async(&target).await.is_err());
    create_dir_all_durable_async(&target).await.unwrap();
    assert!(target.is_dir());
    assert_eq!(
        fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o750
    );
}

#[test]
fn private_directory_creation_supports_a_bare_relative_path() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let target = Path::new(directory.path().file_name().unwrap());
    ensure_private_dir(target, PRIVATE_DIR_MODE).unwrap();
    replace(&target.join("journal.json"), b"{}", PRIVATE_FILE_MODE).unwrap();
}

#[test]
fn ensure_private_dir_tightens_a_loose_existing_directory() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("store");
    fs::create_dir(&target).expect("mkdir");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("loosen");

    ensure_private_dir(&target, PRIVATE_DIR_MODE).expect("tighten");

    let mode = fs::metadata(&target)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, PRIVATE_DIR_MODE);
}

#[test]
fn ensure_private_dir_refuses_a_symlink() {
    let directory = tempdir().expect("tempdir");
    let elsewhere = directory.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("mkdir");
    let link = directory.path().join("store");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");

    let error = ensure_private_dir(&link, PRIVATE_DIR_MODE).expect_err("must refuse");

    assert!(matches!(error, PrivateDirError::Symlink(_)), "{error:?}");
}

#[test]
fn ensure_private_dir_refuses_a_file() {
    let directory = tempdir().expect("tempdir");
    let target = directory.path().join("store");
    fs::write(&target, b"not a directory").expect("seed");

    let error = ensure_private_dir(&target, PRIVATE_DIR_MODE).expect_err("must refuse");

    assert!(
        matches!(error, PrivateDirError::NotADirectory(_)),
        "{error:?}"
    );
}

#[test]
fn bare_filename_can_be_replaced_and_removed_durably() {
    // Use a unique file without changing the process-wide working directory.
    let temporary = tempfile::NamedTempFile::new_in(".").unwrap();
    let path = Path::new(temporary.path().file_name().unwrap());
    replace(path, b"relative", PRIVATE_FILE_MODE).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"relative");
    assert!(remove_durable(path).unwrap());
    assert!(!remove_durable(path).unwrap());
}

#[test]
fn parent_directory_handles_bare_and_nested_paths() {
    assert_eq!(parent_directory(Path::new("record")), Path::new("."));
    assert_eq!(
        parent_directory(Path::new("state/record")),
        Path::new("state")
    );
}

#[test]
fn regular_file_exists_distinguishes_missing_regular_and_dangling_symlink() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("journal.json");

    assert!(!regular_file_exists(&path).expect("missing path"));
    fs::write(&path, b"{}").expect("seed journal");
    assert!(regular_file_exists(&path).expect("regular file"));

    fs::remove_file(&path).expect("remove journal");
    std::os::unix::fs::symlink(directory.path().join("missing-target"), &path)
        .expect("dangling symlink");
    let error = regular_file_exists(&path).expect_err("symlink must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn regular_file_exists_rejects_directory() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("journal.json");
    fs::create_dir(&path).expect("mkdir");

    let error = regular_file_exists(&path).expect_err("directory must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn failed_compensation_preserves_typed_uncertainty_through_async_context() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("intent.json");
    replace(&path, b"old", PRIVATE_FILE_MODE).unwrap();
    fail_replacement_and_compensation(&path);
    let error = replace_preserving_on_error_async(&path, b"new", PRIVATE_FILE_MODE)
        .await
        .unwrap_err();
    let error = anyhow::Error::new(error).context("persist intent");
    assert!(is_indeterminate_write(&error));
    assert_eq!(fs::read(&path).unwrap(), b"new");
    assert!(!is_indeterminate_write(&anyhow::anyhow!(
        "ordinary failure"
    )));
}

#[test]
fn failure_before_publication_does_not_attempt_compensation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("intent.json");
    replace(&path, b"old", PRIVATE_FILE_MODE).unwrap();
    // Fail before rename, leaving another fault to detect an unnecessary write.
    write_faults().lock().unwrap().insert(path.clone(), 3);
    let error = replace_preserving_on_error(&path, b"new", PRIVATE_FILE_MODE).unwrap_err();
    let remaining_fault = write_faults().lock().unwrap().remove(&path);
    assert!(!is_indeterminate_write(&anyhow::Error::new(error)));
    assert_eq!(
        remaining_fault,
        Some(2),
        "compensation must not run before publication"
    );
    assert_eq!(fs::read(&path).unwrap(), b"old");
}
