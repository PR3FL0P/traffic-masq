use std::os::unix::fs::{symlink, MetadataExt};

use tempfile::tempdir;

use super::*;

#[test]
fn writes_are_private_atomic_and_leave_no_temporaries() {
    let root = tempdir().expect("tempdir");
    let store = PrivateJsonDirectory::open(root.path(), "records").expect("store");

    assert_eq!(
        fs::metadata(store.directory()).expect("metadata").mode() & 0o777,
        0o700
    );

    store.write("eth0", b"{\"a\":1}").expect("write");
    store.write("eth0", b"{\"a\":2}").expect("overwrite");

    let path = store.directory().join("eth0.json");
    assert_eq!(fs::metadata(&path).expect("metadata").mode() & 0o777, 0o600);
    assert_eq!(
        store.read("eth0").expect("read").as_deref(),
        Some(&b"{\"a\":2}"[..])
    );
    assert!(fs::read_dir(store.directory())
        .expect("read_dir")
        .all(|entry| !entry
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

    assert_eq!(store.keys().expect("keys"), vec!["eth0".to_string()]);
    store.remove("eth0").expect("remove");
    assert_eq!(store.read("eth0").expect("read"), None);
    assert!(store.keys().expect("keys").is_empty());
}

#[test]
fn refuses_traversal_and_symlinked_documents() {
    let root = tempdir().expect("tempdir");
    let store = PrivateJsonDirectory::open(root.path(), "records").expect("store");

    assert!(matches!(
        store.read("../eth0"),
        Err(PrivateStoreError::InvalidKey)
    ));

    let target = root.path().join("target");
    fs::write(&target, b"do not replace").expect("write target");
    symlink(&target, store.directory().join("eth0.json")).expect("symlink");

    assert!(matches!(
        store.write("eth0", b"{}"),
        Err(PrivateStoreError::Symlink(_))
    ));
    assert_eq!(fs::read(&target).expect("read target"), b"do not replace");
}

#[test]
fn refuses_a_symlinked_store_directory() {
    let root = tempdir().expect("tempdir");
    let elsewhere = tempdir().expect("tempdir");
    symlink(elsewhere.path(), root.path().join("records")).expect("symlink");

    assert!(matches!(
        PrivateJsonDirectory::open(root.path(), "records"),
        Err(PrivateStoreError::Symlink(_))
    ));
}

#[test]
fn store_name_cannot_escape_state_root() {
    let root = tempdir().unwrap();
    for name in ["", ".", "..", "../outside", "/tmp/outside", "nested/store"] {
        assert!(
            PrivateJsonDirectory::open(root.path(), name).is_err(),
            "accepted unsafe store name {name:?}"
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn symlink_check_preserves_metadata_errors() {
    let root = tempdir().unwrap();
    let file = root.path().join("file");
    fs::write(&file, b"data").unwrap();
    assert!(matches!(
        reject_symlink(&file.join("child")),
        Err(PrivateStoreError::Io(error)) if error.kind() == io::ErrorKind::NotADirectory
    ));
    reject_symlink(&root.path().join("missing")).unwrap();
}
