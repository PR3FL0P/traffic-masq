use super::*;
use std::os::unix::fs::MetadataExt;
#[test]
fn recreates_socket_directory_and_group_access_after_reboot() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("run/traffic-masq/api.sock");
    for _ in 0..2 {
        prepare_socket_directory(&socket, Some(nix::unistd::getegid())).unwrap();
        let metadata = fs::metadata(socket.parent().unwrap()).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
        assert_eq!(metadata.gid(), nix::unistd::getegid().as_raw());
        fs::remove_dir_all(root.path().join("run")).unwrap();
    }
}
#[test]
fn does_not_chmod_shared_directories_or_follow_directory_symlinks() {
    assert!(validate_socket_directory(Path::new("/run/api.sock")).is_err());
    let root = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(root.path(), root.path().join("link")).unwrap();
    assert!(prepare_socket_directory(&root.path().join("link/api.sock"), None).is_err());
}
