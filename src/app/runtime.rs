//! Runtime paths must be recreated on every boot, not just during installation.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use nix::unistd::{chown, Gid};

pub fn validate_socket_directory(socket: &Path) -> Result<&Path> {
    let parent = socket
        .parent()
        .context("API socket path has no parent directory")?;
    if ["/", "/run", "/var/run", "/tmp", "/etc", "/var"]
        .iter()
        .any(|p| parent == Path::new(p))
    {
        bail!(
            "a group-accessible API socket requires a dedicated runtime directory, not {}",
            parent.display()
        );
    }
    Ok(parent)
}

pub fn prepare_socket_directory(socket: &Path, group: Option<Gid>) -> Result<()> {
    let parent = if group.is_some() {
        validate_socket_directory(socket)?
    } else {
        socket
            .parent()
            .context("API socket path has no parent directory")?
    };
    if let Ok(metadata) = fs::symlink_metadata(parent) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "API runtime directory {} must be a real directory",
                parent.display()
            );
        }
    }
    fs::create_dir_all(parent)?;
    if let Some(group) = group {
        chown(parent, None, Some(group)).context("failed to set API runtime directory group")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
