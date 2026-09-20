//! Runtime paths must be recreated on every boot, not just during installation.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use nix::unistd::{chown, Gid};

/// Require a dedicated parent directory before granting group access to an API socket.
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

/// Create the socket directory, reject symlinks or non-directories, and apply optional group access.
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
mod tests;
