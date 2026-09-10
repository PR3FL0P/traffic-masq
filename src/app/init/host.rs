//! Read-only discovery of the running init system and required commands.
use super::Backend;
use anyhow::{bail, Result};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Host evidence is separate from selection so a package existing in PATH does
/// not make it the active init system. Auto never guesses in a container.
#[derive(Debug, Default)]
pub struct HostFacts {
    pub(super) pid1: String,
    pub(super) systemd_running: bool,
    pub(super) openrc_running: bool,
    pub(super) runit_dirs: Vec<PathBuf>,
    pub(super) commands: BTreeSet<String>,
}
impl HostFacts {
    pub fn discover() -> Self {
        let commands = [
            "systemctl",
            "rc-service",
            "rc-update",
            "sv",
            "update-rc.d",
            "chkconfig",
            "/sbin/openrc-run",
        ]
        .into_iter()
        .filter(|name| executable(name))
        .map(str::to_owned)
        .collect();
        Self {
            pid1: fs::read_to_string("/proc/1/comm")
                .unwrap_or_default()
                .trim()
                .to_owned(),
            systemd_running: Path::new("/run/systemd/system").is_dir(),
            openrc_running: Path::new("/run/openrc/softlevel").exists(),
            runit_dirs: ["/var/service", "/service", "/etc/service"]
                .into_iter()
                .filter(|path| Path::new(path).is_dir())
                .map(PathBuf::from)
                .collect(),
            commands,
        }
    }
    pub(super) fn detect(&self) -> Option<Backend> {
        if self.systemd_running && self.pid1 == "systemd" {
            Some(Backend::Systemd)
        } else if self.openrc_running {
            Some(Backend::Openrc)
        } else if matches!(self.pid1.as_str(), "runit" | "runit-init") {
            Some(Backend::Runit)
        } else if self.pid1 == "init"
            && (self.commands.contains("update-rc.d") || self.commands.contains("chkconfig"))
        {
            Some(Backend::Sysv)
        } else {
            None
        }
    }
    pub(super) fn require(&self, command: &str) -> Result<()> {
        if !self.commands.contains(command) {
            bail!("init integration requires executable {command}");
        }
        Ok(())
    }
}
fn executable(name: &str) -> bool {
    let check = |path: &Path| {
        fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if name.contains('/') {
        return check(Path::new(name));
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| check(&dir.join(name))))
}
