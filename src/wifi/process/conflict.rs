//! Read-only observations of processes holding interface control sockets.
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

pub async fn wifi_conflict_diagnostics(interface: &str, ctrl_path: &Path) -> String {
    let managers = super::find_competing_network_managers().await;
    diagnostics_at(Path::new("/proc"), interface, ctrl_path, &managers).await
}

async fn diagnostics_at(
    proc_dir: &Path,
    interface: &str,
    ctrl_path: &Path,
    managers: &[String],
) -> String {
    let (sockets, owners, incomplete) = socket_owners_at(proc_dir, ctrl_path).await;
    let node = match tokio::fs::symlink_metadata(ctrl_path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let mut message = format!(
                "Socket file exists (device={}, inode={}, uid={}, gid={}). ",
                metadata.dev(), metadata.ino(), metadata.uid(), metadata.gid()
            );
            if sockets.is_empty() && owners.is_empty() && !incomplete {
                let path = shell_quote(&ctrl_path.to_string_lossy());
                message.push_str(&format!(
                    "No active socket entry was found in /proc/net/unix for this path; the file appears stale, possibly left behind after wpa_supplicant exited. Stop traffic-masqd before manual cleanup with `sudo systemctl stop traffic-masqd`, check `sudo ss -xap` for this exact path, and only if no process uses it, remove only this file with `sudo rm -- {path}`. Then run `sudo systemctl start traffic-masqd` and retry. "
                ));
            }
            message
        }
        Ok(metadata) => {
            let kind = if metadata.file_type().is_symlink() { "symlink" }
                else if metadata.is_dir() { "directory" }
                else if metadata.is_file() { "regular file" }
                else { "non-socket node" };
            format!("The path exists as a {kind}, not a socket; inspect `sudo stat -- {}` and correct the runtime path manually. ", shell_quote(&ctrl_path.to_string_lossy()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            "The socket file is missing; ownership may have changed during observation. Retry and inspect the saved ownership record if this persists. ".into()
        }
        Err(error) => format!("Could not inspect the socket file: {error}. "),
    };
    format!(
        "Control socket {}: {}{}",
        ctrl_path.display(),
        node,
        format_diagnostics(interface, &sockets, &owners, incomplete, managers)
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Debug)]
struct SocketOwner {
    pid: u32,
    name: String,
    executable: PathBuf,
    socket: String,
    service: Option<String>,
}

async fn socket_owners_at(
    proc_dir: &Path,
    ctrl_path: &Path,
) -> (Vec<String>, Vec<SocketOwner>, bool) {
    let unix = match tokio::fs::read_to_string(proc_dir.join("net/unix")).await {
        Ok(unix) => unix,
        Err(_) => return (Vec::new(), Vec::new(), true),
    };
    let mut targets = Vec::new();
    for line in unix.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 8 && Path::new(fields[7]) == ctrl_path {
            targets.push((format!("socket:[{}]", fields[6]), fields[7].to_string()));
        }
    }
    let sockets = targets.iter().map(|(_, path)| path.clone()).collect();
    if targets.is_empty() {
        return (sockets, Vec::new(), false);
    }
    let mut owners = Vec::new();
    let mut incomplete = false;
    let mut entries = match tokio::fs::read_dir(proc_dir).await {
        Ok(entries) => entries,
        Err(_) => return (sockets, owners, true),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let mut fds = match tokio::fs::read_dir(entry.path().join("fd")).await {
            Ok(fds) => fds,
            Err(error) => {
                incomplete |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        while let Ok(Some(fd)) = fds.next_entry().await {
            let Ok(link) = tokio::fs::read_link(fd.path()).await else {
                continue;
            };
            for (inode, socket) in &targets {
                if link == Path::new(inode)
                    && !owners
                        .iter()
                        .any(|owner: &SocketOwner| owner.pid == pid && owner.socket == *socket)
                {
                    let name = tokio::fs::read_to_string(entry.path().join("comm"))
                        .await
                        .unwrap_or_else(|_| "unknown".into())
                        .trim()
                        .to_string();
                    let executable = tokio::fs::read_link(entry.path().join("exe"))
                        .await
                        .unwrap_or_default();
                    let cgroup = tokio::fs::read_to_string(entry.path().join("cgroup"))
                        .await
                        .unwrap_or_default();
                    let service = cgroup
                        .split('/')
                        .map(str::trim)
                        .rfind(|part| {
                            part.ends_with(".service")
                                && part
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_.@:-".contains(&b))
                        })
                        .map(str::to_string);
                    owners.push(SocketOwner {
                        pid,
                        name,
                        executable,
                        socket: socket.clone(),
                        service,
                    });
                }
            }
        }
    }
    owners.sort_by_key(|owner| owner.pid);
    (sockets, owners, incomplete)
}

fn format_diagnostics(
    interface: &str,
    sockets: &[String],
    owners: &[SocketOwner],
    incomplete: bool,
    managers: &[String],
) -> String {
    let mut message = format!(
        "Cannot manage Wi-Fi on {interface}: control-socket ownership could not be verified. "
    );
    for owner in owners {
        message.push_str(&format!(
            "Socket {} is held by {} PID {} executable {}",
            owner.socket,
            owner.name,
            owner.pid,
            owner.executable.display()
        ));
        if let Some(service) = &owner.service {
            message.push_str(&format!(" (service {service}). Inspect `sudo systemctl status {service}`; if this is the unwanted owner, stop it manually with `sudo systemctl stop {service}`. "));
        } else {
            message.push_str(&format!(". Inspect `ps -p {} -o pid,ppid,comm,args` and stop or reconfigure its owning service manually. ", owner.pid));
        }
    }
    if owners.is_empty() {
        message.push_str(&format!("No socket-holding PID could be confirmed; observed sockets: {sockets:?}. A stale socket or an ownership-record mismatch is possible. Inspect `sudo ss -xap` and `ps -eo pid,ppid,comm,args`; do not remove a socket until its owner is verified. "));
    }
    if incomplete {
        message.push_str(
            "Process observation was incomplete (permissions or unavailable /proc data). ",
        );
    }
    if !managers.is_empty() {
        message.push_str(&format!(
            "Running network managers (presence alone does not prove ownership): {}. ",
            managers.join(", ")
        ));
        if managers.iter().any(|name| name == "NetworkManager") {
            let interface_arg = shell_quote(interface);
            message.push_str(&format!(
                "Check `nmcli -f GENERAL.STATE,GENERAL.REASON,GENERAL.NM-MANAGED device show {interface_arg}`. "
            ));
            message.push_str(
                "GENERAL.NM-MANAGED: yes means NetworkManager manages this interface; STATE: unavailable does not mean unmanaged, and REASON: Device is now managed describes a state transition rather than the cause of Wi-Fi unavailability. "
            );
            message.push_str(&format!(
                "If this interface should be managed by traffic-masq and GENERAL.NM-MANAGED is yes, release only this interface with `sudo nmcli device set {interface_arg} managed no`, then repeat the check and confirm GENERAL.NM-MANAGED: no before retrying. This may disconnect Wi-Fi on {interface}. To return it to NetworkManager, use `sudo nmcli device set {interface_arg} managed yes`. "
            ));
            message.push_str(&format!(
                "If Wi-Fi remains unavailable, inspect `rfkill list` for Soft/Hard blocked and `ip link show {interface_arg}` for link state; UP alone does not confirm association with an access point. "
            ));
        }
    }
    message.push_str("traffic-masq will not stop these processes or take over their sockets.");
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[tokio::test]
    async fn identifies_only_the_process_holding_the_interface_socket() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(dir.path().join("net/unix"), "header\n0: 2 0 0 2 1 123 /run/wpa_supplicant/wlan0\n0: 2 0 0 2 1 456 /run/wpa_supplicant/wlan1\n").unwrap();
        for (pid, inode) in [(10, 123), (20, 456)] {
            let process = dir.path().join(pid.to_string());
            std::fs::create_dir_all(process.join("fd")).unwrap();
            std::fs::write(process.join("comm"), "wpa_supplicant\n").unwrap();
            std::fs::write(
                process.join("cgroup"),
                "0::/system.slice/wpa_supplicant.service\n",
            )
            .unwrap();
            symlink(format!("socket:[{inode}]"), process.join("fd/3")).unwrap();
            symlink("/usr/sbin/wpa_supplicant", process.join("exe")).unwrap();
        }
        let (sockets, owners, incomplete) =
            socket_owners_at(dir.path(), Path::new("/run/wpa_supplicant/wlan0")).await;
        assert!(!incomplete);
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].pid, 10);
        let message = format_diagnostics(
            "wlan0",
            &sockets,
            &owners,
            false,
            &["NetworkManager".into()],
        );
        assert!(message.contains("PID 10"));
        assert!(message.contains("sudo systemctl stop wpa_supplicant.service"));
        assert!(message.contains("sudo nmcli device set 'wlan0' managed no"));
        assert!(message.contains("presence alone does not prove ownership"));
        assert!(process_socket_still_exists(dir.path()));
    }

    fn process_socket_still_exists(root: &Path) -> bool {
        std::fs::read_link(root.join("10/fd/3")).is_ok()
    }

    #[tokio::test]
    async fn stale_socket_is_reported_with_manual_cleanup_and_left_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let proc_dir = dir.path().join("proc");
        std::fs::create_dir_all(proc_dir.join("net")).unwrap();
        std::fs::write(proc_dir.join("net/unix"), "header\n").unwrap();
        let path = dir.path().join("wlan0");
        drop(std::os::unix::net::UnixDatagram::bind(&path).unwrap());
        let message = diagnostics_at(&proc_dir, "wlan0", &path, &[]).await;
        assert!(message.contains("Socket file exists"));
        assert!(message.contains("file appears stale"));
        assert!(message.contains("Stop traffic-masqd before manual cleanup"));
        assert!(message.contains(&format!(
            "sudo rm -- {}",
            shell_quote(&path.to_string_lossy())
        )));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
    }

    #[tokio::test]
    async fn active_or_unobservable_socket_does_not_get_cleanup_advice() {
        let dir = tempfile::tempdir().unwrap();
        let proc_dir = dir.path().join("proc");
        std::fs::create_dir_all(proc_dir.join("net")).unwrap();
        let path = dir.path().join("wlan0");
        let _socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        std::fs::write(
            proc_dir.join("net/unix"),
            format!("header\n0: 2 0 0 2 1 123 {}\n", path.display()),
        )
        .unwrap();
        let active = diagnostics_at(&proc_dir, "wlan0", &path, &[]).await;
        assert!(!active.contains("sudo rm --"));
        std::fs::remove_file(proc_dir.join("net/unix")).unwrap();
        let unavailable = diagnostics_at(&proc_dir, "wlan0", &path, &[]).await;
        assert!(unavailable.contains("observation was incomplete"));
        assert!(!unavailable.contains("sudo rm --"));
    }

    #[tokio::test]
    async fn non_socket_and_missing_path_are_distinguished() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wlan0");
        std::fs::write(&path, "foreign file").unwrap();
        let file = diagnostics_at(dir.path(), "wlan0", &path, &[]).await;
        assert!(file.contains("regular file, not a socket"));
        assert!(!file.contains("sudo rm --"));
        std::fs::remove_file(&path).unwrap();
        let missing = diagnostics_at(dir.path(), "wlan0", &path, &[]).await;
        assert!(missing.contains("socket file is missing"));
        assert!(!missing.contains("sudo rm --"));
    }

    #[test]
    fn cleanup_path_is_shell_quoted() {
        assert_eq!(shell_quote("/run/a'b/wlan0"), "'/run/a'\"'\"'b/wlan0'");
    }

    #[test]
    fn unconfirmed_owner_is_not_reported_as_networkmanager() {
        let message = format_diagnostics("wlan0", &[], &[], true, &["NetworkManager".into()]);
        assert!(message.contains("No socket-holding PID could be confirmed"));
        assert!(message.contains("observation was incomplete"));
        assert!(!message.contains("is held by NetworkManager"));
    }
}
