//! Read-only socket/process observations, used only to explain bind failures.
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Diagnose overlapping UDP listeners in the current network namespace.
/// A listener observed here is a candidate, not proof of why a bind failed.
pub fn udp_bind_conflict_diagnostics(address: Ipv4Addr, port: u16) -> String {
    udp_bind_conflict_diagnostics_at(Path::new("/proc"), address, port)
}

/// Refuse a known overlapping IPv4 listener unless its socket is held only
/// by this process. IPv6 listeners remain bind-failure candidates because
/// /proc does not expose whether IPV6_V6ONLY is set.
pub fn foreign_ipv4_udp_listener_diagnostics(address: Ipv4Addr, port: u16) -> Option<String> {
    // Port zero asks the kernel to allocate a free ephemeral port.
    if port == 0 {
        return None;
    }
    let (message, foreign) = udp_observation_at(Path::new("/proc"), address, port);
    foreign.then_some(message)
}

fn udp_bind_conflict_diagnostics_at(proc_dir: &Path, address: Ipv4Addr, port: u16) -> String {
    udp_observation_at(proc_dir, address, port).0
}

/// Explain a failed HTTPS bind, including candidates from both address families.
pub fn tcp_bind_conflict_diagnostics(address: SocketAddr) -> String {
    socket_observation_at(Path::new("/proc"), address.ip(), address.port(), "tcp").0
}

fn udp_observation_at(proc_dir: &Path, address: Ipv4Addr, port: u16) -> (String, bool) {
    socket_observation_at(proc_dir, IpAddr::V4(address), port, "udp")
}

fn socket_observation_at(
    proc_dir: &Path,
    address: IpAddr,
    port: u16,
    protocol: &str,
) -> (String, bool) {
    let mut sockets = Vec::new();
    let mut incomplete = false;
    for (file, ipv6) in [
        (format!("net/{protocol}"), false),
        (format!("net/{protocol}6"), true),
    ] {
        match std::fs::read_to_string(proc_dir.join(file)) {
            Ok(contents) => {
                for line in contents.lines().skip(1) {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() < 10 || (protocol == "tcp" && fields[3] != "0A") {
                        continue;
                    }
                    let Some((hex_address, hex_port)) = fields[1].split_once(':') else {
                        continue;
                    };
                    if u16::from_str_radix(hex_port, 16).ok() != Some(port) {
                        continue;
                    }
                    let local = if ipv6 {
                        if hex_address.len() != 32 {
                            continue;
                        }
                        let mut bytes = [0; 16];
                        let mut valid = true;
                        for (index, chunk) in hex_address.as_bytes().chunks_exact(8).enumerate() {
                            let Ok(word) =
                                u32::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
                            else {
                                valid = false;
                                break;
                            };
                            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                        }
                        if !valid {
                            continue;
                        }
                        let local = Ipv6Addr::from(bytes);
                        // A wildcard IPv6 listener may be dual-stack; report it as a candidate.
                        let overlap = match address {
                            IpAddr::V4(requested) => {
                                local.is_unspecified()
                                    || local
                                        .to_ipv4_mapped()
                                        .is_some_and(|v4| overlaps(v4, requested))
                            }
                            IpAddr::V6(requested) => {
                                local.is_unspecified()
                                    || requested.is_unspecified()
                                    || local == requested
                            }
                        };
                        if !overlap {
                            continue;
                        }
                        format!("[{local}]:{port}")
                    } else {
                        let Ok(word) = u32::from_str_radix(hex_address, 16) else {
                            continue;
                        };
                        let local = Ipv4Addr::from(word.to_ne_bytes());
                        let overlap = match address {
                            IpAddr::V4(requested) => overlaps(local, requested),
                            IpAddr::V6(requested) => {
                                requested.is_unspecified()
                                    || requested
                                        .to_ipv4_mapped()
                                        .is_some_and(|v4| overlaps(local, v4))
                            }
                        };
                        if !overlap {
                            continue;
                        }
                        format!("{local}:{port}")
                    };
                    sockets.push((format!("socket:[{}]", fields[9]), local, ipv6));
                }
            }
            Err(error) if ipv6 && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => incomplete = true,
        }
    }
    let mut owners = Vec::new();
    let mut found = HashSet::new();
    if !sockets.is_empty() {
        match std::fs::read_dir(proc_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let fds = match std::fs::read_dir(entry.path().join("fd")) {
                        Ok(fds) => fds,
                        Err(error) => {
                            incomplete |= error.kind() == std::io::ErrorKind::PermissionDenied;
                            continue;
                        }
                    };
                    for fd in fds.flatten() {
                        let Ok(link) = std::fs::read_link(fd.path()) else {
                            continue;
                        };
                        for (inode, local, _) in &sockets {
                            if link == Path::new(inode) && found.insert((pid, inode.clone())) {
                                let name = std::fs::read_to_string(entry.path().join("comm"))
                                    .unwrap_or_else(|_| "unknown".into());
                                let exe = std::fs::read_link(entry.path().join("exe"))
                                    .unwrap_or_default();
                                let cgroup = std::fs::read_to_string(entry.path().join("cgroup"))
                                    .unwrap_or_default();
                                let service = cgroup.split('/').map(str::trim).rfind(|part| {
                                    part.ends_with(".service")
                                        && part.bytes().all(|b| {
                                            b.is_ascii_alphanumeric() || b"_.@:-".contains(&b)
                                        })
                                });
                                let advice = service.map(|unit| format!("service {unit}; inspect `sudo systemctl status {unit}` and, if this is the unwanted listener, stop it manually with `sudo systemctl stop {unit}`")).unwrap_or_else(|| format!("inspect `ps -p {pid} -o pid,ppid,comm,args` and stop or reconfigure its owning service manually"));
                                owners.push(format!(
                                    "{} {local}: {} PID {pid} executable {}; {advice}",
                                    protocol.to_uppercase(),
                                    name.trim(),
                                    exe.display()
                                ));
                            }
                        }
                    }
                }
            }
            Err(_) => incomplete = true,
        }
    }
    owners.sort();
    let mut message = format!(
        "Overlapping {} listener candidates for {}: ",
        protocol.to_uppercase(),
        SocketAddr::new(address, port)
    );
    if owners.is_empty() {
        message.push_str("no owning PID could be confirmed. ");
    } else {
        message.push_str(&owners.join("; "));
        message.push_str(". ");
    }
    if incomplete {
        message.push_str("Observation was incomplete (unavailable /proc data or permissions). ");
    }
    let ss_flags = if protocol == "tcp" { "-ltnp" } else { "-lunp" };
    message.push_str(&format!("Inspect `sudo ss {ss_flags} 'sport = :{port}'`. Release the port or change the conflicting service's listen address/interface manually, then retry. traffic-masq will not stop another service or take over its socket."));
    let current_pid = std::process::id();
    let foreign = sockets.iter().any(|(inode, _, ipv6)| {
        !ipv6
            && (!found.contains(&(current_pid, inode.clone()))
                || found
                    .iter()
                    .any(|(pid, owned_inode)| *pid != current_pid && owned_inode == inode))
    });
    (message, foreign)
}

fn overlaps(local: Ipv4Addr, requested: Ipv4Addr) -> bool {
    local.is_unspecified() || requested.is_unspecified() || local == requested
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn identifies_the_port_owner_and_preserves_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(dir.path().join("net/udp"), "header\n0: 00000000:0043 00000000:0000 07 0:0 0:0 0 0 0 123\n1: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 456\n").unwrap();
        let process = dir.path().join("42");
        std::fs::create_dir_all(process.join("fd")).unwrap();
        std::fs::write(process.join("comm"), "dnsmasq\n").unwrap();
        std::fs::write(process.join("cgroup"), "0::/system.slice/dnsmasq.service\n").unwrap();
        symlink("socket:[123]", process.join("fd/3")).unwrap();
        symlink("/usr/sbin/dnsmasq", process.join("exe")).unwrap();
        let message = udp_bind_conflict_diagnostics_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67);
        assert!(message.contains("dnsmasq PID 42"));
        assert!(udp_observation_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67).1);
        assert!(message.contains("sudo systemctl stop dnsmasq.service"));
        assert!(!message.contains(":53"));
        assert!(std::fs::read_link(process.join("fd/3")).is_ok());
    }

    #[test]
    fn tcp_reports_only_listeners_including_ipv6_and_keeps_owner_intact() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net/tcp"),
            "header\n0: 0100007F:01BB 00000000:0000 01 0:0 0:0 0 0 0 123\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("net/tcp6"), "header\n0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 456\n").unwrap();
        let process = dir.path().join("42");
        std::fs::create_dir_all(process.join("fd")).unwrap();
        std::fs::write(process.join("comm"), "https-service\n").unwrap();
        symlink("socket:[456]", process.join("fd/3")).unwrap();
        let message =
            socket_observation_at(dir.path(), IpAddr::V6(Ipv6Addr::UNSPECIFIED), 443, "tcp").0;
        assert!(message.contains("TCP [::]:443: https-service PID 42"));
        assert!(message.contains("ss -ltnp"));
        assert!(!message.contains("127.0.0.1"));
        assert!(std::fs::read_link(process.join("fd/3")).is_ok());
    }

    #[test]
    fn only_overlapping_addresses_match() {
        assert!(overlaps(Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST));
        assert!(overlaps(Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED));
        assert!(!overlaps(Ipv4Addr::LOCALHOST, Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn a_socket_held_only_by_this_process_is_not_a_foreign_listener() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net/udp"),
            "header\n0: 00000000:0043 00000000:0000 07 0:0 0:0 0 0 0 123\n",
        )
        .unwrap();
        let process = dir.path().join(std::process::id().to_string());
        std::fs::create_dir_all(process.join("fd")).unwrap();
        symlink("socket:[123]", process.join("fd/3")).unwrap();
        assert!(!udp_observation_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67).1);
    }

    #[test]
    fn unknown_ipv4_owner_blocks_preflight_but_ipv6_only_is_just_a_candidate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net")).unwrap();
        std::fs::write(
            dir.path().join("net/udp"),
            "header\n0: 00000000:0043 00000000:0000 07 0:0 0:0 0 0 0 123\n",
        )
        .unwrap();
        assert!(udp_observation_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67).1);
        std::fs::write(dir.path().join("net/udp"), "header\n").unwrap();
        std::fs::write(dir.path().join("net/udp6"), "header\n0: 00000000000000000000000000000000:0043 00000000000000000000000000000000:0000 07 0:0 0:0 0 0 0 456\n").unwrap();
        assert!(!udp_observation_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67).1);
    }

    #[test]
    fn unavailable_proc_does_not_invent_a_service() {
        let dir = tempfile::tempdir().unwrap();
        let message = udp_bind_conflict_diagnostics_at(dir.path(), Ipv4Addr::UNSPECIFIED, 67);
        assert!(message.contains("no owning PID could be confirmed"));
        assert!(message.contains("Observation was incomplete"));
        assert!(!message.contains("systemctl stop"));
    }
}
