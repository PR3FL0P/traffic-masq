//! Read-only preflight shared by the installer and standalone client.
//! Observations describe current resources, not ownership of desired configuration.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct ConflictReport {
    pub schema_version: u8,
    pub interfaces: Vec<InterfaceObservation>,
    pub processes: Vec<ProcessObservation>,
    pub resources: Vec<ResourceObservation>,
    pub incomplete: Vec<String>,
    pub scope: String,
    pub limitations: String,
}

#[derive(Debug, Serialize)]
pub struct InterfaceObservation {
    pub name: String,
    /// None means unknown, never "unmanaged".
    pub network_manager_managed: Option<bool>,
    pub networkd_state: Option<String>,
    pub network_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessObservation {
    pub pid: u32,
    pub name: String,
    pub service: Option<String>,
    pub network_namespace: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResourceObservation {
    pub kind: String,
    pub resource: String,
    pub holder_pids: Vec<u32>,
    pub ownership: String,
}

impl ConflictReport {
    /// 0 = no findings in checked scope; 1 = review needed; 2 = incomplete.
    pub fn exit_code(&self) -> i32 {
        if !self.incomplete.is_empty() {
            2
        } else if !self.processes.is_empty()
            || !self.resources.is_empty()
            || self.interfaces.iter().any(|i| {
                i.network_manager_managed == Some(true)
                    || i.networkd_state
                        .as_deref()
                        .is_some_and(|s| s != "unmanaged")
            })
        {
            1
        } else {
            0
        }
    }

    /// Suggested manual actions; never executed by the scanner.
    pub fn remediation(&self) -> Vec<String> {
        let mut advice = Vec::new();
        let mut managers: BTreeSet<_> = self.processes.iter().map(|p| p.name.clone()).collect();
        if self
            .interfaces
            .iter()
            .any(|i| i.network_manager_managed == Some(true))
        {
            managers.insert("NetworkManager".into());
        }
        if self.interfaces.iter().any(|i| {
            i.networkd_state
                .as_deref()
                .is_some_and(|s| s != "unmanaged")
        }) {
            managers.insert("systemd-networkd".into());
        }
        if !managers.is_empty() {
            // Advice is deduplicated; commands are specific when one interface is selected.
            let interface = if self.interfaces.len() == 1 {
                &self.interfaces[0].name
            } else {
                "INTERFACE"
            };
            advice.push(crate::format_competing_manager_advice(
                &managers.into_iter().collect::<Vec<_>>(),
                interface,
            ));
            if self.interfaces.len() != 1 {
                advice.push("Replace INTERFACE/NAME with an interface listed above that traffic-masq will configure; rerun with --check-conflicts --interface NAME for focused guidance.".into());
            }
        }
        if !self.resources.is_empty() {
            advice.push("Inspect holders with sudo ss -xap and sudo ss -lunp. Never unlink a live Wi-Fi socket or stop a worker without verifying its owner. Existing addresses/routes must be released through their previous owner.".into());
        }
        advice
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "Network conflict preflight (read-only)".into(),
            self.scope.clone(),
        ];
        for interface in &self.interfaces {
            lines.push(format!(
                "  Interface {}: NetworkManager={}; networkd={}{}",
                interface.name,
                match interface.network_manager_managed {
                    Some(true) => "managed (confirmed)",
                    Some(false) => "unmanaged (confirmed)",
                    None => "not established",
                },
                interface
                    .networkd_state
                    .as_deref()
                    .unwrap_or("not established"),
                interface
                    .network_file
                    .as_ref()
                    .map(|p| format!("; file={p}"))
                    .unwrap_or_default()
            ));
        }
        for process in &self.processes {
            lines.push(format!(
                "  Candidate: {} PID={} service={} netns={}",
                process.name,
                process.pid,
                process.service.as_deref().unwrap_or("unknown"),
                process.network_namespace.as_deref().unwrap_or("unknown")
            ));
        }
        for resource in &self.resources {
            lines.push(format!(
                "  Observed {}: {}; holder PIDs={:?}; {}",
                resource.kind, resource.resource, resource.holder_pids, resource.ownership
            ));
        }
        for issue in &self.incomplete {
            lines.push(format!("  INCOMPLETE: {issue}"));
        }
        if self.exit_code() == 0 {
            lines.push("No candidates found in the checked scope; this is not a guarantee that every interface is free.".into());
        } else {
            lines.push("Review findings before assigning interfaces. Running services and occupied resources may belong to a valid external uplink or traffic-masq itself.".into());
        }
        lines.extend(self.remediation());
        lines.push(self.limitations.clone());
        lines.join("\n")
    }
}

pub async fn scan_conflicts(selected: &[String]) -> ConflictReport {
    let mut report = scan_at(Path::new("/"), selected);
    // Query only a running NetworkManager: avoid activating a stopped service.
    if report.processes.iter().any(|p| p.name == "NetworkManager") {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        for index in 0..report.interfaces.len() {
            if tokio::time::Instant::now() >= deadline {
                report.incomplete.push(
                    "NetworkManager query budget exhausted; remaining interface states are unknown"
                        .into(),
                );
                break;
            }
            let name = report.interfaces[index].name.clone();
            match nm_managed(&name).await {
                Ok(managed) => report.interfaces[index].network_manager_managed = Some(managed),
                Err(reason) => report
                    .incomplete
                    .push(format!("NetworkManager on {name}: {reason}")),
            }
        }
    }
    report
}

async fn nm_managed(interface: &str) -> Result<bool, String> {
    let mut command = tokio::process::Command::new("nmcli");
    command
        .args([
            "--terse",
            "--escape",
            "no",
            "--get-values",
            "GENERAL.NM-MANAGED",
            "device",
            "show",
            interface,
        ])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(3), command.output()).await {
        Ok(Ok(output)) if output.status.success() => {
            parse_nm_managed(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(Ok(output)) => Err(format!(
            "nmcli exited {}; check nmcli device status",
            output.status
        )),
        Ok(Err(error)) => Err(format!("cannot run optional nmcli: {error}")),
        Err(_) => Err("nmcli timed out after 3 seconds".into()),
    }
}

fn parse_nm_managed(output: &str) -> Result<bool, String> {
    match output.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err("nmcli returned an unrecognized management state".into()),
    }
}

fn candidate(comm: &str) -> Option<&str> {
    match comm {
        "systemd-network" | "systemd-networkd" => Some("systemd-networkd"),
        "connmand" | "connman" => Some("connman"),
        "NetworkManager" | "iwd" | "dhcpcd" | "dhclient" | "dhcpd" | "udhcpc" | "hostapd"
        | "wpa_supplicant" | "dnsmasq" | "wickedd" | "wickedd-nanny" | "kea-dhcp4" => Some(comm),
        _ => None,
    }
}

fn scan_at(root: &Path, selected: &[String]) -> ConflictReport {
    let mut report = ConflictReport {
        schema_version: 1,
        limitations: "Scope limits: snapshot of the current network namespace; no desired address/route policy was supplied. Wi-Fi journal ownership and custom control socket paths are not fully checked. Inspect ip -brief address and ip -4 route show table all before handover. Recheck after reboot; provisioning may regenerate settings. See docs/resource-conflicts.md.".into(),
        scope: if selected.is_empty() {
            "All visible interfaces; no interface handover requested.".into()
        } else {
            format!("Selected interfaces: {}. Host-wide process/DHCP candidates are not automatically conflicts on these interfaces.", selected.join(", "))
        },
        ..Default::default()
    };
    let mut names = BTreeSet::new();
    match std::fs::read_dir(root.join("sys/class/net")) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        names.insert(entry.file_name().to_string_lossy().into_owned());
                    }
                    Err(error) => report
                        .incomplete
                        .push(format!("interface enumeration: {error}")),
                }
            }
        }
        Err(error) => report
            .incomplete
            .push(format!("cannot enumerate interfaces: {error}")),
    }
    for name in selected {
        if !names.contains(name) {
            report.incomplete.push(format!(
                "selected interface {name:?} is absent or not visible"
            ));
        }
    }
    for name in names {
        if (name == "lo" && selected.is_empty())
            || (!selected.is_empty() && !selected.contains(&name))
        {
            continue;
        }
        let mut interface = InterfaceObservation {
            name: name.clone(),
            network_manager_managed: None,
            networkd_state: None,
            network_file: None,
        };
        match std::fs::read_to_string(root.join("sys/class/net").join(&name).join("ifindex")) {
            Ok(index) => match index.trim().parse::<u32>() {
                Ok(index) => {
                    let path = root.join(format!("run/systemd/netif/links/{index}"));
                    match std::fs::read_to_string(path) {
                        Ok(state) => {
                            interface.networkd_state = value(&state, "ADMIN_STATE");
                            interface.network_file = value(&state, "NETWORK_FILE");
                            if interface.networkd_state.is_none() {
                                report
                                    .incomplete
                                    .push(format!("networkd state for {name} has no ADMIN_STATE"));
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                        Err(error) => report
                            .incomplete
                            .push(format!("networkd state for {name}: {error}")),
                    }
                }
                Err(error) => report
                    .incomplete
                    .push(format!("invalid interface index for {name}: {error}")),
            },
            Err(error) => report
                .incomplete
                .push(format!("cannot read interface index for {name}: {error}")),
        }
        report.interfaces.push(interface);
    }
    let proc_dir = root.join("proc");
    let current_ns = std::fs::read_link(proc_dir.join("self/ns/net")).ok();
    let mut processes = Vec::new();
    match std::fs::read_dir(&proc_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        if let Some(pid) = entry
                            .file_name()
                            .to_str()
                            .and_then(|s| s.parse::<u32>().ok())
                        {
                            processes.push((pid, entry.path()));
                        }
                    }
                    Err(error) => report
                        .incomplete
                        .push(format!("process enumeration: {error}")),
                }
            }
        }
        Err(error) => report
            .incomplete
            .push(format!("cannot inspect /proc: {error}")),
    }
    for (pid, path) in &processes {
        match std::fs::read_to_string(path.join("comm")) {
            Ok(comm) => {
                if let Some(name) = candidate(comm.trim()) {
                    let ns = std::fs::read_link(path.join("ns/net")).ok();
                    if current_ns.is_some() && ns.is_some() && current_ns != ns {
                        continue;
                    }
                    if ns.is_none() || current_ns.is_none() {
                        report
                            .incomplete
                            .push(format!("cannot establish network namespace for PID {pid}"));
                    }
                    let service = std::fs::read_to_string(path.join("cgroup"))
                        .ok()
                        .and_then(|s| {
                            s.lines()
                                .flat_map(|l| l.split('/'))
                                .find(|c| c.ends_with(".service"))
                                .map(str::to_owned)
                        });
                    report.processes.push(ProcessObservation {
                        pid: *pid,
                        name: name.into(),
                        service,
                        network_namespace: ns.map(|s| s.to_string_lossy().into_owned()),
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (), // exited during scan
            Err(error) => report
                .incomplete
                .push(format!("cannot read PID {pid}: {error}")),
        }
    }
    report.processes.sort_by_key(|p| p.pid);
    // Runtime files can survive networkd. Do not present stale records as a live owner.
    if !report
        .processes
        .iter()
        .any(|p| p.name == "systemd-networkd")
    {
        for interface in &mut report.interfaces {
            if interface.networkd_state.is_some() {
                report.incomplete.push(format!("networkd runtime state for {} exists without a visible networkd process; may be stale", interface.name));
                interface.networkd_state = None;
            }
        }
    }
    let mut sockets: BTreeMap<String, ResourceObservation> = BTreeMap::new();
    for file in ["net/unix", "net/udp", "net/udp6"] {
        match std::fs::read_to_string(proc_dir.join(file)) {
            Ok(contents) => collect_sockets(file, &contents, selected, &mut sockets),
            Err(error) if file == "net/udp6" && error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => report
                .incomplete
                .push(format!("cannot read /proc/{file}: {error}")),
        }
    }
    if !sockets.is_empty() {
        let mut inaccessible = 0;
        for (pid, path) in &processes {
            match std::fs::read_dir(path.join("fd")) {
                Ok(fds) => {
                    for fd in fds {
                        match fd {
                            Ok(fd) => match std::fs::read_link(fd.path()) {
                                Ok(target) => {
                                    let target = target.to_string_lossy();
                                    if let Some(socket) = sockets.get_mut(target.as_ref()) {
                                        if !socket.holder_pids.contains(pid) {
                                            socket.holder_pids.push(*pid);
                                        }
                                    }
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                                Err(_) => inaccessible += 1,
                            },
                            Err(_) => inaccessible += 1,
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => inaccessible += 1,
            }
        }
        if inaccessible > 0 {
            report.incomplete.push(format!("{inaccessible} process FD observations unavailable; socket holder list may be incomplete (retry with sudo where appropriate)"));
        }
    }
    for socket in sockets.values_mut() {
        socket.holder_pids.sort_unstable();
    }
    report.resources = sockets.into_values().collect();
    report
}

fn value(contents: &str, key: &str) -> Option<String> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(str::to_owned))
}

fn collect_sockets(
    file: &str,
    contents: &str,
    selected: &[String],
    sockets: &mut BTreeMap<String, ResourceObservation>,
) {
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let (inode, kind, resource) = if file == "net/unix" {
            if fields.len() < 8 {
                continue;
            }
            let path = fields[7];
            if !path.contains("hostapd") && !path.contains("wpa_supplicant") {
                continue;
            }
            if !selected.is_empty()
                && !selected.iter().any(|name| {
                    Path::new(path)
                        .file_name()
                        .is_some_and(|s| s == name.as_str())
                })
            {
                continue;
            }
            (fields[6], "Wi-Fi control socket", path.to_owned())
        } else {
            if fields.len() < 10 {
                continue;
            }
            let Some((address, port)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(port, 16).ok() != Some(67) {
                continue;
            }
            (
                fields[9],
                "DHCP UDP port 67",
                format!(
                    "{} local={}:67{}",
                    file,
                    decode_address(address).unwrap_or_else(|| format!("unknown ({address})")),
                    if file == "net/udp6" {
                        "; IPv4 overlap depends on IPV6_V6ONLY"
                    } else {
                        ""
                    }
                ),
            )
        };
        sockets.insert(
            format!("socket:[{inode}]"),
            ResourceObservation {
                kind: kind.into(),
                resource,
                holder_pids: Vec::new(),
                ownership:
                    "holder correlation only; foreign vs traffic-masq ownership is not established"
                        .into(),
            },
        );
    }
}

fn decode_address(hex: &str) -> Option<String> {
    if hex.len() == 8 {
        let word = u32::from_str_radix(hex, 16).ok()?;
        Some(std::net::Ipv4Addr::from(word.to_ne_bytes()).to_string())
    } else if hex.len() == 32 && hex.is_ascii() {
        let mut bytes = [0; 16];
        for index in 0..4 {
            let word = u32::from_str_radix(&hex[index * 8..index * 8 + 8], 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        Some(format!("[{}]", std::net::Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
