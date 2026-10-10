//! Observation of competing network-management processes.

/// Well-known daemons that may fight us for control of a wireless interface.
///
/// Deliberately excludes `hostapd`/`wpa_supplicant`: this daemon supervises
/// its own instances of both, so their presence on the machine is normal, not
/// evidence of a foreign manager, and including them here would make the scan
/// report itself as the competitor on almost every restart.
const COMPETING_DAEMONS: &[&str] = &[
    "iwd",
    "NetworkManager",
    "systemd-network",
    "systemd-networkd",
    "connman",
    "connmand",
    "dhcpcd",
    "dhclient",
    "dhcpd",
    "udhcpc",
];

/// Scans /proc for running processes whose comm matches a known network-management
/// daemon. Used to enrich restart diagnostics: when our supervised daemon keeps
/// dying, the usual cause is another manager reconfiguring the interface behind
/// our back.
pub async fn find_competing_network_managers() -> Vec<String> {
    find_competing_network_managers_at(std::path::Path::new("/proc")).await
}

async fn find_competing_network_managers_at(proc_dir: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut entries = match tokio::fs::read_dir(proc_dir).await {
        Ok(entries) => entries,
        Err(_) => return found,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = tokio::fs::read_to_string(&comm_path).await {
            let comm = comm.trim();
            if COMPETING_DAEMONS.contains(&comm) {
                let canonical = match comm {
                    "systemd-network" | "systemd-networkd" => "systemd-networkd",
                    "connmand" | "connman" => "connman",
                    other => other,
                };
                if !found.iter().any(|existing| existing == canonical) {
                    found.push(canonical.to_string());
                }
            }
        }
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests;
