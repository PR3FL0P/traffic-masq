//! Standalone process scan for the `traffic-masq --check-conflicts` command.

/// `hostapd` and `wpa_supplicant` are supervised by traffic-masq itself, so
/// their presence is not evidence of a competing network manager.
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

pub async fn run() {
    let managers = find_competing_network_managers().await;
    if managers.is_empty() {
        println!("No competing network managers detected.");
    } else {
        println!("Detected competing network manager(s) that may control wireless interfaces:");
        println!(
            "{}",
            traffic_masq_protocol::format_competing_manager_advice(&managers, "<interface>")
        );
    }
}

async fn find_competing_network_managers() -> Vec<String> {
    let mut found = Vec::new();
    let mut entries = match tokio::fs::read_dir("/proc").await {
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_is_safe_when_proc_entries_change() {
        // A process may exit between reading its directory entry and `comm`.
        let _ = find_competing_network_managers().await;
    }

    #[test]
    fn supervised_processes_are_not_competitors() {
        assert!(!COMPETING_DAEMONS.contains(&"hostapd"));
        assert!(!COMPETING_DAEMONS.contains(&"wpa_supplicant"));
    }
}
