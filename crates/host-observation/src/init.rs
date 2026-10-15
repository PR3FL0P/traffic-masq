//! Linux init-system observation and operator guidance.

/// Detected init system used to tailor service management commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Runit,
    Systemd,
    OpenRc,
    Unknown,
}

/// Detects the active init system on Linux.
pub fn detect_init_system() -> InitSystem {
    detect_init_system_at(std::path::Path::new("/"))
}

fn detect_init_system_at(root: &std::path::Path) -> InitSystem {
    if let Ok(comm) = std::fs::read_to_string(root.join("proc/1/comm")) {
        let comm = comm.trim();
        if comm == "runit" {
            return InitSystem::Runit;
        }
        if comm == "systemd" {
            return InitSystem::Systemd;
        }
    }
    if root.join("run/systemd/system").exists() {
        return InitSystem::Systemd;
    }
    if root.join("run/runit").exists() {
        return InitSystem::Runit;
    }
    if root.join("run/openrc").exists() {
        return InitSystem::OpenRc;
    }
    InitSystem::Unknown
}

/// Suggest per-interface inspection and handover without guessing service ownership.
pub fn format_competing_manager_advice(managers: &[String], interface: &str) -> String {
    format_competing_manager_advice_for_init(managers, interface, detect_init_system())
}

pub fn format_competing_manager_advice_for_init(
    managers: &[String],
    interface: &str,
    init: InitSystem,
) -> String {
    let config_interface = interface;
    let interface = shell_quote(interface);
    let mut lines = vec!["Release only interfaces traffic-masq will configure; an externally managed WAN can stay with its current manager. Releasing your SSH interface can disconnect this session.".to_string()];
    for manager in managers {
        lines.push(format!("• {manager}: potential competitor; process presence alone does not establish interface ownership."));
        match manager.as_str() {
            "NetworkManager" => {
                lines.push(format!("  Check: nmcli -f GENERAL.STATE,GENERAL.NM-MANAGED device show {interface}"));
                lines.push(format!("  If managed and intended for traffic-masq: sudo nmcli device set {interface} managed no"));
                lines.push(format!("  Persist in /etc/NetworkManager/conf.d/90-traffic-masq-unmanaged.conf (merge existing exclusions):\n      [keyfile]\n      unmanaged-devices=interface-name:{config_interface}\n  Reload: sudo nmcli general reload"));
                lines.push(format!("  Verify unmanaged status now and after reboot. To return control, disable traffic-masq management, remove the exclusion, reload, then sudo nmcli device set {interface} managed yes."));
            }
            "systemd-network" | "systemd-networkd" | "networkd" => {
                lines.push(format!("  Check: networkctl status {interface}"));
                lines.push(format!("  Persist in /etc/systemd/network/00-traffic-masq-unmanaged.network:\n      [Match]\n      Name={config_interface}\n      [Link]\n      Unmanaged=yes"));
                lines.push("  The FIRST matching .network file wins: verify lexical ordering, then sudo networkctl reload and check networkctl status. Update Netplan/cloud-init source if it generates configuration; do not edit /run files. Release existing addresses/routes through their previous owner.".into());
            }
            "iwd" => {
                lines.push(format!("  Inspect iwd's actual service launch arguments. Add --nointerfaces {interface} to that service's existing arguments, preserving other options, then restart the verified service when other Wi-Fi connections can tolerate it."));
                lines.push("  Check the installed iwd(8) manual. [Blacklist] in main.conf controls access-point blacklisting, not interface exclusion.".into());
            }
            "connman" | "connmand" => lines.push("  Merge the selected interface into [General] NetworkInterfaceBlacklist in /etc/connman/main.conf, preserving existing entries; reload/restart the verified service and check the interface.".into()),
            "dhcpcd" => lines.push(format!("  Add denyinterfaces {config_interface} to /etc/dhcpcd.conf; release that interface's existing DHCP client through its verified service before enabling traffic-masq DHCP.")),
            "hostapd" | "wpa_supplicant" => lines.push("  Inspect the reported PID/service and control socket. It may be traffic-masq's own worker; never stop it based on its process name. Release only a verified foreign worker on the selected interface and disable its automatic restart.".into()),
            "dnsmasq" | "dhcpd" | "kea-dhcp4" => lines.push("  Check DHCP listen addresses/interfaces and UDP port 67. Exclude only the LAN assigned to traffic-masq; preserve unrelated DHCP/DNS service.".into()),
            _ => lines.push("  Inspect the reported PID/service and its interface configuration. Exclude the selected interface and prevent its DHCP/Wi-Fi worker from restarting. Do not infer a service name from a process name.".into()),
        }
    }
    lines.push(match init {
        InitSystem::Systemd => "Service manager: systemd; inspect a verified unit with systemctl status UNIT.",
        InitSystem::OpenRc => "Service manager: OpenRC; inspect the verified service with rc-service SERVICE status.",
        InitSystem::Runit => "Service manager: runit; inspect the verified service with sv status SERVICE.",
        InitSystem::Unknown => "Service manager unknown; inspect the host's actual supervisor before changing service startup.",
    }.into());
    lines.join("\n")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests;
