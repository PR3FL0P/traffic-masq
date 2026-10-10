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

/// Generates clear, actionable advice on how to stop/disable competing network managers
/// (or isolate the specific interface from them) adapted to the current operating environment.
pub fn format_competing_manager_advice(managers: &[String], interface: &str) -> String {
    format_competing_manager_advice_for_init(managers, interface, detect_init_system())
}

pub fn format_competing_manager_advice_for_init(
    managers: &[String],
    interface: &str,
    init: InitSystem,
) -> String {
    let mut lines = Vec::new();

    for manager in managers {
        match manager.as_str() {
            "iwd" => {
                lines.push(format!("• Manager '{manager}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down iwd".to_string());
                        lines
                            .push("  - Disable service:   sudo touch /etc/sv/iwd/down".to_string());
                    }
                    InitSystem::Systemd => {
                        lines.push("  - Stop service:      sudo systemctl stop iwd".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now iwd".to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push("  - Stop service:      sudo rc-service iwd stop".to_string());
                        lines.push(
                            "  - Disable service:   sudo rc-update del iwd default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down iwd   (or: sudo systemctl stop iwd)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/iwd/down   (or: sudo systemctl disable --now iwd)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/iwd/main.conf:"
                ));
                lines.push("      [Blacklist]".to_string());
                lines.push(format!("      Interfaces={interface}"));
            }
            "NetworkManager" => {
                lines.push(format!("• Manager '{manager}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines
                            .push("  - Stop service:      sudo sv down NetworkManager".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/NetworkManager/down"
                                .to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines.push(
                            "  - Stop service:      sudo systemctl stop NetworkManager".to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now NetworkManager"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push(
                            "  - Stop service:      sudo rc-service NetworkManager stop"
                                .to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo rc-update del NetworkManager default"
                                .to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down NetworkManager   (or: sudo systemctl stop NetworkManager)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/NetworkManager/down   (or: sudo systemctl disable --now NetworkManager)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: sudo nmcli device set {interface} managed no"
                ));
                lines.push(format!("    (or in /etc/NetworkManager/conf.d/99-traffic-masq.conf: [keyfile] unmanaged-devices=interface-name:{interface})"));
            }
            "systemd-network" | "systemd-networkd" | "networkd" => {
                lines.push("• Manager 'systemd-networkd' is running:".to_string());
                lines.push(
                    "  - Stop service:      sudo systemctl stop systemd-networkd".to_string(),
                );
                lines.push(
                    "  - Disable service:   sudo systemctl disable --now systemd-networkd"
                        .to_string(),
                );
                lines.push(format!("  - Release '{interface}' only: create /etc/systemd/network/99-{interface}-unmanaged.network:"));
                lines.push("      [Match]".to_string());
                lines.push(format!("      Name={interface}"));
                lines.push("      [Link]".to_string());
                lines.push("      Unmanaged=yes".to_string());
            }
            "connman" | "connmand" => {
                lines.push("• Manager 'connman' is running:".to_string());
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down connman".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/connman/down".to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines
                            .push("  - Stop service:      sudo systemctl stop connman".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now connman"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines.push(
                            "  - Stop service:      sudo rc-service connman stop".to_string(),
                        );
                        lines.push(
                            "  - Disable service:   sudo rc-update del connman default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down connman   (or: sudo systemctl stop connman)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/connman/down   (or: sudo systemctl disable --now connman)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/connman/main.conf:"
                ));
                lines.push(format!("      NetworkInterfaceBlacklist = {interface}"));
            }
            "dhcpcd" => {
                lines.push("• Manager 'dhcpcd' is running:".to_string());
                match init {
                    InitSystem::Runit => {
                        lines.push("  - Stop service:      sudo sv down dhcpcd".to_string());
                        lines.push(
                            "  - Disable service:   sudo touch /etc/sv/dhcpcd/down".to_string(),
                        );
                    }
                    InitSystem::Systemd => {
                        lines.push("  - Stop service:      sudo systemctl stop dhcpcd".to_string());
                        lines.push(
                            "  - Disable service:   sudo systemctl disable --now dhcpcd"
                                .to_string(),
                        );
                    }
                    InitSystem::OpenRc => {
                        lines
                            .push("  - Stop service:      sudo rc-service dhcpcd stop".to_string());
                        lines.push(
                            "  - Disable service:   sudo rc-update del dhcpcd default".to_string(),
                        );
                    }
                    _ => {
                        lines.push("  - Stop service:      sudo sv down dhcpcd   (or: sudo systemctl stop dhcpcd)".to_string());
                        lines.push("  - Disable service:   sudo touch /etc/sv/dhcpcd/down   (or: sudo systemctl disable --now dhcpcd)".to_string());
                    }
                }
                lines.push(format!(
                    "  - Release '{interface}' only: add to /etc/dhcpcd.conf:"
                ));
                lines.push(format!("      denyinterfaces {interface}"));
            }
            other => {
                lines.push(format!("• Manager '{other}' is running:"));
                match init {
                    InitSystem::Runit => {
                        lines.push(format!("  - Stop service:      sudo sv down {other}"));
                        lines.push(format!(
                            "  - Disable service:   sudo touch /etc/sv/{other}/down"
                        ));
                    }
                    InitSystem::Systemd => {
                        lines.push(format!(
                            "  - Stop service:      sudo systemctl stop {other}"
                        ));
                        lines.push(format!(
                            "  - Disable service:   sudo systemctl disable --now {other}"
                        ));
                    }
                    InitSystem::OpenRc => {
                        lines.push(format!(
                            "  - Stop service:      sudo rc-service {other} stop"
                        ));
                        lines.push(format!(
                            "  - Disable service:   sudo rc-update del {other} default"
                        ));
                    }
                    _ => {
                        lines.push(format!("  - Stop service:      sudo sv down {other}   (or: sudo systemctl stop {other})"));
                        lines.push(format!("  - Disable service:   sudo touch /etc/sv/{other}/down   (or: sudo systemctl disable --now {other})"));
                    }
                }
            }
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests;
