//! Bounded, read-only snapshots. Host probes never claim client reachability.
use super::*;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use traffic_masq_protocol::{SharingDiagnosticSection, SharingDiagnostics};

const LIMIT: u64 = 32 * 1024;
static COLLECTIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

fn section(title: &str, detail: impl Into<String>) -> SharingDiagnosticSection {
    SharingDiagnosticSection {
        title: title.into(),
        detail: detail.into(),
    }
}

/// No shell, caller-controlled executable, or unbounded subprocess/output.
async fn command<const N: usize>(program: &str, args: [&str; N]) -> String {
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdout = child.stdout.take().expect("piped stdout").take(LIMIT + 1);
        let mut stderr = child.stderr.take().expect("piped stderr").take(LIMIT + 1);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )?;
        let truncated = out.len() as u64 > LIMIT || err.len() as u64 > LIMIT;
        out.truncate(LIMIT as usize);
        err.truncate(LIMIT as usize);
        Ok::<_, std::io::Error>(format!(
            "{}\n{}{}{}",
            if status.success() {
                "Observation completed".into()
            } else {
                format!("Observation failed ({status}); connectivity unknown")
            },
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err),
            if truncated {
                "\n[output truncated]"
            } else {
                ""
            }
        ))
    })
    .await;
    match result {
        Ok(Ok(text)) => text,
        Ok(Err(error)) => format!("Unavailable: {error}"),
        Err(_) => "Observation timed out after 3 seconds; result unknown".into(),
    }
}

impl ControlService {
    pub(super) async fn sharing_diagnostics(&self, from: String, to: String) -> Response {
        if let Err(error) = traffic_masq_protocol::validate_interface_name(&from)
            .and_then(|()| traffic_masq_protocol::validate_interface_name(&to))
        {
            return Response::Error { message: error };
        }
        let Ok(_permit) = COLLECTIONS.try_acquire() else {
            return Response::Error {
                message: "Sharing diagnostics are busy; retry shortly".into(),
            };
        };
        match tokio::time::timeout(Duration::from_secs(12), self.collect(&from, &to)).await {
            Ok(Ok(report)) => Response::SharingDiagnostics { report },
            Ok(Err(error)) => runtime::error_response(error),
            Err(_) => Response::Error {
                message: "Sharing diagnostics timed out; retry after the current network operation"
                    .into(),
            },
        }
    }

    async fn collect(&self, from: &str, to: &str) -> Result<SharingDiagnostics> {
        let effective = self
            .overrides
            .snapshot()
            .await
            .effective_config(&self.base_config)?;
        let rule = effective
            .router
            .forwarding
            .as_ref()
            .and_then(|rules| rules.iter().find(|rule| rule.from == from && rule.to == to));
        let mut sections = vec![section("Scope", "Snapshot of saved sharing and current runtime; no settings changed. One ICMP probe goes to 1.1.1.1 through the selected egress. A successful host probe does not prove a client's forwarding or DNS works. Retry Diagnose while the phone opens a new website and compare counters.")];
        if let Some(router) = &self.router {
            sections.push(section("Router transaction", format!("State: {:?}. Pending changes may differ from saved intent; expired unconfirmed changes roll back.", router.view().await.status())));
        }
        sections.push(section("Saved sharing", match rule {
            Some(rule) => format!("{from} -> {to}; masquerade={}; source={}. Router enabled={}.\n{}", rule.masquerade,
                rule.source_subnet.map_or("any".into(), |net| net.to_string()), effective.router.is_active(),
                if rule.masquerade { "NAT is configured; inspect the live rules below." } else { "NAT is off: the upstream network needs a return route to the client subnet." }),
            None => "No saved sharing rule matches this pair. Apply and commit the draft first; observations below describe live runtime, not draft settings.".into(),
        }));
        let interfaces =
            tokio::time::timeout(Duration::from_secs(1), self.network.list_interfaces()).await;
        for name in [from, to] {
            let detail = match &interfaces {
                Ok(Ok(interfaces)) => match interfaces.iter().find(|item| item.name == name) {
                    Some(item) => format!("{name}: administrative link {}; RX {} bytes; TX {} bytes. Link-up alone does not prove carrier or connectivity.", if item.is_up { "up" } else { "DOWN" }, item.rx_bytes, item.tx_bytes),
                    None => format!("{name}: MISSING. For a concurrent Wi-Fi AP, select the actual AP virtual interface as From, not its parent/client interface."),
                },
                _ => format!("{name}: interface observation unavailable"),
            };
            sections.push(section("Interface", detail));
        }
        let (lan_addresses, wan_addresses) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(1),
                self.network.list_ipv4_addresses(from)
            ),
            tokio::time::timeout(Duration::from_secs(1), self.network.list_ipv4_addresses(to))
        );
        let addressing = match (&lan_addresses, &wan_addresses) {
            (Ok(Ok(lan)), Ok(Ok(wan))) => {
                let mut findings = Vec::new();
                if lan.is_empty() {
                    findings.push("WARNING: ingress has no IPv4 address; clients may have no reachable gateway.".into());
                }
                if wan.is_empty() {
                    findings.push("WARNING: egress has no IPv4 address; check upstream DHCP/static configuration (unnumbered links need separate routing).".into());
                }
                for left in lan {
                    for right in wan {
                        if let (Ok(a), Ok(b)) = (
                            ipnet::Ipv4Net::new(left.address, left.prefix_len),
                            ipnet::Ipv4Net::new(right.address, right.prefix_len),
                        ) {
                            if a.contains(&b.addr()) || b.contains(&a.addr()) {
                                findings.push(format!("WARNING: client and upstream subnets overlap ({a}, {b}); choose a different AP subnet."));
                            }
                        }
                    }
                }
                if findings.is_empty() {
                    "IPv4 addresses exist on both ends; no overlapping subnet observed. This does not establish connectivity.".into()
                } else {
                    findings.join("\n")
                }
            }
            _ => "Address comparison unavailable; inspect the IPv4 observations below.".into(),
        };
        sections.push(section("Addressing checks", addressing));
        let dhcp = self.dhcp.spec(from).await;
        let running = self
            .dhcp
            .running_interfaces()
            .await
            .contains(&from.to_owned());
        let unhealthy = self
            .dhcp
            .unhealthy_interfaces()
            .await
            .contains(&from.to_owned());
        sections.push(section("Client DHCP / DNS", dhcp.map_or_else(
            || format!("No traffic-masq DHCP service on {from}. Clients need an address, gateway and DNS from another server or manual configuration. Wi-Fi association alone is insufficient."),
            |spec| format!("Running={running}; unhealthy={unhealthy}; server={}/{}; pool={}–{}; advertised gateway={}; DNS={:?}.\nThe phone's gateway must be the AP-side router address. Advertising the router as DNS only works if a DNS resolver actually listens there; traffic-masq does not provide one.", spec.server_ip, spec.prefix_len, spec.pool_start, spec.pool_end, spec.router, spec.dns_servers)
        )));
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let leases = LeaseStore::for_interface(&self.base_config.dhcp.leases_dir, from)
            .load()
            .await;
        let mut client_ip = None;
        sections.push(section(
            "DHCP leases (not proof of current association)",
            match leases {
                Ok(leases) => {
                    let active: Vec<_> = leases
                        .iter()
                        .filter(|lease| lease.expires_at_unix > now)
                        .collect();
                    client_ip = active.first().map(|lease| lease.ip);
                    let mut detail = format!(
                        "{} unexpired lease(s). Static clients may be absent.\n",
                        active.len()
                    );
                    for lease in active.iter().take(32) {
                        detail.push_str(&format!(
                            "{}  {}  expires={}\n",
                            traffic_masq_protocol::MacAddr::new(lease.mac),
                            lease.ip,
                            lease.expires_at_unix
                        ));
                    }
                    if active.len() > 32 {
                        detail.push_str("[lease list truncated]\n");
                    }
                    detail
                }
                Err(error) => format!("Lease observation unavailable: {error:#}"),
            },
        ));
        if let Some(wifi) = &self.wifi {
            let detail = match tokio::time::timeout(Duration::from_secs(1), wifi.status(from)).await {
                Ok(Some(status)) => format!("AP state={:?}; associated stations={:?}; health={:?}. In AP + client mode check that the upstream client remains connected on the parent radio.", status.hostapd_state, status.num_stations, status.health),
                Ok(None) => "No supervised AP on this ingress; it may be wired or the wrong virtual interface.".into(),
                Err(_) => "AP observation timed out; association unknown.".into(),
            };
            sections.push(section("Wi-Fi AP", detail));
        }
        let (ingress, egress, neighbours, routes, rules, firewall, probe) = tokio::join!(
            command("ip", ["-4", "address", "show", "dev", from]),
            command("ip", ["-4", "address", "show", "dev", to]),
            command("ip", ["-4", "neigh", "show", "dev", from]),
            command("ip", ["-4", "route", "show", "table", "all"]),
            command("ip", ["-4", "rule", "show"]),
            async {
                let (forward, nat) = tokio::join!(
                    command(
                        "nft",
                        ["-a", "list", "chain", "inet", "traffic_masq", "forward"]
                    ),
                    command(
                        "nft",
                        ["-a", "list", "chain", "inet", "traffic_masq", "postrouting"]
                    )
                );
                format!(
                    "Forward / return / drop counters:\n{forward}\nNAT (new-flow) counters:\n{nat}"
                )
            },
            command(
                "ping",
                ["-4", "-n", "-c", "1", "-W", "2", "-I", to, "1.1.1.1"]
            )
        );
        let mut sysctls = String::new();
        for key in [
            "ip_forward".to_owned(),
            "conf/all/rp_filter".to_owned(),
            format!("conf/{from}/rp_filter"),
            format!("conf/{to}/rp_filter"),
        ] {
            let value = tokio::fs::read_to_string(format!("/proc/sys/net/ipv4/{key}")).await;
            if key == "ip_forward" && value.as_ref().is_ok_and(|value| value.trim() == "0") {
                sysctls.push_str("BLOCKED: IPv4 forwarding is disabled. The kernel cannot route client packets between interfaces even if this host has Internet access. Review / Apply and commit sharing; inspect router health if forwarding was changed externally.\n");
            }
            sysctls.push_str(&format!(
                "{key}: {}\n",
                value.map_or_else(
                    |error| format!("unknown ({error})"),
                    |value| value.trim().to_owned()
                )
            ));
        }
        sections.push(section("Kernel forwarding", format!("{sysctls}ip_forward must be 1. Strict rp_filter (1) may reject asymmetric/VPN return paths; inspect routes before changing it.")));
        if let Some(client_ip) = client_ip {
            let client = client_ip.to_string();
            let route = command(
                "ip",
                [
                    "-4", "route", "get", "1.1.1.1", "from", &client, "iif", from,
                ],
            )
            .await;
            sections.push(section("Forwarded route lookup (first unexpired lease)", format!("Source {client}, ingress {from}, destination 1.1.1.1:\n{route}\nExpected egress: {to}. This is a routing lookup, not a transmitted client packet; packet marks or VPN policy can change the actual path.")));
        }
        sections.extend([
            section("Ingress IPv4", ingress), section("Egress IPv4", egress),
            section("Client neighbours", neighbours), section("IPv4 routes (all tables)", routes),
            section("Policy routing", rules),
            section("Live sharing firewall / counters", format!("{firewall}\nCompare outbound, established return and drop packet counts between snapshots. Counters are cumulative and reset when rules are replaced; NAT counts only new flows, not every packet. Existing rules may lack counters until replaced by this build. An accept here can still be dropped by another firewall chain.\nFor other firewall owners inspect: sudo nft -a list ruleset")),
            section("Router-only Internet probe (ICMP to 1.1.1.1)", format!("{probe}\nSuccess proves only this host's ICMP path through {to}. Failure may mean ICMP is blocked; it does not prove Internet failure or DNS failure.")),
        ]);
        sections.push(section("What to test from the phone", format!("1. Confirm its IPv4 address, gateway and DNS match DHCP above.\n2. Reach the gateway first; if that fails check the AP interface, subnet and neighbour state.\n3. Open a new Internet connection while comparing firewall counters: outbound unchanged suggests wrong ingress/route/source subnet; outbound increasing with no return suggests upstream/NAT/return-path filtering; drops increasing suggests a rule or route mismatch. Other clients can also increment counters.\n4. If an external IP is reachable but names fail, check the advertised DNS server. A daemon-side DNS lookup would test the router's resolver, not the phone's.\n5. Packet capture, if needed: sudo tcpdump -ni {from} 'arp or icmp or port 53' and sudo tcpdump -ni {to} 'icmp or port 53'. These are manual observations; no capture runs automatically.")));
        Ok(SharingDiagnostics {
            from: from.into(),
            to: to.into(),
            captured_at_unix: now,
            sections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_observer_is_unknown_not_a_connectivity_failure() {
        let result = command("/missing/traffic-masq-observer", []).await;
        assert!(result.starts_with("Unavailable:"));
    }
}
