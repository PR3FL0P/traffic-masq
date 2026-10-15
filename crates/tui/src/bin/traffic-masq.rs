use anyhow::{Context, Result};
use clap::Parser;
use traffic_masq_api_client::ControlApiClient as ApiClient;
use traffic_masq_tui::tui::connections::{self, SavedConnection};
use traffic_masq_tui::{change_device_password_with_client, run_tui_with_client};

mod conflicts;

const DEFAULT_SOCKET_PATH: &str = "/run/traffic-masq/traffic-masqd.sock";

#[derive(Debug, Parser)]
#[command(name = "traffic-masq", about = "traffic-masq TUI client")]
struct Args {
    #[arg(
        long,
        conflicts_with = "change_password",
        help = "Run directly instead of connecting to daemon; read-only recovery mode"
    )]
    direct: bool,

    #[arg(
        long,
        conflicts_with = "direct",
        help = "Change the shared device password through the running daemon"
    )]
    change_password: bool,

    #[arg(
        long,
        conflicts_with = "change_password",
        conflicts_with = "direct",
        help = "Inspect interface managers, Wi-Fi sockets and DHCP listeners without changing networking"
    )]
    check_conflicts: bool,

    #[arg(
        long,
        requires = "check_conflicts",
        value_name = "NAME",
        help = "Focus conflict checks on this interface; repeat for multiple interfaces"
    )]
    interface: Vec<String>,

    #[arg(
        long,
        requires = "check_conflicts",
        help = "Print the conflict report as JSON"
    )]
    json: bool,

    #[arg(
        long,
        default_value = DEFAULT_SOCKET_PATH,
        help = "Unix socket exposed by traffic-masqd"
    )]
    socket: std::path::PathBuf,

    #[arg(long, conflicts_with_all = ["socket", "direct", "check_conflicts", "connection", "list_connections", "delete_connection"], help = "HTTPS daemon origin, e.g. https://router.example:8443")]
    server: Option<String>,
    #[arg(
        long,
        requires = "server",
        help = "Trusted CA/server certificate PEM; defaults to the system CA bundle"
    )]
    ca_cert: Option<std::path::PathBuf>,
    #[arg(
        long,
        requires = "server",
        conflicts_with = "change_password",
        help = "Save this HTTPS destination under a name and exit"
    )]
    save_connection: Option<String>,
    #[arg(long, conflicts_with_all = ["socket", "direct", "check_conflicts", "list_connections", "delete_connection"], help = "Connect to a saved HTTPS destination")]
    connection: Option<String>,
    #[arg(long, conflicts_with_all = ["socket", "direct", "check_conflicts", "change_password", "delete_connection"], help = "List saved HTTPS destinations and exit")]
    list_connections: bool,
    #[arg(long, conflicts_with_all = ["socket", "direct", "check_conflicts", "change_password"], help = "Delete a saved destination; does not change the daemon")]
    delete_connection: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.list_connections {
        for (name, connection) in connections::list_connections()? {
            println!("{name}: {}", connection.server);
        }
        return Ok(());
    }
    if let Some(name) = &args.delete_connection {
        connections::delete_connection(name)?;
        println!("Deleted connection {name}");
        return Ok(());
    }
    if args.check_conflicts {
        let code = conflicts::run(&args.interface, args.json).await?;
        std::process::exit(code);
    }
    let remote = if let Some(name) = &args.connection {
        Some(connections::load_connection(name)?)
    } else {
        args.server.map(|server| SavedConnection {
            server,
            ca_cert: args.ca_cert,
        })
    };
    if let Some(name) = &args.save_connection {
        connections::save_connection(name, remote.context("--server is required")?)?;
        println!("Saved connection {name}. Open it with --connection {name}");
        return Ok(());
    }
    let client = match remote {
        Some(connection) => ApiClient::https(&connection.server, connection.ca_cert.as_deref())?,
        None => ApiClient::new(args.socket),
    };
    if args.change_password {
        change_device_password_with_client(client).await
    } else {
        run_tui_with_client(client, args.direct).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_options_are_unambiguous() {
        assert!(Args::try_parse_from(["traffic-masq", "--server", "https://router:8443"]).is_ok());
        for args in [
            vec!["--server", "https://router", "--direct"],
            vec!["--server", "https://router", "--socket", "/tmp/x"],
            vec!["--connection", "pi", "--server", "https://router"],
            vec!["--ca-cert", "/tmp/ca.pem"],
            vec!["--save-connection", "pi"],
            vec!["--list-connections", "--change-password"],
        ] {
            assert!(Args::try_parse_from(std::iter::once("traffic-masq").chain(args)).is_err());
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn conflict_options_require_scan_and_accept_repeated_interfaces() {
        assert!(Args::try_parse_from(["traffic-masq", "--json"]).is_err());
        assert!(Args::try_parse_from(["traffic-masq", "--interface", "wlan0"]).is_err());
        assert!(Args::try_parse_from(["traffic-masq", "--check-conflicts", "--direct"]).is_err());
        let args = Args::try_parse_from([
            "traffic-masq",
            "--check-conflicts",
            "--interface",
            "wlan0",
            "--interface",
            "lan0",
            "--json",
        ])
        .unwrap();
        assert_eq!(args.interface, ["wlan0", "lan0"]);
        assert!(args.json);
    }
}
