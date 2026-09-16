use anyhow::Result;
use clap::Parser;
use traffic_masq::tui::{change_device_password, run_tui};

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
        help = "Scan for competing network managers (iwd, NetworkManager, systemd-networkd, etc.) and print resolution advice"
    )]
    check_conflicts: bool,

    #[arg(
        long,
        default_value = DEFAULT_SOCKET_PATH,
        help = "Unix socket exposed by traffic-masqd"
    )]
    socket: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.check_conflicts {
        let managers = traffic_masq::wifi::process::find_competing_network_managers().await;
        if managers.is_empty() {
            println!("No competing network managers detected.");
        } else {
            println!("Detected competing network manager(s) that may control wireless interfaces:");
            println!(
                "{}",
                traffic_masq::wifi::process::format_competing_manager_advice(
                    &managers,
                    "<interface>"
                )
            );
        }
        Ok(())
    } else if args.change_password {
        change_device_password(args.socket).await
    } else {
        run_tui(args.socket, args.direct).await
    }
}
