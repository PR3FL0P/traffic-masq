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
        default_value = DEFAULT_SOCKET_PATH,
        help = "Unix socket exposed by traffic-masqd"
    )]
    socket: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.change_password {
        change_device_password(args.socket).await
    } else {
        run_tui(args.socket, args.direct).await
    }
}
