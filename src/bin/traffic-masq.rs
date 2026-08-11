use anyhow::Result;
use clap::Parser;
use traffic_masq::config::ResolvedConfig;
use traffic_masq::tui::{change_device_password, run_tui};

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

    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let resolved = ResolvedConfig::load(args.config)?;
    if resolved.source.is_built_in() {
        eprintln!(
            "No configuration file found; using safe built-in defaults (no interfaces are managed)."
        );
    }
    if args.change_password {
        change_device_password(resolved.config).await
    } else {
        run_tui(resolved.config, args.direct).await
    }
}
