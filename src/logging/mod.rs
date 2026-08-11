use std::fs;

use anyhow::Result;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;

pub fn init_logging(config: &AppConfig) -> Result<()> {
    fs::create_dir_all(&config.runtime.log_dir)?;

    let file_appender =
        tracing_appender::rolling::daily(&config.runtime.log_dir, "traffic-masqd.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    Box::leak(Box::new(guard));

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("traffic_masq=info".parse()?))
        .with_writer(std::io::stderr.and(non_blocking))
        .init();

    Ok(())
}
