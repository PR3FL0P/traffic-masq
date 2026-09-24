use std::fs;

use anyhow::Result;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;

/// Initialize stderr logging unconditionally and add the rolling file sink when available.
///
/// Recovery must not depend on a writable log directory. The optional guard only exists when the
/// file appender was successfully created; keeping it alive preserves non-blocking file writes.
pub fn init_logging(
    config: &AppConfig,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::from_default_env().add_directive("traffic_masq=info".parse()?);

    match fs::create_dir_all(&config.runtime.log_dir) {
        Ok(()) => {
            let file_appender =
                tracing_appender::rolling::daily(&config.runtime.log_dir, "traffic-masqd.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr.and(non_blocking))
                .init();
            Ok(Some(guard))
        }
        Err(error) => {
            eprintln!(
                "warning: cannot initialize file logging at {}: {error}; continuing with stderr so startup recovery remains available",
                config.runtime.log_dir.display()
            );
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
            Ok(None)
        }
    }
}
