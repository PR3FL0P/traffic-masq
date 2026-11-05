use std::{fmt, fs};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{DefaultFields, FormatFields, Writer};
pub mod recent;

use anyhow::Result;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;

/// Embedded at compile time; installing a binary does not change its identity.
pub const BUILD_REVISION: &str = env!("TRAFFIC_MASQ_BUILD_REVISION");
pub const BUILD_DIRTY: &str = env!("TRAFFIC_MASQ_BUILD_DIRTY");
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("TRAFFIC_MASQ_BUILD_REVISION"),
    ", dirty=",
    env!("TRAFFIC_MASQ_BUILD_DIRTY"),
    ")"
);

#[derive(Clone)]
struct BuildFields {
    run_id: String,
}

impl BuildFields {
    fn new() -> Self {
        Self {
            run_id: format!("{:032x}", rand::random::<u128>()),
        }
    }
}

impl<'writer> FormatFields<'writer> for BuildFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        write!(
            writer,
            "build_version={} build_revision={} build_dirty={} daemon_pid={} run_id={} ",
            env!("CARGO_PKG_VERSION"),
            BUILD_REVISION,
            BUILD_DIRTY,
            std::process::id(),
            self.run_id
        )?;
        DefaultFields::new().format_fields(writer, fields)
    }
}

/// Initialize stderr logging unconditionally and add the rolling file sink when available.
///
/// Recovery must not depend on a writable log directory. The optional guard only exists when the
/// file appender was successfully created; keeping it alive preserves non-blocking file writes.
pub fn init_logging(
    config: &AppConfig,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::from_default_env().add_directive("traffic_masq=info".parse()?);

    let fields = BuildFields::new();
    match fs::create_dir_all(&config.runtime.log_dir) {
        Ok(()) => {
            let file_appender =
                tracing_appender::rolling::daily(&config.runtime.log_dir, "traffic-masqd.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .fmt_fields(fields)
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
                .with_ansi(false)
                .fmt_fields(fields)
                .with_writer(std::io::stderr)
                .init();
            Ok(None)
        }
    }
}

#[cfg(test)]
mod build_tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn every_event_carries_build_and_run_identity_without_changing_level_layout() {
        let output = Output::default();
        let sink = output.clone();
        let fields = BuildFields::new();
        let run = fields.run_id.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .fmt_fields(fields)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("first event");
            tracing::warn!(interface = "wan0", diagnostic = %"x".repeat(3000), "second event");
        });
        let bytes = output.0.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.contains(&format!("build_revision={BUILD_REVISION}")));
            assert!(line.contains(&format!("build_dirty={BUILD_DIRTY}")));
            // API log tails truncate long lines: identity must precede diagnostics.
            assert!(line
                .chars()
                .take(2048)
                .collect::<String>()
                .contains(&format!("run_id={run}")));
            assert!(line.contains(&format!("daemon_pid={}", std::process::id())));
        }
        assert_eq!(lines[0].split_whitespace().nth(1), Some("INFO"));
        assert_eq!(lines[1].split_whitespace().nth(1), Some("WARN"));
        assert!(lines[1].contains("interface=\"wan0\""));
        assert_ne!(BuildFields::new().run_id, run);
    }
}
