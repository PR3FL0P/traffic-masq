//! Daemon adapter for the standalone dataplane crate.

pub use traffic_masq_dataplane::*;

#[derive(Debug, Default, Clone, Copy)]
pub struct NftCommandExecutor;

impl NftExecutor for NftCommandExecutor {
    fn execute(&self, arguments: &[&str], input: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Production async callers run the backend on the blocking pool.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(crate::command::run(
                std::path::Path::new("nft"),
                arguments,
                input,
                crate::command::COMMAND_TIMEOUT,
            ))
    }
}
