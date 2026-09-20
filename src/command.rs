//! Bounded execution of short-lived system commands.
use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Drain one output stream, rejecting data larger than the per-stream limit.
async fn read_output(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    anyhow::ensure!(
        bytes.len() <= MAX_OUTPUT_BYTES,
        "command output exceeds limit"
    );
    Ok(bytes)
}

/// Run a command with piped input and a deadline, returning stdout on success.
/// Drain stdout and stderr concurrently; kill and reap the child on timeout or I/O failure.
/// A nonzero exit status is an error containing stderr.
pub(crate) async fn run(
    program: &Path,
    arguments: &[&str],
    input: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>> {
    run_inner(program, arguments, input, deadline, true).await
}

/// Version probes only test whether the binary runs: hostapd -v exits with 1.
pub(crate) async fn probe(program: &Path) -> Result<()> {
    run_inner(program, &["-v"], &[], COMMAND_TIMEOUT, false)
        .await
        .map(|_| ())
}

/// Execute a bounded command; optionally accept nonzero exit codes for version probes.
async fn run_inner(
    program: &Path,
    arguments: &[&str],
    input: &[u8],
    deadline: Duration,
    require_success: bool,
) -> Result<Vec<u8>> {
    let mut child = tokio::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {}", program.display()))?;
    let mut stdin = child.stdin.take().context("command stdin unavailable")?;
    let stdout = child.stdout.take().context("command stdout unavailable")?;
    let stderr = child.stderr.take().context("command stderr unavailable")?;
    // Drain output while writing input: either pipe may otherwise fill up.
    let result = tokio::time::timeout(deadline, async {
        tokio::try_join!(
            async {
                stdin.write_all(input).await?;
                drop(stdin);
                Ok::<_, anyhow::Error>(())
            },
            read_output(stdout),
            read_output(stderr),
            async { child.wait().await.map_err(anyhow::Error::from) },
        )
    })
    .await;
    match result {
        Ok(Ok(((), stdout, stderr, status))) => {
            if require_success && !status.success() {
                bail!(
                    "{} exited with status {status}: {}",
                    program.display(),
                    String::from_utf8_lossy(&stderr).trim()
                );
            }
            Ok(stdout)
        }
        result => {
            // Reap before reporting failure so no accepted operation leaves a
            // live command capable of changing the network afterwards.
            child
                .kill()
                .await
                .context("failed to terminate failed command")?;
            match result {
                Ok(Err(error)) => Err(error),
                Err(_) => bail!(
                    "{} timed out after {} seconds",
                    program.display(),
                    deadline.as_secs_f64()
                ),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests;
