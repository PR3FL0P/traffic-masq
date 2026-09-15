//! Bounded execution of short-lived system commands.
use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

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
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_terminates_and_reaps_the_child() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        // A shell builtin loop keeps the test to exactly one child process.
        let error = run(
            Path::new("/bin/sh"),
            &[
                "-c",
                "echo $$ > \"$1\"; while :; do :; done",
                "test",
                pid_path.to_str().unwrap(),
            ],
            &[],
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error:#}");
        let pid: u32 = std::fs::read_to_string(pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[tokio::test]
    async fn large_input_and_output_are_processed_concurrently() {
        let input = vec![b'x'; 256 * 1024];
        let output = run(Path::new("/bin/cat"), &[], &input, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn excessive_output_is_rejected() {
        let size = (MAX_OUTPUT_BYTES + 1).to_string();
        let error = run(
            Path::new("/usr/bin/head"),
            &["-c", &size, "/dev/zero"],
            &[],
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("output exceeds limit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn version_probe_allows_hostapd_style_exit_status() {
        let output = run_inner(
            Path::new("/bin/sh"),
            &["-c", "echo version; exit 1"],
            &[],
            Duration::from_secs(5),
            false,
        )
        .await
        .unwrap();
        assert_eq!(output, b"version\n");
    }

    #[tokio::test]
    async fn nonzero_exit_is_not_a_successful_preflight() {
        let error = run(
            Path::new("/bin/sh"),
            &["-c", "echo broken >&2; exit 3"],
            &[],
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("broken"));
    }
}
