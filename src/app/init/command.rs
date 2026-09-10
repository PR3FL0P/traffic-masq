//! Argument-vector native commands with bounded execution and injectable runners.
use super::render;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::{path::Path, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub(super) program: String,
    pub(super) args: Vec<String>,
    pub(super) timeout: Duration,
}
impl CommandSpec {
    pub(super) fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|v| (*v).into()).collect(),
            timeout: Duration::from_secs(60),
        }
    }
}
impl std::fmt::Display for CommandSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {}", render::shell_quote(Path::new(arg)))?;
        }
        Ok(())
    }
}
#[async_trait]
pub trait CommandRunner {
    async fn run(&self, command: &CommandSpec) -> Result<()>;
}
pub struct NativeRunner;
#[async_trait]
impl CommandRunner for NativeRunner {
    async fn run(&self, command: &CommandSpec) -> Result<()> {
        let child = tokio::process::Command::new(&command.program)
            .args(&command.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to execute {command}"))?;
        let output = tokio::time::timeout(command.timeout, child.wait_with_output()).await
            .with_context(|| format!("init command timed out: {command}; inspect native service status before retrying"))??;
        if !output.status.success() {
            bail!(
                "init command {command} failed ({}): {}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}
