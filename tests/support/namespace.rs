#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

pub fn create_veth(host_if: &str, peer_if: &str, peer_ns: &str) -> Result<()> {
    run(
        "ip",
        &[
            "link", "add", host_if, "type", "veth", "peer", "name", peer_if,
        ],
    )?;
    run("ip", &["link", "set", peer_if, "netns", peer_ns])
}

pub fn require_root() -> Result<()> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("failed to run id -u")?;
    if String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("this ignored integration test must be run as root");
    }
    Ok(())
}

pub fn require_command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("required command is not available: {program}"))?;
    if !status.success() {
        bail!("required command failed its availability check: {program}");
    }
    Ok(())
}

pub fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    if !output.status.success() {
        bail!(
            "command failed: {program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .subsec_nanos();
    format!("{:05}", (nanos ^ std::process::id()) % 100_000)
}
