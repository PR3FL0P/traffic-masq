#![allow(dead_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::time::{sleep, timeout};

const STOP_GRACE: Duration = Duration::from_secs(5);

pub fn read_pid_file(path: &Path) -> Result<u32> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon PID file {}", path.display()))?
        .trim()
        .parse()
        .with_context(|| format!("daemon PID file {} is invalid", path.display()))
}

pub fn validate_interface(interface: &str, variable: &str) -> Result<()> {
    if interface.len() > 15
        || interface.is_empty()
        || !interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        bail!("{variable} is not a valid Linux interface name");
    }
    let path = Path::new("/sys/class/net").join(interface);
    if !path.exists() {
        bail!("selected interface does not exist");
    }
    if !path.join("wireless").exists() || !path.join("phy80211").exists() {
        bail!("selected interface is not an nl80211 wireless interface");
    }
    Ok(())
}

pub fn validate_psk_file(path: &Path, variable: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{variable} must be absolute");
    }
    let metadata = fs::symlink_metadata(path).context("failed to inspect PSK file metadata")?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_socket()
    {
        bail!("PSK path must be a regular non-symlink file");
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("PSK file must have mode 0600");
    }
    Ok(())
}

pub fn refuse_management_uplink(interface: &str) -> Result<()> {
    for args in [
        vec!["route", "get", "1.1.1.1"],
        vec!["-6", "route", "get", "2606:4700:4700::1111"],
    ] {
        let output = Command::new("ip")
            .args(&args)
            .output()
            .context("failed to inspect routes")?;
        if output.status.success()
            && route_uses_interface(&String::from_utf8_lossy(&output.stdout), interface)
        {
            bail!("refusing selected interface because it is used by the current best route");
        }
    }
    Ok(())
}

fn route_uses_interface(routes: &str, interface: &str) -> bool {
    routes.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        words.windows(2).any(|pair| pair == ["dev", interface])
    })
}

pub fn interface_phy(interface: &str) -> Result<String> {
    let target = fs::canonicalize(Path::new("/sys/class/net").join(interface).join("phy80211"))
        .context("failed to identify selected interface PHY")?;
    target
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .context("selected interface PHY name is not valid UTF-8")
}

pub fn interfaces_on_phy(namespace: Option<&str>, phy: &str) -> Result<Vec<String>> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "iw", &["dev"]),
        None => Command::new("iw")
            .arg("dev")
            .output()
            .context("failed to run iw dev"),
    }?;
    if !output.status.success() {
        bail!("failed to enumerate wireless interfaces");
    }
    let mut current_phy = None;
    let mut interfaces = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if let Some(index) = trimmed.strip_prefix("phy#") {
            current_phy = Some(format!("phy{index}"));
        } else if current_phy.as_deref() == Some(phy) {
            if let Some(interface) = trimmed.strip_prefix("Interface ") {
                interfaces.push(interface.to_string());
            }
        }
    }
    Ok(interfaces)
}

pub fn command_path(program: &str) -> Result<PathBuf> {
    for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return fs::canonicalize(candidate)
                .with_context(|| format!("failed to resolve {program}"));
        }
    }
    bail!("could not resolve required command {program}")
}

pub fn list_phys(namespace: Option<&str>) -> Result<BTreeSet<String>> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "iw", &["phy"]),
        None => Command::new("iw")
            .arg("phy")
            .output()
            .context("failed to run iw phy"),
    }?;
    if !output.status.success() {
        bail!("iw phy failed: {}", output_text(&output));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Wiphy "))
        .map(str::to_string)
        .collect())
}

pub fn list_interfaces(namespace: Option<&str>) -> Result<Vec<String>> {
    let output = match namespace {
        Some(namespace) => output_ns(namespace, "iw", &["dev"]),
        None => Command::new("iw")
            .arg("dev")
            .output()
            .context("failed to run iw dev"),
    }?;
    if !output.status.success() {
        bail!("iw dev failed: {}", output_text(&output));
    }
    let mut interfaces: Vec<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Interface "))
        .map(str::to_string)
        .collect();
    interfaces.sort();
    Ok(interfaces)
}

pub fn rename_interface(namespace: &str, old: &str, new: &str) -> Result<()> {
    run_ns(namespace, "ip", &["link", "set", old, "down"])?;
    run_ns(namespace, "ip", &["link", "set", old, "name", new])
}

pub fn spawn_ns(
    namespace: &str,
    program: &str,
    args: &[&str],
    stdout: fs::File,
    stderr: fs::File,
) -> Result<Child> {
    Command::new("ip")
        .args(["netns", "exec", namespace, program])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("failed to spawn {program} in network namespace"))
}

pub fn output_ns(namespace: &str, program: &str, args: &[&str]) -> Result<Output> {
    Command::new("ip")
        .args(["netns", "exec", namespace, program])
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program} in network namespace"))
}

pub fn run_ns(namespace: &str, program: &str, args: &[&str]) -> Result<()> {
    let output = output_ns(namespace, program, args)?;
    if !output.status.success() {
        bail!(
            "{program} failed in network namespace: {}",
            output_text(&output)
        );
    }
    Ok(())
}

pub fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        bail!("{program} failed: {}", output_text(&output));
    }
    Ok(())
}

pub fn ensure_child_running(child: Option<&mut Child>, name: &str) -> Result<()> {
    let child = child.with_context(|| format!("{name} child is not tracked"))?;
    if let Some(status) = child.try_wait()? {
        bail!("{name} exited unexpectedly with status {status}");
    }
    Ok(())
}

pub fn signal_pid(pid: u32, signal: Signal, name: &str) -> Result<()> {
    let raw = i32::try_from(pid).context("process PID exceeds pid_t range")?;
    kill(Pid::from_raw(raw), signal).with_context(|| format!("failed to signal {name}"))
}

pub async fn stop_child(
    mut child: Child,
    signal: Signal,
    wait: Duration,
    name: &str,
) -> Result<()> {
    signal_pid(child.id(), signal, name)?;
    timeout(wait, async {
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    bail!("{name} exited with non-zero status {status}");
                }
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .with_context(|| format!("{name} did not stop within {wait:?}"))?
}

pub fn stop_child_blocking(mut child: Child, name: &str) {
    stop_pid_blocking(child.id(), name);
    let _ = child.try_wait();
}

pub fn stop_pid_blocking(pid: u32, name: &str) {
    let Ok(raw) = i32::try_from(pid) else { return };
    let process = Pid::from_raw(raw);
    let _ = kill(process, Signal::SIGTERM);
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("cleanup: tracked {name} ignored SIGTERM; sending SIGKILL");
    let _ = kill(process, Signal::SIGKILL);
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

pub fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn redact_ssid(text: &str, ssid: &str) -> String {
    text.replace(ssid, "<redacted-ssid>")
}

pub fn path_str(path: &Path) -> Result<&str> {
    path.to_str().context("test path is not valid UTF-8")
}

pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_nanos();
    format!(
        "{:08x}",
        (nanos as u64 ^ u64::from(std::process::id())) as u32
    )
}
