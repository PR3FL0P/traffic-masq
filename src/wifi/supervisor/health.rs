//! AP diagnostic interpretation and retry-suspension guidance.

use crate::wifi::lifecycle::WifiHealth;

pub(super) fn diagnostic_summary(lines: &[String]) -> Option<String> {
    if lines.is_empty() {
        return None;
    }

    const ERROR_MARKERS: &[&str] = &[
        "unable",
        "failed",
        "failure",
        "error",
        "invalid",
        "not supported",
        "could not",
        "cannot",
        "permission denied",
        "refused",
        "not found",
        "wasn't started",
    ];

    let mut selected = Vec::new();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if (ERROR_MARKERS.iter().any(|marker| lower.contains(marker))
            || hostapd_failure_text_should_suspend_retry(line))
            && !selected.contains(line)
        {
            selected.push(line.clone());
        }
    }

    if selected.len() > 8 {
        let mut compact = selected[..4].to_vec();
        compact.extend_from_slice(&selected[selected.len() - 4..]);
        // Startup errors are classified from this summary after the launch is
        // cleaned up. Do not drop the only permanent cause while compacting it.
        if !hostapd_failure_should_suspend_retry(&compact) {
            if let Some(cause) = selected
                .iter()
                .find(|line| hostapd_failure_text_should_suspend_retry(line))
            {
                compact[3] = cause.clone();
            }
        }
        selected = compact;
    }

    if selected.is_empty() {
        selected = lines.iter().rev().take(8).cloned().collect();
        selected.reverse();
    } else if let Some(exit) = lines
        .iter()
        .rev()
        .find(|line| line.starts_with("process exited with "))
    {
        selected.push(exit.clone());
    }

    Some(selected.join(" | "))
}

pub(super) fn hostapd_failure_should_suspend_retry(lines: &[String]) -> bool {
    lines
        .iter()
        .any(|line| hostapd_failure_text_should_suspend_retry(line))
}

pub(super) fn hostapd_failure_text_should_suspend_retry(text: &str) -> bool {
    const DETERMINISTIC_MARKERS: &[&str] = &[
        "acs: unable to collect survey data",
        "acs: all study options have failed",
        "possibly channel configuration is invalid",
        "unknown configuration item",
        "errors found in configuration file",
        "invalid hw_mode",
        "unknown hw_mode",
        "could not select hw_mode and channel",
        "hardware does not support configured mode",
        "no usable channels found",
        "configured channel is not found",
        "channel is not allowed",
        "frequency is not allowed",
        "driver does not support ap",
        "ap mode is not supported",
    ];

    let lower = text.to_ascii_lowercase();
    if DETERMINISTIC_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }
    // Driver setup can also fail because another manager holds the radio.
    // Classify each line separately so an unrelated error cannot make a
    // transient channel/beacon failure look deterministic.
    lower.split(" | ").flat_map(str::lines).any(|line| {
        [
            "failed to set beacon parameters",
            "nl80211: failed to set channel",
        ]
        .iter()
        .any(|marker| line.contains(marker))
            && ["invalid argument", "not supported", "-22", "-95"]
                .iter()
                .any(|cause| line.contains(cause))
    })
}

const RETRY_SUSPENSION_SUFFIX: &str =
    "automatic retry suspended until the AP configuration or interface identity changes";

pub(super) fn suspended_failure_message(error: &str) -> String {
    if error.contains(RETRY_SUSPENSION_SUFFIX) {
        error.to_string()
    } else {
        format!("{error}; {RETRY_SUSPENSION_SUFFIX}")
    }
}

pub(super) fn clear_suspended_failure_message(error: &str) -> String {
    error
        .strip_suffix(&format!("; {RETRY_SUSPENSION_SUFFIX}"))
        .unwrap_or(error)
        .to_string()
}

pub(super) async fn suspended_retry_health(
    error: &str,
    attempts: u32,
    interface: &str,
) -> WifiHealth {
    let competing_managers = crate::wifi::process::find_competing_network_managers().await;
    let mut advice =
        "Automatic retry is suspended until the AP configuration or interface identity changes."
            .to_string();
    if !competing_managers.is_empty() {
        advice.push(' ');
        advice.push_str(&crate::wifi::process::format_competing_manager_advice(
            &competing_managers,
            interface,
        ));
    }
    WifiHealth::Retrying {
        error: error.to_string(),
        attempts,
        retry_in_secs: None,
        competing_managers,
        advice: Some(advice),
    }
}
