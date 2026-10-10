//! Shared restart state and backoff policy, independent of process operations.

use super::lifecycle::WifiHealth;
use std::time::{Duration, Instant};

pub(crate) const BACKOFF_CEILING: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Default)]
pub(crate) struct RetryState {
    consecutive_failures: u32,
    next_restart_earliest: Option<Instant>,
    last_failure: Option<String>,
    retry_suspended: bool,
    suspended_ifindex: Option<u32>,
}

impl RetryState {
    pub(crate) fn failed_startup(base_seconds: u64, error: &str) -> Self {
        Self {
            consecutive_failures: 1,
            next_restart_earliest: Some(Instant::now() + backoff_duration(base_seconds, 1)),
            last_failure: Some(error.to_string()),
            retry_suspended: false,
            suspended_ifindex: None,
        }
    }

    pub(crate) fn is_waiting(&self) -> bool {
        self.next_restart_earliest
            .is_some_and(|earliest| Instant::now() < earliest)
    }

    pub(crate) fn respawn_failed(&mut self, base_seconds: u64, error: &str) {
        self.last_failure = Some(error.to_string());
        self.retry_suspended = false;
        self.suspended_ifindex = None;
        self.next_restart_earliest =
            Some(Instant::now() + backoff_duration(base_seconds, self.consecutive_failures));
    }

    pub(crate) fn suspend(&mut self, error: &str, ifindex: Option<u32>) {
        self.last_failure = Some(error.to_string());
        self.next_restart_earliest = None;
        self.retry_suspended = true;
        self.suspended_ifindex = ifindex;
    }

    pub(crate) fn attempts(&self) -> u32 {
        self.consecutive_failures
    }
    pub(crate) fn next_restart(&self) -> Option<Instant> {
        self.next_restart_earliest
    }
    pub(crate) fn failure(&self) -> Option<&str> {
        self.last_failure.as_deref()
    }
    pub(crate) fn is_suspended(&self) -> bool {
        self.retry_suspended
    }
    pub(crate) fn suspended_interface(&self) -> Option<u32> {
        self.suspended_ifindex
    }

    pub(crate) fn record_failure(&mut self, error: String) {
        self.last_failure = Some(error);
    }

    pub(crate) fn record_attempt(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// A device disappearance retains suspension, but invalidates its identity.
    /// Only observing a new existing interface permits another attempt.
    pub(crate) fn resume_for_interface(&mut self, current: Option<u32>) -> bool {
        if !self.retry_suspended {
            return false;
        }
        if current.is_none() {
            self.suspended_ifindex = None;
            return false;
        }
        if current == self.suspended_ifindex {
            return false;
        }
        self.retry_suspended = false;
        self.suspended_ifindex = None;
        self.next_restart_earliest = None;
        true
    }

    /// Configuration changed: reset attempts while retaining the last diagnostic.
    pub(crate) fn reset_restart_budget(&mut self) {
        self.consecutive_failures = 0;
        self.next_restart_earliest = None;
    }

    /// STA startup has a responsive endpoint; retain attempts until health passes.
    pub(crate) fn respawn_ready(&mut self) {
        self.next_restart_earliest = None;
        self.last_failure = None;
    }

    /// AP startup is not proof of a working radio. Keep backoff until ENABLED.
    pub(crate) fn await_health(&mut self, base_seconds: u64) {
        self.next_restart_earliest =
            Some(Instant::now() + backoff_duration(base_seconds, self.consecutive_failures));
    }

    #[cfg(test)]
    pub(crate) fn retry_now(&mut self) {
        self.next_restart_earliest = Some(Instant::now());
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
}

pub(crate) async fn retry_health(
    error: &str,
    attempts: u32,
    next_restart_earliest: Option<Instant>,
    interface: &str,
) -> WifiHealth {
    let retry_in_secs = next_restart_earliest
        .map(|earliest| earliest.saturating_duration_since(Instant::now()).as_secs());
    let competing_managers = crate::wifi::process::find_competing_network_managers().await;
    let advice = if competing_managers.is_empty() {
        None
    } else {
        Some(crate::wifi::process::format_competing_manager_advice(
            &competing_managers,
            interface,
        ))
    };
    WifiHealth::Retrying {
        error: error.to_string(),
        attempts,
        retry_in_secs,
        competing_managers,
        advice,
    }
}

/// Compute a bounded exponential restart delay from the consecutive failure count.
pub(crate) fn backoff_duration(base_seconds: u64, consecutive_failures: u32) -> Duration {
    let multiplier = 1u64.checked_shl(consecutive_failures.saturating_sub(1));
    let seconds = multiplier
        .and_then(|multiplier| base_seconds.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

#[cfg(test)]
mod tests;
