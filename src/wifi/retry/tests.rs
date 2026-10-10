use super::*;

#[test]
fn suspension_requires_a_changed_or_reappearing_device() {
    let mut retry = RetryState::failed_startup(5, "startup failed");
    retry.suspend("unsupported radio", Some(7));
    assert!(!retry.resume_for_interface(Some(7)));
    assert!(retry.is_suspended());
    assert!(retry.next_restart().is_none());

    assert!(!retry.resume_for_interface(None));
    assert!(retry.is_suspended());
    // An interface may reuse its old index after disappearing.
    assert!(retry.resume_for_interface(Some(7)));
    assert!(!retry.is_suspended());
    assert_eq!(retry.failure(), Some("unsupported radio"));
}

#[test]
fn an_ap_respawn_keeps_backoff_until_health_is_verified() {
    let mut retry = RetryState::failed_startup(5, "ACS failed");
    retry.record_attempt();
    retry.await_health(5);
    assert_eq!(retry.attempts(), 2);
    assert!(retry.is_waiting());
    assert_eq!(retry.failure(), Some("ACS failed"));

    retry.clear();
    assert_eq!(retry.attempts(), 0);
    assert!(!retry.is_waiting());
    assert!(retry.failure().is_none());
}

#[test]
fn repeated_failures_cap_delay_even_at_counter_overflow() {
    let mut retry = RetryState {
        consecutive_failures: u32::MAX,
        ..RetryState::default()
    };
    retry.record_attempt();
    assert_eq!(retry.attempts(), u32::MAX);
    assert_eq!(
        backoff_duration(u64::MAX, retry.attempts()),
        BACKOFF_CEILING
    );
    retry.respawn_failed(5, "temporary failure");
    assert!(retry.is_waiting());
    assert_eq!(retry.failure(), Some("temporary failure"));
}
