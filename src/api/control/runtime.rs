use super::*;

pub(super) fn error_response(error: impl std::fmt::Display) -> Response {
    Response::Error {
        message: format!("{error:#}"),
    }
}

pub(super) fn compensation_message(
    action: &str,
    original: &impl std::fmt::Display,
    restoration: std::result::Result<(), impl std::fmt::Display>,
) -> String {
    match restoration {
        Ok(()) => format!("{action}; runtime state was restored: {original:#}"),
        Err(error) => {
            tracing::error!(original = %format!("{original:#}"), rollback_error = %format!("{error:#}"), "runtime restoration failed");
            format!(
                "{action}: {original:#}; runtime restoration failed: {error:#}; recovery required"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_messages_preserve_original_and_restoration_causes() {
        let original = anyhow::anyhow!("Network is unreachable").context("failed to add route");
        let restoration = anyhow::anyhow!("Permission denied").context("failed to restore address");
        let message = compensation_message("apply failed", &original, Err(restoration));
        assert!(message.contains("failed to add route: Network is unreachable"));
        assert!(message.contains("failed to restore address: Permission denied"));
        let Response::Error { message } = error_response(original) else {
            panic!("expected error response");
        };
        assert_eq!(message, "failed to add route: Network is unreachable");
    }
}
