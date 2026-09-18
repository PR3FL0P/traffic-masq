use super::*;

pub(super) fn error_response(error: impl std::fmt::Display) -> Response {
    Response::Error {
        message: error.to_string(),
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
            tracing::error!(%original, rollback_error = %error, "runtime restoration failed");
            format!(
                "{action}: {original:#}; runtime restoration failed: {error}; recovery required"
            )
        }
    }
}
