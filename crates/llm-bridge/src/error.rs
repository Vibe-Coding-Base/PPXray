//! Failures this crate can produce.
//!
//! The variants are split finer than a single `String` because the UI reacts
//! differently to each: a missing key opens Settings, an unreviewed payload
//! opens the preview, a refusal is the model's decision rather than a bug,
//! and a transport error is worth a retry button.

use thiserror::Error;

use crate::sql_guard::SqlRejection;

pub type LlmResult<T> = Result<T, LlmError>;

#[derive(Debug, Error)]
pub enum LlmError {
    /// The assistant is switched off. Every entry point checks this first,
    /// so a bug elsewhere cannot produce a request from a default install.
    #[error("the assistant is disabled — turn it on under Settings")]
    Disabled,

    /// The endpoint needs a credential and the credential store has none.
    #[error("no API key stored for this provider")]
    MissingKey,

    /// The user has not yet looked at what would be sent.
    #[error("the outgoing payload has not been reviewed yet")]
    PayloadNotReviewed,

    /// Transport-level: DNS, connect, TLS, timeout.
    ///
    /// The field is `reason` rather than `source` because thiserror treats a
    /// field named `source` as an `Error` to chain, and this one is already
    /// flattened to a string.
    #[error("could not reach {endpoint}: {reason}")]
    Transport { endpoint: String, reason: String },

    /// A non-2xx response. The body is included because provider error
    /// messages are the only useful diagnostic for a misconfigured model
    /// name or an expired key.
    #[error("{endpoint} returned HTTP {status}: {body}")]
    Status { endpoint: String, status: u16, body: String },

    /// A 2xx response that did not parse.
    #[error("unexpected response shape: {0}")]
    Protocol(String),

    /// The model declined the request. Not an error in this app's sense,
    /// but it is not an answer either.
    #[error("the model declined: {0}")]
    Refused(String),

    /// A query the model proposed was not allowed to run.
    #[error("{0}")]
    Sql(#[from] SqlRejection),

    #[error("credential store: {0}")]
    Credential(String),

    #[error("{0}")]
    Audit(String),

    #[error("{0}")]
    Other(String),
}

impl LlmError {
    /// Whether retrying the identical request could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            // 408/409/429 and 5xx are the retryable statuses; a 400 or 401
            // will fail identically forever.
            Self::Status { status, .. } => matches!(status, 408 | 409 | 429) || *status >= 500,
            _ => false,
        }
    }
}

impl From<crate::audit::AuditError> for LlmError {
    fn from(e: crate::audit::AuditError) -> Self {
        Self::Audit(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(
            LlmError::Transport { endpoint: "x".into(), reason: "timed out".into() }.is_retryable()
        );
        for status in [429, 500, 503, 408] {
            assert!(
                LlmError::Status { endpoint: "x".into(), status, body: String::new() }
                    .is_retryable(),
                "{status} should be retryable"
            );
        }
        for status in [400, 401, 403, 404] {
            assert!(
                !LlmError::Status { endpoint: "x".into(), status, body: String::new() }
                    .is_retryable(),
                "{status} should not be retryable"
            );
        }
        assert!(!LlmError::Disabled.is_retryable());
        assert!(!LlmError::Refused("no".into()).is_retryable());
    }

    #[test]
    fn messages_do_not_leak_a_key() {
        // The endpoint is logged and displayed; it is stripped to scheme and
        // host elsewhere, but assert here that nothing formats a credential.
        let e = LlmError::Status {
            endpoint: "https://api.anthropic.com".into(),
            status: 401,
            body: "invalid x-api-key".into(),
        };
        let text = e.to_string();
        assert!(text.contains("401"));
        assert!(!text.contains("sk-ant"));
    }
}
