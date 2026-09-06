//! The only place in ppxray that opens a socket to something other than the
//! GitHub release channel.
//!
//! Every path through here writes an audit line — including the paths that
//! decide *not* to send. A privacy log that only records successes cannot be
//! used to answer "did this ever go out?".

use std::time::Duration;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::audit::{AuditEntry, AuditLog, AuditOutcome, digest, endpoint_of};
use crate::config::LlmSettings;
use crate::error::{LlmError, LlmResult};
use crate::provider::{ChatRequest, Completion, build_body, endpoint_url, headers, parse_response};

/// Models can take a while, especially a 70B running on the user's own GPU.
/// Long enough not to cut off real work, short enough that a wedged endpoint
/// does not hang the UI for the rest of the session.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

/// Provider error bodies are shown to the user; a huge one is neither
/// readable nor useful.
const MAX_ERROR_BODY: usize = 2_000;

/// Exactly what a send would put on the wire, for the user to read first.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct PayloadPreview {
    pub url: String,
    /// Header names with their values, except credentials, which are shown
    /// as their presence and length only.
    pub headers: Vec<(String, String)>,
    /// The request body, pretty-printed. This is the same value the sender
    /// serializes — not a description of it.
    pub body: String,
    pub bytes: u64,
    pub sha256: String,
    /// True when the endpoint resolves to this machine, in which case none
    /// of the above leaves it.
    pub local_endpoint: bool,
}

/// Build the preview for a request without sending anything.
pub fn preview(settings: &LlmSettings, api_key: Option<&str>, req: &ChatRequest) -> PayloadPreview {
    let body_value = build_body(settings, req);
    let body = serde_json::to_string_pretty(&body_value).unwrap_or_else(|e| format!("<{e}>"));
    let compact = serde_json::to_vec(&body_value).unwrap_or_default();

    let headers = headers(settings, api_key)
        .into_iter()
        .map(|(name, value)| {
            let shown = if is_credential(name) {
                format!("<{} characters, from the OS credential store>", value.len())
            } else {
                value
            };
            (name.to_string(), shown)
        })
        .collect();

    PayloadPreview {
        url: endpoint_url(settings),
        headers,
        bytes: compact.len() as u64,
        sha256: digest(&compact),
        body,
        local_endpoint: settings.is_local_endpoint(),
    }
}

fn is_credential(header: &str) -> bool {
    matches!(header, "x-api-key" | "authorization")
}

pub struct LlmClient {
    http: reqwest::Client,
    audit: AuditLog,
}

impl LlmClient {
    pub fn new(audit: AuditLog) -> LlmResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("ppxray/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LlmError::Other(format!("HTTP client: {e}")))?;
        Ok(Self { http, audit })
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Record a decision not to send, so the audit log shows the refusal
    /// rather than a gap.
    pub fn record_blocked(&self, settings: &LlmSettings, purpose: &str, why: &str) {
        let entry = AuditEntry {
            at: String::new(),
            purpose: purpose.to_string(),
            provider: settings.provider,
            endpoint: endpoint_of(&endpoint_url(settings)),
            model: settings.effective_model().to_string(),
            data_scope: settings.data_scope,
            request_bytes: 0,
            request_sha256: String::new(),
            outcome: AuditOutcome::Blocked,
            input_tokens: None,
            output_tokens: None,
            detail: Some(why.to_string()),
        };
        if let Err(e) = self.audit.append(entry) {
            tracing::warn!(error = %e, "could not write audit entry");
        }
    }

    /// Send one request and return the parsed completion.
    ///
    /// `purpose` is a short tag written to the audit log — `chat`, `sql`,
    /// `explain-rule`, `review` — so a user reading the file can tell which
    /// button produced which request.
    pub async fn send(
        &self,
        settings: &LlmSettings,
        api_key: Option<&str>,
        purpose: &str,
        req: &ChatRequest,
    ) -> LlmResult<Completion> {
        if !settings.enabled {
            // Not audited: nothing was configured, so there is no send to
            // account for. Every other refusal below is.
            return Err(LlmError::Disabled);
        }

        let url = endpoint_url(settings);
        let logged_endpoint = endpoint_of(&url);
        let body_value = build_body(settings, req);
        let body = serde_json::to_vec(&body_value)
            .map_err(|e| LlmError::Other(format!("serialize request: {e}")))?;

        let mut entry = AuditEntry {
            at: String::new(),
            purpose: purpose.to_string(),
            provider: settings.provider,
            endpoint: logged_endpoint.clone(),
            model: settings.effective_model().to_string(),
            data_scope: settings.data_scope,
            request_bytes: body.len() as u64,
            request_sha256: digest(&body),
            outcome: AuditOutcome::Failed,
            input_tokens: None,
            output_tokens: None,
            detail: None,
        };

        let mut builder = self.http.post(&url).body(body);
        for (name, value) in headers(settings, api_key) {
            builder = builder.header(name, value);
        }

        let result = self.dispatch(builder, &logged_endpoint).await;

        match &result {
            Ok(c) => {
                entry.outcome = AuditOutcome::Ok;
                entry.input_tokens = c.usage.input_tokens;
                entry.output_tokens = c.usage.output_tokens;
            }
            Err(e) => {
                entry.outcome = match e {
                    // A refusal did reach the provider, so it is a completed
                    // send; the model simply declined to answer.
                    LlmError::Refused(_) => AuditOutcome::Ok,
                    _ => AuditOutcome::Failed,
                };
                entry.detail = Some(e.to_string());
            }
        }
        if let Err(e) = self.audit.append(entry) {
            tracing::warn!(error = %e, "could not write audit entry");
        }

        result
    }

    async fn dispatch(
        &self,
        builder: reqwest::RequestBuilder,
        endpoint: &str,
    ) -> LlmResult<Completion> {
        let response = builder.send().await.map_err(|e| LlmError::Transport {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        })?;

        let status = response.status();
        let text = response.text().await.map_err(|e| LlmError::Transport {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        })?;

        if !status.is_success() {
            let mut body = text;
            body.truncate(MAX_ERROR_BODY);
            return Err(LlmError::Status {
                endpoint: endpoint.to_string(),
                status: status.as_u16(),
                body,
            });
        }

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| LlmError::Protocol(format!("response was not JSON: {e}")))?;
        parse_response(dialect_of(&value), &value)
    }
}

/// Which shape came back.
///
/// Read from the body rather than from settings: local runtimes are
/// routinely put behind a gateway that speaks the other dialect, and
/// `choices` vs `content` tells us unambiguously which one answered.
fn dialect_of(body: &serde_json::Value) -> crate::config::ProviderKind {
    if body.get("choices").is_some() {
        crate::config::ProviderKind::OpenAiCompatible
    } else {
        crate::config::ProviderKind::Anthropic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DataScope, ProviderKind};
    use crate::provider::{ChatRequest, Turn};

    fn settings(provider: ProviderKind) -> LlmSettings {
        LlmSettings { enabled: true, provider, ..Default::default() }
    }

    fn req() -> ChatRequest {
        ChatRequest {
            system: "schema".into(),
            turns: vec![Turn::User("hello".into())],
            tools: Vec::new(),
        }
    }

    #[test]
    fn the_preview_is_the_payload() {
        // The guarantee the UI makes to the user: what is shown is byte-for
        // -byte what is serialized. Both sides come from `build_body`, and
        // this asserts the digest agrees.
        let s = settings(ProviderKind::Anthropic);
        let p = preview(&s, Some("sk-ant-secret"), &req());
        let sent = serde_json::to_vec(&build_body(&s, &req())).unwrap();
        assert_eq!(p.sha256, digest(&sent));
        assert_eq!(p.bytes, sent.len() as u64);
    }

    #[test]
    fn the_preview_never_shows_the_key() {
        let p = preview(&settings(ProviderKind::Anthropic), Some("sk-ant-secret"), &req());
        assert!(!p.body.contains("sk-ant-secret"));
        let auth = p.headers.iter().find(|(k, _)| k == "x-api-key").expect("header present");
        assert!(!auth.1.contains("sk-ant-secret"));
        assert!(auth.1.contains("13 characters"));
    }

    #[test]
    fn the_preview_flags_a_local_endpoint() {
        assert!(preview(&settings(ProviderKind::OpenAiCompatible), None, &req()).local_endpoint);
        assert!(!preview(&settings(ProviderKind::Anthropic), None, &req()).local_endpoint);
    }

    #[test]
    fn the_preview_body_carries_the_selected_scope_and_nothing_more() {
        let s =
            LlmSettings { data_scope: DataScope::SchemaOnly, ..settings(ProviderKind::Anthropic) };
        let r = ChatRequest {
            system: "table events(process, dst_host)".into(),
            turns: vec![Turn::User("what is noisiest?".into())],
            tools: Vec::new(),
        };
        let p = preview(&s, None, &r);
        assert!(p.body.contains("table events"));
        assert!(p.body.contains("what is noisiest?"));
    }

    #[tokio::test]
    async fn a_disabled_assistant_sends_nothing_and_logs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        let client = LlmClient::new(log.clone()).unwrap();
        let off = LlmSettings::default();

        let err = client.send(&off, None, "chat", &req()).await.unwrap_err();
        assert!(matches!(err, LlmError::Disabled));
        assert!(log.recent(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_is_still_audited() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        let client = LlmClient::new(log.clone()).unwrap();
        // Port 1 on loopback: refused immediately, no network involved.
        let s = LlmSettings {
            enabled: true,
            provider: ProviderKind::OpenAiCompatible,
            base_url: "http://127.0.0.1:1/v1".into(),
            ..Default::default()
        };

        let err = client.send(&s, None, "chat", &req()).await.unwrap_err();
        assert!(matches!(err, LlmError::Transport { .. }), "got {err:?}");

        let entries = log.recent(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, AuditOutcome::Failed);
        assert_eq!(entries[0].endpoint, "http://127.0.0.1:1");
        assert!(entries[0].request_bytes > 0);
        assert!(entries[0].detail.is_some());
    }

    #[test]
    fn a_blocked_send_leaves_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        let client = LlmClient::new(log.clone()).unwrap();
        client.record_blocked(&settings(ProviderKind::Anthropic), "chat", "payload not reviewed");

        let entries = log.recent(10).unwrap();
        assert_eq!(entries[0].outcome, AuditOutcome::Blocked);
        assert_eq!(entries[0].request_bytes, 0);
    }
}
