//! What the user has chosen: which endpoint to talk to, and how much of
//! their traffic history is allowed to leave the machine.
//!
//! Everything here is off by default. A fresh install makes no LLM request
//! of any kind, and the only way to change that is the switch in Settings.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Wire dialect. Not a vendor list — `OpenAiCompatible` is spoken by Ollama,
/// llama.cpp, LM Studio, vLLM, OpenRouter and OpenAI itself, so one arm
/// covers the entire local-first path as well as the hosted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum ProviderKind {
    Anthropic,
    OpenAiCompatible,
}

impl ProviderKind {
    /// Where the model runs when the user has not overridden `base_url`.
    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com",
            // Ollama's default listener. Chosen as the default so the first
            // thing this feature offers is the option where no data leaves
            // the machine at all.
            Self::OpenAiCompatible => "http://localhost:11434/v1",
        }
    }

    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-opus-5",
            Self::OpenAiCompatible => "llama3.1",
        }
    }

    /// Credential-store account name. Keyed per dialect so switching between
    /// a local endpoint and a hosted one cannot silently reuse a key.
    pub fn credential_account(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAiCompatible => "openai-compatible",
        }
    }
}

/// How much of the user's traffic history a request is allowed to carry.
///
/// This is the whole privacy story in one enum, and it is a *setting*
/// rather than a constant because only the user knows whether the endpoint
/// they configured is their own laptop or someone else's datacentre.
///
/// The ordering is meaningful: each level is a superset of the one above.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS,
)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum DataScope {
    /// Table and column names, plus the question. No values.
    ///
    /// The assistant answers by writing SQL that ppxray executes locally
    /// against the sandboxed DuckDB file; rows never reach the model unless
    /// a higher level allows it. This is enough for most questions because
    /// the interesting work — the aggregation — happens here.
    #[default]
    SchemaOnly,
    /// Counts and shapes: top processes, top destinations, beacon cadence,
    /// rare hosts. Hostnames are reduced to their registrable domain and
    /// process paths to a bare filename before they are serialized.
    Aggregates,
    /// Event rows as they are, within whatever filter the user had applied.
    /// Nothing is masked. Deliberately the last option in the list.
    Raw,
}

impl DataScope {
    pub fn allows_values(self) -> bool {
        self >= Self::Aggregates
    }

    pub fn allows_raw_rows(self) -> bool {
        self == Self::Raw
    }
}

/// Persisted LLM configuration. Lives inside the app's `settings.json`; the
/// API key deliberately does **not** — see [`crate::credentials`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct LlmSettings {
    /// Master switch. False on a fresh install, and while it is false no
    /// code path in this crate opens a socket.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_provider")]
    pub provider: ProviderKind,
    /// Empty means "use [`ProviderKind::default_base_url`]".
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub data_scope: DataScope,
    /// Cap on rows handed back to the model from a locally-executed query.
    #[serde(default = "default_row_limit")]
    pub max_result_rows: u32,
    /// Whether the user has seen the payload preview at least once. The
    /// first send is gated on it; afterwards the preview stays available
    /// but stops interrupting.
    #[serde(default)]
    pub reviewed_payload: bool,
}

fn default_provider() -> ProviderKind {
    ProviderKind::Anthropic
}

fn default_row_limit() -> u32 {
    200
}

impl Default for LlmSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_provider(),
            base_url: String::new(),
            model: String::new(),
            data_scope: DataScope::default(),
            max_result_rows: default_row_limit(),
            reviewed_payload: false,
        }
    }
}

impl LlmSettings {
    pub fn effective_base_url(&self) -> &str {
        if self.base_url.trim().is_empty() {
            self.provider.default_base_url()
        } else {
            self.base_url.trim().trim_end_matches('/')
        }
    }

    pub fn effective_model(&self) -> &str {
        if self.model.trim().is_empty() { self.provider.default_model() } else { self.model.trim() }
    }

    /// True when the configured endpoint is on this machine — the case the
    /// UI highlights, because there "sending data to an LLM" involves no
    /// network egress at all.
    pub fn is_local_endpoint(&self) -> bool {
        let url = self.effective_base_url();
        let authority = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
        let host = authority.split(['/', ':']).next().unwrap_or("");
        matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0" | "") || host.ends_with(".local")
    }
}

/// Models that accept `thinking: {"type": "adaptive"}`.
///
/// Sending it to anything else is a 400, and omitting it on a model that
/// supports it wastes the capability, so the decision has to be made from
/// the model id. A prefix list works because Anthropic ids are stable
/// strings with no date suffix.
pub fn supports_adaptive_thinking(model: &str) -> bool {
    const ADAPTIVE: &[&str] = &[
        "claude-opus-5",
        "claude-opus-4-8",
        "claude-opus-4-7",
        "claude-opus-4-6",
        "claude-sonnet-5",
        "claude-sonnet-4-6",
        "claude-fable-5",
        "claude-mythos-5",
    ];
    ADAPTIVE.iter().any(|m| model.starts_with(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_settings_are_inert() {
        let s = LlmSettings::default();
        assert!(!s.enabled);
        assert_eq!(s.data_scope, DataScope::SchemaOnly);
        assert!(!s.reviewed_payload);
    }

    #[test]
    fn scope_levels_nest() {
        assert!(!DataScope::SchemaOnly.allows_values());
        assert!(DataScope::Aggregates.allows_values());
        assert!(!DataScope::Aggregates.allows_raw_rows());
        assert!(DataScope::Raw.allows_values());
        assert!(DataScope::Raw.allows_raw_rows());
    }

    #[test]
    fn blank_fields_fall_back_to_provider_defaults() {
        let s = LlmSettings { provider: ProviderKind::Anthropic, ..Default::default() };
        assert_eq!(s.effective_base_url(), "https://api.anthropic.com");
        assert_eq!(s.effective_model(), "claude-opus-5");
    }

    #[test]
    fn trailing_slash_does_not_produce_a_double_slash_path() {
        let s = LlmSettings {
            base_url: "http://localhost:11434/v1/".into(),
            provider: ProviderKind::OpenAiCompatible,
            ..Default::default()
        };
        assert_eq!(s.effective_base_url(), "http://localhost:11434/v1");
    }

    #[test]
    fn localhost_endpoints_are_recognised() {
        let local = LlmSettings { provider: ProviderKind::OpenAiCompatible, ..Default::default() };
        assert!(local.is_local_endpoint());

        let hosted = LlmSettings { provider: ProviderKind::Anthropic, ..Default::default() };
        assert!(!hosted.is_local_endpoint());

        // A hostname that merely *starts* with the word must not pass, or
        // the UI would claim "stays on your machine" about someone's server.
        let lookalike = LlmSettings {
            base_url: "https://localhost.evil.example/v1".into(),
            provider: ProviderKind::OpenAiCompatible,
            ..Default::default()
        };
        assert!(!lookalike.is_local_endpoint());
    }

    #[test]
    fn thinking_support_tracks_the_model_family() {
        assert!(supports_adaptive_thinking("claude-opus-5"));
        assert!(supports_adaptive_thinking("claude-sonnet-5"));
        // Haiku 4.5 still takes budget_tokens; adaptive would be a 400.
        assert!(!supports_adaptive_thinking("claude-haiku-4-5"));
        assert!(!supports_adaptive_thinking("llama3.1"));
    }
}
