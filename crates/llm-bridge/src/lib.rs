//! Optional LLM assistance for ppxray.
//!
//! A Proxifier log is a timestamped list of every host the machine contacted
//! and which program did it, so adding a model to a tool that promises local-
//! only analysis is a decision about that promise. The design keeps it:
//!
//! * Off unless asked — [`config::LlmSettings::enabled`] is false on a fresh
//!   install and nothing here opens a socket while it is.
//! * The user picks the boundary — [`config::DataScope`] defaults to its
//!   tightest level, where the model writes SQL, ppxray runs it locally, and
//!   the rows are never sent.
//! * Local endpoints are first-class; the OpenAI-compatible provider defaults
//!   to Ollama on `localhost`.
//! * [`client::preview`] returns the exact body [`client::LlmClient::send`]
//!   serializes — same function, so it cannot drift.
//! * [`audit`] records every request, including refused ones.
//!
//! Letting a model write SQL is acceptable because
//! `log_ingest::store::harden` already sandboxes the connection for shared
//! rule packs, [`sql_guard`] rejects anything but a single read-only query,
//! and the caller wraps what survives in `SELECT * FROM ( … ) LIMIT n`.
pub mod audit;
pub mod client;
pub mod config;
pub mod error;
pub mod prompt;
pub mod provider;
pub mod redact;
pub mod sql_guard;
pub mod table;

pub use audit::{AuditEntry, AuditLog, AuditOutcome};
pub use client::{LlmClient, PayloadPreview, preview};
pub use config::{DataScope, LlmSettings, ProviderKind};
pub use error::{LlmError, LlmResult};
pub use provider::{ChatRequest, Completion, ToolCall, ToolSpec, Turn, Usage};
pub use sql_guard::SqlRejection;
pub use table::QueryTable;
