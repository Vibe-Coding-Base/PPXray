//! Shared runtime state held behind Tauri's `Manager`. Kept minimal for now —
//! future modules (log DB connection pool, detection engine handles, ingest
//! job registry) will live here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use llm_bridge::{LlmClient, provider::Turn};
use log_ingest::LogStore;

#[derive(Default)]
pub struct AppState {
    /// Absolute path of the most recently opened profile, if any. Used to
    /// support "Save" (versus "Save As…") from the renderer.
    pub current_profile_path: Mutex<Option<String>>,
    /// Active log analysis DB, if any. Populated by `log_ingest` /
    /// `log_open_existing`, cleared by `log_close`.
    pub log_store: Mutex<Option<LogStore>>,

    /// HTTP client for the assistant, built on first use.
    ///
    /// Lazy because constructing it needs the app-data path for the egress
    /// audit log, which is not resolvable until Tauri has set up. `OnceLock`
    /// rather than a `Mutex<Option<_>>` because it is written once and read
    /// on every request.
    pub llm: OnceLock<Arc<LlmClient>>,

    /// Assistant transcripts, keyed by conversation id.
    ///
    /// Held here rather than in the renderer: tool calls and their results are
    /// part of the transcript, and round-tripping them through the UI would
    /// let it rewrite what the model is told it already saw.
    ///
    /// In memory only. Above the default privacy level a transcript holds log
    /// content the user chose to share once, and persisting it would leave a
    /// second copy outliving the session. Cleared when the provider or the
    /// privacy level changes.
    pub llm_chats: Mutex<HashMap<String, Vec<Turn>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }
}
