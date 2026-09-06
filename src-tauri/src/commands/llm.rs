//! Assistant commands: configuration, the payload preview, and the loop that
//! lets the model ask questions of the log without being handed the log.
//!
//! # The loop
//!
//! The model gets exactly one tool, `run_sql`. Each turn:
//!
//! 1. it proposes a statement;
//! 2. `llm_bridge::sql_guard` rejects anything that is not a single
//!    read-only query, and the survivor is wrapped in `SELECT * FROM ( … )
//!    LIMIT n`;
//! 3. `log_ingest::adhoc::run` executes it against the sandboxed DuckDB file;
//! 4. `llm_bridge::table::tool_result` decides what the model is told — at
//!    the default privacy level, the shape of the result and nothing else.
//!
//! The rows always reach the *user*, on every level. The privacy setting
//! governs what reaches the model, which is a different question and the
//! only one that involves a network.

use std::sync::Arc;

use llm_bridge::config::{DataScope, LlmSettings, ProviderKind};
use llm_bridge::provider::{ChatRequest, ToolCall, Turn};
use llm_bridge::{AuditEntry, AuditLog, LlmClient, LlmError, PayloadPreview, QueryTable, prompt};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tracing::instrument;

use crate::commands::logs::{blocking, optional_store};
use crate::{credentials, error::AppError, settings, state::AppState};

/// How many tool round-trips one question may take before we stop.
///
/// Each is a paid request. Six is enough for "ask, look, refine, look,
/// confirm, answer" and short enough that a model stuck in a loop costs
/// cents rather than dollars.
const MAX_TOOL_STEPS: usize = 6;

/// Audit-log file name, under app-data next to `settings.json`.
const AUDIT_FILE: &str = "llm-audit.jsonl";

// ---------------------------------------------------------------------------
// Renderer-facing shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct LlmStatus {
    pub settings: LlmSettings,
    /// Whether a key is in the credential store. The key itself never
    /// crosses this boundary.
    pub has_key: bool,
    /// Resolved defaults, so the UI can show them as placeholders rather
    /// than duplicating the table in TypeScript.
    pub effective_base_url: String,
    pub effective_model: String,
    pub local_endpoint: bool,
    /// Where the egress log is, so the user can open it themselves.
    pub audit_path: String,
}

/// One query the assistant ran, as the user sees it.
#[derive(Debug, Serialize)]
pub struct AgentStep {
    /// The model's own one-line statement of what it was establishing.
    pub purpose: String,
    pub sql: String,
    /// Present when the query ran. Always the full, unmasked result — this
    /// is the user's own data on the user's own screen.
    pub table: Option<QueryTable>,
    /// Present when the query was refused or failed.
    pub error: Option<String>,
    /// Whether the result was also shared with the model. False at the
    /// default privacy level, and shown in the UI so the reader knows what
    /// the answer above it was based on.
    pub shared_with_model: bool,
}

#[derive(Debug, Serialize)]
pub struct AssistantReply {
    pub text: String,
    /// Summarized reasoning, when the provider returns any.
    pub thinking: String,
    pub steps: Vec<AgentStep>,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// Always true. Present as a field rather than a UI constant so it
    /// cannot be forgotten in one of the places a reply is rendered.
    pub unverified: bool,
}

/// Which prompt a request uses. Also the `purpose` tag in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Task {
    Chat,
    Review,
    ExplainRule,
}

impl Task {
    fn tag(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Review => "review",
            Self::ExplainRule => "explain-rule",
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn llm_status(app: tauri::AppHandle) -> Result<LlmStatus, AppError> {
    let s = settings::load(&app)?.llm;
    let has_key = has_key(s.provider).await?;
    Ok(status_of(&app, s, has_key))
}

/// Ask the credential store whether a key exists, off the async runtime.
///
/// On Linux the Secret Service can put up an unlock prompt, and on any
/// platform the call crosses an IPC boundary. Neither belongs on a Tokio
/// worker: a user staring at a keyring dialog would otherwise be holding a
/// thread the rest of the UI needs.
async fn has_key(provider: ProviderKind) -> Result<bool, AppError> {
    blocking(move || Ok(credentials::has(provider))).await
}

/// The stored key, off the async runtime for the same reason.
async fn read_key(provider: ProviderKind) -> Result<Option<String>, AppError> {
    blocking(move || credentials::get(provider)).await
}

#[tauri::command]
#[instrument(skip(app, state))]
pub async fn llm_set_settings(
    settings: LlmSettings,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<LlmStatus, AppError> {
    let mut all = settings::load(&app)?;
    let previous = all.llm.clone();

    let mut next = settings;
    if revokes_approval(&previous, &next) {
        next.reviewed_payload = false;
    }

    all.llm = next.clone();
    settings::save(&app, &all)?;

    // A conversation carries turns produced under the old settings, and its
    // tool results were filtered by the old scope. Continuing it after a
    // change would send data the new level does not permit.
    reset_conversations(&state, None)?;

    let has_key = has_key(next.provider).await?;
    Ok(status_of(&app, next, has_key))
}

#[tauri::command]
pub async fn llm_set_api_key(key: String, app: tauri::AppHandle) -> Result<bool, AppError> {
    let provider = settings::load(&app)?.llm.provider;
    blocking(move || credentials::set(provider, &key)).await?;
    has_key(provider).await
}

#[tauri::command]
pub async fn llm_clear_api_key(app: tauri::AppHandle) -> Result<bool, AppError> {
    let provider = settings::load(&app)?.llm.provider;
    blocking(move || credentials::delete(provider)).await?;
    has_key(provider).await
}

/// Record that the user has read the payload preview.
///
/// Set from the preview dialog rather than from `llm_set_settings`, so it
/// can only become true after the preview has actually been rendered.
#[tauri::command]
pub async fn llm_mark_reviewed(app: tauri::AppHandle) -> Result<LlmStatus, AppError> {
    let mut all = settings::load(&app)?;
    all.llm.reviewed_payload = true;
    settings::save(&app, &all)?;
    let has_key = has_key(all.llm.provider).await?;
    Ok(status_of(&app, all.llm, has_key))
}

#[tauri::command]
pub async fn llm_audit_entries(
    limit: Option<u32>,
    app: tauri::AppHandle,
) -> Result<Vec<AuditEntry>, AppError> {
    let limit = limit.unwrap_or(200).min(2_000) as usize;
    audit_log(&app)?.recent(limit).map_err(|e| AppError::Other(e.to_string()))
}

#[tauri::command]
pub async fn llm_clear_audit(app: tauri::AppHandle) -> Result<(), AppError> {
    audit_log(&app)?.clear().map_err(|e| AppError::Other(e.to_string()))
}

/// What a connection test found out.
#[derive(Debug, Serialize)]
pub struct ConnectionCheck {
    pub ok: bool,
    /// One line, written for the person reading it rather than for a log.
    pub summary: String,
    /// What to do about it, when there is something to do.
    pub hint: Option<String>,
    /// Round trip in milliseconds, on success.
    pub latency_ms: Option<u64>,
    /// The model that actually answered, when the provider reports one - a
    /// silent substitution is worth seeing before it shows up in a bill.
    pub model: Option<String>,
}

/// Send the smallest possible real request and report what came back.
///
/// A settings page that only stores an endpoint and a key tells you nothing
/// about whether either works; the first sign of a typo would otherwise be a
/// failed analysis. This is a genuine round trip - one token of output - so
/// it exercises the same client, headers and parser as the real thing, and
/// it is written to the egress log like any other request.
#[tauri::command]
#[instrument(skip(app, state))]
pub async fn llm_test_connection(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<ConnectionCheck, AppError> {
    let cfg = settings::load(&app)?.llm;
    if !cfg.enabled {
        return Ok(ConnectionCheck {
            ok: false,
            summary: "The assistant is switched off.".into(),
            hint: Some("Turn it on with the switch above before testing.".into()),
            latency_ms: None,
            model: None,
        });
    }

    let client = client(&app, &state)?;
    let key = read_key(cfg.provider).await?;

    if key.is_none() && !cfg.is_local_endpoint() {
        return Ok(ConnectionCheck {
            ok: false,
            summary: format!("No API key stored for {}.", cfg.effective_base_url()),
            hint: Some("Paste a key above and press Store, then test again.".into()),
            latency_ms: None,
            model: None,
        });
    }

    // No tools and no schema: this is about reachability and credentials, so
    // it must not carry any of the user's data.
    let probe = ChatRequest {
        system: "Reply with the single word: ok".into(),
        turns: vec![Turn::User("ok".into())],
        tools: Vec::new(),
    };

    let started = std::time::Instant::now();
    let outcome = client.send(&cfg, key.as_deref(), "test", &probe).await;
    let latency_ms = started.elapsed().as_millis() as u64;

    Ok(match outcome {
        Ok(completion) => ConnectionCheck {
            ok: true,
            summary: format!("{} answered in {} ms.", cfg.effective_model(), latency_ms),
            hint: completion
                .usage
                .input_tokens
                .map(|n| format!("Billed {n} input tokens for this check.")),
            latency_ms: Some(latency_ms),
            model: Some(cfg.effective_model().to_string()),
        },
        // A refusal is a strange answer to "say ok", but it proves the
        // endpoint, the key and the model are all real.
        Err(LlmError::Refused(_)) => ConnectionCheck {
            ok: true,
            summary: format!("Reached {}, which declined the probe.", cfg.effective_base_url()),
            hint: Some("The connection works; the model simply refused this prompt.".into()),
            latency_ms: Some(latency_ms),
            model: Some(cfg.effective_model().to_string()),
        },
        Err(e) => {
            let (summary, hint) = explain_failure(&cfg, &e);
            ConnectionCheck { ok: false, summary, hint, latency_ms: None, model: None }
        }
    })
}

/// Turn a transport or HTTP failure into something a person can act on.
fn explain_failure(cfg: &LlmSettings, e: &LlmError) -> (String, Option<String>) {
    match e {
        LlmError::Status { status: 401, .. } | LlmError::Status { status: 403, .. } => (
            "The provider rejected the API key.".into(),
            Some("Check the key belongs to this provider and has not been revoked.".into()),
        ),
        LlmError::Status { status: 404, .. } => (
            format!("`{}` was not found at this endpoint.", cfg.effective_model()),
            Some("Check the model name - a typo here looks exactly like this.".into()),
        ),
        LlmError::Status { status: 429, .. } => (
            "Rate limited before the check could complete.".into(),
            Some("The endpoint and key look right. Try again shortly.".into()),
        ),
        LlmError::Status { status, body, .. } => (
            format!("The provider returned HTTP {status}."),
            Some(body.chars().take(300).collect()),
        ),
        LlmError::Transport { endpoint, .. } => (
            format!("Could not reach {endpoint}."),
            Some(if cfg.is_local_endpoint() {
                "Nothing is listening there. Start the local model server first.".into()
            } else {
                "Check the URL, your connection, and whether a proxy rule is                  blocking ppxray itself."
                    .to_string()
            }),
        ),
        LlmError::Protocol(detail) => (
            "Reached the endpoint, but the reply was not a model response.".into(),
            Some(format!("{detail} - a captive portal or proxy error page looks like this.")),
        ),
        other => (other.to_string(), None),
    }
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

/// Exactly what would be sent for `task`, without sending it.
#[tauri::command]
#[instrument(skip(app, state))]
pub async fn llm_preview(
    task: Task,
    input: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<PayloadPreview, AppError> {
    let cfg = settings::load(&app)?.llm;
    let key = read_key(cfg.provider).await?;
    let store = optional_store(&state)?;

    // Reading the schema touches DuckDB, so it belongs on the blocking pool
    // like every other query in this app.
    let for_build = cfg.clone();
    let request = blocking(move || build_request(&for_build, task, &input, &store)).await?;

    Ok(llm_bridge::preview(&cfg, key.as_deref(), &request))
}

// ---------------------------------------------------------------------------
// Conversation
// ---------------------------------------------------------------------------

/// Forget a conversation's transcript. `None` forgets every one of them.
#[tauri::command]
pub async fn llm_reset_chat(
    conversation_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    reset_conversations(&state, conversation_id.as_deref())
}

#[tauri::command]
#[instrument(skip(app, state))]
/// `conversation_id` selects the transcript to continue. Only `Task::Chat`
/// threads; the other tasks are one-shot and ignore it.
pub async fn llm_ask(
    task: Task,
    input: String,
    conversation_id: Option<String>,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<AssistantReply, AppError> {
    let cfg = settings::load(&app)?.llm;
    let client = client(&app, &state)?;

    if !cfg.enabled {
        return Err(AppError::Other(LlmError::Disabled.to_string()));
    }
    if !cfg.reviewed_payload {
        // Audited: "we did not send" is the most important thing this log
        // can record, and an absent line does not record it.
        client.record_blocked(&cfg, task.tag(), "payload not reviewed by the user");
        return Err(AppError::Other(LlmError::PayloadNotReviewed.to_string()));
    }
    if task == Task::Review && !cfg.data_scope.allows_values() {
        client.record_blocked(&cfg, task.tag(), "review needs at least the aggregates level");
        return Err(AppError::Other(
            "Reviewing a log means sending a summary of it. At the schema-only privacy \
             level nothing from the log is shared, so there is nothing to review. Raise \
             the level to Aggregates under Settings if you want this."
                .into(),
        ));
    }

    let key = read_key(cfg.provider).await?;
    let store = optional_store(&state)?;

    // Only the chat carries history. A rule explanation and a log review are
    // one-shot by design: each is a fresh question about a fresh subject,
    // and threading them would quietly re-send the previous subject.
    let thread = conversation_id.clone().unwrap_or_else(|| "default".to_string());
    let mut turns = if task == Task::Chat { conversation(&state, &thread)? } else { Vec::new() };

    let store_for_prompt = store.clone();
    let cfg_for_prompt = cfg.clone();
    let system = blocking(move || build_system(&cfg_for_prompt, task, &store_for_prompt)).await?;
    turns.push(Turn::User(opening_message(task, &input)));

    let tools = if task == Task::ExplainRule { Vec::new() } else { vec![prompt::sql_tool()] };

    let mut steps: Vec<AgentStep> = Vec::new();
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    let mut text = String::new();
    let mut thinking = String::new();

    for round in 0..=MAX_TOOL_STEPS {
        let request =
            ChatRequest { system: system.clone(), turns: turns.clone(), tools: tools.clone() };
        let completion = client
            .send(&cfg, key.as_deref(), task.tag(), &request)
            .await
            .map_err(|e| AppError::Other(e.to_string()))?;

        input_tokens = input_tokens.saturating_add(completion.usage.input_tokens.unwrap_or(0));
        output_tokens = output_tokens.saturating_add(completion.usage.output_tokens.unwrap_or(0));
        if !completion.thinking.is_empty() {
            thinking = completion.thinking.clone();
        }

        if !completion.wants_tools() {
            text = completion.text;
            turns.push(Turn::Assistant { text: text.clone(), calls: Vec::new() });
            break;
        }

        // The budget is spent. Tell the model so in-band rather than
        // truncating: it can still answer from what it already has.
        if round == MAX_TOOL_STEPS {
            text = if completion.text.is_empty() {
                format!(
                    "Stopped after {MAX_TOOL_STEPS} queries without reaching a conclusion. \
                     The queries and their results are below; ask a narrower question to \
                     continue."
                )
            } else {
                completion.text.clone()
            };
            turns.push(Turn::Assistant { text: text.clone(), calls: Vec::new() });
            break;
        }

        turns.push(Turn::Assistant {
            text: completion.text.clone(),
            calls: completion.calls.clone(),
        });
        if !completion.text.is_empty() {
            text = completion.text.clone();
        }

        for call in &completion.calls {
            let (step, result) = run_tool_call(call, store.as_ref(), &cfg).await?;
            steps.push(step);
            turns.push(result);
        }
    }

    if task == Task::Chat {
        set_conversation(&state, &thread, turns)?;
    }

    Ok(AssistantReply {
        text,
        thinking,
        steps,
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        unverified: true,
    })
}

/// Execute one `run_sql` call, producing both what the user sees and what
/// goes back to the model.
async fn run_tool_call(
    call: &ToolCall,
    store: Option<&log_ingest::LogStore>,
    cfg: &LlmSettings,
) -> Result<(AgentStep, Turn), AppError> {
    let purpose =
        call.input.get("purpose").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let raw_sql = call.input.get("sql").and_then(|v| v.as_str()).unwrap_or_default().to_string();

    let fail = |step_error: String, model_error: String| {
        (
            AgentStep {
                purpose: purpose.clone(),
                sql: raw_sql.clone(),
                table: None,
                error: Some(step_error),
                shared_with_model: false,
            },
            Turn::ToolResult {
                id: call.id.clone(),
                name: call.name.clone(),
                content: model_error,
                is_error: true,
            },
        )
    };

    if call.name != prompt::SQL_TOOL {
        let why = format!("`{}` is not a tool this application provides.", call.name);
        return Ok(fail(why.clone(), why));
    }

    let Some(store) = store else {
        let why = "No log is open. Ask the user to open one first.".to_string();
        return Ok(fail(why.clone(), why));
    };

    let statement = match llm_bridge::sql_guard::check(&raw_sql) {
        Ok(s) => s,
        Err(rejection) => {
            let why = rejection.to_string();
            return Ok(fail(
                why.clone(),
                format!("Refused: {why}. Rewrite it as a single read-only SELECT."),
            ));
        }
    };

    let limit = cfg.max_result_rows.max(1);
    let wrapped = llm_bridge::sql_guard::wrap(&statement, limit);
    let store = store.clone();
    // `limit + 1` so a result that exactly fills the limit can be told apart
    // from one the limit cut short.
    let executed = blocking(move || {
        log_ingest::adhoc::run(&store, &wrapped, limit as usize + 1)
            .map_err(|e| AppError::Other(e.to_string()))
    })
    .await;

    let result = match executed {
        Ok(r) => r,
        Err(e) => {
            let why = e.to_string();
            return Ok(fail(
                why.clone(),
                format!(
                    "The query failed: {why}

This is DuckDB. If the message names a                      different function or column, use that one and try again."
                ),
            ));
        }
    };

    let truncated = result.rows.len() > limit as usize;
    let mut rows = result.rows;
    rows.truncate(limit as usize);
    let table = QueryTable { columns: result.columns, rows, truncated };

    let content = llm_bridge::table::tool_result(&table, cfg.data_scope);
    Ok((
        AgentStep {
            purpose,
            sql: statement,
            table: Some(table),
            error: None,
            shared_with_model: cfg.data_scope.allows_values(),
        },
        Turn::ToolResult { id: call.id.clone(), name: call.name.clone(), content, is_error: false },
    ))
}

// ---------------------------------------------------------------------------
// Prompt assembly
// ---------------------------------------------------------------------------

fn opening_message(task: Task, input: &str) -> String {
    match task {
        Task::Chat => input.to_string(),
        Task::ExplainRule => format!("Explain this rule.\n\n{input}"),
        Task::Review => "Review this log for anything that does not belong. Start by \
             establishing the overall shape — how many processes, how much \
             traffic, over what period — then look for outliers."
            .to_string(),
    }
}

fn build_system(
    cfg: &LlmSettings,
    task: Task,
    store: &Option<log_ingest::LogStore>,
) -> Result<String, AppError> {
    Ok(match task {
        Task::ExplainRule => prompt::rule_explainer(),
        Task::Review => {
            let (schema, context) = log_context(store, cfg.data_scope)?;
            format!(
                "{}\n\nDATABASE SCHEMA\n{schema}\n\n{context}",
                prompt::anomaly_reviewer(cfg.data_scope)
            )
        }
        Task::Chat => {
            let (schema, context) = log_context(store, cfg.data_scope)?;
            prompt::log_assistant(cfg.data_scope, &schema, &context)
        }
    })
}

/// The schema, plus a few facts about the log that is open.
///
/// The facts are counts and a time span — no process names, no hostnames —
/// so they carry the same weight at every privacy level. The model needs
/// them to size its queries; without them it writes `LIMIT 10` against a
/// three-million-row table and draws conclusions from the first ten rows.
fn log_context(
    store: &Option<log_ingest::LogStore>,
    _scope: DataScope,
) -> Result<(String, String), AppError> {
    let Some(store) = store else {
        return Ok((
            "(no log is open — the tables listed above do not exist yet)".to_string(),
            String::new(),
        ));
    };
    let schema =
        log_ingest::schema_description(store).map_err(|e| AppError::Other(e.to_string()))?;
    let stats = log_ingest::query::stats(store).map_err(|e| AppError::Other(e.to_string()))?;
    let context = format!(
        "{} connection events and {} DNS events, from {} distinct processes, \
         spanning {} to {}.",
        stats.total_events,
        stats.total_dns,
        stats.distinct_processes,
        stats.span_start.as_deref().unwrap_or("(unknown)"),
        stats.span_end.as_deref().unwrap_or("(unknown)"),
    );
    Ok((schema, context))
}

/// Build the request a given task would send, for the preview.
fn build_request(
    cfg: &LlmSettings,
    task: Task,
    input: &str,
    store: &Option<log_ingest::LogStore>,
) -> Result<ChatRequest, AppError> {
    Ok(ChatRequest {
        system: build_system(cfg, task, store)?,
        turns: vec![Turn::User(opening_message(task, input))],
        tools: if task == Task::ExplainRule { Vec::new() } else { vec![prompt::sql_tool()] },
    })
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn status_of(app: &tauri::AppHandle, s: LlmSettings, has_key: bool) -> LlmStatus {
    LlmStatus {
        effective_base_url: s.effective_base_url().to_string(),
        effective_model: s.effective_model().to_string(),
        local_endpoint: s.is_local_endpoint(),
        audit_path: audit_path(app).to_string_lossy().into_owned(),
        has_key,
        settings: s,
    }
}

fn audit_path(app: &tauri::AppHandle) -> std::path::PathBuf {
    app.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")).join(AUDIT_FILE)
}

fn audit_log(app: &tauri::AppHandle) -> Result<AuditLog, AppError> {
    Ok(AuditLog::new(audit_path(app)))
}

/// The process-wide client, built once so connections are pooled.
fn client(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<Arc<LlmClient>, AppError> {
    if let Some(existing) = state.llm.get() {
        return Ok(existing.clone());
    }
    let built =
        Arc::new(LlmClient::new(audit_log(app)?).map_err(|e| AppError::Other(e.to_string()))?);
    // A concurrent initialiser wins the race; either instance is equivalent.
    let _ = state.llm.set(built);
    state.llm.get().cloned().ok_or_else(|| AppError::Other("assistant client unavailable".into()))
}

/// Whether a settings change invalidates the user's approval of the payload.
///
/// The approval was for a specific request to a specific place: this body,
/// at this privacy level, to this endpoint. Move any of those three and the
/// thing they approved no longer exists, so the preview has to be shown
/// again before anything else is sent.
///
/// Deliberately *not* triggered by the model name or the row limit. Those
/// change what the request costs and how much comes back, not who receives
/// the data or how much of it they see, and re-prompting on every harmless
/// tweak is how a consent gate turns into a thing people click through.
fn revokes_approval(previous: &LlmSettings, next: &LlmSettings) -> bool {
    previous.provider != next.provider
        || previous.effective_base_url() != next.effective_base_url()
        || previous.data_scope != next.data_scope
}

fn conversation(state: &State<'_, AppState>, id: &str) -> Result<Vec<Turn>, AppError> {
    Ok(state
        .llm_chats
        .lock()
        .map_err(|e| AppError::Other(format!("chat lock poisoned: {e}")))?
        .get(id)
        .cloned()
        .unwrap_or_default())
}

fn set_conversation(
    state: &State<'_, AppState>,
    id: &str,
    turns: Vec<Turn>,
) -> Result<(), AppError> {
    state
        .llm_chats
        .lock()
        .map_err(|e| AppError::Other(format!("chat lock poisoned: {e}")))?
        .insert(id.to_string(), turns);
    Ok(())
}

/// Forget one conversation, or all of them when `id` is `None`.
///
/// Everything goes when the provider or the privacy level changes: those
/// transcripts were produced under a boundary that no longer applies, and
/// continuing one would resend content the new level does not permit.
fn reset_conversations(state: &State<'_, AppState>, id: Option<&str>) -> Result<(), AppError> {
    let mut guard =
        state.llm_chats.lock().map_err(|e| AppError::Other(format!("chat lock poisoned: {e}")))?;
    match id {
        Some(id) => {
            guard.remove(id);
        }
        None => guard.clear(),
    }
    Ok(())
}

/// A provider the UI can offer, with its defaults.
#[derive(Debug, Serialize)]
pub struct ProviderDefaults {
    pub provider: ProviderKind,
    pub base_url: String,
    pub model: String,
    /// Known endpoints that speak this dialect, so the user picks a name
    /// instead of looking up a URL.
    pub presets: Vec<EndpointPreset>,
}

/// One named endpoint. Selecting it fills in the URL and a starting model.
#[derive(Debug, Serialize)]
pub struct EndpointPreset {
    pub label: String,
    pub base_url: String,
    pub model: String,
    /// True when this runs on the user's own machine, which the UI calls out
    /// because at those endpoints the privacy level stops mattering.
    pub local: bool,
    /// One line on what picking this means.
    pub note: String,
}

fn preset(label: &str, base_url: &str, model: &str, local: bool, note: &str) -> EndpointPreset {
    EndpointPreset {
        label: label.into(),
        base_url: base_url.into(),
        model: model.into(),
        local,
        note: note.into(),
    }
}

/// The provider list, sent to the renderer rather than duplicated there, so
/// the defaults shown as placeholders are the ones actually used.
///
/// The local-first option is first in the list because it is the one where
/// this feature costs the user no privacy at all.
#[tauri::command]
pub async fn llm_provider_defaults() -> Result<Vec<ProviderDefaults>, AppError> {
    Ok(vec![
        ProviderDefaults {
            provider: ProviderKind::OpenAiCompatible,
            base_url: ProviderKind::OpenAiCompatible.default_base_url().to_string(),
            model: ProviderKind::OpenAiCompatible.default_model().to_string(),
            // Local endpoints first: at those, none of this leaves the machine
            // whatever the privacy level says.
            presets: vec![
                preset(
                    "Ollama (this machine)",
                    "http://localhost:11434/v1",
                    "llama3.1",
                    true,
                    "Nothing leaves your machine. Needs `ollama serve` running.",
                ),
                preset(
                    "LM Studio (this machine)",
                    "http://localhost:1234/v1",
                    "local-model",
                    true,
                    "Nothing leaves your machine. Start the LM Studio server first.",
                ),
                preset(
                    "llama.cpp (this machine)",
                    "http://localhost:8080/v1",
                    "local-model",
                    true,
                    "Nothing leaves your machine. Start `llama-server` first.",
                ),
                preset(
                    "DeepSeek",
                    "https://api.deepseek.com/v1",
                    "deepseek-chat",
                    false,
                    "Hosted in China; check that against your own policy before                      raising the privacy level.",
                ),
                preset(
                    "OpenAI",
                    "https://api.openai.com/v1",
                    "gpt-4o",
                    false,
                    "Hosted. Requires an API key.",
                ),
                preset(
                    "OpenRouter",
                    "https://openrouter.ai/api/v1",
                    "anthropic/claude-sonnet-4.5",
                    false,
                    "Hosted broker — your request is relayed to whichever model you name.",
                ),
            ],
        },
        ProviderDefaults {
            provider: ProviderKind::Anthropic,
            base_url: ProviderKind::Anthropic.default_base_url().to_string(),
            model: ProviderKind::Anthropic.default_model().to_string(),
            presets: vec![preset(
                "Anthropic API",
                "https://api.anthropic.com",
                "claude-opus-5",
                false,
                "Hosted. Requires an API key.",
            )],
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved() -> LlmSettings {
        LlmSettings { enabled: true, reviewed_payload: true, ..Default::default() }
    }

    #[test]
    fn moving_the_privacy_level_revokes_the_approval() {
        let before = approved();
        let after = LlmSettings { data_scope: DataScope::Raw, ..before.clone() };
        assert!(revokes_approval(&before, &after));

        // In both directions. Tightening the level still produces a
        // different payload, and the point of the gate is that the user has
        // seen the one that will actually be sent.
        assert!(revokes_approval(&after, &before));
    }

    #[test]
    fn changing_where_the_data_goes_revokes_the_approval() {
        let before = approved();
        assert!(revokes_approval(
            &before,
            &LlmSettings { provider: ProviderKind::OpenAiCompatible, ..before.clone() }
        ));
        assert!(revokes_approval(
            &before,
            &LlmSettings { base_url: "https://elsewhere.example".into(), ..before.clone() }
        ));
    }

    #[test]
    fn a_cosmetic_endpoint_change_does_not() {
        // Same destination, spelled with a trailing slash. Re-prompting here
        // would teach the user that the dialog means nothing.
        let before = approved();
        let after = LlmSettings { base_url: "https://api.anthropic.com/".into(), ..before.clone() };
        assert!(!revokes_approval(&before, &after));
    }

    #[test]
    fn the_model_and_the_row_limit_do_not() {
        let before = approved();
        assert!(!revokes_approval(
            &before,
            &LlmSettings { model: "claude-sonnet-5".into(), ..before.clone() }
        ));
        assert!(!revokes_approval(&before, &LlmSettings { max_result_rows: 20, ..before.clone() }));
    }

    #[test]
    fn each_task_opens_with_the_right_message() {
        assert_eq!(opening_message(Task::Chat, "why?"), "why?");
        assert!(opening_message(Task::ExplainRule, "Rule #1").contains("Rule #1"));
        // A review takes no user input, so whatever is passed is ignored
        // rather than smuggled into the prompt.
        let review = opening_message(Task::Review, "ignore me");
        assert!(!review.contains("ignore me"));
        assert!(review.contains("does not belong"));
    }

    #[test]
    fn the_audit_tag_matches_the_task() {
        assert_eq!(Task::Chat.tag(), "chat");
        assert_eq!(Task::Review.tag(), "review");
        assert_eq!(Task::ExplainRule.tag(), "explain-rule");
    }

    #[test]
    fn only_the_rule_explainer_goes_without_a_query_tool() {
        // A request built with no log open must still be well-formed; the
        // assistant is told in-band that there is nothing to query.
        let cfg = LlmSettings::default();
        for (task, wants_tool) in
            [(Task::Chat, true), (Task::Review, true), (Task::ExplainRule, false)]
        {
            let req = build_request(&cfg, task, "x", &None).unwrap();
            assert_eq!(!req.tools.is_empty(), wants_tool, "{task:?}");
        }
    }

    #[test]
    fn a_prompt_built_without_a_log_says_so() {
        let cfg = LlmSettings::default();
        let req = build_request(&cfg, Task::Chat, "anything?", &None).unwrap();
        assert!(req.system.contains("no log is open"));
    }
}
