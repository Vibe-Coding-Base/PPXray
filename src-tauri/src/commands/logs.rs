//! Log ingest + analysis commands.
//!
//! Design:
//! - `log_ingest` takes a source path, finds (or creates) a per-log DuckDB
//!   file under the user's data dir, and streams the file into it on a
//!   dedicated blocking task. Progress events are emitted on the
//!   `log:ingest-progress` channel; the command resolves with final stats.
//! - Subsequent analysis commands reuse the same `LogStore` cached in
//!   `AppState`, so the UI doesn't round-trip through the path on every
//!   query.
//!
//! # Every DuckDB call goes through `spawn_blocking`
//!
//! These handlers are `async`, but the work inside them is synchronous and
//! unbounded: a `GROUP BY` over a multi-million-row table takes as long as
//! it takes. Running that directly on a Tokio worker parks the whole async
//! runtime — every other command, including the ones the UI issues to stay
//! responsive, queues behind it. [`on_store`] moves the work onto the
//! blocking pool so only the caller waits.

use std::path::PathBuf;

use log_ingest::{
    DashboardLimits, EventFilter, EventRow, IngestProgress, IngestStats, LogDashboard, LogStats,
    LogStore, SuggestOptions, TargetSuggestions, ingest_file, open_store,
    query::{FacetValues, dashboard, facets, stats},
    query_events, store_path_for, suggest_targets,
};
use serde::Serialize;
use tauri::{Emitter, Manager, State};
use tracing::{info, instrument};

use crate::{error::AppError, state::AppState};

const INGEST_PROGRESS_EVENT: &str = "log:ingest-progress";

#[derive(Debug, Serialize)]
pub struct OpenLogResult {
    pub stats: IngestStats,
    pub counts: LogStats,
}

#[tauri::command]
#[instrument(skip(app, state))]
pub async fn log_ingest(
    path: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<OpenLogResult, AppError> {
    let source = PathBuf::from(&path);
    if !source.exists() {
        return Err(AppError::Other(format!("log file not found: {path}")));
    }

    let data_dir = ensure_data_dir(&app)?;
    let db_path = store_path_for(&data_dir, &source);
    let store = open_analysis_store(&db_path)?;

    let emitter = app.clone();
    let store_for_task = store.clone();
    let src_for_task = source.clone();

    let stats = tauri::async_runtime::spawn_blocking(move || {
        ingest_file(&src_for_task, &store_for_task, |progress: IngestProgress| {
            let _ = emitter.emit(INGEST_PROGRESS_EVENT, &progress);
        })
    })
    .await
    .map_err(|e| AppError::Other(format!("ingest task join error: {e}")))?
    .map_err(map_ingest_err)?;

    // Ingest drops the alert tables on its way through `truncate_events` —
    // it has to, because `alert_evidence.event_id` points at rows the
    // re-ingest renumbers. Recreate them here so the Hunt tab has something
    // to read; without this the tables exist only between opening the store
    // and the first byte of the log.
    ensure_alert_schema(&store)?;

    let store_for_counts = store.clone();
    let counts =
        blocking(move || log_ingest::query::stats(&store_for_counts).map_err(map_ingest_err))
            .await?;

    set_store(&state, store)?;

    info!(?db_path, events = stats.total_events, "log ingest done");
    Ok(OpenLogResult { stats, counts })
}

#[tauri::command]
pub async fn log_open_existing(
    path: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<LogStats, AppError> {
    let source = PathBuf::from(&path);
    let data_dir = ensure_data_dir(&app)?;
    let db_path = store_path_for(&data_dir, &source);
    if !db_path.exists() {
        return Err(AppError::Other(format!("no analysis exists for {path} yet — ingest first")));
    }
    let store = open_analysis_store(&db_path)?;

    let store_for_counts = store.clone();
    let counts = blocking(move || stats(&store_for_counts).map_err(map_ingest_err)).await?;

    set_store(&state, store)?;
    Ok(counts)
}

#[tauri::command]
pub async fn log_close(state: State<'_, AppState>) -> Result<(), AppError> {
    lock_store(&state)?.take();
    Ok(())
}

#[tauri::command]
pub async fn log_stats(state: State<'_, AppState>) -> Result<LogStats, AppError> {
    on_store(&state, |s| stats(s).map_err(map_ingest_err)).await
}

#[tauri::command]
pub async fn log_facets(state: State<'_, AppState>) -> Result<FacetValues, AppError> {
    on_store(&state, |s| facets(s).map_err(map_ingest_err)).await
}

#[tauri::command]
pub async fn log_query_events(
    filter: EventFilter,
    state: State<'_, AppState>,
) -> Result<Vec<EventRow>, AppError> {
    on_store(&state, move |s| query_events(s, &filter).map_err(map_ingest_err)).await
}

/// Every filter-dependent panel in one round trip. See
/// [`log_ingest::query::dashboard`] for why this exists.
#[tauri::command]
pub async fn log_dashboard(
    filter: EventFilter,
    bucket_secs: Option<u32>,
    processes: Option<u32>,
    hosts: Option<u32>,
    rules: Option<u32>,
    state: State<'_, AppState>,
) -> Result<LogDashboard, AppError> {
    let defaults = DashboardLimits::default();
    let limits = DashboardLimits {
        processes: processes.unwrap_or(defaults.processes),
        hosts: hosts.unwrap_or(defaults.hosts),
        rules: rules.unwrap_or(defaults.rules),
        bucket_secs: bucket_secs.unwrap_or(defaults.bucket_secs).max(1),
    };
    on_store(&state, move |s| dashboard(s, &filter, limits).map_err(map_ingest_err)).await
}

/// Destinations a process actually reached, shaped for a rule's Targets
/// field. See [`log_ingest::suggest`] for the roll-up rules.
#[tauri::command]
pub async fn log_suggest_targets(
    process: String,
    min_events: Option<u64>,
    min_hosts_for_wildcard: Option<u32>,
    include_ips: Option<bool>,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<TargetSuggestions, AppError> {
    let d = SuggestOptions::default();
    let opts = SuggestOptions {
        min_events: min_events.unwrap_or(d.min_events),
        min_hosts_for_wildcard: min_hosts_for_wildcard.unwrap_or(d.min_hosts_for_wildcard).max(2),
        include_ips: include_ips.unwrap_or(d.include_ips),
        limit: limit.unwrap_or(d.limit).min(1000),
    };
    on_store(&state, move |s| suggest_targets(s, &process, opts).map_err(map_ingest_err)).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open a log DB and make sure *both* crates' tables exist.
///
/// `log_ingest::open_store` creates the event tables. The alert tables belong
/// to `detect-engine` and used to be created only by a hunt run, which left a
/// window the UI walks straight into: the Alerts tab queries `alerts` as soon
/// as it mounts, so before the first hunt — and again after every re-ingest,
/// because `log_ingest::schema::truncate_events` drops the alert tables along
/// with the events they reference — Hunt greeted the user with a raw
/// `Catalog Error: Table with name alerts does not exist!`.
///
/// This is the layer that knows about both crates, so it is where the two
/// schemas get reconciled. Creating them is idempotent `CREATE TABLE IF NOT
/// EXISTS`, so the cost is one cheap DDL per open.
fn open_analysis_store(db_path: &std::path::Path) -> Result<LogStore, AppError> {
    let store = open_store(db_path).map_err(map_ingest_err)?;
    ensure_alert_schema(&store)?;
    Ok(store)
}

/// Create `detect-engine`'s tables if they are not there. Idempotent.
fn ensure_alert_schema(store: &LogStore) -> Result<(), AppError> {
    store
        .with_conn(|conn| {
            detect_engine::init_schema(conn)
                .map_err(|e| log_ingest::IngestError::Custom(format!("alert schema: {e}")))
        })
        .map_err(map_ingest_err)
}

fn ensure_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Other(format!("resolve app_data_dir: {e}")))?
        .join("logs");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

type StoreGuard<'a> = std::sync::MutexGuard<'a, Option<LogStore>>;

fn lock_store<'a>(state: &'a State<'_, AppState>) -> Result<StoreGuard<'a>, AppError> {
    state.log_store.lock().map_err(|e| AppError::Other(format!("log_store lock poisoned: {e}")))
}

fn set_store(state: &State<'_, AppState>, store: LogStore) -> Result<(), AppError> {
    lock_store(state)?.replace(store);
    Ok(())
}

/// Clone the active store out of app state, or explain that none is open.
///
/// `LogStore` is an `Arc` around the connection, so this is a refcount bump —
/// it lets the caller release the `AppState` mutex before doing slow work.
fn require_store(state: &State<'_, AppState>) -> Result<LogStore, AppError> {
    lock_store(state)?
        .clone()
        .ok_or_else(|| AppError::Other("no log loaded — call log_ingest first".into()))
}

/// The active store, or `None` when no log is open.
///
/// The assistant needs this rather than [`require_store`]: it can answer
/// questions about rules with no log loaded, and "no log is open" is
/// something it should be told in-band rather than a command failure.
pub(crate) fn optional_store(state: &State<'_, AppState>) -> Result<Option<LogStore>, AppError> {
    Ok(lock_store(state)?.clone())
}

/// Run `f` against the active store on the blocking pool.
async fn on_store<R, F>(state: &State<'_, AppState>, f: F) -> Result<R, AppError>
where
    F: FnOnce(&LogStore) -> Result<R, AppError> + Send + 'static,
    R: Send + 'static,
{
    let store = require_store(state)?;
    blocking(move || f(&store)).await
}

/// `spawn_blocking` with the join error folded into `AppError`.
pub(crate) async fn blocking<R, F>(f: F) -> Result<R, AppError>
where
    F: FnOnce() -> Result<R, AppError> + Send + 'static,
    R: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Other(format!("query task join error: {e}")))?
}

fn map_ingest_err(e: log_ingest::IngestError) -> AppError {
    AppError::Other(format!("{e}"))
}
