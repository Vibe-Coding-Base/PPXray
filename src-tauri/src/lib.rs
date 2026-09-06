//! Tauri host library for ppxray.
//!
//! The main binary (`main.rs`) is intentionally thin — it delegates to [`run`]
//! here so the same code path is exercised on desktop and during integration
//! tests.

use std::path::PathBuf;

use tauri::Manager;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

mod atomic;
mod commands;
mod credentials;
mod error;
mod settings;
mod state;

pub use error::AppError;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Log file sink lives alongside the per-log DuckDB stores under
            // the OS app-data directory. We install it at setup-time (not
            // module init) because resolving the app-data dir requires the
            // AppHandle.
            if let Ok(dir) = app.path().app_data_dir() {
                let _guard = init_tracing(Some(dir.join("logs")));
                // The guard must outlive the process. Leak it into static
                // storage so it's never dropped — dropping would flush +
                // close the appender mid-session.
                std::mem::forget(_guard);
            } else {
                let _guard = init_tracing(None);
                std::mem::forget(_guard);
            }
            Ok(())
        })
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::profile::profile_open_from_path,
            commands::profile::profile_save_to_path,
            commands::profile::profile_parse_xml,
            commands::profile::profile_serialize_to_xml,
            commands::rules::rule_simulate_match,
            commands::rules::rule_overshadow_scan,
            commands::rules::profile_exposure,
            commands::logs::log_ingest,
            commands::logs::log_open_existing,
            commands::logs::log_close,
            commands::logs::log_stats,
            commands::logs::log_facets,
            commands::logs::log_query_events,
            commands::logs::log_dashboard,
            commands::logs::log_suggest_targets,
            commands::hunt::hunt_catalog,
            commands::hunt::hunt_run,
            commands::hunt::hunt_list_alerts,
            commands::hunt::hunt_alert_evidence,
            commands::hunt::hunt_triage,
            commands::hunt::hunt_user_rules,
            commands::hunt::hunt_save_user_rule,
            commands::hunt::hunt_delete_user_rule,
            commands::hunt::settings_rule_dir,
            commands::hunt::settings_set_rule_dir,
            commands::llm::llm_status,
            commands::llm::llm_set_settings,
            commands::llm::llm_provider_defaults,
            commands::llm::llm_set_api_key,
            commands::llm::llm_clear_api_key,
            commands::llm::llm_mark_reviewed,
            commands::llm::llm_preview,
            commands::llm::llm_test_connection,
            commands::llm::llm_ask,
            commands::llm::llm_reset_chat,
            commands::llm::llm_audit_entries,
            commands::llm::llm_clear_audit,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ppxray");
}

/// Initialize tracing with two sinks:
///
/// 1. **stderr** — useful in dev (captured by the Tauri CLI) and harmless in
///    release (the GUI subsystem has no console so nothing leaks on screen).
/// 2. **rolling log file** under `<app-data>/logs/ppxray.log.*`,
///    rotated daily. The last ~7 files are retained; older ones are
///    removed on rotation. Gives the user a paste-ready artifact when
///    they hit a bug — see `docs/DISTRIBUTION.md#bug-reports`.
///
/// Returns a `WorkerGuard` whose drop flushes pending writes. Caller is
/// expected to keep it alive for the lifetime of the process (we leak it
/// into static storage at the call site).
fn init_tracing(log_dir: Option<PathBuf>) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ppxray_lib=debug,ppx_core=debug"));

    let stderr_layer = fmt::layer().with_target(true).with_writer(std::io::stderr);

    let (file_layer, guard) = match log_dir {
        Some(dir) => match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                let appender = tracing_appender::rolling::daily(&dir, "ppxray.log");
                let (non_blocking, guard) = tracing_appender::non_blocking(appender);
                let layer = fmt::layer()
                    .with_ansi(false)
                    .with_target(true)
                    .with_writer(non_blocking)
                    .with_filter(filter.clone())
                    .boxed();
                (Some(layer), Some(guard))
            }
            Err(_) => (None, None),
        },
        None => (None, None),
    };

    let registry = Registry::default().with(stderr_layer.with_filter(filter));
    let _ = if let Some(file_layer) = file_layer {
        registry.with(file_layer).try_init()
    } else {
        registry.try_init()
    };
    guard
}
