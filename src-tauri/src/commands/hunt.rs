//! Hunt commands. Run the (built-in + user) detection catalog against the
//! active log store, list / triage alerts, manage user YAML rules, and look
//! up evidence event IDs for the alert detail drawer.

use std::path::PathBuf;

use detect_engine::{
    Alert, AlertTriage, DetectionRule, HuntRunReport, alert::AlertFilter, all_rules, list_alerts,
    list_evidence, load_rule_dir, parse_yaml, run_all_rules, set_triage,
};
use log_ingest::LogStore;
use serde::Serialize;
use tauri::State;
use tracing::instrument;

use crate::{error::AppError, settings, state::AppState};

#[derive(Debug, Serialize)]
pub struct HuntCatalogEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub mitre: Vec<String>,
    pub references: Vec<String>,
    /// `"builtin"` or the user filename (e.g. `my-rule.yml`).
    pub source: String,
    pub query: QueryDetail,
}

/// Rule-query data exposed to the UI for View / Clone flows. Matches the
/// shape of `RuleQuery` but stringifies the group-by enum.
#[derive(Debug, Serialize)]
pub struct QueryDetail {
    pub kind: &'static str,
    pub where_sql: Option<String>,
    pub group_by: Option<&'static str>,
    pub min_count: Option<u32>,
    pub max_per_run: Option<u32>,
    pub select_sql: Option<String>,
}

fn query_detail(q: &detect_engine::RuleQuery) -> QueryDetail {
    use detect_engine::{GroupBy, RuleQuery};
    match q {
        RuleQuery::EventsWhere { where_sql, max_per_run } => QueryDetail {
            kind: "events_where",
            where_sql: Some(where_sql.clone()),
            group_by: None,
            min_count: None,
            max_per_run: Some(*max_per_run),
            select_sql: None,
        },
        RuleQuery::EventsGrouped { where_sql, group_by, having_min_count, max_per_run } => {
            QueryDetail {
                kind: "events_grouped",
                where_sql: Some(where_sql.clone()),
                group_by: Some(match group_by {
                    GroupBy::Process => "process",
                    GroupBy::Dst => "dst",
                    GroupBy::ProcessAndDst => "process_and_dst",
                }),
                min_count: Some(*having_min_count),
                max_per_run: Some(*max_per_run),
                select_sql: None,
            }
        }
        RuleQuery::DnsWhere { where_sql, max_per_run } => QueryDetail {
            kind: "dns_where",
            where_sql: Some(where_sql.clone()),
            group_by: None,
            min_count: None,
            max_per_run: Some(*max_per_run),
            select_sql: None,
        },
        RuleQuery::Custom { select_sql } => QueryDetail {
            kind: "custom",
            where_sql: None,
            group_by: None,
            min_count: None,
            max_per_run: None,
            select_sql: Some(select_sql.clone()),
        },
    }
}

/// Combined catalog view: built-in rules + whatever parses cleanly from the
/// configured user rule dir. Broken user files are surfaced via
/// [`hunt_user_rules`] instead.
#[tauri::command]
pub async fn hunt_catalog(app: tauri::AppHandle) -> Result<Vec<HuntCatalogEntry>, AppError> {
    let combined = load_combined_rules(&app)?;
    Ok(combined
        .into_iter()
        .map(|r| HuntCatalogEntry {
            id: r.id,
            title: r.title,
            description: r.description,
            severity: r.severity.as_str().into(),
            mitre: r.mitre,
            references: r.references,
            source: match r.source {
                detect_engine::RuleSource::Builtin => "builtin".into(),
                detect_engine::RuleSource::UserFile(f) => f,
            },
            query: query_detail(&r.query),
        })
        .collect())
}

#[tauri::command]
#[instrument(skip(app, state))]
pub async fn hunt_run(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<HuntRunReport, AppError> {
    let store = require_store(&state)?;
    let rules = load_combined_rules(&app)?;
    let report = tauri::async_runtime::spawn_blocking(move || run_all_rules(&store, &rules))
        .await
        .map_err(|e| AppError::Other(format!("hunt task join error: {e}")))?
        .map_err(|e| AppError::Other(format!("{e}")))?;
    Ok(report)
}

#[tauri::command]
pub async fn hunt_list_alerts(
    filter: AlertFilter,
    state: State<'_, AppState>,
) -> Result<Vec<Alert>, AppError> {
    on_store(&state, move |s| list_alerts(s, &filter).map_err(|e| AppError::Other(format!("{e}"))))
        .await
}

#[tauri::command]
pub async fn hunt_alert_evidence(
    alert_id: u64,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<u64>, AppError> {
    on_store(&state, move |s| {
        list_evidence(s, alert_id, limit.unwrap_or(50)).map_err(|e| AppError::Other(format!("{e}")))
    })
    .await
}

#[tauri::command]
pub async fn hunt_triage(
    alert_id: u64,
    triage: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    let t = match triage.as_str() {
        "tp" => AlertTriage::TruePositive,
        "fp" => AlertTriage::FalsePositive,
        "suppressed" => AlertTriage::Suppressed,
        _ => AlertTriage::New,
    };
    on_store(&state, move |s| {
        set_triage(s, alert_id, t).map_err(|e| AppError::Other(format!("{e}")))
    })
    .await
}

// ---------------------------------------------------------------------------
// User rules CRUD
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct UserRuleView {
    pub filename: String,
    pub raw_yaml: String,
    /// Present when the file parsed cleanly.
    pub id: Option<String>,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub mitre: Option<Vec<String>>,
    /// Present when parsing failed — surfaces the validation message.
    pub error: Option<String>,
}

#[tauri::command]
pub async fn hunt_user_rules(app: tauri::AppHandle) -> Result<Vec<UserRuleView>, AppError> {
    let dir = settings::effective_rule_dir(&app)?;
    let entries = load_rule_dir(&dir).map_err(|e| AppError::Other(format!("{e}")))?;
    Ok(entries
        .into_iter()
        .map(|u| UserRuleView {
            filename: u.filename,
            raw_yaml: u.raw_yaml,
            id: u.parsed.as_ref().map(|r| r.id.clone()),
            title: u.parsed.as_ref().map(|r| r.title.clone()),
            severity: u.parsed.as_ref().map(|r| r.severity.as_str().into()),
            mitre: u.parsed.as_ref().map(|r| r.mitre.clone()),
            error: u.error,
        })
        .collect())
}

/// Validate `yaml` + write it to `<rule_dir>/<filename>`. Fails before
/// writing if the YAML doesn't parse.
#[tauri::command]
pub async fn hunt_save_user_rule(
    app: tauri::AppHandle,
    filename: String,
    yaml: String,
) -> Result<(), AppError> {
    let safe = safe_filename(&filename)?;
    parse_yaml(&yaml, &safe).map_err(|e| AppError::Other(format!("YAML validation: {e}")))?;

    let dir = settings::effective_rule_dir(&app)?;
    std::fs::create_dir_all(&dir)?;
    crate::atomic::write(&dir.join(&safe), yaml.as_bytes(), crate::atomic::Backup::Skip)
}

#[tauri::command]
pub async fn hunt_delete_user_rule(
    app: tauri::AppHandle,
    filename: String,
) -> Result<(), AppError> {
    let safe = safe_filename(&filename)?;
    let dir = settings::effective_rule_dir(&app)?;
    let path = dir.join(&safe);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings commands (rule directory only, for now)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct RuleDirInfo {
    /// Absolute path currently in effect.
    pub effective: String,
    /// User-configured override (None = using default).
    pub configured: Option<String>,
    /// Default path under the OS app-data directory.
    pub default: String,
}

#[tauri::command]
pub async fn settings_rule_dir(app: tauri::AppHandle) -> Result<RuleDirInfo, AppError> {
    let s = settings::load(&app)?;
    let default = settings::default_rule_dir(&app)?;
    let effective = match s.rule_dir.clone() {
        Some(p) => PathBuf::from(p),
        None => default.clone(),
    };
    Ok(RuleDirInfo {
        effective: effective.to_string_lossy().into_owned(),
        configured: s.rule_dir,
        default: default.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
pub async fn settings_set_rule_dir(
    app: tauri::AppHandle,
    path: Option<String>,
) -> Result<(), AppError> {
    let mut s = settings::load(&app)?;
    s.rule_dir = path;
    settings::save(&app, &s)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_store(state: &State<'_, AppState>) -> Result<LogStore, AppError> {
    let guard = state
        .log_store
        .lock()
        .map_err(|e| AppError::Other(format!("log_store lock poisoned: {e}")))?;
    guard.clone().ok_or_else(|| AppError::Other("no log loaded — open a log first".into()))
}

/// Run `f` against the active store on the blocking pool.
///
/// Alert queries hit the same DuckDB file as the log module, so they carry
/// the same rule: never run them on a Tokio worker. See the module comment
/// on `commands::logs` for the reasoning.
async fn on_store<R, F>(state: &State<'_, AppState>, f: F) -> Result<R, AppError>
where
    F: FnOnce(&LogStore) -> Result<R, AppError> + Send + 'static,
    R: Send + 'static,
{
    let store = require_store(state)?;
    tauri::async_runtime::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| AppError::Other(format!("hunt task join error: {e}")))?
}

/// Return built-in catalog + successfully-parsed user rules. Rules with the
/// same `id` — user wins so analysts can override a built-in.
fn load_combined_rules(app: &tauri::AppHandle) -> Result<Vec<DetectionRule>, AppError> {
    let mut out = all_rules();

    let dir = settings::effective_rule_dir(app)?;
    let user_entries = load_rule_dir(&dir).map_err(|e| AppError::Other(format!("{e}")))?;
    let mut user_ids = std::collections::HashSet::new();
    let mut user_rules: Vec<DetectionRule> = Vec::new();
    for u in user_entries {
        if let Some(rule) = u.parsed {
            user_ids.insert(rule.id.clone());
            user_rules.push(rule);
        }
    }
    // Drop built-ins that the user overrides, then append user rules.
    out.retain(|r| !user_ids.contains(&r.id));
    out.extend(user_rules);
    Ok(out)
}

/// Windows device names. `CON.yml` does not create a file — it opens the
/// console device — so a rule saved under one of these silently vanishes.
/// Reserved with *any* extension, hence the check on the stem.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Validate a user-supplied rule filename before it is joined onto the rule
/// directory.
///
/// The filename arrives from the renderer, so it is untrusted input used to
/// build a path. Rejecting outright beats sanitising: a name that needs
/// rewriting to be safe is a name the user should retype.
fn safe_filename(filename: &str) -> Result<String, AppError> {
    let reject =
        |why: &str| Err(AppError::Other(format!("invalid rule filename {filename:?}: {why}")));

    if filename.is_empty() {
        return reject("empty");
    }
    if filename.contains('/') || filename.contains('\\') {
        return reject("must not contain a path separator");
    }
    if filename.contains("..") {
        return reject("must not contain `..`");
    }
    if filename.starts_with('.') {
        return reject("must not start with `.`");
    }
    // `rule.yml:evil` writes to an NTFS alternate data stream — the rule
    // list would not show it, but it is on disk all the same. A colon is
    // also a drive separator (`C:rule.yml` is relative to CWD on C:).
    if filename.contains(':') {
        return reject("must not contain `:`");
    }
    // Windows silently strips these, so `rule.yml ` and `rule.yml` name the
    // same file while comparing as different strings.
    if filename.ends_with(' ') || filename.ends_with('.') {
        return reject("must not end with a space or a dot");
    }
    // Control characters and the shell/NTFS-illegal set.
    if let Some(bad) =
        filename.chars().find(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return reject(&format!("contains an illegal character {bad:?}"));
    }

    let lower = filename.to_ascii_lowercase();
    if !lower.ends_with(".yml") && !lower.ends_with(".yaml") {
        return reject("must end in .yml or .yaml");
    }

    let stem = lower.split('.').next().unwrap_or("");
    if WINDOWS_RESERVED.contains(&stem) {
        return reject("is a reserved Windows device name");
    }

    Ok(filename.to_string())
}

#[cfg(test)]
mod tests {
    use super::safe_filename;

    #[test]
    fn accepts_ordinary_rule_names() {
        for name in ["rule.yml", "my.org.beacon.yaml", "a-b_c.123.yml"] {
            assert!(safe_filename(name).is_ok(), "should accept {name:?}");
        }
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for name in
            ["../escape.yml", "..\\escape.yml", "sub/dir.yml", "sub\\dir.yml", ".hidden.yml"]
        {
            assert!(safe_filename(name).is_err(), "should reject {name:?}");
        }
    }

    /// The cases the original check let through.
    #[test]
    fn rejects_windows_specific_traps() {
        for name in [
            "rule.yml:hidden", // NTFS alternate data stream
            "C:rule.yml",      // drive-relative path
            "CON.yml",         // reserved device name
            "nul.yaml",        // reserved, lowercase
            "LPT1.yml",        // reserved, numbered
            "rule.yml ",       // trailing space, silently stripped
            "rule.yml.",       // trailing dot, silently stripped
            "rule\u{7}.yml",   // control character
            "ru*le.yml",       // wildcard
        ] {
            assert!(safe_filename(name).is_err(), "should reject {name:?}");
        }
    }

    #[test]
    fn rejects_wrong_extension() {
        for name in ["rule.txt", "rule", "rule.yml.exe"] {
            assert!(safe_filename(name).is_err(), "should reject {name:?}");
        }
    }
}
