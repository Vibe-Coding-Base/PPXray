//! Rule runner.
//!
//! Walks the rule catalog, executes each rule against DuckDB, materializes
//! alerts + evidence into the alert tables. Designed to be cheap to re-run:
//! a typical 30 MB log analyzed by 18 rules completes in under a second on
//! the fixture.

use chrono::NaiveDateTime;
use duckdb::{Connection, params, types::Value};
use log_ingest::LogStore;
use serde::Serialize;
use serde_json::json;
use ts_rs::TS;

use crate::error::{DetectError, DetectResult};
use crate::rule::{DetectionRule, GroupBy, RuleQuery};
use crate::schema;

/// Max evidence event IDs we attach to a single alert. The detail drawer
/// shows these; users can open the events table for unbounded drill-in.
const MAX_EVIDENCE_PER_ALERT: u32 = 50;

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct RulePerRuleStat {
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub alerts: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct HuntRunReport {
    pub total_alerts: u64,
    pub duration_ms: u64,
    pub per_rule: Vec<RulePerRuleStat>,
}

/// Wipe prior alerts and run the entire rule catalog. Returns a per-rule
/// breakdown so the UI can show which rule produced what (and which failed).
pub fn run_all_rules(store: &LogStore, rules: &[DetectionRule]) -> DetectResult<HuntRunReport> {
    store.with_conn(|c| schema::init(c).map_err(map_for_ingest))?;
    store.with_conn(|c| schema::reset(c).map_err(map_for_ingest))?;

    let started = std::time::Instant::now();
    let mut next_id: u64 = 1;
    let mut per_rule = Vec::with_capacity(rules.len());
    let mut total: u64 = 0;

    for rule in rules {
        let rule_started = std::time::Instant::now();

        // Each rule runs inside `catch_unwind` so a single broken rule
        // (panicking on a malformed query result, an unexpected DuckDB
        // value variant, etc.) cannot abort the entire hunt run. Panics
        // are converted to per-rule errors and surfaced to the UI.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.with_conn_mut(|conn| {
                run_one_rule(conn, rule, &mut next_id).map_err(|e| {
                    log_ingest::IngestError::Custom(format!("rule `{}`: {e}", rule.id))
                })
            })
        }));

        let duration_ms = rule_started.elapsed().as_millis() as u64;
        let result: Result<u64, String> = match outcome {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(e.to_string()),
            Err(panic) => {
                let msg = panic_message(&*panic);
                Err(format!("internal panic: {msg}"))
            }
        };

        match result {
            Ok(n) => {
                tracing::debug!(rule = %rule.id, alerts = n, ms = duration_ms, "rule ok");
                total += n;
                per_rule.push(RulePerRuleStat {
                    rule_id: rule.id.clone(),
                    rule_title: rule.title.clone(),
                    severity: rule.severity.as_str().into(),
                    alerts: n,
                    duration_ms,
                    error: None,
                });
            }
            Err(e) => {
                tracing::warn!(rule = %rule.id, "{e}");
                per_rule.push(RulePerRuleStat {
                    rule_id: rule.id.clone(),
                    rule_title: rule.title.clone(),
                    severity: rule.severity.as_str().into(),
                    alerts: 0,
                    duration_ms,
                    error: Some(e),
                });
            }
        }
    }

    Ok(HuntRunReport {
        total_alerts: total,
        duration_ms: started.elapsed().as_millis() as u64,
        per_rule,
    })
}

fn map_for_ingest(e: DetectError) -> log_ingest::IngestError {
    log_ingest::IngestError::Custom(e.to_string())
}

/// Best-effort downcast of a `catch_unwind` payload into a human string.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "unknown panic payload".to_string()
    }
}

// ---------------------------------------------------------------------------
// Per-rule execution
// ---------------------------------------------------------------------------

fn run_one_rule(
    conn: &mut Connection,
    rule: &DetectionRule,
    next_id: &mut u64,
) -> DetectResult<u64> {
    match &rule.query {
        RuleQuery::EventsWhere { where_sql, max_per_run } => {
            run_events_where(conn, rule, where_sql, *max_per_run, next_id)
        }
        RuleQuery::EventsGrouped { where_sql, group_by, having_min_count, max_per_run } => {
            run_events_grouped(
                conn,
                rule,
                where_sql,
                *group_by,
                *having_min_count,
                *max_per_run,
                next_id,
            )
        }
        RuleQuery::DnsWhere { where_sql, max_per_run } => {
            run_dns_where(conn, rule, where_sql, *max_per_run, next_id)
        }
        RuleQuery::Custom { select_sql } => run_custom(conn, rule, select_sql, next_id),
    }
}

fn run_events_where(
    conn: &mut Connection,
    rule: &DetectionRule,
    where_sql: &str,
    max: u32,
    next_id: &mut u64,
) -> DetectResult<u64> {
    let sql = format!(
        "SELECT id, ts, process, dst_host, dst_ip, dst_port, action, matched_rule
         FROM events
         WHERE {where_sql}
         ORDER BY ts DESC
         LIMIT {max}"
    );
    let rows: Vec<EventRowLite> = collect_event_rows(conn, &sql)?;
    let mut count = 0;
    for r in rows {
        let alert_id = take_id(next_id);
        let dst = r.dst_host.clone().or(r.dst_ip.clone());
        let detail = json!({
            "dst_host": r.dst_host,
            "dst_ip": r.dst_ip,
            "dst_port": r.dst_port,
            "action": r.action,
            "matched_rule": r.matched_rule,
        });
        insert_alert(conn, alert_id, rule, r.ts, Some(r.process.clone()), dst, detail.to_string())?;
        insert_evidence(conn, alert_id, &[r.id])?;
        count += 1;
    }
    Ok(count)
}

fn run_events_grouped(
    conn: &mut Connection,
    rule: &DetectionRule,
    where_sql: &str,
    group_by: GroupBy,
    having_min_count: u32,
    max: u32,
    next_id: &mut u64,
) -> DetectResult<u64> {
    let group_cols = match group_by {
        GroupBy::Process => "process",
        GroupBy::Dst => "COALESCE(dst_host, dst_ip)",
        GroupBy::ProcessAndDst => "process, COALESCE(dst_host, dst_ip)",
    };
    let dst_expr = match group_by {
        GroupBy::Process => "NULL",
        GroupBy::Dst | GroupBy::ProcessAndDst => "COALESCE(dst_host, dst_ip)",
    };
    let process_expr = match group_by {
        GroupBy::Dst => "NULL",
        GroupBy::Process | GroupBy::ProcessAndDst => "process",
    };
    let sql = format!(
        "SELECT {process_expr} AS process, {dst_expr} AS dst,
                COUNT(*) AS c,
                MIN(ts) AS first_ts,
                MAX(ts) AS last_ts,
                list_slice(array_agg(id ORDER BY ts DESC), 1, {MAX_EVIDENCE_PER_ALERT}) AS evidence_ids
         FROM events
         WHERE {where_sql}
         GROUP BY {group_cols}
         HAVING COUNT(*) >= {having_min_count}
         ORDER BY c DESC
         LIMIT {max}"
    );

    // Read every column as a `Value` first; `chrono::NaiveDateTime` via
    // duckdb-rs's FromSql can panic on out-of-range timestamps, and we'd
    // rather fail soft than abort the whole hunt run.
    let groups: Vec<GroupedRow> = {
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            let vals: Vec<Value> =
                (0..6).map(|i| row.get::<_, Value>(i)).collect::<Result<Vec<_>, _>>()?;
            let process = match &vals[0] {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            };
            let dst = match &vals[1] {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            };
            let count = match &vals[2] {
                Value::UBigInt(n) => *n,
                Value::BigInt(n) => *n as u64,
                _ => 0,
            };
            let first_ts = expect_timestamp(&vals[3]).unwrap_or_default();
            let last_ts = expect_timestamp(&vals[4]).unwrap_or(first_ts);
            let evidence_ids = read_evidence_list(&vals[5]);
            Ok(GroupedRow { process, dst, count, first_ts, last_ts, evidence_ids })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    let mut count = 0;
    for g in groups {
        let alert_id = take_id(next_id);
        let detail = json!({
            "count": g.count,
            "first_ts": g.first_ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "last_ts": g.last_ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
        });
        insert_alert(conn, alert_id, rule, g.last_ts, g.process, g.dst, detail.to_string())?;
        insert_evidence(conn, alert_id, &g.evidence_ids)?;
        count += 1;
    }
    Ok(count)
}

fn run_dns_where(
    conn: &mut Connection,
    rule: &DetectionRule,
    where_sql: &str,
    max: u32,
    next_id: &mut u64,
) -> DetectResult<u64> {
    let sql = format!(
        "SELECT id, ts, process, qname, qtype, server, answer_ip, kind
         FROM dns_events
         WHERE {where_sql}
         ORDER BY ts DESC
         LIMIT {max}"
    );
    let rows: Vec<DnsRowLite> = {
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            // Timestamps go through `expect_timestamp` to dodge chrono FromSql
            // panics on edge cases (see comment in `run_events_grouped`).
            let ts_val: Value = r.get(1)?;
            let ts = expect_timestamp(&ts_val).unwrap_or_default();
            Ok(DnsRowLite {
                id: r.get::<_, u64>(0)?,
                ts,
                process: r.get(2)?,
                qname: r.get(3)?,
                qtype: r.get::<_, Option<i32>>(4)?,
                server: r.get(5)?,
                answer_ip: r.get(6)?,
                kind: r.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    let mut count = 0;
    for r in rows {
        let alert_id = take_id(next_id);
        let detail = json!({
            "qname": r.qname,
            "qtype": r.qtype,
            "server": r.server,
            "answer_ip": r.answer_ip,
            "kind": r.kind,
            "dns_event_id": r.id,
        });
        insert_alert(
            conn,
            alert_id,
            rule,
            r.ts,
            Some(r.process),
            Some(r.qname),
            detail.to_string(),
        )?;
        // No event-table evidence for DNS-only alerts; the DNS event id is
        // surfaced via the `detail` JSON.
        count += 1;
    }
    Ok(count)
}

fn run_custom(
    conn: &mut Connection,
    rule: &DetectionRule,
    select_sql: &str,
    next_id: &mut u64,
) -> DetectResult<u64> {
    // duckdb-rs 1.4 insists that `column_count` / `column_name` / `column_names`
    // only be called AFTER the prepared statement has been executed — with
    // CTE + window-function queries (beacon-low-jitter etc.) calling these
    // on the raw `Statement` panics with "The statement was not executed
    // yet" or `Option::unwrap()` on None.
    //
    // Fix: kick off execution via `stmt.query()` first, then capture the
    // column schema from the live `Rows` cursor (the `Row` it yields carries
    // column count / name via `row.as_ref()`). We materialize every row into
    // a `Vec<Value>` snapshot up front because we need to post-process them
    // in Rust (JSON detail encoding) AND because subsequent inserts into
    // `alerts` / `alert_evidence` need an open mutable connection — you
    // can't hold `Rows` open while also calling `conn.execute(...)`.
    let mut stmt = conn.prepare(select_sql)?;
    let mut rows = stmt.query([])?;

    let mut column_count: usize = 0;
    let mut column_names: Vec<String> = Vec::new();
    let mut materialized: Vec<Vec<Value>> = Vec::new();

    while let Some(row) = rows.next()? {
        if column_count == 0 {
            // First row: schema is now fully resolved. Capture it once.
            let parent = row.as_ref();
            column_count = parent.column_count();
            if column_count < 6 {
                return Err(DetectError::Custom(format!(
                    "rule `{}`: custom SELECT must have at least 6 columns; got {}",
                    rule.id, column_count
                )));
            }
            column_names = (0..column_count)
                .map(|i| {
                    parent
                        .column_name(i)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| format!("col_{i}"))
                })
                .collect();
        }
        let mut values: Vec<Value> = Vec::with_capacity(column_count);
        for i in 0..column_count {
            values.push(row.get::<_, Value>(i)?);
        }
        materialized.push(values);
    }

    drop(rows);
    drop(stmt);

    // Zero-row result is a valid outcome (the rule just didn't fire this run).
    if materialized.is_empty() {
        return Ok(0);
    }

    let last_idx = column_count - 1;
    let rows = materialized;

    let mut count = 0;
    for values in rows {
        let alert_id = take_id(next_id);

        let process = match &values[0] {
            Value::Text(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(format!("{other:?}")),
        };
        let dst = match &values[1] {
            Value::Text(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(format!("{other:?}")),
        };
        let row_count = match &values[2] {
            Value::UBigInt(n) => *n,
            Value::BigInt(n) => *n as u64,
            Value::UInt(n) => *n as u64,
            Value::Int(n) => *n as u64,
            _ => 0,
        };
        let first_ts = expect_timestamp(&values[3]).unwrap_or_default();
        let last_ts = expect_timestamp(&values[4]).unwrap_or(first_ts);
        let evidence_ids = read_evidence_list(&values[last_idx]);

        // Build the detail JSON from the in-between columns, using the
        // SELECT column aliases as JSON keys. This dodges DuckDB's JSON
        // extension entirely.
        let mut detail = serde_json::Map::new();
        detail.insert("count".into(), serde_json::Value::from(row_count));
        detail.insert(
            "first_ts".into(),
            serde_json::Value::String(first_ts.format("%Y-%m-%dT%H:%M:%S").to_string()),
        );
        detail.insert(
            "last_ts".into(),
            serde_json::Value::String(last_ts.format("%Y-%m-%dT%H:%M:%S").to_string()),
        );
        for i in 5..last_idx {
            let key = column_names[i].clone();
            detail.insert(key, value_to_json(&values[i]));
        }
        let detail_json = serde_json::Value::Object(detail).to_string();

        insert_alert(conn, alert_id, rule, last_ts, process, dst, detail_json)?;
        insert_evidence(conn, alert_id, &evidence_ids)?;
        count += 1;
    }
    Ok(count)
}

fn expect_timestamp(v: &Value) -> Option<NaiveDateTime> {
    use duckdb::types::TimeUnit;
    match v {
        Value::Timestamp(unit, n) => match unit {
            TimeUnit::Second => chrono::DateTime::from_timestamp(*n, 0).map(|d| d.naive_utc()),
            TimeUnit::Millisecond => {
                chrono::DateTime::from_timestamp_millis(*n).map(|d| d.naive_utc())
            }
            TimeUnit::Microsecond => {
                chrono::DateTime::from_timestamp_micros(*n).map(|d| d.naive_utc())
            }
            TimeUnit::Nanosecond => {
                let secs = n.div_euclid(1_000_000_000);
                let nsec = n.rem_euclid(1_000_000_000) as u32;
                chrono::DateTime::from_timestamp(secs, nsec).map(|d| d.naive_utc())
            }
        },
        _ => None,
    }
}

fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::UTinyInt(n) => serde_json::Value::from(*n),
        Value::USmallInt(n) => serde_json::Value::from(*n),
        Value::UInt(n) => serde_json::Value::from(*n),
        Value::UBigInt(n) => serde_json::Value::from(*n),
        Value::TinyInt(n) => serde_json::Value::from(*n),
        Value::SmallInt(n) => serde_json::Value::from(*n),
        Value::Int(n) => serde_json::Value::from(*n),
        Value::BigInt(n) => serde_json::Value::from(*n),
        Value::Float(f) => serde_json::Number::from_f64(f64::from(*f))
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Double(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Timestamp(..) => match expect_timestamp(v) {
            Some(dt) => serde_json::Value::String(dt.format("%Y-%m-%dT%H:%M:%S").to_string()),
            None => serde_json::Value::Null,
        },
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Insertion helpers
// ---------------------------------------------------------------------------

fn insert_alert(
    conn: &Connection,
    id: u64,
    rule: &DetectionRule,
    ts: NaiveDateTime,
    process: Option<String>,
    dst: Option<String>,
    detail: String,
) -> DetectResult<()> {
    let mitre = if rule.mitre.is_empty() { None } else { Some(rule.mitre.join(",")) };
    conn.execute(
        "INSERT INTO alerts(id, rule_id, rule_title, severity, mitre, ts, process, dst, detail, triage)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')",
        params![
            id,
            rule.id,
            rule.title,
            rule.severity.as_str(),
            mitre,
            ts,
            process,
            dst,
            detail,
        ],
    )?;
    Ok(())
}

fn insert_evidence(conn: &Connection, alert_id: u64, event_ids: &[u64]) -> DetectResult<()> {
    if event_ids.is_empty() {
        return Ok(());
    }
    let mut stmt = conn.prepare("INSERT INTO alert_evidence(alert_id, event_id) VALUES (?, ?)")?;
    for eid in event_ids {
        stmt.execute(params![alert_id, *eid])?;
    }
    Ok(())
}

fn take_id(next_id: &mut u64) -> u64 {
    let id = *next_id;
    *next_id += 1;
    id
}

// ---------------------------------------------------------------------------
// Lite row structs + helpers
// ---------------------------------------------------------------------------

struct EventRowLite {
    id: u64,
    ts: NaiveDateTime,
    process: String,
    dst_host: Option<String>,
    dst_ip: Option<String>,
    dst_port: Option<i32>,
    action: String,
    matched_rule: Option<String>,
}

fn collect_event_rows(conn: &Connection, sql: &str) -> DetectResult<Vec<EventRowLite>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        // Read TIMESTAMP as Value to avoid duckdb-rs's chrono FromSql panic
        // path on out-of-range values.
        let ts_val: Value = r.get(1)?;
        let ts = expect_timestamp(&ts_val).unwrap_or_default();
        Ok(EventRowLite {
            id: r.get(0)?,
            ts,
            process: r.get(2)?,
            dst_host: r.get(3)?,
            dst_ip: r.get(4)?,
            dst_port: r.get(5)?,
            action: r.get(6)?,
            matched_rule: r.get(7)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

struct GroupedRow {
    process: Option<String>,
    dst: Option<String>,
    count: u64,
    first_ts: NaiveDateTime,
    last_ts: NaiveDateTime,
    evidence_ids: Vec<u64>,
}

struct DnsRowLite {
    id: u64,
    ts: NaiveDateTime,
    process: String,
    qname: String,
    qtype: Option<i32>,
    server: Option<String>,
    answer_ip: Option<String>,
    kind: String,
}

/// DuckDB returns array-aggregated columns as `Value::List`. Map them into
/// `Vec<u64>`; non-numeric or null entries are silently dropped.
fn read_evidence_list(v: &Value) -> Vec<u64> {
    match v {
        Value::List(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::UBigInt(n) => Some(*n),
                Value::BigInt(n) => Some(*n as u64),
                Value::UInt(n) => Some(*n as u64),
                Value::Int(n) => Some(*n as u64),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
