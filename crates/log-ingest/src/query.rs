//! Query layer: filters, pagination, aggregates.
//!
//! All parameter values are bound (not string-concatenated) even though
//! DuckDB queries happen in-process and are technically free from injection;
//! keeping the habit means these helpers port cleanly to any future remote
//! query surface.

use chrono::NaiveDateTime;
use duckdb::types::Value;
use duckdb::{Connection, params_from_iter};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::IngestResult;
use crate::store::LogStore;

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct EventFilter {
    /// ISO 8601 (e.g. `2026-04-17T23:30:00`). Inclusive.
    pub ts_from: Option<String>,
    /// Inclusive upper bound.
    pub ts_to: Option<String>,
    pub processes: Option<Vec<String>>,
    pub matched_rules: Option<Vec<String>>,
    pub actions: Option<Vec<String>>,
    /// Substring match on `dst_host` OR `dst_ip` (case-insensitive).
    pub host_contains: Option<String>,
    pub protos: Option<Vec<String>>,
    pub ipv6: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Compile a `EventFilter` to `(where_clause, params)`. Returns an empty
/// `WHERE` if the filter is empty.
fn where_clause(f: &EventFilter) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Value> = Vec::new();

    if let Some(from) = &f.ts_from
        && let Ok(ts) = NaiveDateTime::parse_from_str(from, "%Y-%m-%dT%H:%M:%S")
    {
        clauses.push("ts >= ?".into());
        params.push(Value::Timestamp(
            duckdb::types::TimeUnit::Microsecond,
            ts.and_utc().timestamp_micros(),
        ));
    }
    if let Some(to) = &f.ts_to
        && let Ok(ts) = NaiveDateTime::parse_from_str(to, "%Y-%m-%dT%H:%M:%S")
    {
        clauses.push("ts <= ?".into());
        params.push(Value::Timestamp(
            duckdb::types::TimeUnit::Microsecond,
            ts.and_utc().timestamp_micros(),
        ));
    }
    if let Some(procs) = &f.processes
        && !procs.is_empty()
    {
        let placeholders = vec!["?"; procs.len()].join(",");
        clauses.push(format!("process IN ({placeholders})"));
        for p in procs {
            params.push(Value::Text(p.clone()));
        }
    }
    if let Some(rs) = &f.matched_rules
        && !rs.is_empty()
    {
        let placeholders = vec!["?"; rs.len()].join(",");
        clauses.push(format!("matched_rule IN ({placeholders})"));
        for p in rs {
            params.push(Value::Text(p.clone()));
        }
    }
    if let Some(as_) = &f.actions
        && !as_.is_empty()
    {
        let placeholders = vec!["?"; as_.len()].join(",");
        clauses.push(format!("action IN ({placeholders})"));
        for p in as_ {
            params.push(Value::Text(p.clone()));
        }
    }
    if let Some(ps) = &f.protos
        && !ps.is_empty()
    {
        let placeholders = vec!["?"; ps.len()].join(",");
        clauses.push(format!("proto IN ({placeholders})"));
        for p in ps {
            params.push(Value::Text(p.clone()));
        }
    }
    if let Some(ipv6) = f.ipv6 {
        clauses.push("ipv6 = ?".into());
        params.push(Value::Boolean(ipv6));
    }
    if let Some(needle) = &f.host_contains
        && !needle.is_empty()
    {
        clauses.push(
            "(COALESCE(LOWER(dst_host),'') LIKE ? OR COALESCE(LOWER(dst_ip),'') LIKE ?)".into(),
        );
        let pat = format!("%{}%", needle.to_lowercase());
        params.push(Value::Text(pat.clone()));
        params.push(Value::Text(pat));
    }

    let clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    (clause, params)
}

// ---------------------------------------------------------------------------
// Row types + queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct EventRow {
    pub id: u64,
    /// ISO 8601 (seconds precision).
    pub ts: String,
    pub process: String,
    pub pid: Option<u32>,
    pub parent: Option<String>,
    pub proto: String,
    pub ipv6: bool,
    pub dst_host: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u32>,
    pub matched_rule: Option<String>,
    pub action: String,
    pub raw_offset: u64,
}

pub fn query_events(store: &LogStore, f: &EventFilter) -> IngestResult<Vec<EventRow>> {
    let (where_sql, params) = where_clause(f);
    let limit = f.limit.unwrap_or(500).min(10_000);
    let offset = f.offset.unwrap_or(0);
    let sql = format!(
        "SELECT id, ts, process, pid, parent, proto, ipv6, dst_host, dst_ip, dst_port,
                matched_rule, action, raw_offset
         FROM events{where_sql}
         ORDER BY ts DESC, id DESC
         LIMIT {limit} OFFSET {offset}"
    );

    store.with_conn(|conn| {
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
            let ts: NaiveDateTime = row.get(1)?;
            Ok(EventRow {
                id: row.get::<_, u64>(0)?,
                ts: ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
                process: row.get(2)?,
                pid: row.get::<_, Option<i32>>(3)?.map(|v| v as u32),
                parent: row.get(4)?,
                proto: row.get(5)?,
                ipv6: row.get(6)?,
                dst_host: row.get(7)?,
                dst_ip: row.get(8)?,
                dst_port: row.get::<_, Option<i32>>(9)?.map(|v| v as u32),
                matched_rule: row.get(10)?,
                action: row.get(11)?,
                raw_offset: row.get(12)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    })
}

pub fn count_events(store: &LogStore, f: &EventFilter) -> IngestResult<u64> {
    store.with_conn(|c| count_events_on(c, f))
}

fn count_events_on(conn: &Connection, f: &EventFilter) -> IngestResult<u64> {
    let (where_sql, params) = where_clause(f);
    let sql = format!("SELECT COUNT(*) FROM events{where_sql}");
    let count: i64 = conn.query_row(&sql, params_from_iter(params.iter()), |r| r.get(0))?;
    Ok(count as u64)
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct LogStats {
    pub total_events: u64,
    pub total_dns: u64,
    pub distinct_processes: u64,
    pub distinct_hosts: u64,
    pub distinct_rules: u64,
    /// First and last event timestamps as ISO 8601.
    pub span_start: Option<String>,
    pub span_end: Option<String>,
    pub blocked_count: u64,
    pub direct_count: u64,
    pub proxy_count: u64,
}

pub fn stats(store: &LogStore) -> IngestResult<LogStats> {
    store.with_conn(|conn| {
        let total_events: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        let total_dns: i64 = conn.query_row("SELECT COUNT(*) FROM dns_events", [], |r| r.get(0))?;
        let distinct_processes: i64 =
            conn.query_row("SELECT COUNT(DISTINCT process) FROM events", [], |r| r.get(0))?;
        let distinct_hosts: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT COALESCE(dst_host, dst_ip)) FROM events",
            [],
            |r| r.get(0),
        )?;
        let distinct_rules: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT matched_rule) FROM events WHERE matched_rule IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        let span: (Option<NaiveDateTime>, Option<NaiveDateTime>) = conn
            .query_row("SELECT MIN(ts), MAX(ts) FROM events", [], |r| {
                Ok((r.get(0).ok(), r.get(1).ok()))
            })
            .unwrap_or((None, None));

        let mut blocked = 0i64;
        let mut direct = 0i64;
        let mut proxy = 0i64;
        let mut stmt = conn.prepare("SELECT action, COUNT(*) FROM events GROUP BY action")?;
        let rows = stmt.query_map([], |r| {
            let action: String = r.get(0)?;
            let count: i64 = r.get(1)?;
            Ok((action, count))
        })?;
        for pair in rows {
            let (a, c) = pair?;
            match a.as_str() {
                "Block" => blocked = c,
                "Direct" => direct = c,
                "Proxy" => proxy = c,
                _ => {}
            }
        }

        Ok(LogStats {
            total_events: total_events as u64,
            total_dns: total_dns as u64,
            distinct_processes: distinct_processes as u64,
            distinct_hosts: distinct_hosts as u64,
            distinct_rules: distinct_rules as u64,
            span_start: span.0.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            span_end: span.1.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            blocked_count: blocked as u64,
            direct_count: direct as u64,
            proxy_count: proxy as u64,
        })
    })
}

// ---------------------------------------------------------------------------
// Per-dimension aggregates (top-N lists)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ProcessCount {
    pub process: String,
    pub count: u64,
    pub distinct_hosts: u64,
}

pub fn top_processes(
    store: &LogStore,
    f: &EventFilter,
    limit: u32,
) -> IngestResult<Vec<ProcessCount>> {
    store.with_conn(|c| top_processes_on(c, f, limit))
}

fn top_processes_on(
    conn: &Connection,
    f: &EventFilter,
    limit: u32,
) -> IngestResult<Vec<ProcessCount>> {
    let (where_sql, params) = where_clause(f);
    let sql = format!(
        "SELECT process, COUNT(*) AS c,
                COUNT(DISTINCT COALESCE(dst_host, dst_ip)) AS dh
         FROM events{where_sql}
         GROUP BY process
         ORDER BY c DESC
         LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
        Ok(ProcessCount {
            process: r.get(0)?,
            count: r.get::<_, i64>(1)? as u64,
            distinct_hosts: r.get::<_, i64>(2)? as u64,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct RuleCount {
    pub rule: String,
    pub count: u64,
    pub distinct_processes: u64,
    pub last_match: Option<String>,
}

pub fn top_rules(store: &LogStore, f: &EventFilter, limit: u32) -> IngestResult<Vec<RuleCount>> {
    store.with_conn(|c| top_rules_on(c, f, limit))
}

fn top_rules_on(conn: &Connection, f: &EventFilter, limit: u32) -> IngestResult<Vec<RuleCount>> {
    let (where_sql, params) = where_clause(f);
    let sql = format!(
        "SELECT COALESCE(matched_rule, '(none)') AS rule,
                COUNT(*) AS c,
                COUNT(DISTINCT process) AS dp,
                MAX(ts) AS last_match
         FROM events{where_sql}
         GROUP BY rule
         ORDER BY c DESC
         LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
        let last_ts: Option<NaiveDateTime> = r.get(3)?;
        Ok(RuleCount {
            rule: r.get(0)?,
            count: r.get::<_, i64>(1)? as u64,
            distinct_processes: r.get::<_, i64>(2)? as u64,
            last_match: last_ts.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct HostCount {
    pub host: String,
    pub count: u64,
    pub distinct_processes: u64,
}

pub fn top_hosts(store: &LogStore, f: &EventFilter, limit: u32) -> IngestResult<Vec<HostCount>> {
    store.with_conn(|c| top_hosts_on(c, f, limit))
}

fn top_hosts_on(conn: &Connection, f: &EventFilter, limit: u32) -> IngestResult<Vec<HostCount>> {
    let (where_sql, params) = where_clause(f);
    let sql = format!(
        "SELECT COALESCE(dst_host, dst_ip, '(unknown)') AS host,
                COUNT(*) AS c,
                COUNT(DISTINCT process) AS dp
         FROM events{where_sql}
         GROUP BY host
         ORDER BY c DESC
         LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
        Ok(HostCount {
            host: r.get(0)?,
            count: r.get::<_, i64>(1)? as u64,
            distinct_processes: r.get::<_, i64>(2)? as u64,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct TimeBucket {
    pub ts: String,
    pub direct: u64,
    pub proxy: u64,
    pub block: u64,
    pub other: u64,
}

/// Bucket size in seconds. For display we typically pick so that ~200
/// buckets cover the visible range.
pub fn timeline(
    store: &LogStore,
    f: &EventFilter,
    bucket_secs: u32,
) -> IngestResult<Vec<TimeBucket>> {
    store.with_conn(|c| timeline_on(c, f, bucket_secs))
}

fn timeline_on(
    conn: &Connection,
    f: &EventFilter,
    bucket_secs: u32,
) -> IngestResult<Vec<TimeBucket>> {
    let bucket_secs = bucket_secs.max(1);
    let (where_sql, params) = where_clause(f);
    // DuckDB `time_bucket` snaps to a regular grid.
    let sql = format!(
        "SELECT time_bucket(INTERVAL '{bucket_secs} seconds', ts) AS bucket,
                SUM(CASE WHEN action = 'Direct' THEN 1 ELSE 0 END) AS direct,
                SUM(CASE WHEN action = 'Proxy'  THEN 1 ELSE 0 END) AS proxy,
                SUM(CASE WHEN action = 'Block'  THEN 1 ELSE 0 END) AS block,
                SUM(CASE WHEN action NOT IN ('Direct','Proxy','Block') THEN 1 ELSE 0 END) AS other
         FROM events{where_sql}
         GROUP BY bucket
         ORDER BY bucket"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |r| {
        let ts: NaiveDateTime = r.get(0)?;
        Ok(TimeBucket {
            ts: ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
            direct: r.get::<_, i64>(1)? as u64,
            proxy: r.get::<_, i64>(2)? as u64,
            block: r.get::<_, i64>(3)? as u64,
            other: r.get::<_, i64>(4)? as u64,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Facet lists for the filter bar dropdowns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct FacetValues {
    pub processes: Vec<String>,
    pub rules: Vec<String>,
    pub actions: Vec<String>,
    pub protos: Vec<String>,
}

pub fn facets(store: &LogStore) -> IngestResult<FacetValues> {
    store.with_conn(|conn| {
        let mut processes = Vec::new();
        let mut stmt =
            conn.prepare("SELECT DISTINCT process FROM events ORDER BY process LIMIT 1000")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for r in rows {
            processes.push(r?);
        }

        let mut rules = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT matched_rule FROM events
             WHERE matched_rule IS NOT NULL
             ORDER BY matched_rule",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for r in rows {
            rules.push(r?);
        }

        let mut actions = Vec::new();
        let mut stmt = conn.prepare("SELECT DISTINCT action FROM events ORDER BY action")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for r in rows {
            actions.push(r?);
        }

        let mut protos = Vec::new();
        let mut stmt = conn.prepare("SELECT DISTINCT proto FROM events ORDER BY proto")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for r in rows {
            protos.push(r?);
        }

        Ok(FacetValues { processes, rules, actions, protos })
    })
}

// ---------------------------------------------------------------------------
// Combined dashboard read
// ---------------------------------------------------------------------------

/// Everything the log dashboard redraws when the filter changes.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct LogDashboard {
    /// Rows matching the filter — the denominator the events table shows.
    pub total_matching: u64,
    pub top_processes: Vec<ProcessCount>,
    pub top_hosts: Vec<HostCount>,
    pub top_rules: Vec<RuleCount>,
    pub timeline: Vec<TimeBucket>,
}

/// Per-panel row caps, so the caller keeps control of how much it renders.
#[derive(Debug, Clone, Copy)]
pub struct DashboardLimits {
    pub processes: u32,
    pub hosts: u32,
    pub rules: u32,
    pub bucket_secs: u32,
}

impl Default for DashboardLimits {
    fn default() -> Self {
        Self { processes: 20, hosts: 25, rules: 50, bucket_secs: 60 }
    }
}

/// Answer every filter-dependent panel in one pass.
///
/// The UI previously issued five independent commands whenever the filter
/// changed — one per panel, plus the row count. Each took the store mutex,
/// crossed the IPC boundary, and re-scanned `events` from cold. Doing them
/// back to back under a single lock means DuckDB's buffer pool is already
/// warm for scans 2..n, and the renderer gets one atomic snapshot instead of
/// five that can disagree while they land.
///
/// Global counts ([`stats`]) deliberately stay out of this: they don't depend
/// on the filter, so re-running them on every keystroke would be pure waste.
pub fn dashboard(
    store: &LogStore,
    f: &EventFilter,
    limits: DashboardLimits,
) -> IngestResult<LogDashboard> {
    store.with_conn(|conn| {
        Ok(LogDashboard {
            total_matching: count_events_on(conn, f)?,
            top_processes: top_processes_on(conn, f, limits.processes)?,
            top_hosts: top_hosts_on(conn, f, limits.hosts)?,
            top_rules: top_rules_on(conn, f, limits.rules)?,
            timeline: timeline_on(conn, f, limits.bucket_secs)?,
        })
    })
}
