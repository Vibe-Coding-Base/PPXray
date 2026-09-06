//! Running a query this crate did not write.
//!
//! Every other query here has a fixed projection that maps onto a struct.
//! This statement comes from the assistant in `llm-bridge` and its columns
//! are whatever the model asked for, so the result is column names plus JSON
//! cells.
//!
//! Nothing here validates the SQL, deliberately: `llm_bridge::sql_guard`
//! rejects anything but a single read-only statement, the caller wraps what
//! survives in `SELECT * FROM ( … ) LIMIT n`, and [`crate::store`]'s `harden`
//! has already revoked external access on this connection.

use duckdb::types::ValueRef;
use serde_json::Value as Json;

use crate::error::IngestResult;
use crate::store::LogStore;

/// A result set with a shape known only at runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct AdhocResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Json>>,
}

/// Execute `sql` and collect up to `max_rows` rows.
///
/// `max_rows` is enforced here as well as in the wrapping `LIMIT`, because
/// the wrap is the caller's responsibility and a caller that forgets it
/// should still not be able to pull a ten-million-row table into memory.
pub fn run(store: &LogStore, sql: &str, max_rows: usize) -> IngestResult<AdhocResult> {
    // A scratch connection: see `LogStore::with_scratch_conn` for why a bad
    // statement must not be able to reach the handle the app runs on.
    store.with_scratch_conn(|conn| {
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

        let mut columns: Vec<String> = Vec::new();
        let mut out: Vec<Vec<Json>> = Vec::new();

        while let Some(row) = rows.next()? {
            // Column names are only available once a statement has produced
            // a row; asking before that returns an empty list on some
            // DuckDB versions.
            if columns.is_empty() {
                columns = row.as_ref().column_names().into_iter().map(|c| c.to_string()).collect();
            }
            let mut cells = Vec::with_capacity(columns.len());
            for i in 0..columns.len() {
                cells.push(to_json(row.get_ref(i)?));
            }
            out.push(cells);
            if out.len() >= max_rows {
                break;
            }
        }

        // A query that matched nothing still has columns, and the UI needs
        // them to render an empty table rather than nothing at all.
        if columns.is_empty() {
            columns = stmt.column_names().into_iter().map(|c| c.to_string()).collect();
        }

        Ok(AdhocResult { columns, rows: out })
    })
}

/// Convert one DuckDB cell to JSON.
///
/// Numbers stay numbers so the UI can right-align them and the model can do
/// arithmetic on them.
///
/// Temporal types get an explicit arm rather than falling through to the
/// catch-all. `Debug` renders a timestamp as `Timestamp(Microsecond,
/// 1704103200000000)`, which is not a date to a reader and not a date to a
/// model either — it would happily "interpret" it.
fn to_json(v: ValueRef<'_>) -> Json {
    match v {
        ValueRef::Null => Json::Null,
        ValueRef::Boolean(b) => Json::Bool(b),
        ValueRef::TinyInt(n) => Json::from(n),
        ValueRef::SmallInt(n) => Json::from(n),
        ValueRef::Int(n) => Json::from(n),
        ValueRef::BigInt(n) => Json::from(n),
        ValueRef::HugeInt(n) => Json::String(n.to_string()),
        ValueRef::UTinyInt(n) => Json::from(n),
        ValueRef::USmallInt(n) => Json::from(n),
        ValueRef::UInt(n) => Json::from(n),
        ValueRef::UBigInt(n) => Json::from(n),
        ValueRef::Float(n) => Json::from(n),
        ValueRef::Double(n) => Json::from(n),
        ValueRef::Text(bytes) => Json::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Json::String(format!("<{} bytes>", bytes.len())),
        ValueRef::Timestamp(unit, n) => timestamp_to_json(unit, n),
        ValueRef::Date32(days) => chrono::DateTime::from_timestamp(i64::from(days) * 86_400, 0)
            .map(|d| Json::String(d.date_naive().to_string()))
            .unwrap_or(Json::Null),
        other => Json::String(format!("{:?}", duckdb::types::Value::from(other))),
    }
}

fn timestamp_to_json(unit: duckdb::types::TimeUnit, n: i64) -> Json {
    use duckdb::types::TimeUnit;
    let (secs, nanos) = match unit {
        TimeUnit::Second => (n, 0),
        TimeUnit::Millisecond => (n.div_euclid(1_000), n.rem_euclid(1_000) * 1_000_000),
        TimeUnit::Microsecond => (n.div_euclid(1_000_000), n.rem_euclid(1_000_000) * 1_000),
        TimeUnit::Nanosecond => (n.div_euclid(1_000_000_000), n.rem_euclid(1_000_000_000)),
    };
    match chrono::DateTime::from_timestamp(secs, nanos as u32) {
        // The log's timestamps carry no timezone, so neither does this: it
        // is rendered as the wall-clock value that was written in the file.
        Some(dt) => Json::String(dt.naive_utc().format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
        None => Json::Null,
    }
}

/// A description of the live schema, for a prompt that must not drift.
///
/// Read from `information_schema` rather than written by hand: the tables
/// here are created by [`crate::schema`] and dropped and rebuilt whenever
/// its version changes, so a hard-coded copy in a prompt would eventually
/// have the assistant writing queries against columns that no longer exist.
///
/// The value semantics below are the part `information_schema` cannot
/// supply, and they are what stops the model inventing `action = 'ALLOW'`.
pub fn schema_description(store: &LogStore) -> IngestResult<String> {
    use std::fmt::Write as _;

    let mut out = String::new();
    store.with_conn(|conn| {
        // `_schema_version` is this crate's migration bookkeeping. Listing
        // it would only invite questions about it.
        let mut stmt = conn.prepare(
            "SELECT table_name, column_name, data_type
             FROM information_schema.columns
             WHERE table_schema = 'main' AND NOT starts_with(table_name, '_')
             ORDER BY table_name, ordinal_position",
        )?;
        let mut rows = stmt.query([])?;
        let mut current = String::new();
        while let Some(row) = rows.next()? {
            let table: String = row.get(0)?;
            let column: String = row.get(1)?;
            let ty: String = row.get(2)?;
            if table != current {
                if !current.is_empty() {
                    out.push_str("\n);\n\n");
                }
                let _ = writeln!(out, "CREATE TABLE {table} (");
                current = table;
            } else {
                out.push_str(",\n");
            }
            let _ = write!(out, "  {column} {ty}");
        }
        if !current.is_empty() {
            out.push_str("\n);\n");
        }
        Ok(())
    })?;

    out.push_str(COLUMN_SEMANTICS);
    Ok(out)
}

/// What the column types do not say.
const COLUMN_SEMANTICS: &str = r#"
Value semantics:
* events.action is exactly one of 'Direct', 'Proxy', 'Block', 'Other'.
* events.proto is 'TCP', 'UDP' or 'ICMP'.
* events.dst_host is NULL when the connection carried no hostname, in which
  case events.dst_ip holds a literal address. Both can be non-NULL.
* events.matched_rule is the name of the Proxifier rule that won, or NULL if
  the log line recorded none.
* dns_events.kind is 'Request', 'Response', 'EmptyResponse' or 'Resolve'.
* alerts and alert_evidence exist only after the user has run a hunt, and may
  be empty. alert_evidence.event_id joins events.id.
* One row in ingest_runs per ingest of the source file.
* Timestamps are local time as written in the log, with no timezone.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::open_store;

    fn store() -> (tempfile::TempDir, LogStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir.path().join("t.duckdb")).unwrap();
        store
            .with_conn(|conn| {
                conn.execute_batch(
                    "INSERT INTO events VALUES
                       (1, TIMESTAMP '2024-01-01 10:00:00', 'a.exe', 10, NULL, 'TCP',
                        false, 'example.com', '1.2.3.4', 443, 'r1', 'Direct', 0),
                       (2, TIMESTAMP '2024-01-01 10:00:01', 'b.exe', 11, NULL, 'TCP',
                        false, NULL, '5.6.7.8', 80, NULL, 'Block', 1);",
                )?;
                Ok(())
            })
            .unwrap();
        (dir, store)
    }

    #[test]
    fn columns_and_typed_cells_come_back() {
        let (_dir, store) = store();
        let r =
            run(&store, "SELECT process, dst_port, dst_host FROM events ORDER BY id", 100).unwrap();
        assert_eq!(r.columns, vec!["process", "dst_port", "dst_host"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0], Json::String("a.exe".into()));
        // A port is a number, not a string.
        assert_eq!(r.rows[0][1], Json::from(443));
        // A NULL host is JSON null, not the string "null".
        assert_eq!(r.rows[1][2], Json::Null);
    }

    #[test]
    fn the_row_cap_is_enforced_here_too() {
        let (_dir, store) = store();
        // No LIMIT in the statement: the cap has to come from this function.
        let r = run(&store, "SELECT * FROM events", 1).unwrap();
        assert_eq!(r.rows.len(), 1);
    }

    #[test]
    fn an_empty_result_still_reports_its_columns() {
        let (_dir, store) = store();
        let r = run(&store, "SELECT process, dst_host FROM events WHERE 1 = 0", 10).unwrap();
        assert!(r.rows.is_empty());
        assert_eq!(r.columns, vec!["process", "dst_host"]);
    }

    #[test]
    fn timestamps_render_rather_than_failing() {
        let (_dir, store) = store();
        let r = run(&store, "SELECT ts FROM events ORDER BY id LIMIT 1", 10).unwrap();
        let cell = r.rows[0][0].as_str().expect("timestamp rendered as text");
        // The wall-clock value from the log, not a microsecond counter.
        assert_eq!(cell, "2024-01-01 10:00:00.000");
    }

    #[test]
    fn the_schema_description_reflects_the_real_tables() {
        let (_dir, store) = store();
        let text = schema_description(&store).unwrap();
        assert!(text.contains("CREATE TABLE events"));
        assert!(text.contains("dst_host"));
        assert!(text.contains("CREATE TABLE dns_events"));
        // Internal bookkeeping is not something to ask questions about.
        assert!(!text.contains("_schema_version"));
        // The semantics the type list cannot carry.
        assert!(text.contains("'Direct', 'Proxy', 'Block', 'Other'"));
    }

    #[test]
    fn the_sandbox_still_applies_to_queries_that_arrive_here() {
        // The guard in llm-bridge lets `read_csv` through — it is a legal
        // SELECT. This is the layer that actually stops it.
        let (_dir, store) = store();
        let err = run(&store, "SELECT * FROM read_csv('/etc/passwd')", 10).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("Permission Error") || text.contains("permission"),
            "expected the sandbox to refuse, got: {text}"
        );
    }
}

#[cfg(test)]
mod regression {
    use super::*;
    use crate::store::open_store;

    /// A statement that fails to parse must not take the connection with it.
    ///
    /// Reported from the assistant: one malformed query, and every query
    /// after it in the session failed with DuckDB's "resource deadlock would
    /// occur" — so a single bad guess by the model bricked the feature until
    /// the app was restarted.
    #[test]
    fn a_failed_statement_leaves_the_connection_usable() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir.path().join("t.duckdb")).unwrap();

        let first = run(&store, "SELECT * FROM events WHERE x =", 10);
        assert!(first.is_err(), "the malformed statement should fail");

        let second = run(&store, "SELECT COUNT(*) FROM events", 10);
        assert!(second.is_ok(), "the next query failed too: {:?}", second.err());
    }

    /// Many failures in a row must neither degrade the connection nor abort.
    ///
    /// The abort is the sharper half: a connection that hit a parse error
    /// throws from its C++ destructor, and that exception crossing into Rust
    /// kills the process outright. This test would have caught the crash as
    /// well as the deadlock.
    #[test]
    fn repeated_failures_do_not_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(&dir.path().join("t.duckdb")).unwrap();

        for _ in 0..3 {
            assert!(run(&store, "SELECT nope FROM nowhere", 10).is_err());
        }
        assert!(run(&store, "SELECT 1", 10).is_ok(), "connection did not recover");
    }
}
