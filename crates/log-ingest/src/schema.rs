//! DuckDB schema and migrations.
//!
//! One database file per log file, so opening a different log cannot mix
//! state and deleting an old analysis is deleting a file.
//!
//! The database is a cache derived from a `.txt` the user still has, so a
//! schema mismatch drops every table and rebuilds rather than migrating in
//! place. Re-ingesting costs seconds; a subtly wrong column costs a wrong
//! answer in a security tool.
//!
//! There are deliberately no indexes. Every query here and every detection
//! rule is an aggregate over a large row range, which DuckDB answers by
//! scanning with zonemaps; the ART indexes `CREATE INDEX` and `PRIMARY KEY`
//! build only pay for selective point lookups, and cost build time and memory
//! during bulk load. `id` is a plain `UBIGINT` counter written by the only
//! writer.
use duckdb::{Connection, params};

use crate::error::IngestResult;

/// Bump whenever the shape of `events` / `dns_events` / `ingest_runs`
/// changes. Any DB stamped with a different value is dropped and rebuilt by
/// [`init`], so a stale file can never answer a query with the wrong
/// columns.
///
/// * 1 — initial schema.
/// * 2 — dropped all ART indexes and the `PRIMARY KEY`s on the event tables.
pub const CURRENT_VERSION: u32 = 2;

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS _schema_version (
  version UINTEGER PRIMARY KEY,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
  id           UBIGINT NOT NULL,
  ts           TIMESTAMP NOT NULL,
  process      VARCHAR NOT NULL,
  pid          INTEGER,
  parent       VARCHAR,
  proto        VARCHAR NOT NULL,       -- 'TCP' | 'UDP' | 'ICMP'
  ipv6         BOOLEAN NOT NULL,
  dst_host     VARCHAR,
  dst_ip       VARCHAR,
  dst_port     INTEGER,
  matched_rule VARCHAR,
  action       VARCHAR NOT NULL,       -- 'Direct' | 'Proxy' | 'Block' | 'Other'
  raw_offset   UBIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_events (
  id           UBIGINT NOT NULL,
  ts           TIMESTAMP NOT NULL,
  process      VARCHAR NOT NULL,
  pid          INTEGER,
  qname        VARCHAR NOT NULL,
  qtype        INTEGER,
  server       VARCHAR,
  answer_ip    VARCHAR,
  ttl          UINTEGER,
  kind         VARCHAR NOT NULL,       -- 'Request' | 'Response' | 'EmptyResponse' | 'Resolve'
  raw_offset   UBIGINT NOT NULL
);

-- Source log file metadata. One row per ingest run.
CREATE TABLE IF NOT EXISTS ingest_runs (
  id            BIGINT NOT NULL,
  source_path   VARCHAR NOT NULL,
  source_size   UBIGINT NOT NULL,
  source_mtime  TIMESTAMP,
  ingested_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  total_events  UBIGINT,
  total_dns     UBIGINT,
  duration_ms   UBIGINT
);
"#;

/// Every table this database file may hold, newest-dependency first.
///
/// `alerts` / `alert_evidence` belong to `detect-engine`, not to this crate,
/// but they live in the same file and `alert_evidence.event_id` references
/// `events.id`. A rebuild renumbers those ids, so leaving the alert tables
/// behind would leave evidence pointing at unrelated rows. Dropping them
/// here is the honest option: the user re-runs the hunt, which is a
/// sub-second operation.
const ALL_TABLES: &[&str] =
    &["alert_evidence", "alerts", "ingest_runs", "dns_events", "events", "_schema_version"];

/// Open-time migration. Creates the schema on a fresh file; drops and
/// recreates it when the file was written by a build with a different
/// [`CURRENT_VERSION`].
pub fn init(conn: &Connection) -> IngestResult<()> {
    match on_disk_version(conn) {
        // Fresh file, or one predating the version table.
        None => {
            drop_all(conn)?;
            create(conn)?;
        }
        Some(v) if v == CURRENT_VERSION => {
            // Still create: covers a file stamped with the right version
            // whose tables were dropped out from under us.
            create(conn)?;
        }
        Some(stale) => {
            tracing::info!(
                from = stale,
                to = CURRENT_VERSION,
                "log DB schema is stale — dropping and rebuilding"
            );
            drop_all(conn)?;
            create(conn)?;
        }
    }
    Ok(())
}

/// The version stamped in the file, or `None` if the file has no
/// `_schema_version` table (fresh) or an empty one.
fn on_disk_version(conn: &Connection) -> Option<u32> {
    conn.query_row("SELECT MAX(version) FROM _schema_version", [], |r| r.get::<_, Option<u32>>(0))
        .ok()
        .flatten()
}

fn create(conn: &Connection) -> IngestResult<()> {
    conn.execute_batch(CREATE_TABLES)?;
    conn.execute(
        "INSERT INTO _schema_version(version) SELECT ?
         WHERE NOT EXISTS (SELECT 1 FROM _schema_version WHERE version = ?)",
        params![CURRENT_VERSION, CURRENT_VERSION],
    )?;
    Ok(())
}

fn drop_all(conn: &Connection) -> IngestResult<()> {
    for table in ALL_TABLES {
        conn.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
    }
    Ok(())
}

/// Wipe ingested data so we can re-ingest from scratch.
///
/// `DROP` + recreate rather than `DELETE`: DuckDB does not return the space
/// freed by a `DELETE` to the operating system, so the "open log → re-ingest"
/// loop would grow the file without bound. Dropping the table releases its
/// blocks back to the file's free list.
pub fn truncate_events(conn: &Connection) -> IngestResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS alert_evidence;
         DROP TABLE IF EXISTS alerts;
         DROP TABLE IF EXISTS ingest_runs;
         DROP TABLE IF EXISTS dns_events;
         DROP TABLE IF EXISTS events;",
    )?;
    conn.execute_batch(CREATE_TABLES)?;
    Ok(())
}
