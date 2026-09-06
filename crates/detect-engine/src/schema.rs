//! Schema migration for the alert tables. Lives next to the events tables in
//! the same per-log DuckDB file, so a single `Connection` powers everything.

use duckdb::Connection;

use crate::error::DetectResult;

pub const ALERT_SCHEMA_VERSION: u32 = 1;

pub fn init(conn: &Connection) -> DetectResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS alerts (
          id          UBIGINT PRIMARY KEY,
          rule_id     VARCHAR NOT NULL,
          rule_title  VARCHAR NOT NULL,
          severity    VARCHAR NOT NULL,
          mitre       VARCHAR,           -- comma-separated tags
          ts          TIMESTAMP NOT NULL,
          process     VARCHAR,
          dst         VARCHAR,
          detail      VARCHAR,           -- JSON
          triage      VARCHAR DEFAULT 'new'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_rule    ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_sev     ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_triage  ON alerts(triage);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(ts);

        CREATE TABLE IF NOT EXISTS alert_evidence (
          alert_id  UBIGINT NOT NULL,
          event_id  UBIGINT NOT NULL,
          PRIMARY KEY (alert_id, event_id)
        );
        "#,
    )?;
    Ok(())
}

/// Wipe alert state so a fresh hunt run starts from zero. Keeps event tables
/// untouched.
pub fn reset(conn: &Connection) -> DetectResult<()> {
    conn.execute_batch("DELETE FROM alert_evidence; DELETE FROM alerts;")?;
    Ok(())
}
