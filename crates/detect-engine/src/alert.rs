//! Alert types + persistence.

use chrono::NaiveDateTime;
use duckdb::params;
use log_ingest::LogStore;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::DetectResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum AlertTriage {
    #[serde(rename = "new")]
    New,
    /// True positive: the alert is correct and the analyst is acting on it.
    #[serde(rename = "tp")]
    TruePositive,
    /// False positive: noise. Future runs should suppress identical alerts.
    #[serde(rename = "fp")]
    FalsePositive,
    /// Suppressed by a per-rule allowlist. Hidden from inbox by default.
    #[serde(rename = "suppressed")]
    Suppressed,
}

impl AlertTriage {
    pub fn parse(s: &str) -> Self {
        match s {
            "tp" => Self::TruePositive,
            "fp" => Self::FalsePositive,
            "suppressed" => Self::Suppressed,
            _ => Self::New,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::TruePositive => "tp",
            Self::FalsePositive => "fp",
            Self::Suppressed => "suppressed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Alert {
    pub id: u64,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String, // "Low" | "Medium" | "High" | "Critical"
    /// Comma-separated MITRE tags.
    pub mitre: Option<String>,
    pub ts: String, // ISO 8601 (seconds precision)
    pub process: Option<String>,
    pub dst: Option<String>,
    /// JSON string with rule-specific evidence detail (count, jitter, etc.).
    pub detail: Option<String>,
    pub triage: AlertTriage,
    /// Evidence event count (filled by the read path; not stored on the row).
    pub evidence_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct AlertEvidence {
    pub event_id: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct AlertFilter {
    pub severities: Option<Vec<String>>,
    pub triage: Option<Vec<String>>,
    pub rule_ids: Option<Vec<String>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub fn list_alerts(store: &LogStore, f: &AlertFilter) -> DetectResult<Vec<Alert>> {
    let mut clauses: Vec<String> = Vec::new();
    if let Some(s) = &f.severities
        && !s.is_empty()
    {
        let placeholders: Vec<String> =
            s.iter().map(|x| format!("'{}'", x.replace('\'', "''"))).collect();
        clauses.push(format!("severity IN ({})", placeholders.join(",")));
    }
    if let Some(t) = &f.triage
        && !t.is_empty()
    {
        let placeholders: Vec<String> =
            t.iter().map(|x| format!("'{}'", x.replace('\'', "''"))).collect();
        clauses.push(format!("triage IN ({})", placeholders.join(",")));
    }
    if let Some(r) = &f.rule_ids
        && !r.is_empty()
    {
        let placeholders: Vec<String> =
            r.iter().map(|x| format!("'{}'", x.replace('\'', "''"))).collect();
        clauses.push(format!("rule_id IN ({})", placeholders.join(",")));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let limit = f.limit.unwrap_or(500).min(5000);
    let offset = f.offset.unwrap_or(0);

    let sql = format!(
        "SELECT a.id, a.rule_id, a.rule_title, a.severity, a.mitre, a.ts,
                a.process, a.dst, a.detail, a.triage,
                (SELECT COUNT(*) FROM alert_evidence e WHERE e.alert_id = a.id) AS ec
         FROM alerts a{where_clause}
         ORDER BY
           CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                         WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END DESC,
           ts DESC
         LIMIT {limit} OFFSET {offset}"
    );

    store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                let ts: NaiveDateTime = row.get(5)?;
                Ok(Alert {
                    id: row.get::<_, u64>(0)?,
                    rule_id: row.get(1)?,
                    rule_title: row.get(2)?,
                    severity: row.get(3)?,
                    mitre: row.get(4)?,
                    ts: ts.format("%Y-%m-%dT%H:%M:%S").to_string(),
                    process: row.get(6)?,
                    dst: row.get(7)?,
                    detail: row.get(8)?,
                    triage: AlertTriage::parse(&row.get::<_, String>(9)?),
                    evidence_count: row.get::<_, i64>(10)? as u32,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
        .map_err(Into::into)
}

pub fn list_evidence(store: &LogStore, alert_id: u64, limit: u32) -> DetectResult<Vec<u64>> {
    store
        .with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT event_id FROM alert_evidence WHERE alert_id = ? ORDER BY event_id LIMIT ?",
            )?;
            let rows = stmt.query_map(params![alert_id, limit], |r| r.get::<_, u64>(0))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
        .map_err(Into::into)
}

pub fn set_triage(store: &LogStore, alert_id: u64, triage: AlertTriage) -> DetectResult<()> {
    store
        .with_conn(|conn| {
            conn.execute(
                "UPDATE alerts SET triage = ? WHERE id = ?",
                params![triage.as_str(), alert_id],
            )?;
            Ok(())
        })
        .map_err(Into::into)
}
