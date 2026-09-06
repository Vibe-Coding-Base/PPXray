//! Detection rule data model.
//!
//! Rules use owned `String` fields so the same struct holds:
//! - **Built-in catalog** entries (literal `.into()` at startup, see
//!   [`crate::builtin::all_rules`]).
//! - **User-authored YAML** rules deserialized at runtime from the
//!   configured rule directory.
//!
//! The handful of allocations at startup is negligible compared to a
//! single DuckDB query.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    Process,
    Dst,
    ProcessAndDst,
}

#[derive(Debug, Clone)]
pub enum RuleQuery {
    /// One alert per matching event row from the `events` table.
    EventsWhere { where_sql: String, max_per_run: u32 },
    /// Group `events` rows by the chosen dimension.
    EventsGrouped { where_sql: String, group_by: GroupBy, having_min_count: u32, max_per_run: u32 },
    /// One alert per matching DNS event from `dns_events`.
    DnsWhere { where_sql: String, max_per_run: u32 },
    /// Custom SQL — see column contract in `eval::run_custom`.
    Custom { select_sql: String },
}

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub mitre: Vec<String>,
    pub references: Vec<String>,
    pub query: RuleQuery,
    /// Whether this rule comes from the built-in catalog or a user file. The
    /// UI uses this to decide whether Edit / Delete actions are available.
    pub source: RuleSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    Builtin,
    /// Filename (relative to the configured rule dir) the rule was loaded from.
    UserFile(String),
}

impl RuleSource {
    pub fn is_user(&self) -> bool {
        matches!(self, Self::UserFile(_))
    }
    pub fn filename(&self) -> Option<&str> {
        match self {
            Self::UserFile(s) => Some(s),
            Self::Builtin => None,
        }
    }
}
