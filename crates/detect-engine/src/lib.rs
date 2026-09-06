//! Detection engine.
//!
//! Runs the built-in catalog (and, in the future, user-authored YAML rules)
//! against a [`log_ingest::LogStore`]. Results are persisted in two new
//! tables in the same DuckDB file, so subsequent UI launches can show the
//! alert inbox without re-running anything.
//!
//! # Architecture
//!
//! Each detection rule is a small Rust value ([`rule::DetectionRule`]) that
//! describes what SQL to execute and how to map the result rows to alerts.
//! Rules run in isolation from one another; there is no cross-rule
//! correlation.
//!
//! Rules ship as inline Rust because the catalog is small (≈ 18) and we
//! avoid pulling a YAML dep for what is essentially compile-time data. A
//! future YAML-loader can sit alongside [`builtin::all_rules`].

pub mod alert;
pub mod builtin;
pub mod error;
pub mod eval;
pub mod loader;
pub mod rule;
pub mod schema;

pub use alert::{Alert, AlertEvidence, AlertTriage, list_alerts, list_evidence, set_triage};
pub use builtin::all_rules;
pub use error::{DetectError, DetectResult};
pub use eval::{HuntRunReport, RulePerRuleStat, run_all_rules};
pub use loader::{
    UserRule, default_dir as default_rule_dir, load_dir as load_rule_dir, parse_yaml,
};
pub use rule::{DetectionRule, GroupBy, RuleQuery, RuleSource, Severity};
pub use schema::init as init_schema;
