//! YAML loader for user-authored detection rules.
//!
//! Schema (one rule per file):
//!
//! ```yaml
//! id: my.org.suspicious-thing
//! title: Suspicious thing happening
//! description: |
//!   Multi-line description. Optional.
//! severity: high                # low | medium | high | critical
//! mitre:                         # optional, list of ATT&CK technique ids
//!   - T1071.001
//! references:                    # optional, list of URLs
//!   - https://attack.mitre.org/...
//! detection:
//!   kind: events_where           # required: selects the query shape
//!   where: "process = 'foo.exe' AND dst_port = 443"
//!   max_per_run: 100             # optional, default 200
//! ```
//!
//! Supported `kind` values:
//!
//! - `events_where` — `where: <sql>`; `max_per_run: <u32>`
//! - `events_grouped` — `where: <sql>`; `group_by: process|dst|process_and_dst`;
//!   `min_count: <u32>`; `max_per_run: <u32>`
//! - `dns_where` — `where: <sql>`; `max_per_run: <u32>` (queries `dns_events`)
//! - `custom` — `select: <sql>` (advanced; see `rule::RuleQuery::Custom`
//!   for the column contract)
//!
//! Each file in the configured directory is loaded; a parse error per file
//! is surfaced via [`UserRule::error`] so the UI can show validation
//! feedback alongside the raw YAML.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{DetectError, DetectResult};
use crate::rule::{DetectionRule, GroupBy, RuleQuery, RuleSource, Severity};

/// Per-file scan result.
pub struct UserRule {
    /// Filename relative to the rule directory (e.g. `my.org.foo.yml`).
    pub filename: String,
    /// Raw YAML on disk; surfaced for the UI editor.
    pub raw_yaml: String,
    /// Parsed rule on success.
    pub parsed: Option<DetectionRule>,
    /// Parse / validation error, if any.
    pub error: Option<String>,
}

/// Walk `dir` and try to load every `.yml` / `.yaml` file as a rule.
/// Returns one entry per file, including failures, so the caller can decide
/// whether to ignore them or surface them to the user.
pub fn load_dir(dir: &Path) -> DetectResult<Vec<UserRule>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_yaml(&path) {
            continue;
        }
        let filename =
            path.file_name().and_then(|s| s.to_str()).unwrap_or("(unknown).yml").to_string();
        let raw_yaml = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                out.push(UserRule {
                    filename,
                    raw_yaml: String::new(),
                    parsed: None,
                    error: Some(format!("read failed: {e}")),
                });
                continue;
            }
        };
        match parse_yaml(&raw_yaml, &filename) {
            Ok(rule) => out.push(UserRule { filename, raw_yaml, parsed: Some(rule), error: None }),
            Err(e) => {
                out.push(UserRule { filename, raw_yaml, parsed: None, error: Some(e.to_string()) })
            }
        }
    }
    Ok(out)
}

/// Validate raw YAML and produce a rule. Used by the "save user rule"
/// command — we parse-on-write so the user sees errors before the file
/// hits disk.
pub fn parse_yaml(text: &str, source_filename: &str) -> DetectResult<DetectionRule> {
    let dto: YamlRule = serde_yaml_ng::from_str(text)
        .map_err(|e| DetectError::Custom(format!("YAML parse error: {e}")))?;
    dto.into_rule(source_filename.to_string())
}

/// Compute the default rule directory under the OS app-data area.
pub fn default_dir(app_data_root: &Path) -> PathBuf {
    app_data_root.join("rules")
}

fn is_yaml(p: &Path) -> bool {
    matches!(p.extension().and_then(|s| s.to_str()), Some("yml") | Some("yaml"))
}

// ---------------------------------------------------------------------------
// YAML deserialization DTOs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct YamlRule {
    id: String,
    title: String,
    #[serde(default)]
    description: String,
    severity: YamlSeverity,
    #[serde(default)]
    mitre: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    detection: YamlDetection,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum YamlSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl YamlSeverity {
    fn into_severity(self) -> Severity {
        match self {
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

/// Internally-tagged enum (`kind: events_where` etc.) so the YAML has a
/// consistent shape regardless of the variant. `serde_yaml_ng`'s default
/// external-tagging mode requires YAML tags (`!events_where`) which is
/// awkward to type in a config file; internal tagging side-steps this.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum YamlDetection {
    EventsWhere {
        #[serde(rename = "where")]
        where_clause: String,
        #[serde(default = "default_max")]
        max_per_run: u32,
    },
    EventsGrouped {
        #[serde(rename = "where")]
        where_clause: String,
        #[serde(default = "default_group_by")]
        group_by: YamlGroupBy,
        #[serde(default = "default_min_count")]
        min_count: u32,
        #[serde(default = "default_max")]
        max_per_run: u32,
    },
    DnsWhere {
        #[serde(rename = "where")]
        where_clause: String,
        #[serde(default = "default_max")]
        max_per_run: u32,
    },
    Custom {
        select: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum YamlGroupBy {
    Process,
    Dst,
    ProcessAndDst,
}

impl YamlGroupBy {
    fn into_group_by(self) -> GroupBy {
        match self {
            Self::Process => GroupBy::Process,
            Self::Dst => GroupBy::Dst,
            Self::ProcessAndDst => GroupBy::ProcessAndDst,
        }
    }
}

fn default_max() -> u32 {
    200
}
fn default_min_count() -> u32 {
    1
}
fn default_group_by() -> YamlGroupBy {
    YamlGroupBy::ProcessAndDst
}

impl YamlRule {
    fn into_rule(self, filename: String) -> DetectResult<DetectionRule> {
        if self.id.trim().is_empty() {
            return Err(DetectError::Custom("rule `id` must be non-empty".into()));
        }
        if self.title.trim().is_empty() {
            return Err(DetectError::Custom("rule `title` must be non-empty".into()));
        }
        let query = match self.detection {
            YamlDetection::EventsWhere { where_clause, max_per_run } => {
                RuleQuery::EventsWhere { where_sql: where_clause, max_per_run }
            }
            YamlDetection::EventsGrouped { where_clause, group_by, min_count, max_per_run } => {
                RuleQuery::EventsGrouped {
                    where_sql: where_clause,
                    group_by: group_by.into_group_by(),
                    having_min_count: min_count,
                    max_per_run,
                }
            }
            YamlDetection::DnsWhere { where_clause, max_per_run } => {
                RuleQuery::DnsWhere { where_sql: where_clause, max_per_run }
            }
            YamlDetection::Custom { select } => RuleQuery::Custom { select_sql: select },
        };
        Ok(DetectionRule {
            id: self.id,
            title: self.title,
            description: self.description,
            severity: self.severity.into_severity(),
            mitre: self.mitre,
            references: self.references,
            query,
            source: RuleSource::UserFile(filename),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_events_where_rule() {
        let yaml = r#"
id: test.minimal
title: Minimal rule
severity: medium
detection:
  kind: events_where
  where: "process = 'foo.exe'"
"#;
        let rule = parse_yaml(yaml, "test.yml").unwrap();
        assert_eq!(rule.id, "test.minimal");
        assert_eq!(rule.severity, Severity::Medium);
        assert!(matches!(rule.query, RuleQuery::EventsWhere { .. }));
        assert_eq!(rule.source, RuleSource::UserFile("test.yml".into()));
    }

    #[test]
    fn parses_grouped_with_optional_fields() {
        let yaml = r#"
id: g.rule
title: Grouped
description: ""
severity: high
mitre: [T1071, T1218]
references:
  - https://example.com
detection:
  kind: events_grouped
  where: "process IN ('a.exe')"
  group_by: process
  min_count: 5
  max_per_run: 50
"#;
        let r = parse_yaml(yaml, "g.yml").unwrap();
        assert_eq!(r.mitre, vec!["T1071".to_string(), "T1218".into()]);
        match r.query {
            RuleQuery::EventsGrouped { having_min_count, max_per_run, .. } => {
                assert_eq!(having_min_count, 5);
                assert_eq!(max_per_run, 50);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn rejects_missing_id() {
        let yaml = r#"
id: ""
title: x
severity: low
detection:
  kind: events_where
  where: "1=1"
"#;
        assert!(parse_yaml(yaml, "f.yml").is_err());
    }

    #[test]
    fn rejects_unknown_detection_kind() {
        let yaml = r#"
id: a
title: a
severity: low
detection:
  kind: not_a_real_shape
  foo: 1
"#;
        assert!(parse_yaml(yaml, "f.yml").is_err());
    }
}
