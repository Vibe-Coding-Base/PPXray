//! An append-only record of every request this crate has sent.
//!
//! The app's claim is that it does not phone home. Turning the assistant on
//! narrows that claim rather than deleting it, and a narrowed claim is only
//! worth anything if the user can check it. So: one line per outbound
//! request, on disk, in a format they can read with `type` / `cat` and diff
//! against their own firewall log.
//!
//! What is recorded is metadata plus a digest — endpoint, model, scope, byte
//! count, SHA-256 of the exact body. The body itself is not stored: at
//! [`crate::config::DataScope::Raw`] that would be a second copy of the
//! user's traffic history sitting in app-data, which is the opposite of the
//! point. The digest is enough to prove after the fact that a payload the
//! preview showed is the payload that went.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::config::{DataScope, ProviderKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum AuditOutcome {
    /// The request completed and the model answered.
    Ok,
    /// The endpoint refused, timed out, or returned a non-2xx status.
    Failed,
    /// ppxray declined to send. Recorded because "nothing went out" is the
    /// most important thing a privacy log can say, and an absent line does
    /// not say it.
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct AuditEntry {
    /// RFC 3339, UTC.
    pub at: String,
    /// What the request was for: `chat`, `sql`, `explain-rule`, `review`.
    pub purpose: String,
    pub provider: ProviderKind,
    /// Scheme and authority only. Paths can carry ids and query strings can
    /// carry keys, so neither is written here.
    pub endpoint: String,
    pub model: String,
    pub data_scope: DataScope,
    pub request_bytes: u64,
    /// SHA-256 of the exact request body, lower-case hex.
    pub request_sha256: String,
    pub outcome: AuditOutcome,
    /// Present on `Ok`, when the provider reported usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    /// Failure reason, or why the send was blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit log: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Lower-case hex SHA-256 of `body`.
pub fn digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    format!("{:x}", h.finalize())
}

/// Strip a URL down to scheme and authority.
pub fn endpoint_of(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            format!("{scheme}://{authority}")
        }
        None => url.split(['/', '?', '#']).next().unwrap_or(url).to_string(),
    }
}

/// Current time as RFC 3339, or the epoch if the clock is before it.
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// The log file itself. Cheap to construct; holds no handle between writes,
/// because writes are rare and a permanently open handle would keep the
/// file locked on Windows for the life of the process.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry, stamping `at` from the clock.
    pub fn append(&self, mut entry: AuditEntry) -> Result<AuditEntry, AuditError> {
        entry.at = now_rfc3339();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(&entry).unwrap_or_else(|e| {
            // Serializing this struct cannot fail on well-formed data, but a
            // panic here would take down a send that already succeeded.
            format!(r#"{{"at":"{}","error":"audit serialize: {e}"}}"#, entry.at)
        });
        line.push('\n');

        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        Ok(entry)
    }

    /// The most recent `limit` entries, newest first.
    ///
    /// Unparseable lines are skipped rather than failing the read: this file
    /// is user-visible and hand-editable, and one mangled line should not
    /// hide the rest of the history.
    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&self.path)?;
        let mut out: Vec<AuditEntry> = text
            .lines()
            .rev()
            .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
            .take(limit)
            .collect();
        out.shrink_to_fit();
        Ok(out)
    }

    pub fn clear(&self) -> Result<(), AuditError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(purpose: &str) -> AuditEntry {
        AuditEntry {
            at: String::new(),
            purpose: purpose.into(),
            provider: ProviderKind::Anthropic,
            endpoint: "https://api.anthropic.com".into(),
            model: "claude-opus-5".into(),
            data_scope: DataScope::SchemaOnly,
            request_bytes: 12,
            request_sha256: digest(b"hello"),
            outcome: AuditOutcome::Ok,
            input_tokens: Some(10),
            output_tokens: Some(20),
            detail: None,
        }
    }

    #[test]
    fn entries_round_trip_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("llm-audit.jsonl"));

        log.append(entry("first")).unwrap();
        log.append(entry("second")).unwrap();

        let got = log.recent(10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].purpose, "second");
        assert_eq!(got[1].purpose, "first");
        assert!(got[0].at.starts_with("20"), "timestamp was not stamped: {}", got[0].at);
    }

    #[test]
    fn a_mangled_line_does_not_hide_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("llm-audit.jsonl");
        let log = AuditLog::new(&path);
        log.append(entry("kept")).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{ not json\n")
            .unwrap();
        log.append(entry("also kept")).unwrap();

        let got = log.recent(10).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn a_missing_file_reads_as_no_history() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("nope.jsonl"));
        assert!(log.recent(10).unwrap().is_empty());
    }

    #[test]
    fn the_parent_directory_is_created_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("nested/deeper/llm-audit.jsonl"));
        log.append(entry("x")).unwrap();
        assert_eq!(log.recent(1).unwrap().len(), 1);
    }

    #[test]
    fn endpoints_keep_only_scheme_and_host() {
        assert_eq!(
            endpoint_of("https://api.anthropic.com/v1/messages"),
            "https://api.anthropic.com"
        );
        assert_eq!(
            endpoint_of("http://localhost:11434/v1/chat/completions"),
            "http://localhost:11434"
        );
        // A key smuggled into the query string must not land in the log.
        assert_eq!(endpoint_of("https://host.example/v1?key=SECRET"), "https://host.example");
    }

    #[test]
    fn the_digest_is_the_standard_one() {
        // Known vector, so a future change of hash library is caught.
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn clearing_removes_the_history() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("llm-audit.jsonl"));
        log.append(entry("x")).unwrap();
        log.clear().unwrap();
        assert!(log.recent(10).unwrap().is_empty());
        // Clearing twice is not an error.
        log.clear().unwrap();
    }
}
