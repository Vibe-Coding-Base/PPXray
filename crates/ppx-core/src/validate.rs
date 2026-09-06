//! Validators for individual rule-field entries.
//!
//! The UI uses these on every chip keystroke to decorate invalid entries.
//! All validators are forgiving — they reject obviously broken inputs but
//! don't try to match Proxifier's exact parser. Real Proxifier is lenient
//! about leading/trailing whitespace, case, and mixed IPv6 notation, so we
//! accept anything Proxifier itself would accept.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum EntryKind {
    Hostname,
    Wildcard,
    Ipv4,
    Ipv6,
    Ipv4Cidr,
    Ipv6Cidr,
    /// E.g. `10.*` or `172.16.*`
    Ipv4WildcardRange,
    /// Environment variable placeholder, e.g. `%ComputerName%`.
    EnvPlaceholder,
    Empty,
    Invalid,
}

/// Decide which kind of target one entry of a rule's `Targets` field is.
///
/// Proxifier accepts hostnames, globs, bare IPs, CIDRs, wildcard ranges and
/// `%EnvVar%` placeholders in the same semicolon-separated list, with no
/// syntax to tell them apart. The matcher and the shadow detector both need
/// to know which is which before they can compare two entries.
pub fn classify_target(entry: &str) -> EntryKind {
    let e = entry.trim();
    if e.is_empty() {
        return EntryKind::Empty;
    }

    if e.starts_with('%') && e.ends_with('%') && e.len() > 2 {
        return EntryKind::EnvPlaceholder;
    }

    // IPv6 — presence of `::` or multiple `:` segments is the giveaway.
    if e.contains(':') && !e.contains('/') && looks_like_ipv6(e) {
        return EntryKind::Ipv6;
    }
    if let Some((net, pre)) = e.split_once('/')
        && looks_like_ipv6(net)
        && pre.parse::<u8>().map(|p| p <= 128).unwrap_or(false)
    {
        return EntryKind::Ipv6Cidr;
    }

    // IPv4 CIDR
    if let Some((net, pre)) = e.split_once('/')
        && looks_like_ipv4(net)
        && pre.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
    {
        return EntryKind::Ipv4Cidr;
    }

    // IPv4 wildcard-range like 10.* or 10.1.*
    if let Some(kind) = classify_ipv4_wildcard(e) {
        return kind;
    }

    if e.contains(['*', '?']) {
        return EntryKind::Wildcard;
    }

    if looks_like_ipv4(e) {
        return EntryKind::Ipv4;
    }

    if looks_like_hostname(e) {
        return EntryKind::Hostname;
    }
    EntryKind::Invalid
}

pub fn validate_port(entry: &str) -> bool {
    let s = entry.trim();
    if s.is_empty() {
        return false;
    }
    if let Some((a, b)) = s.split_once('-') {
        let a: Option<u16> = a.trim().parse().ok();
        let b: Option<u16> = b.trim().parse().ok();
        matches!((a, b), (Some(a), Some(b)) if a > 0 && b > 0)
    } else {
        matches!(s.parse::<u16>(), Ok(p) if p > 0)
    }
}

pub fn validate_application(entry: &str) -> bool {
    let e = entry.trim();
    if e.is_empty() {
        return false;
    }
    // Allow either a path-like string (contains `\` or `/`) or a bare name
    // (no spaces in the basename beyond the extension).
    let has_suspicious_chars = e.chars().any(|c| matches!(c, '\n' | '\r' | '\t' | '<' | '>' | '|'));
    !has_suspicious_chars
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
}

fn looks_like_ipv6(s: &str) -> bool {
    // Cheap shape check: contains `:` and only hex / `:` / optional final `%zone`.
    if !s.contains(':') {
        return false;
    }
    // Reject clearly wrong strings with multiple `::`.
    if s.matches("::").count() > 1 {
        return false;
    }
    let core = s.split_once('%').map(|(a, _)| a).unwrap_or(s);
    let groups: Vec<&str> = core.split(':').collect();
    if groups.len() < 3 || groups.len() > 8 {
        // `::` produces empty groups; we still need at least a few colons.
        if groups.len() < 2 {
            return false;
        }
    }
    groups
        .iter()
        .all(|g| g.is_empty() || (g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit())))
}

fn classify_ipv4_wildcard(s: &str) -> Option<EntryKind> {
    // Pattern `N.N.N.*` or `N.N.*` or `N.*`; each `N` is 0..=255, last part
    // must be `*`.
    if !s.contains('.') || !s.ends_with('*') {
        return None;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 4 || parts.is_empty() {
        return None;
    }
    let (last, head) = parts.split_last()?;
    if *last != "*" {
        return None;
    }
    if head.is_empty() {
        return None;
    }
    let ok = head.iter().all(|p| p.parse::<u16>().map(|n| n <= 255).unwrap_or(false));
    ok.then_some(EntryKind::Ipv4WildcardRange)
}

fn looks_like_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_classify() {
        assert_eq!(classify_target("localhost"), EntryKind::Hostname);
        assert_eq!(classify_target("api.example.com"), EntryKind::Hostname);
        assert_eq!(classify_target("*.example.com"), EntryKind::Wildcard);
        assert_eq!(classify_target("10.0.0.1"), EntryKind::Ipv4);
        assert_eq!(classify_target("10.0.0.0/8"), EntryKind::Ipv4Cidr);
        assert_eq!(classify_target("10.*"), EntryKind::Ipv4WildcardRange);
        assert_eq!(classify_target("172.16.*"), EntryKind::Ipv4WildcardRange);
        assert_eq!(classify_target("::1"), EntryKind::Ipv6);
        assert_eq!(classify_target("ff02::1:3"), EntryKind::Ipv6);
        assert_eq!(classify_target("%ComputerName%"), EntryKind::EnvPlaceholder);
        assert_eq!(classify_target("..bad.."), EntryKind::Invalid);
        assert_eq!(classify_target(""), EntryKind::Empty);
    }

    #[test]
    fn ports_validate() {
        assert!(validate_port("443"));
        assert!(validate_port("8000-8100"));
        assert!(validate_port("22 - 25"));
        assert!(!validate_port("0"));
        assert!(!validate_port("70000"));
        assert!(!validate_port("abc"));
        assert!(!validate_port(""));
    }

    #[test]
    fn apps_validate() {
        assert!(validate_application("firefox.exe"));
        assert!(validate_application(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
        assert!(validate_application(r"C:\*.exe"));
        assert!(!validate_application(""));
        assert!(!validate_application("bad<file>name.exe"));
    }
}
