//! Rule-matching engine.
//!
//! Simulates Proxifier's first-match-wins semantics so the UI can:
//! 1. answer "which rule would match this connection?" (rule testing sandbox);
//! 2. surface overshadow warnings for rules that can never fire because an
//!    earlier rule already covers them (conflict detector).
//!
//! The matching rules below mirror Proxifier's documented behavior:
//! - A rule matches when **every** populated field matches the candidate.
//! - An empty field (no entries) means "match any".
//! - `targets` accept hostname-or-IP, glob with `*`, CIDR `a.b.c.d/prefix`,
//!   and wildcard ranges `10.*`, `172.16.*`.
//! - `applications` accept a literal path, a bare executable name, or a glob.
//! - `ports` accept a single port `443` or an inclusive range `8000-8100`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::model::{Rule, RuleAction};

/// Describes a single connection attempt to simulate against a ruleset.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Candidate {
    /// Executable path or bare name (e.g. `"C:\\Windows\\System32\\svchost.exe"`
    /// or `"chrome.exe"`). Empty string means "don't consider applications".
    pub application: String,
    /// Hostname or dotted-quad IP. Empty string means "don't consider host".
    pub host: String,
    /// Destination port. `0` means "don't consider port".
    pub port: u16,
}

/// Outcome for a single rule against a candidate.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct RuleEvaluation {
    pub rule_index: usize,
    pub rule_name: String,
    pub enabled: bool,
    pub matched: bool,
    /// Per-field breakdown so the UI can explain why a rule did/didn't match.
    pub targets_match: FieldOutcome,
    pub applications_match: FieldOutcome,
    pub ports_match: FieldOutcome,
}

/// Outcome of evaluating a single rule field against a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum FieldOutcome {
    /// Field is empty, so it matches anything.
    Any,
    /// Field has entries and at least one matched the candidate value.
    Matched,
    /// Field has entries but none matched the candidate value.
    Unmatched,
    /// Candidate did not supply a value for this field; treated as a miss
    /// when the rule constrains this field.
    CandidateMissing,
}

/// Top-level simulation result.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct SimulationResult {
    pub evaluations: Vec<RuleEvaluation>,
    /// Index of the first rule that matched (skipping disabled rules).
    /// `None` means the connection would fall through all rules.
    pub winner: Option<usize>,
    /// Convenience copy of the winning rule's action.
    pub winner_action: Option<WinnerAction>,
}

/// Flat enum for the winning action (TS-friendly).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum WinnerAction {
    Direct,
    Block,
    Proxy { proxy_id: u32 },
    Chain { chain_id: u32 },
}

impl From<&RuleAction> for WinnerAction {
    fn from(a: &RuleAction) -> Self {
        match a {
            RuleAction::Direct => Self::Direct,
            RuleAction::Block => Self::Block,
            RuleAction::Proxy { proxy_id } => Self::Proxy { proxy_id: *proxy_id },
            RuleAction::Chain { chain_id } => Self::Chain { chain_id: *chain_id },
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn simulate(rules: &[Rule], candidate: &Candidate) -> SimulationResult {
    let mut evals = Vec::with_capacity(rules.len());
    let mut winner: Option<usize> = None;

    for (i, rule) in rules.iter().enumerate() {
        let e = evaluate_rule(i, rule, candidate);
        if winner.is_none() && rule.enabled && e.matched {
            winner = Some(i);
        }
        evals.push(e);
    }

    let winner_action = winner.map(|i| WinnerAction::from(&rules[i].action));
    SimulationResult { evaluations: evals, winner, winner_action }
}

/// Structured explanation of *why* an earlier rule shadows a later one.
/// Returned alongside each shadow pair so the UI can show the analyst
/// exactly which fields caused the conflict.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ShadowReason {
    /// `true` if the earlier rule's targets cover the later rule's targets
    /// (including the trivial "earlier has no targets → matches any").
    pub targets: ShadowField,
    pub applications: ShadowField,
    pub ports: ShadowField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum ShadowField {
    /// The earlier rule leaves this field empty ⇒ matches everything.
    Any,
    /// The earlier rule constrains this field AND its set of values is a
    /// superset of the later rule's set.
    Covers,
    /// The earlier rule's values are **identical** to the later rule's —
    /// special-cased because identical rules (or rules whose every field is
    /// identical) are almost always redundant user mistakes.
    Identical,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ShadowPair {
    /// Index of the rule that can never fire.
    pub shadowed: usize,
    /// Index of the earlier rule consuming the traffic.
    pub shadower: usize,
    pub reason: ShadowReason,
}

/// Compute overshadow pairs: for each enabled rule, find the FIRST earlier
/// enabled rule whose field constraints are supersets of this rule's.
///
/// This is conservative — pattern equivalence is undecidable with globs, so
/// we cover the high-value cases and punt on exotic ones:
///
/// - **Targets**: exact literal equality, IPv4 CIDR subsets, IPv4
///   `N.*`-style wildcard ranges (including range-vs-CIDR interop), simple
///   glob suffix/prefix subsumption (e.g. `*.example.com` covers
///   `*.api.example.com`), literal-covered-by-glob.
/// - **Applications**: same glob logic plus basename-covers-path and
///   case-insensitive comparison.
/// - **Ports**: range subset.
/// - **Empty field = "any" = covers everything.**
pub fn overshadow_pairs(rules: &[Rule]) -> Vec<ShadowPair> {
    let mut pairs = Vec::new();
    for (j, later) in rules.iter().enumerate() {
        if !later.enabled {
            continue;
        }
        for (i, earlier) in rules.iter().enumerate().take(j) {
            if !earlier.enabled {
                continue;
            }
            if let Some(reason) = rule_covers(earlier, later) {
                pairs.push(ShadowPair { shadowed: j, shadower: i, reason });
                break; // only report the first shadower
            }
        }
    }
    pairs
}

// ---------------------------------------------------------------------------
// Per-rule evaluation
// ---------------------------------------------------------------------------

fn evaluate_rule(index: usize, rule: &Rule, c: &Candidate) -> RuleEvaluation {
    let targets_match = match_target_list(&rule.targets, &c.host);
    let applications_match = match_application_list(&rule.applications, &c.application);
    let ports_match = match_port_list(&rule.ports, c.port);

    let matched = is_pass(targets_match) && is_pass(applications_match) && is_pass(ports_match);

    RuleEvaluation {
        rule_index: index,
        rule_name: rule.name.clone(),
        enabled: rule.enabled,
        matched,
        targets_match,
        applications_match,
        ports_match,
    }
}

fn is_pass(o: FieldOutcome) -> bool {
    matches!(o, FieldOutcome::Any | FieldOutcome::Matched)
}

// ---------------------------------------------------------------------------
// Target matching
// ---------------------------------------------------------------------------

fn match_target_list(entries: &[String], candidate: &str) -> FieldOutcome {
    if entries.is_empty() {
        return FieldOutcome::Any;
    }
    if candidate.is_empty() {
        return FieldOutcome::CandidateMissing;
    }
    for entry in entries {
        if target_entry_matches(entry, candidate) {
            return FieldOutcome::Matched;
        }
    }
    FieldOutcome::Unmatched
}

fn target_entry_matches(entry: &str, candidate: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }

    // CIDR: a.b.c.d/prefix
    if let Some((net, prefix)) = entry.split_once('/')
        && let Ok(prefix) = prefix.parse::<u8>()
        && let Some(base) = parse_ipv4(net)
        && let Some(cand) = parse_ipv4(candidate)
    {
        return ipv4_in_cidr(cand, base, prefix);
    }

    // Wildcard range like `10.*` or `172.16.*`
    if entry.contains('*') || entry.contains('?') {
        return glob_matches(entry, candidate);
    }

    // Literal host / IP comparison (case-insensitive for hostnames).
    entry.eq_ignore_ascii_case(candidate)
}

// ---------------------------------------------------------------------------
// Application matching
// ---------------------------------------------------------------------------

fn match_application_list(entries: &[String], candidate: &str) -> FieldOutcome {
    if entries.is_empty() {
        return FieldOutcome::Any;
    }
    if candidate.is_empty() {
        return FieldOutcome::CandidateMissing;
    }
    let cand_lower = candidate.to_ascii_lowercase();
    let cand_basename = basename_lower(&cand_lower);
    for entry in entries {
        if application_entry_matches(entry, &cand_lower, cand_basename) {
            return FieldOutcome::Matched;
        }
    }
    FieldOutcome::Unmatched
}

fn application_entry_matches(entry: &str, cand_lower: &str, cand_basename: &str) -> bool {
    let entry = strip_quotes(entry.trim());
    if entry.is_empty() {
        return false;
    }
    let entry_lower = entry.to_ascii_lowercase();

    if !entry_lower.contains(['*', '?']) {
        // No glob: match by full path equality OR by basename-only when the
        // entry itself is a basename (no path separators).
        if !entry_lower.contains(['\\', '/']) {
            return entry_lower == cand_basename;
        }
        return entry_lower == cand_lower;
    }
    glob_matches(&entry_lower, cand_lower)
}

// ---------------------------------------------------------------------------
// Port matching
// ---------------------------------------------------------------------------

fn match_port_list(entries: &[String], candidate: u16) -> FieldOutcome {
    if entries.is_empty() {
        return FieldOutcome::Any;
    }
    if candidate == 0 {
        return FieldOutcome::CandidateMissing;
    }
    for entry in entries {
        if port_entry_matches(entry, candidate) {
            return FieldOutcome::Matched;
        }
    }
    FieldOutcome::Unmatched
}

fn port_entry_matches(entry: &str, candidate: u16) -> bool {
    let entry = entry.trim();
    if let Some((a, b)) = entry.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            return candidate >= lo && candidate <= hi;
        }
        return false;
    }
    entry.parse::<u16>().map(|p| p == candidate).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Shadow / coverage check
// ---------------------------------------------------------------------------

/// Returns `Some(ShadowReason)` if `earlier` covers every connection the
/// `later` rule would cover — i.e. the later rule can never fire because
/// `earlier` is reached first on every possible candidate. Returns `None`
/// when there's at least one candidate the later rule could win.
fn rule_covers(earlier: &Rule, later: &Rule) -> Option<ShadowReason> {
    let targets = list_covers(&earlier.targets, &later.targets, target_entry_covers)?;
    let applications =
        list_covers(&earlier.applications, &later.applications, application_entry_covers)?;
    let ports = list_covers(&earlier.ports, &later.ports, port_entry_covers)?;
    Some(ShadowReason { targets, applications, ports })
}

/// Per-field cover check. Returns `Some(ShadowField)` describing *how* the
/// earlier list covers the later one, or `None` if it doesn't.
///
/// Semantics:
/// - Earlier empty → `Any` (matches everything ⇒ trivially covers).
/// - Later empty → the earlier list is narrower than "any", so cannot cover.
/// - Both non-empty: every entry in `later` must have at least one cover in
///   `earlier`. If the two lists are also element-wise identical, tag it
///   as `Identical` so the UI can flag dead duplicates distinctly.
fn list_covers<F: Fn(&str, &str) -> bool>(
    earlier_entries: &[String],
    later_entries: &[String],
    covers: F,
) -> Option<ShadowField> {
    if earlier_entries.is_empty() {
        return Some(ShadowField::Any);
    }
    if later_entries.is_empty() {
        return None;
    }
    for l in later_entries {
        let mut any = false;
        for e in earlier_entries {
            if covers(e, l) {
                any = true;
                break;
            }
        }
        if !any {
            return None;
        }
    }
    let identical = entries_equivalent(earlier_entries, later_entries);
    Some(if identical { ShadowField::Identical } else { ShadowField::Covers })
}

/// Case-insensitive, order-insensitive set equality on trimmed entries.
fn entries_equivalent(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let norm = |s: &str| s.trim().to_ascii_lowercase();
    let mut a_set: Vec<String> = a.iter().map(|x| norm(x)).collect();
    let mut b_set: Vec<String> = b.iter().map(|x| norm(x)).collect();
    a_set.sort();
    b_set.sort();
    a_set == b_set
}

fn target_entry_covers(earlier: &str, later: &str) -> bool {
    let earlier = earlier.trim();
    let later = later.trim();

    // Exact identical entries always cover.
    if earlier.eq_ignore_ascii_case(later) {
        return true;
    }

    // --- IPv4 range / CIDR / literal interop ---
    //
    // Normalize both sides to an Option<(base, prefix_bits)>. A literal IP
    // becomes a /32. A `N.*` wildcard becomes a /8 (or /16, /24). A CIDR is
    // parsed directly. This gives us one uniform "earlier covers later?"
    // check across all three syntactic forms, which is critical for catching
    // common real-world shadow patterns like `10.*` overshadowing `10.0.0.0/16`.
    let e_range = parse_ipv4_range(earlier);
    let l_range = parse_ipv4_range(later);
    if let (Some((eb, ep)), Some((lb, lp))) = (e_range, l_range) {
        // Earlier covers later iff later's block ⊆ earlier's block.
        return lp >= ep && ipv4_in_cidr(lb, eb, ep);
    }
    if e_range.is_some() {
        // Earlier is an IP-range expression; later is a hostname/glob.
        // No meaningful coverage claim (we don't resolve hostnames here).
        return false;
    }

    // --- Glob / literal string interop ---
    let earlier_has_wild = earlier.contains(['*', '?']);
    let later_has_wild = later.contains(['*', '?']);

    if earlier_has_wild {
        if !later_has_wild {
            // Earlier is a glob, later is a concrete hostname/IP.
            return glob_matches(earlier, later);
        }
        // Both globs. Use structural subsumption.
        return glob_covers_glob(earlier, later);
    }

    // Earlier is a non-wildcard literal hostname. Only exact equality (already
    // checked above) counts as coverage.
    false
}

fn application_entry_covers(earlier: &str, later: &str) -> bool {
    let e = strip_quotes(earlier.trim()).to_ascii_lowercase();
    let l = strip_quotes(later.trim()).to_ascii_lowercase();

    if e == l {
        return true;
    }

    let e_wild = e.contains(['*', '?']);
    let l_wild = l.contains(['*', '?']);

    if e_wild {
        if !l_wild {
            return glob_matches(&e, &l);
        }
        return glob_covers_glob(&e, &l);
    }

    // Earlier is a non-wildcard literal. A bare basename (no `\` or `/`)
    // covers any path ending in `\basename`.
    if !e.contains(['\\', '/']) {
        if l_wild {
            // Conservative: later's glob could generate names other than e.
            // E.g. earlier = "firefox.exe", later = "fire*.exe" — "fire.exe"
            // matches later but not earlier. Do not claim coverage.
            return false;
        }
        let l_base = basename_lower(&l);
        return e == l_base;
    }

    false
}

/// Parse any IPv4 range expression — literal IP, `N.*` wildcard, or
/// `a.b.c.d/prefix` CIDR — into `(base, prefix_bits)`. Literal IPs become
/// `/32`; `10.*` becomes base `10.0.0.0` prefix 8; `10.1.*` becomes
/// `10.1.0.0/16`; `10.1.2.*` becomes `10.1.2.0/24`.
fn parse_ipv4_range(s: &str) -> Option<(u32, u8)> {
    let s = s.trim();

    if let Some((net, pfx)) = s.split_once('/') {
        let prefix: u8 = pfx.trim().parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let base = parse_ipv4(net.trim())?;
        // Canonicalize the base so host bits are zeroed; otherwise
        // `ipv4_in_cidr` with the raw base can produce surprises.
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        return Some((base & mask, prefix));
    }

    if let Some(stripped) = s.strip_suffix('*').map(|t| t.trim_end_matches('.')) {
        if stripped.is_empty() {
            return None;
        }
        let parts: Vec<&str> = stripped.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return None;
        }
        let mut bytes = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = p.trim().parse::<u8>().ok()?;
        }
        let addr = u32::from_be_bytes(bytes);
        let prefix = (parts.len() as u8) * 8;
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        return Some((addr & mask, prefix));
    }

    if let Some(ip) = parse_ipv4(s) {
        return Some((ip, 32));
    }

    None
}

/// Conservative "does glob A cover glob B?" check. Both patterns are split
/// on `*` into literal chunks; we then require:
///
/// 1. **Leading anchor**: if A has a literal prefix (doesn't start with
///    `*`), B must also start with a literal that begins with A's prefix.
///    Otherwise B might expand to strings A rejects.
/// 2. **Trailing anchor**: symmetric for literal suffixes.
/// 3. **Interior chunks**: every interior chunk of A must appear, in order,
///    in B's concatenated literal body. If B contains any `*` we're more
///    conservative (can't be sure what B will expand to between its stars).
///
/// Catches: `*` covers anything; `*.X` covers `*.Y.X` / `Y.X`; `X*` covers
/// `X*Y`; `*foo*` covers any concrete string containing `foo`.
/// Does NOT catch the rare `*a*` vs `*b*a*` overlap (we'd need regex-
/// equivalent subsumption for that; not worth the complexity here).
fn glob_covers_glob(a: &str, b: &str) -> bool {
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();
    if a == b {
        return true;
    }
    if a == "*" {
        return true;
    }

    // Treat `?` in either side as "unknown single char"; for simplicity we
    // require `a` to have no `?` (rare in Proxifier rules). If it does, fall
    // back to equality.
    if a.contains('?') || b.contains('?') {
        return false;
    }

    let a_parts: Vec<&str> = a.split('*').collect();
    let b_parts: Vec<&str> = b.split('*').collect();

    let a_starts_wild = a.starts_with('*');
    let b_starts_wild = b.starts_with('*');
    let a_ends_wild = a.ends_with('*');
    let b_ends_wild = b.ends_with('*');

    // Leading anchor
    if !a_starts_wild {
        let a_head = a_parts.first().copied().unwrap_or("");
        if b_starts_wild {
            return false; // b's expansion can start with anything
        }
        let b_head = b_parts.first().copied().unwrap_or("");
        if !b_head.starts_with(a_head) {
            return false;
        }
    }

    // Trailing anchor
    if !a_ends_wild {
        let a_tail = a_parts.last().copied().unwrap_or("");
        if b_ends_wild {
            return false;
        }
        let b_tail = b_parts.last().copied().unwrap_or("");
        if !b_tail.ends_with(a_tail) {
            return false;
        }
    }

    // Interior chunks of A must appear in order inside B's concatenated
    // literal body. Only valid when B has no interior `*`s we can't reason
    // about — if B has any `*`, we verify by searching inside the full b
    // string (including the asterisks) as a best-effort: the asterisks
    // effectively allow free extension, which is even more permissive for
    // us, but can produce false positives. We err toward *not* marking a
    // shadow when uncertain.
    let a_interior: &[&str] = if a_parts.len() > 2 { &a_parts[1..a_parts.len() - 1] } else { &[] };
    if !a_interior.is_empty() {
        if b.contains('*') {
            // Too hard to guarantee — punt.
            return false;
        }
        let mut cursor = 0usize;
        for part in a_interior {
            if part.is_empty() {
                continue;
            }
            match b[cursor..].find(part) {
                Some(pos) => cursor += pos + part.len(),
                None => return false,
            }
        }
    }

    true
}

fn port_entry_covers(earlier: &str, later: &str) -> bool {
    let (e_lo, e_hi) = match parse_port_range(earlier) {
        Some(r) => r,
        None => return false,
    };
    let (l_lo, l_hi) = match parse_port_range(later) {
        Some(r) => r,
        None => return false,
    };
    e_lo <= l_lo && e_hi >= l_hi
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let s = s.trim();
    if let Some((a, b)) = s.split_once('-') {
        let a: u16 = a.trim().parse().ok()?;
        let b: u16 = b.trim().parse().ok()?;
        Some(if a <= b { (a, b) } else { (b, a) })
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') { &s[1..s.len() - 1] } else { s }
}

fn basename_lower(path: &str) -> &str {
    match path.rfind(['\\', '/']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = s.split('.');
    let a: u32 = parts.next()?.parse().ok()?;
    let b: u32 = parts.next()?.parse().ok()?;
    let c: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if a > 255 || b > 255 || c > 255 || d > 255 {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

fn ipv4_in_cidr(ip: u32, base: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    (ip & mask) == (base & mask)
}

/// `*` matches any run (including empty) of non-delimiter chars; `?` matches
/// exactly one char. Case-insensitive. No backslash escaping — Proxifier
/// globs don't support it.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let t: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut back) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            back = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            back += 1;
            ti = back;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Rule, RuleAction};

    fn mk_rule(name: &str, targets: &[&str], apps: &[&str], ports: &[&str]) -> Rule {
        Rule {
            enabled: true,
            name: name.into(),
            action: RuleAction::Direct,
            targets: targets.iter().map(|s| s.to_string()).collect(),
            applications: apps.iter().map(|s| s.to_string()).collect(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn glob_basics() {
        assert!(glob_matches("*.example.com", "api.example.com"));
        assert!(glob_matches("*.example.com", "a.b.example.com"));
        assert!(!glob_matches("*.example.com", "example.com"));
        assert!(glob_matches("10.*", "10.1.2.3"));
        assert!(!glob_matches("10.*", "11.0.0.1"));
        assert!(glob_matches("foo?bar", "fooxbar"));
        assert!(!glob_matches("foo?bar", "fooxxbar"));
    }

    #[test]
    fn cidr_membership() {
        let base = parse_ipv4("10.0.0.0").unwrap();
        assert!(ipv4_in_cidr(parse_ipv4("10.1.2.3").unwrap(), base, 8));
        assert!(!ipv4_in_cidr(parse_ipv4("11.0.0.1").unwrap(), base, 8));
        assert!(ipv4_in_cidr(
            parse_ipv4("149.154.167.99").unwrap(),
            parse_ipv4("149.154.160.0").unwrap(),
            20
        ));
        assert!(!ipv4_in_cidr(
            parse_ipv4("149.154.192.1").unwrap(),
            parse_ipv4("149.154.160.0").unwrap(),
            20
        ));
    }

    #[test]
    fn port_ranges() {
        assert!(port_entry_matches("443", 443));
        assert!(!port_entry_matches("443", 80));
        assert!(port_entry_matches("8000-8100", 8050));
        assert!(port_entry_matches("8000-8100", 8000));
        assert!(port_entry_matches("8000-8100", 8100));
        assert!(!port_entry_matches("8000-8100", 8101));
    }

    #[test]
    fn app_basename_vs_full_path() {
        let cand_full = r"c:\program files\mozilla firefox\firefox.exe";
        assert!(application_entry_matches("firefox.exe", cand_full, "firefox.exe"));
        assert!(application_entry_matches(
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            cand_full,
            "firefox.exe",
        ));
        assert!(application_entry_matches(
            r"C:\Program Files\Mozilla Firefox\*.exe",
            cand_full,
            "firefox.exe",
        ));
        assert!(!application_entry_matches("chrome.exe", cand_full, "firefox.exe"));
    }

    #[test]
    fn simulate_first_match_wins() {
        let rules =
            vec![mk_rule("Block foo", &["foo.com"], &[], &[]), mk_rule("Allow all", &[], &[], &[])];
        let result = simulate(
            &rules,
            &Candidate { application: "".into(), host: "foo.com".into(), port: 443 },
        );
        assert_eq!(result.winner, Some(0));
    }

    #[test]
    fn simulate_falls_through_disabled() {
        let mut rules = vec![mk_rule("Block foo", &["foo.com"], &[], &[])];
        rules[0].enabled = false;
        let result = simulate(
            &rules,
            &Candidate { application: "".into(), host: "foo.com".into(), port: 443 },
        );
        assert_eq!(result.winner, None);
        assert!(!result.evaluations[0].enabled);
        assert!(result.evaluations[0].matched); // still records the match for explanation
    }

    #[test]
    fn simulate_port_constraint() {
        let rules = vec![mk_rule("443-only", &[], &[], &["443"])];
        let r1 =
            simulate(&rules, &Candidate { application: "".into(), host: "".into(), port: 443 });
        assert_eq!(r1.winner, Some(0));
        let r2 = simulate(&rules, &Candidate { application: "".into(), host: "".into(), port: 80 });
        assert_eq!(r2.winner, None);
    }

    fn indices(pairs: &[ShadowPair]) -> Vec<(usize, usize)> {
        pairs.iter().map(|p| (p.shadowed, p.shadower)).collect()
    }

    #[test]
    fn overshadow_wildcard() {
        let rules = vec![
            mk_rule("Broad", &["*.example.com"], &[], &[]),
            mk_rule("Narrow", &["api.example.com"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    #[test]
    fn overshadow_disabled_ignored() {
        let mut rules = vec![
            mk_rule("Broad", &["*.example.com"], &[], &[]),
            mk_rule("Narrow", &["api.example.com"], &[], &[]),
        ];
        rules[0].enabled = false;
        assert!(overshadow_pairs(&rules).is_empty());
    }

    #[test]
    fn overshadow_port_subset() {
        let rules = vec![
            mk_rule("Broad ports", &[], &[], &["80-500"]),
            mk_rule("Narrow port", &[], &[], &["443"]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    #[test]
    fn no_overshadow_when_narrower_first() {
        let rules = vec![
            mk_rule("Narrow", &["api.example.com"], &[], &[]),
            mk_rule("Broad", &["*.example.com"], &[], &[]),
        ];
        assert!(overshadow_pairs(&rules).is_empty());
    }

    // --- IPv4 range / CIDR / literal interop ---------------------------------

    #[test]
    fn ipv4_wildcard_range_parses() {
        assert_eq!(parse_ipv4_range("10.*"), Some((parse_ipv4("10.0.0.0").unwrap(), 8)));
        assert_eq!(parse_ipv4_range("10.1.*"), Some((parse_ipv4("10.1.0.0").unwrap(), 16)));
        assert_eq!(parse_ipv4_range("10.1.2.*"), Some((parse_ipv4("10.1.2.0").unwrap(), 24)));
        assert_eq!(parse_ipv4_range("10.0.0.0/8"), Some((parse_ipv4("10.0.0.0").unwrap(), 8)));
        // Base is canonicalized: 10.255.0.0/8 normalizes to 10.0.0.0/8.
        assert_eq!(parse_ipv4_range("10.255.0.0/8"), Some((parse_ipv4("10.0.0.0").unwrap(), 8)));
        assert_eq!(parse_ipv4_range("10.1.2.3"), Some((parse_ipv4("10.1.2.3").unwrap(), 32)));
    }

    #[test]
    fn ipv4_wildcard_covers_cidr_and_vice_versa() {
        // `10.*` is /8, `10.0.0.0/16` is narrower → covered.
        let rules = vec![
            mk_rule("Wildcard", &["10.*"], &[], &[]),
            mk_rule("CIDR sub", &["10.0.0.0/16"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);

        // Reverse: narrower CIDR first → no shadow.
        let rules = vec![
            mk_rule("CIDR sub", &["10.0.0.0/16"], &[], &[]),
            mk_rule("Wildcard", &["10.*"], &[], &[]),
        ];
        assert!(overshadow_pairs(&rules).is_empty());

        // `10.0.0.0/8` covers `10.1.*` (/16) ✓
        let rules = vec![
            mk_rule("CIDR /8", &["10.0.0.0/8"], &[], &[]),
            mk_rule("Wildcard .1.*", &["10.1.*"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);

        // `10.*` covers a single literal IP in the range.
        let rules = vec![
            mk_rule("Broad", &["10.*"], &[], &[]),
            mk_rule("Specific", &["10.5.6.7"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);

        // Different /8 — no shadow.
        let rules = vec![
            mk_rule("10-net", &["10.*"], &[], &[]),
            mk_rule("11-net", &["11.5.6.7"], &[], &[]),
        ];
        assert!(overshadow_pairs(&rules).is_empty());
    }

    // --- Glob-vs-glob subsumption --------------------------------------------

    #[test]
    fn glob_covers_nested_wildcard_domain() {
        // Very common real-world case: broad `*.example.com` rule placed
        // before a more-specific `*.api.example.com` rule.
        let rules = vec![
            mk_rule("Broad", &["*.example.com"], &[], &[]),
            mk_rule("Sub-glob", &["*.api.example.com"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    #[test]
    fn star_covers_anything_domain() {
        let rules = vec![
            mk_rule("Catch-all", &["*"], &[], &[]),
            mk_rule("Specific", &["api.example.com"], &[], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    #[test]
    fn glob_does_not_cover_unrelated_domain() {
        let rules = vec![
            mk_rule("Example", &["*.example.com"], &[], &[]),
            mk_rule("Other", &["*.acme.io"], &[], &[]),
        ];
        assert!(overshadow_pairs(&rules).is_empty());
    }

    #[test]
    fn glob_missing_leading_dot_not_covered() {
        // `*.example.com` requires a subdomain; it should NOT cover
        // `example.com` (bare apex) because `*` can't match empty without
        // also eating the `.`.
        let rules = vec![
            mk_rule("Subdomain-only", &["*.example.com"], &[], &[]),
            mk_rule("Apex", &["example.com"], &[], &[]),
        ];
        assert!(overshadow_pairs(&rules).is_empty());
    }

    // --- Application coverage ------------------------------------------------

    #[test]
    fn bare_basename_covers_full_path() {
        let rules = vec![
            mk_rule("Bare", &[], &["firefox.exe"], &[]),
            mk_rule("Path", &[], &[r"C:\Program Files\Mozilla\firefox.exe"], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    #[test]
    fn app_glob_covers_specific_path() {
        let rules = vec![
            mk_rule("Glob exe", &[], &[r"C:\Program Files\*\*.exe"], &[]),
            mk_rule("Specific", &[], &[r"C:\Program Files\App\app.exe"], &[]),
        ];
        assert_eq!(indices(&overshadow_pairs(&rules)), vec![(1, 0)]);
    }

    // --- Identical-rule detection --------------------------------------------

    #[test]
    fn identical_rule_is_shadowed_with_identical_tag() {
        let rules = vec![
            mk_rule("First", &["api.example.com"], &[], &["443"]),
            mk_rule("Duplicate", &["api.example.com"], &[], &["443"]),
        ];
        let pairs = overshadow_pairs(&rules);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].shadowed, 1);
        assert_eq!(pairs[0].reason.targets, ShadowField::Identical);
        assert_eq!(pairs[0].reason.ports, ShadowField::Identical);
        // Applications: both empty → Any.
        assert_eq!(pairs[0].reason.applications, ShadowField::Any);
    }

    #[test]
    fn blanket_rule_shadows_all_subsequent() {
        // A catch-all rule (no fields set) at the top shadows every rule
        // after it, since any candidate matches the catch-all.
        let rules = vec![
            mk_rule("Blanket", &[], &[], &[]),
            mk_rule("Specific 1", &["api.example.com"], &[], &[]),
            mk_rule("Specific 2", &["foo.com"], &["app.exe"], &["443"]),
        ];
        let pairs = overshadow_pairs(&rules);
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().all(|p| p.shadower == 0));
        for p in &pairs {
            assert_eq!(p.reason.targets, ShadowField::Any);
            assert_eq!(p.reason.applications, ShadowField::Any);
            assert_eq!(p.reason.ports, ShadowField::Any);
        }
    }

    // --- Port subset edge cases ----------------------------------------------

    #[test]
    fn port_equal_list_is_identical() {
        let rules = vec![
            mk_rule("A", &[], &[], &["80", "443"]),
            mk_rule("B", &[], &[], &["443", "80"]), // same set, different order
        ];
        let pairs = overshadow_pairs(&rules);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].reason.ports, ShadowField::Identical);
    }

    #[test]
    fn earlier_has_narrower_port_list_does_not_shadow() {
        // Earlier allows only 443; later allows 443 and 80 → later's 80
        // isn't covered, so no shadow.
        let rules = vec![mk_rule("A", &[], &[], &["443"]), mk_rule("B", &[], &[], &["443", "80"])];
        assert!(overshadow_pairs(&rules).is_empty());
    }
}
