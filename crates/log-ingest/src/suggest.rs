//! Turning observed traffic into a Proxifier `Targets` list.
//!
//! The workflow this serves: someone allowed a process to reach anything
//! while they worked out what it needed, and now wants to narrow the rule.
//! The log already knows the answer — every host that process actually
//! reached — so this reads it back in the exact shape Proxifier's Targets
//! field takes.
//!
//! # Rolling subdomains up to a wildcard
//!
//! Listing 200 individual CDN hosts is not a usable rule, so hosts sharing a
//! parent domain collapse to `*.example.com`. The risk is collapsing *too*
//! far: `*.co.uk` or `*.com.vn` would hand a process most of a country's
//! internet, which is worse than the wide-open rule the user is trying to
//! replace.
//!
//! Guarding that properly needs the Public Suffix List. Rather than vendor
//! and refresh one, this uses two conservative rules that fail toward being
//! too narrow:
//!
//! * A parent must have at least two labels, and if its second-to-last label
//!   is a known registry label (`co`, `com`, `org`, …) it must have three —
//!   so `example.co.uk` can be a parent but `co.uk` cannot.
//! * A parent is only offered when enough distinct hosts sit under it
//!   ([`SuggestOptions::min_hosts_for_wildcard`]).
//!
//! Being too narrow shows up as a longer list the user can still paste.
//! Being too wide silently re-opens the hole they were closing.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::error::IngestResult;
use crate::store::LogStore;

/// Second-level labels that behave like registry suffixes, so `foo.co.uk`
/// must not roll up to `co.uk`. Not exhaustive — it does not need to be,
/// because an unlisted one only costs a narrower suggestion.
const REGISTRY_LABELS: &[&str] =
    &["co", "com", "net", "org", "gov", "edu", "ac", "mil", "int", "biz", "info", "or", "ne", "gr"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum SuggestionKind {
    /// `*.example.com` — stands in for several observed hosts.
    Wildcard,
    /// A single hostname, exactly as observed.
    Host,
    /// A literal address, for connections that carried no hostname.
    Ip,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct HostSuggestion {
    /// The entry to paste, already in Proxifier's syntax.
    pub value: String,
    pub kind: SuggestionKind,
    /// Connections this entry accounts for.
    pub events: u64,
    /// Distinct observed hosts it stands in for. 1 unless `Wildcard`.
    pub covers: u32,
    /// The hosts a wildcard replaced, so the user can see what they are
    /// accepting before they accept it. Empty for non-wildcards.
    pub covered_hosts: Vec<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct TargetSuggestions {
    pub process: String,
    /// Connections by this process in the window examined.
    pub total_events: u64,
    /// Distinct hosts and addresses seen, before any roll-up.
    pub distinct_destinations: u32,
    pub suggestions: Vec<HostSuggestion>,
}

#[derive(Debug, Clone, Copy)]
pub struct SuggestOptions {
    /// Ignore destinations seen fewer times than this. Filters one-off
    /// noise without needing the user to prune by hand.
    pub min_events: u64,
    /// Distinct hosts under a parent before it is offered as a wildcard.
    pub min_hosts_for_wildcard: u32,
    /// Cap on returned entries, most-contacted first.
    pub limit: u32,
    /// Include literal addresses for connections with no hostname. Off by
    /// default: addresses churn, and a rule pinned to one is brittle.
    pub include_ips: bool,
}

impl Default for SuggestOptions {
    fn default() -> Self {
        Self { min_events: 2, min_hosts_for_wildcard: 3, limit: 200, include_ips: false }
    }
}

/// One `GROUP BY dst_host, dst_ip` row: hostname, address, count, last seen.
type DestRow = (Option<String>, Option<String>, u64, Option<String>);

/// Every domain a host could roll up into, deepest first.
///
/// All ancestors, not just the immediate parent. YouTube's CDN is the case
/// that forces this: `rr5.sn-abcd1234.googlevideo.com` has a unique
/// `sn-…` label per host, so grouping on immediate parents alone puts every
/// host in a group of one and rolls up nothing. `googlevideo.com` two levels
/// up is the wildcard that actually collapses them.
///
/// Stops before anything too broad to be a safe rule — see the module
/// comment.
fn wildcard_parents(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let mut out = Vec::new();
    // Start one label in: a host is not its own wildcard. Stop while at least
    // two labels remain, so `example.com` can be a parent but `com` cannot.
    for start in 1..labels.len().saturating_sub(1) {
        let parent = &labels[start..];
        // `foo.co.uk` -> `co.uk` is a registry suffix, not a site. Shallower
        // ancestors of a rejected one are broader still, so stop here.
        if parent.len() == 2 && REGISTRY_LABELS.contains(&parent[0]) {
            break;
        }
        out.push(parent.join("."));
    }
    out
}

/// Observed destinations for `process`, collapsed into a paste-ready list.
pub fn suggest_targets(
    store: &LogStore,
    process: &str,
    opts: SuggestOptions,
) -> IngestResult<TargetSuggestions> {
    let rows: Vec<DestRow> = store.with_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT dst_host, dst_ip, COUNT(*) AS c, MAX(ts) AS last_seen
             FROM events
             WHERE process = ?
             GROUP BY dst_host, dst_ip
             ORDER BY c DESC",
        )?;
        let rows = stmt.query_map([process], |r| {
            let last: Option<chrono::NaiveDateTime> = r.get(3)?;
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, i64>(2)? as u64,
                last.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string()),
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    })?;

    Ok(build(process, rows, opts))
}

/// Split out from the query so the roll-up logic is testable without a DB.
fn build(process: &str, rows: Vec<DestRow>, opts: SuggestOptions) -> TargetSuggestions {
    use std::collections::HashMap;

    struct Agg {
        events: u64,
        last: Option<String>,
    }
    let mut hosts: HashMap<String, Agg> = HashMap::new();
    let mut ips: HashMap<String, Agg> = HashMap::new();
    let mut total_events = 0u64;

    for (host, ip, count, last) in rows {
        total_events += count;
        // A row carries a hostname or, when Proxifier never resolved one, an
        // address. Prefer the hostname: it survives the host changing IP.
        let (bucket, key) = match (host, ip) {
            (Some(h), _) if !h.is_empty() => (&mut hosts, h.to_ascii_lowercase()),
            (_, Some(i)) if !i.is_empty() && i != "0.0.0.0" => (&mut ips, i),
            _ => continue,
        };
        let e = bucket.entry(key).or_insert(Agg { events: 0, last: None });
        e.events += count;
        if last > e.last {
            e.last = last;
        }
    }

    let distinct_destinations = (hosts.len() + ips.len()) as u32;

    // Index every host under each domain it could roll up into. A host
    // appears under several; the greedy pass below picks one.
    let mut by_parent: HashMap<String, Vec<String>> = HashMap::new();
    for name in hosts.keys() {
        for parent in wildcard_parents(name) {
            by_parent.entry(parent).or_default().push(name.clone());
        }
    }

    let mut out: Vec<HostSuggestion> = Vec::new();
    let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut parents: Vec<(String, Vec<String>)> = by_parent.into_iter().collect();
    // Deepest first, so `a.cdn.example.com` and `b.cdn.example.com` become
    // `*.cdn.example.com` rather than being swallowed by `*.example.com`
    // alongside unrelated siblings. A host indexed under several domains is
    // claimed by the first that qualifies and skipped by the rest, so a
    // shallower domain is only reached when no deeper one had enough hosts.
    parents.sort_by(|a, b| {
        b.0.matches('.').count().cmp(&a.0.matches('.').count()).then_with(|| a.0.cmp(&b.0))
    });

    for (parent, members) in parents {
        let members: Vec<String> = members.into_iter().filter(|m| !consumed.contains(m)).collect();
        if (members.len() as u32) < opts.min_hosts_for_wildcard {
            continue;
        }
        let events: u64 = members.iter().map(|m| hosts[m].events).sum();
        let last = members.iter().filter_map(|m| hosts[m].last.clone()).max();
        let mut covered = members.clone();
        covered.sort();
        for m in members {
            consumed.insert(m);
        }
        out.push(HostSuggestion {
            value: format!("*.{parent}"),
            kind: SuggestionKind::Wildcard,
            events,
            covers: covered.len() as u32,
            covered_hosts: covered,
            last_seen: last,
        });
    }

    for (name, agg) in hosts {
        if consumed.contains(&name) || agg.events < opts.min_events {
            continue;
        }
        out.push(HostSuggestion {
            value: name,
            kind: SuggestionKind::Host,
            events: agg.events,
            covers: 1,
            covered_hosts: Vec::new(),
            last_seen: agg.last,
        });
    }

    if opts.include_ips {
        for (addr, agg) in ips {
            if agg.events < opts.min_events {
                continue;
            }
            out.push(HostSuggestion {
                value: addr,
                kind: SuggestionKind::Ip,
                events: agg.events,
                covers: 1,
                covered_hosts: Vec::new(),
                last_seen: agg.last,
            });
        }
    }

    out.sort_by(|a, b| b.events.cmp(&a.events).then_with(|| a.value.cmp(&b.value)));
    out.truncate(opts.limit as usize);

    TargetSuggestions {
        process: process.to_string(),
        total_events,
        distinct_destinations,
        suggestions: out,
    }
}

/// Join entries the way Proxifier's Targets field expects.
pub fn to_targets_line(suggestions: &[HostSuggestion]) -> String {
    suggestions.iter().map(|s| s.value.as_str()).collect::<Vec<_>>().join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, count: u64) -> DestRow {
        (Some(host.into()), None, count, Some("2026-04-17T23:30:00".into()))
    }

    #[test]
    fn rolls_subdomains_into_a_wildcard() {
        let rows = vec![
            row("a.cdn.example.com", 5),
            row("b.cdn.example.com", 4),
            row("c.cdn.example.com", 3),
        ];
        let s = build("app.exe", rows, SuggestOptions::default());
        assert_eq!(s.suggestions.len(), 1);
        let w = &s.suggestions[0];
        assert_eq!(w.value, "*.cdn.example.com");
        assert_eq!(w.kind, SuggestionKind::Wildcard);
        assert_eq!(w.covers, 3);
        assert_eq!(w.events, 12);
    }

    #[test]
    fn keeps_hosts_separate_below_the_threshold() {
        let rows = vec![row("a.example.com", 5), row("b.example.com", 4)];
        let s = build("app.exe", rows, SuggestOptions::default());
        assert!(s.suggestions.iter().all(|x| x.kind == SuggestionKind::Host));
        assert_eq!(s.suggestions.len(), 2);
    }

    /// The failure that would matter: a rule opening most of a TLD.
    #[test]
    fn never_wildcards_a_registry_suffix() {
        for parent in ["co.uk", "com.vn", "or.jp", "ac.uk", "com.au"] {
            let rows: Vec<_> = ["a", "b", "c", "d"]
                .iter()
                .map(|p| row(&format!("{p}.site.{parent}"), 5))
                .collect();
            let s = build("app.exe", rows, SuggestOptions::default());
            let values: Vec<&str> = s.suggestions.iter().map(|x| x.value.as_str()).collect();
            let too_broad = format!("*.{parent}");
            let expected = format!("*.site.{parent}");
            assert!(
                !values.iter().any(|v| *v == too_broad),
                "rolled up to the registry suffix {too_broad}: {values:?}"
            );
            assert!(
                values.iter().any(|v| *v == expected),
                "should still roll up one level below it: {values:?}"
            );
        }
    }

    #[test]
    fn a_two_label_domain_is_never_a_wildcard() {
        let rows: Vec<_> =
            ["a", "b", "c", "d"].iter().map(|p| row(&format!("{p}.com"), 5)).collect();
        let s = build("app.exe", rows, SuggestOptions::default());
        assert!(
            s.suggestions.iter().all(|x| x.kind == SuggestionKind::Host),
            "{:?}",
            s.suggestions
        );
    }

    /// The case that forced multi-level roll-up: a CDN whose hosts each carry
    /// a unique label, so no two share an immediate parent.
    #[test]
    fn rolls_up_past_a_unique_intermediate_label() {
        let rows = vec![
            row("rr1.sn-aaaa.googlevideo.com", 9),
            row("rr2.sn-bbbb.googlevideo.com", 8),
            row("rr3.sn-cccc.googlevideo.com", 7),
            row("rr4.sn-dddd.googlevideo.com", 6),
        ];
        let s = build("firefox.exe", rows, SuggestOptions::default());
        let values: Vec<&str> = s.suggestions.iter().map(|x| x.value.as_str()).collect();
        assert_eq!(values, vec!["*.googlevideo.com"], "{values:?}");
        assert_eq!(s.suggestions[0].covers, 4);
        assert_eq!(s.suggestions[0].events, 30);
    }

    /// Reaching further up must still stop at the registry suffix.
    #[test]
    fn multi_level_roll_up_still_respects_registry_suffixes() {
        let rows: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|p| row(&format!("{p}.uniq-{p}.site.co.uk"), 5))
            .collect();
        let s = build("app.exe", rows, SuggestOptions::default());
        let values: Vec<&str> = s.suggestions.iter().map(|x| x.value.as_str()).collect();
        assert!(!values.contains(&"*.co.uk"), "{values:?}");
        assert_eq!(values, vec!["*.site.co.uk"], "{values:?}");
    }

    #[test]
    fn prefers_the_deeper_parent() {
        let rows = vec![
            row("a.cdn.example.com", 5),
            row("b.cdn.example.com", 5),
            row("c.cdn.example.com", 5),
            row("x.api.example.com", 5),
            row("y.api.example.com", 5),
            row("z.api.example.com", 5),
        ];
        let s = build("app.exe", rows, SuggestOptions::default());
        let values: Vec<&str> = s.suggestions.iter().map(|x| x.value.as_str()).collect();
        assert!(values.contains(&"*.cdn.example.com"), "{values:?}");
        assert!(values.contains(&"*.api.example.com"), "{values:?}");
        assert!(!values.contains(&"*.example.com"), "{values:?}");
    }

    #[test]
    fn drops_one_off_noise_but_keeps_repeat_visits() {
        let rows = vec![row("seen-once.example.com", 1), row("regular.example.com", 9)];
        let s = build("app.exe", rows, SuggestOptions::default());
        let values: Vec<&str> = s.suggestions.iter().map(|x| x.value.as_str()).collect();
        assert_eq!(values, vec!["regular.example.com"]);
    }

    #[test]
    fn addresses_are_opt_in() {
        let rows = vec![(None, Some("203.0.113.7".to_string()), 9u64, None)];
        let off = build("app.exe", rows.clone(), SuggestOptions::default());
        assert!(off.suggestions.is_empty());

        let on = build(
            "app.exe",
            rows,
            SuggestOptions { include_ips: true, ..SuggestOptions::default() },
        );
        assert_eq!(on.suggestions[0].kind, SuggestionKind::Ip);
        assert_eq!(on.suggestions[0].value, "203.0.113.7");
    }

    #[test]
    fn formats_for_the_targets_field() {
        let rows = vec![
            row("a.cdn.example.com", 5),
            row("b.cdn.example.com", 5),
            row("c.cdn.example.com", 5),
            row("solo.example.org", 4),
        ];
        let s = build("app.exe", rows, SuggestOptions::default());
        let line = to_targets_line(&s.suggestions);
        assert_eq!(line, "*.cdn.example.com; solo.example.org");
    }

    #[test]
    fn hostname_wins_over_address_for_the_same_connection() {
        let rows = vec![(Some("api.example.com".into()), Some("203.0.113.1".into()), 7u64, None)];
        let s = build(
            "app.exe",
            rows,
            SuggestOptions { include_ips: true, ..SuggestOptions::default() },
        );
        assert_eq!(s.suggestions.len(), 1);
        assert_eq!(s.suggestions[0].value, "api.example.com");
    }
}
