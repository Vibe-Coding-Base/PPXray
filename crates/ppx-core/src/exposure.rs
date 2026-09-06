//! Internet-exposure surface analysis.
//!
//! Turns a `Profile` into an `ExposureGraph`: a six-column flow model of how
//! traffic from a process reaches the internet, and through what port and
//! proxy.
//!
//! ```text
//!   Processes ── Rules ── Ports ── Exits ── (Proxy hops) ── Internet
//!                                    │
//!                                   Block ⊗  (terminates, no Internet)
//! ```
//!
//! Processes are bucketed by basename, plus a synthetic `Unlisted` bucket for
//! everything the profile does not name. Ports include an `any` sentinel, so a
//! rule with `[443, 80]` produces two flows. Proxy hops cover every proxy
//! defined in the profile, not only the referenced ones.
//!
//! Findings are emitted alongside the graph; see [`FindingKind`].
//!
//! Pure over the profile — no log data, no live system state — so it is safe
//! to call on every keystroke. The frontend debounces to 400 ms.
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::model::{Profile, Proxy, ProxyType, Rule, RuleAction};

// ----------------------------------------------------------------------------
// Wire types (ts-rs exported to the renderer)
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ExposureGraph {
    pub processes: Vec<ProcessBucket>,
    pub rules: Vec<RuleRef>,
    pub ports: Vec<PortGroup>,
    pub channels: Vec<ExitChannel>,
    pub proxy_hops: Vec<ProxyHop>,
    pub chain_descriptors: Vec<ChainDescriptor>,
    pub flows: Vec<Flow>,
    pub findings: Vec<ExposureFinding>,
    pub summary: ExposureSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ExposureSummary {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub has_default_deny: bool,
    pub process_count: usize,
    /// Sum of every flow's breadth — one number "how exposed is this host?"
    pub aggregate_breadth: f32,
    pub finding_counts: FindingCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct FindingCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ProcessBucket {
    /// `firefox.exe`, `chrome.exe`, `svchost.exe`, or the synthetic
    /// `(unlisted)`.
    pub name: String,
    pub kind: ProcessBucketKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum ProcessBucketKind {
    Listed,
    Unlisted,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct RuleRef {
    /// Index into the original `profile.rules` vector — lets the UI pivot
    /// back to the rule editor on click.
    pub index: usize,
    pub name: String,
    pub action: RuleActionKind,
    pub breadth: f32,
    pub applies_to_any_process: bool,
    pub any_target: bool,
    pub any_port: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum RuleActionKind {
    Direct,
    Block,
    Proxy { proxy_id: u32 },
    Chain { chain_id: u32 },
}

impl From<&RuleAction> for RuleActionKind {
    fn from(a: &RuleAction) -> Self {
        match a {
            RuleAction::Direct => Self::Direct,
            RuleAction::Block => Self::Block,
            RuleAction::Proxy { proxy_id } => Self::Proxy { proxy_id: *proxy_id },
            RuleAction::Chain { chain_id } => Self::Chain { chain_id: *chain_id },
        }
    }
}

/// One lane in the "Ports" column. A rule with 3 distinct port tokens
/// produces 3 `PortGroup` references (one lane each).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct PortGroup {
    /// Display label: `"443"`, `"8000-8100"`, or `"any"` for the empty-ports
    /// sentinel.
    pub label: String,
    pub is_any: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ExitChannel {
    pub kind: ExitChannelKind,
    /// Display label: `"Direct"`, `"Block"`, `"Proxy #3 corp-socks"`, …
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum ExitChannelKind {
    Direct,
    Block,
    Proxy { proxy_id: u32 },
    Chain { chain_id: u32 },
}

/// One entry in the "Proxy hops" column. We emit one per proxy defined in
/// the profile — even if no rule references it — so the user can see the
/// full pool available.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ProxyHop {
    pub proxy_id: u32,
    pub proxy_type: ProxyType,
    pub address: String,
    pub port: u16,
    pub label: Option<String>,
    /// True when the transport provides confidentiality against a passive
    /// observer between host and proxy. SOCKS5 + HTTPS → yes. SOCKS4 + HTTP
    /// → no (credentials + payload in cleartext on this leg).
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ChainDescriptor {
    pub chain_id: u32,
    pub name: Option<String>,
    /// Ordered list of hop positions into `proxy_hops`. `None` slots mean
    /// "chain references a proxy_id that doesn't exist" — those also feed
    /// the `BrokenChain` finding.
    pub hop_proxy_indices: Vec<Option<usize>>,
}

/// One flow lane: a (process, rule, port, channel) tuple. For Proxy / Chain
/// channels the downstream hop column can be derived by looking up
/// `channels[channel_index]` and then into `proxy_hops` / `chain_descriptors`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct Flow {
    pub process_index: usize,
    pub rule_index: usize,
    pub port_index: usize,
    pub channel_index: usize,
    pub breadth: f32,
    /// True when this is the **first** rule that would fire for this
    /// (process, port) pair. Non-first-match flows are "dead lanes" — the
    /// UI renders them dimmer so shadows are visible at a glance.
    pub is_first_match: bool,
}

// ----------------------------------------------------------------------------
// Findings
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct ExposureFinding {
    pub severity: FindingSeverity,
    pub kind: FindingKind,
    pub title: String,
    pub detail: String,
    pub rule_indices: Vec<usize>,
    pub process_indices: Vec<usize>,
    pub proxy_ids: Vec<u32>,
    pub chain_ids: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub enum FindingKind {
    MissingDefaultDeny,
    BlanketDirectRule,
    AnyTargetDirect,
    UnlistedReachesInternet,
    WideBreadthDirect,
    ShadowedRule,
    DisabledTerminalRule,
    OrphanProxyReference,
    BrokenChain,
    UnencryptedProxy,
}

// ----------------------------------------------------------------------------
// Entry point
// ----------------------------------------------------------------------------

pub fn compute_exposure(profile: &Profile) -> ExposureGraph {
    let processes = build_process_buckets(&profile.rules);
    let (rules, rule_index_map) = build_rule_refs(&profile.rules);
    let ports = build_port_groups(&profile.rules);
    let channels = build_channels(&profile.rules, &profile.proxies);
    let channel_lookup = ChannelLookup::new(&channels);
    let proxy_hops = build_proxy_hops(&profile.proxies);
    let proxy_hop_lookup = ProxyHopLookup::new(&proxy_hops);
    let chain_descriptors = build_chain_descriptors(&profile.chains, &proxy_hop_lookup);

    let flows = build_flows(&profile.rules, &processes, &rule_index_map, &ports, &channel_lookup);

    let findings = build_findings(
        profile,
        &processes,
        &rules,
        &flows,
        &channels,
        &proxy_hops,
        &chain_descriptors,
    );

    let has_default_deny = detect_default_deny(&profile.rules);
    let enabled_rules = profile.rules.iter().filter(|r| r.enabled).count();
    let aggregate_breadth = flows.iter().map(|f| f.breadth).sum();

    let mut counts = FindingCounts::default();
    for f in &findings {
        match f.severity {
            FindingSeverity::Critical => counts.critical += 1,
            FindingSeverity::High => counts.high += 1,
            FindingSeverity::Medium => counts.medium += 1,
            FindingSeverity::Low => counts.low += 1,
        }
    }

    ExposureGraph {
        summary: ExposureSummary {
            total_rules: profile.rules.len(),
            enabled_rules,
            has_default_deny,
            process_count: processes.len(),
            aggregate_breadth,
            finding_counts: counts,
        },
        processes,
        rules,
        ports,
        channels,
        proxy_hops,
        chain_descriptors,
        flows,
        findings,
    }
}

// ----------------------------------------------------------------------------
// Process buckets
// ----------------------------------------------------------------------------

const UNLISTED_LABEL: &str = "(unlisted)";

/// System processes the UI renders as "listed" buckets even when no rule
/// names them. Short by design — this list bloats fast if we try to be
/// comprehensive.
const SYSTEM_PROCESS_HINTS: &[&str] =
    &["svchost.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe"];

fn build_process_buckets(rules: &[Rule]) -> Vec<ProcessBucket> {
    let mut seen: Vec<String> = Vec::new();
    for rule in rules {
        for app in &rule.applications {
            if let Some(base) = normalize_app_basename(app)
                && !seen.iter().any(|s| s.eq_ignore_ascii_case(&base))
            {
                seen.push(base);
            }
        }
    }
    for hint in SYSTEM_PROCESS_HINTS {
        if !seen.iter().any(|s| s.eq_ignore_ascii_case(hint)) {
            seen.push((*hint).to_string());
        }
    }
    seen.sort_by_key(|s| s.to_ascii_lowercase());

    let mut buckets: Vec<ProcessBucket> = seen
        .into_iter()
        .map(|name| ProcessBucket { name, kind: ProcessBucketKind::Listed })
        .collect();
    buckets.push(ProcessBucket {
        name: UNLISTED_LABEL.to_string(),
        kind: ProcessBucketKind::Unlisted,
    });
    buckets
}

fn normalize_app_basename(entry: &str) -> Option<String> {
    let e = entry.trim().trim_matches('"').trim();
    if e.is_empty() || e.contains(['*', '?']) {
        return None;
    }
    let base = match e.rfind(['\\', '/']) {
        Some(i) => &e[i + 1..],
        None => e,
    };
    if base.is_empty() { None } else { Some(base.to_ascii_lowercase()) }
}

// ----------------------------------------------------------------------------
// Rule refs
// ----------------------------------------------------------------------------

fn build_rule_refs(rules: &[Rule]) -> (Vec<RuleRef>, Vec<Option<usize>>) {
    let mut refs = Vec::new();
    let mut map = vec![None; rules.len()];
    for (i, rule) in rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        let pos = refs.len();
        refs.push(RuleRef {
            index: i,
            name: rule.name.clone(),
            action: RuleActionKind::from(&rule.action),
            breadth: breadth_score(rule),
            applies_to_any_process: rule.applications.is_empty(),
            any_target: rule.targets.is_empty(),
            any_port: rule.ports.is_empty(),
        });
        map[i] = Some(pos);
    }
    (refs, map)
}

// ----------------------------------------------------------------------------
// Port groups
// ----------------------------------------------------------------------------

/// Sentinel label for "rule has no port constraint".
const PORT_ANY_LABEL: &str = "any";

fn build_port_groups(rules: &[Rule]) -> Vec<PortGroup> {
    let mut labels: Vec<String> = Vec::new();
    let mut any_used = false;
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if rule.ports.is_empty() {
            any_used = true;
            continue;
        }
        for p in &rule.ports {
            let norm = p.trim().to_string();
            if norm.is_empty() {
                any_used = true;
                continue;
            }
            if !labels.iter().any(|l| l == &norm) {
                labels.push(norm);
            }
        }
    }
    // Sort ports naturally: by first parsed number, ties broken by string.
    labels.sort_by(|a, b| port_sort_key(a).cmp(&port_sort_key(b)).then_with(|| a.cmp(b)));

    let mut out: Vec<PortGroup> = Vec::new();
    if any_used {
        out.push(PortGroup { label: PORT_ANY_LABEL.into(), is_any: true });
    }
    for l in labels {
        out.push(PortGroup { label: l, is_any: false });
    }
    out
}

fn port_sort_key(s: &str) -> u32 {
    s.trim().split('-').next().and_then(|t| t.trim().parse().ok()).unwrap_or(u32::MAX)
}

fn port_group_index(ports: &[PortGroup], token: Option<&str>) -> Option<usize> {
    match token {
        None => ports.iter().position(|p| p.is_any),
        Some(t) => {
            let t = t.trim();
            ports.iter().position(|p| !p.is_any && p.label == t)
        }
    }
}

// ----------------------------------------------------------------------------
// Channels
// ----------------------------------------------------------------------------

fn build_channels(rules: &[Rule], proxies: &[Proxy]) -> Vec<ExitChannel> {
    let mut out: Vec<ExitChannel> = Vec::new();
    let push = |ch: ExitChannel, out: &mut Vec<ExitChannel>| {
        if !out.iter().any(|c| c.kind == ch.kind) {
            out.push(ch);
        }
    };
    // Always show Direct + Block so the baseline is visible even before the
    // user adds rules.
    push(ExitChannel { kind: ExitChannelKind::Direct, label: "Direct".into() }, &mut out);
    push(ExitChannel { kind: ExitChannelKind::Block, label: "Block".into() }, &mut out);

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        match &rule.action {
            RuleAction::Direct | RuleAction::Block => {}
            RuleAction::Proxy { proxy_id } => {
                let label = proxies
                    .iter()
                    .find(|p| p.id == *proxy_id)
                    .and_then(|p| p.label.clone())
                    .map(|lbl| format!("Proxy #{} {}", proxy_id, lbl))
                    .unwrap_or_else(|| format!("Proxy #{}", proxy_id));
                push(
                    ExitChannel { kind: ExitChannelKind::Proxy { proxy_id: *proxy_id }, label },
                    &mut out,
                );
            }
            RuleAction::Chain { chain_id } => {
                push(
                    ExitChannel {
                        kind: ExitChannelKind::Chain { chain_id: *chain_id },
                        label: format!("Chain #{}", chain_id),
                    },
                    &mut out,
                );
            }
        }
    }
    out
}

struct ChannelLookup<'a> {
    channels: &'a [ExitChannel],
}
impl<'a> ChannelLookup<'a> {
    fn new(channels: &'a [ExitChannel]) -> Self {
        Self { channels }
    }
    fn for_action(&self, action: &RuleAction) -> Option<usize> {
        let k = match action {
            RuleAction::Direct => ExitChannelKind::Direct,
            RuleAction::Block => ExitChannelKind::Block,
            RuleAction::Proxy { proxy_id } => ExitChannelKind::Proxy { proxy_id: *proxy_id },
            RuleAction::Chain { chain_id } => ExitChannelKind::Chain { chain_id: *chain_id },
        };
        self.channels.iter().position(|c| c.kind == k)
    }
}

// ----------------------------------------------------------------------------
// Proxy hops + chain descriptors
// ----------------------------------------------------------------------------

/// SOCKS5 + HTTPS provide confidentiality on the host→proxy leg. SOCKS4 +
/// HTTP do not (credentials + payload observable by anyone on path).
fn is_transport_encrypted(t: ProxyType) -> bool {
    matches!(t, ProxyType::Socks5 | ProxyType::Https)
}

fn build_proxy_hops(proxies: &[Proxy]) -> Vec<ProxyHop> {
    proxies
        .iter()
        .map(|p| ProxyHop {
            proxy_id: p.id,
            proxy_type: p.proxy_type,
            address: p.address.clone(),
            port: p.port,
            label: p.label.clone(),
            is_encrypted: is_transport_encrypted(p.proxy_type),
        })
        .collect()
}

struct ProxyHopLookup<'a> {
    hops: &'a [ProxyHop],
}
impl<'a> ProxyHopLookup<'a> {
    fn new(hops: &'a [ProxyHop]) -> Self {
        Self { hops }
    }
    fn index_of(&self, proxy_id: u32) -> Option<usize> {
        self.hops.iter().position(|h| h.proxy_id == proxy_id)
    }
}

fn build_chain_descriptors(
    chains: &[crate::model::Chain],
    proxy_lookup: &ProxyHopLookup<'_>,
) -> Vec<ChainDescriptor> {
    chains
        .iter()
        .map(|c| ChainDescriptor {
            chain_id: c.id,
            name: c.name.clone(),
            hop_proxy_indices: c
                .members
                .iter()
                .map(|m| proxy_lookup.index_of(m.proxy_id))
                .collect(),
        })
        .collect()
}

// ----------------------------------------------------------------------------
// Flow construction
// ----------------------------------------------------------------------------

/// Produce one Flow per (matching process bucket, rule, port token) triple.
/// `first_match` is set for the first rule/port token combination that would
/// catch a given process's outbound at that port — subsequent matches are
/// shadowed lanes and get a dim render.
fn build_flows(
    rules: &[Rule],
    processes: &[ProcessBucket],
    rule_index_map: &[Option<usize>],
    ports: &[PortGroup],
    channels: &ChannelLookup<'_>,
) -> Vec<Flow> {
    let mut flows = Vec::new();

    for (p_idx, bucket) in processes.iter().enumerate() {
        // Track per-port "has a first-match been recorded yet" so we mark
        // only the earliest rule per port as first_match.
        let mut first_match_seen_for_port = vec![false; ports.len()];

        for (r_idx, rule) in rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            if !rule_matches_bucket(rule, bucket) {
                continue;
            }
            let Some(rule_ref_pos) = rule_index_map[r_idx] else {
                continue;
            };
            let Some(channel_idx) = channels.for_action(&rule.action) else {
                continue;
            };

            let breadth = breadth_score(rule);

            // Expand rule.ports into one Flow per port token; empty → "any".
            if rule.ports.is_empty() {
                if let Some(pi) = port_group_index(ports, None) {
                    let is_first = !first_match_seen_for_port[pi];
                    flows.push(Flow {
                        process_index: p_idx,
                        rule_index: rule_ref_pos,
                        port_index: pi,
                        channel_index: channel_idx,
                        breadth,
                        is_first_match: is_first,
                    });
                    first_match_seen_for_port[pi] = true;
                }
            } else {
                for token in &rule.ports {
                    let token = token.trim();
                    let pi_opt = if token.is_empty() {
                        port_group_index(ports, None)
                    } else {
                        port_group_index(ports, Some(token))
                    };
                    if let Some(pi) = pi_opt {
                        let is_first = !first_match_seen_for_port[pi];
                        flows.push(Flow {
                            process_index: p_idx,
                            rule_index: rule_ref_pos,
                            port_index: pi,
                            channel_index: channel_idx,
                            breadth,
                            is_first_match: is_first,
                        });
                        first_match_seen_for_port[pi] = true;
                    }
                }
            }
        }
    }

    flows
}

fn rule_matches_bucket(rule: &Rule, bucket: &ProcessBucket) -> bool {
    if rule.applications.is_empty() {
        return true;
    }
    match bucket.kind {
        ProcessBucketKind::Listed => {
            rule.applications.iter().any(|entry| app_entry_matches_basename(entry, &bucket.name))
        }
        ProcessBucketKind::Unlisted => rule.applications.iter().any(|e| {
            let trimmed = e.trim().trim_matches('"').trim();
            trimmed.contains(['*', '?'])
        }),
    }
}

fn app_entry_matches_basename(entry: &str, basename: &str) -> bool {
    let entry = entry.trim().trim_matches('"').trim().to_ascii_lowercase();
    let basename = basename.to_ascii_lowercase();
    if entry.is_empty() {
        return false;
    }
    if let Some(norm) = normalize_app_basename(&entry)
        && norm == basename
    {
        return true;
    }
    if entry.contains(['*', '?']) {
        return glob_matches(&entry, &basename);
    }
    false
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
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

// ----------------------------------------------------------------------------
// Breadth heuristic
// ----------------------------------------------------------------------------

/// Log-scale "how big a slice of the Internet does this rule cover?" score,
/// clamped to `0.0..=1.0`.
///
/// Three axes combined in log-space: target bits (0..32), port bits (0..16),
/// app bits (0..16). Divided by 64 and clamped. Preserves relative ordering
/// without linear IP counting's long tail.
pub fn breadth_score(rule: &Rule) -> f32 {
    let total = target_bits(&rule.targets) + port_bits(&rule.ports) + app_bits(&rule.applications);
    (total / 64.0).clamp(0.0, 1.0)
}

fn target_bits(entries: &[String]) -> f32 {
    if entries.is_empty() {
        return 32.0;
    }
    entries
        .iter()
        .map(|e| {
            let e = e.trim();
            if e == "*" {
                return 32.0;
            }
            if let Some((_, pre)) = e.split_once('/')
                && let Ok(prefix) = pre.parse::<u8>()
                && prefix <= 32
            {
                return (32 - prefix) as f32;
            }
            if let Some(stripped) = e.strip_suffix('*').map(|t| t.trim_end_matches('.')) {
                let octets = stripped.split('.').count();
                if octets <= 3 {
                    return (32 - octets as i32 * 8).max(0) as f32;
                }
                return 24.0;
            }
            if e.contains(['*', '?']) {
                return 24.0;
            }
            0.0
        })
        .fold(0.0_f32, f32::max)
}

fn port_bits(entries: &[String]) -> f32 {
    if entries.is_empty() {
        return 16.0;
    }
    entries
        .iter()
        .map(|e| {
            let e = e.trim();
            if let Some((a, b)) = e.split_once('-')
                && let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>())
            {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                let span = (hi - lo + 1).max(1) as f32;
                return span.log2();
            }
            0.0
        })
        .fold(0.0_f32, f32::max)
}

fn app_bits(entries: &[String]) -> f32 {
    if entries.is_empty() {
        return 16.0;
    }
    entries
        .iter()
        .map(|e| {
            let e = e.trim().trim_matches('"').trim();
            if e == "*" {
                return 16.0;
            }
            if e.contains(['*', '?']) {
                return 8.0;
            }
            0.0
        })
        .fold(0.0_f32, f32::max)
}

// ----------------------------------------------------------------------------
// Finding detection
// ----------------------------------------------------------------------------

fn detect_default_deny(rules: &[Rule]) -> bool {
    for rule in rules.iter().rev() {
        if !rule.enabled {
            continue;
        }
        let catch_all =
            rule.targets.is_empty() && rule.applications.is_empty() && rule.ports.is_empty();
        if catch_all && matches!(rule.action, RuleAction::Block) {
            return true;
        }
        if catch_all {
            return false;
        }
    }
    false
}

fn empty_finding(
    severity: FindingSeverity,
    kind: FindingKind,
    title: String,
    detail: String,
) -> ExposureFinding {
    ExposureFinding {
        severity,
        kind,
        title,
        detail,
        rule_indices: vec![],
        process_indices: vec![],
        proxy_ids: vec![],
        chain_ids: vec![],
    }
}

fn build_findings(
    profile: &Profile,
    processes: &[ProcessBucket],
    rules: &[RuleRef],
    flows: &[Flow],
    _channels: &[ExitChannel],
    proxy_hops: &[ProxyHop],
    chain_descriptors: &[ChainDescriptor],
) -> Vec<ExposureFinding> {
    let mut out = Vec::new();

    // MissingDefaultDeny — HIGH (least-privilege priority).
    if !detect_default_deny(&profile.rules) {
        out.push(empty_finding(
            FindingSeverity::High,
            FindingKind::MissingDefaultDeny,
            "No terminal Block rule".into(),
            "The rule list has no catch-all Block at the bottom. Any \
             connection that misses every rule falls through to Proxifier's \
             default action (usually Direct), which means unlisted processes \
             can still reach the Internet."
                .into(),
        ));
    }

    // BlanketDirectRule — CRITICAL.
    for (idx, rule) in profile.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        if rule.targets.is_empty()
            && rule.applications.is_empty()
            && rule.ports.is_empty()
            && matches!(rule.action, RuleAction::Direct)
        {
            out.push(ExposureFinding {
                severity: FindingSeverity::Critical,
                kind: FindingKind::BlanketDirectRule,
                title: format!("Blanket Direct rule: {}", rule.name),
                detail: "This rule has no Applications, Targets, or Ports \
                    constraint — any process on the system can reach any \
                    host on any port through it. This is the canonical \
                    silent policy hole."
                    .into(),
                rule_indices: vec![idx],
                process_indices: vec![],
                proxy_ids: vec![],
                chain_ids: vec![],
            });
        }
    }

    // AnyTargetDirect — HIGH.
    for (idx, rule) in profile.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        if !matches!(rule.action, RuleAction::Direct) {
            continue;
        }
        let has_other_constraint = !rule.applications.is_empty() || !rule.ports.is_empty();
        let any_targets = rule.targets.is_empty() || rule.targets.iter().any(|t| t.trim() == "*");
        if any_targets && has_other_constraint {
            out.push(ExposureFinding {
                severity: FindingSeverity::High,
                kind: FindingKind::AnyTargetDirect,
                title: format!("Direct rule reaches any host: {}", rule.name),
                detail: "Target field is empty or `*`. The named processes \
                    can reach any host on the Internet without inspection."
                    .into(),
                rule_indices: vec![idx],
                process_indices: vec![],
                proxy_ids: vec![],
                chain_ids: vec![],
            });
        }
    }

    // UnlistedReachesInternet — HIGH.
    if let Some((unlisted_idx, _)) =
        processes.iter().enumerate().find(|(_, p)| p.kind == ProcessBucketKind::Unlisted)
        && let Some(flow) =
            flows.iter().find(|f| f.process_index == unlisted_idx && f.is_first_match)
    {
        let rule_ref = &rules[flow.rule_index];
        if !matches!(rule_ref.action, RuleActionKind::Block) {
            out.push(ExposureFinding {
                severity: FindingSeverity::High,
                kind: FindingKind::UnlistedReachesInternet,
                title: "Unlisted processes have a Direct path".into(),
                detail: format!(
                    "Processes not explicitly named by any rule hit `{}` \
                     first, which is not a Block. Malware dropped on the \
                     host would exit here.",
                    rule_ref.name
                ),
                rule_indices: vec![rule_ref.index],
                process_indices: vec![unlisted_idx],
                proxy_ids: vec![],
                chain_ids: vec![],
            });
        }
    }

    // WideBreadthDirect — MEDIUM.
    for (idx, rule) in profile.rules.iter().enumerate() {
        if !rule.enabled || !matches!(rule.action, RuleAction::Direct) {
            continue;
        }
        let b = breadth_score(rule);
        if b >= 0.7
            && !(rule.targets.is_empty() && rule.applications.is_empty() && rule.ports.is_empty())
        {
            out.push(ExposureFinding {
                severity: FindingSeverity::Medium,
                kind: FindingKind::WideBreadthDirect,
                title: format!("Wide-breadth Direct: {}", rule.name),
                detail: format!(
                    "Breadth score {:.2} / 1.00. Covers a large portion of \
                     the host/port/application space.",
                    b
                ),
                rule_indices: vec![idx],
                process_indices: vec![],
                proxy_ids: vec![],
                chain_ids: vec![],
            });
        }
    }

    // ShadowedRule — MEDIUM (reuse the existing overshadow detector).
    let shadow_pairs = crate::matcher::overshadow_pairs(&profile.rules);
    for pair in &shadow_pairs {
        let shadowed_rule = &profile.rules[pair.shadowed];
        let shadower_rule = &profile.rules[pair.shadower];
        out.push(ExposureFinding {
            severity: FindingSeverity::Medium,
            kind: FindingKind::ShadowedRule,
            title: format!("Rule can never fire: {}", shadowed_rule.name),
            detail: format!(
                "Earlier rule `{}` already covers this rule's constraints, \
                 so it can never win a match.",
                shadower_rule.name
            ),
            rule_indices: vec![pair.shadowed, pair.shadower],
            process_indices: vec![],
            proxy_ids: vec![],
            chain_ids: vec![],
        });
    }

    // DisabledTerminalRule — LOW.
    for (idx, rule) in profile.rules.iter().enumerate() {
        if rule.enabled {
            continue;
        }
        let catch_all =
            rule.targets.is_empty() && rule.applications.is_empty() && rule.ports.is_empty();
        if catch_all && matches!(rule.action, RuleAction::Block) {
            out.push(ExposureFinding {
                severity: FindingSeverity::Low,
                kind: FindingKind::DisabledTerminalRule,
                title: format!("Disabled terminal Block: {}", rule.name),
                detail: "A catch-all Block rule exists but is disabled. \
                    Re-enable it to restore default-deny posture."
                    .into(),
                rule_indices: vec![idx],
                process_indices: vec![],
                proxy_ids: vec![],
                chain_ids: vec![],
            });
        }
    }

    // OrphanProxyReference — HIGH. Any rule targeting a proxy_id not in the
    // profile's proxy table effectively has no exit: Proxifier falls through
    // to the next rule, which is almost never what the author intended.
    for (idx, rule) in profile.rules.iter().enumerate() {
        if !rule.enabled {
            continue;
        }
        if let RuleAction::Proxy { proxy_id } = &rule.action
            && !proxy_hops.iter().any(|h| h.proxy_id == *proxy_id)
        {
            out.push(ExposureFinding {
                severity: FindingSeverity::High,
                kind: FindingKind::OrphanProxyReference,
                title: format!("Rule points at missing proxy #{}", proxy_id),
                detail: format!(
                    "Rule `{}` uses Proxy #{} but that proxy is not defined \
                     in this profile. The rule will not route traffic — \
                     Proxifier falls through to the next rule silently.",
                    rule.name, proxy_id
                ),
                rule_indices: vec![idx],
                process_indices: vec![],
                proxy_ids: vec![*proxy_id],
                chain_ids: vec![],
            });
        }
    }

    // BrokenChain — HIGH. A chain whose members include a missing proxy_id.
    for chain in chain_descriptors {
        let missing: Vec<usize> = chain
            .hop_proxy_indices
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.is_none().then_some(i))
            .collect();
        if !missing.is_empty() {
            out.push(ExposureFinding {
                severity: FindingSeverity::High,
                kind: FindingKind::BrokenChain,
                title: format!(
                    "Chain #{} has {} missing hop{}",
                    chain.chain_id,
                    missing.len(),
                    if missing.len() == 1 { "" } else { "s" }
                ),
                detail: format!(
                    "Chain `{}` references proxies that aren't defined. \
                     Traffic routed through this chain stalls at the missing \
                     hop.",
                    chain.name.clone().unwrap_or_else(|| format!("Chain #{}", chain.chain_id))
                ),
                rule_indices: vec![],
                process_indices: vec![],
                proxy_ids: vec![],
                chain_ids: vec![chain.chain_id],
            });
        }
    }

    // UnencryptedProxy — MEDIUM. Any proxy with a cleartext transport on
    // the host→proxy leg. Users often miss this when they add a dev HTTP
    // proxy for inspection and forget to remove it.
    for hop in proxy_hops {
        if !hop.is_encrypted {
            let lbl = hop.label.clone().unwrap_or_else(|| format!("Proxy #{}", hop.proxy_id));
            out.push(ExposureFinding {
                severity: FindingSeverity::Medium,
                kind: FindingKind::UnencryptedProxy,
                title: format!("Cleartext proxy: {}", lbl),
                detail: format!(
                    "Proxy #{} ({} at {}:{}) uses a cleartext transport. \
                     Credentials and payload on the host→proxy leg are \
                     observable by anyone on path.",
                    hop.proxy_id,
                    proxy_type_label(hop.proxy_type),
                    hop.address,
                    hop.port,
                ),
                rule_indices: vec![],
                process_indices: vec![],
                proxy_ids: vec![hop.proxy_id],
                chain_ids: vec![],
            });
        }
    }

    out.sort_by_key(|f| severity_ord(f.severity));
    out
}

fn severity_ord(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
    }
}

fn proxy_type_label(t: ProxyType) -> &'static str {
    match t {
        ProxyType::Socks4 => "SOCKS4",
        ProxyType::Socks5 => "SOCKS5",
        ProxyType::Http => "HTTP",
        ProxyType::Https => "HTTPS",
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Chain, ChainMember, Profile, Proxy, ProxyType, Rule, RuleAction};

    fn rule(
        name: &str,
        action: RuleAction,
        targets: &[&str],
        apps: &[&str],
        ports: &[&str],
    ) -> Rule {
        Rule {
            enabled: true,
            name: name.into(),
            action,
            targets: targets.iter().map(|s| s.to_string()).collect(),
            applications: apps.iter().map(|s| s.to_string()).collect(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn profile_with(rules: Vec<Rule>) -> Profile {
        let mut p = Profile::empty();
        p.rules = rules;
        p
    }

    fn proxy(id: u32, t: ProxyType, addr: &str, port: u16, label: Option<&str>) -> Proxy {
        Proxy {
            id,
            proxy_type: t,
            address: addr.into(),
            port,
            options: None,
            label: label.map(String::from),
            authentication: None,
        }
    }

    #[test]
    fn empty_profile_flags_missing_default_deny() {
        let g = compute_exposure(&Profile::empty());
        assert!(g.findings.iter().any(|f| f.kind == FindingKind::MissingDefaultDeny));
        assert!(g.processes.iter().any(|p| p.kind == ProcessBucketKind::Unlisted));
        // Ports column contains nothing yet (no enabled rules) → no "any" sentinel.
        assert!(g.ports.is_empty());
    }

    #[test]
    fn blanket_direct_rule_is_critical() {
        let p = profile_with(vec![rule("Catch-all", RuleAction::Direct, &[], &[], &[])]);
        let g = compute_exposure(&p);
        let crit = g
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::BlanketDirectRule)
            .expect("BlanketDirectRule");
        assert_eq!(crit.severity, FindingSeverity::Critical);
        assert_eq!(crit.rule_indices, vec![0]);
    }

    #[test]
    fn terminal_block_clears_default_deny_warning() {
        let p = profile_with(vec![
            rule("Allow firefox", RuleAction::Direct, &[], &["firefox.exe"], &["443"]),
            rule("Default deny", RuleAction::Block, &[], &[], &[]),
        ]);
        let g = compute_exposure(&p);
        assert!(g.summary.has_default_deny);
        assert!(!g.findings.iter().any(|f| f.kind == FindingKind::MissingDefaultDeny));
    }

    #[test]
    fn port_groups_split_multiport_rule_into_multiple_flows() {
        let p = profile_with(vec![
            rule("FF HTTPS/HTTP", RuleAction::Direct, &[], &["firefox.exe"], &["443", "80"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ]);
        let g = compute_exposure(&p);
        // Port column has 443, 80, and "any" (from the terminal block).
        assert!(g.ports.iter().any(|pg| pg.label == "443" && !pg.is_any));
        assert!(g.ports.iter().any(|pg| pg.label == "80" && !pg.is_any));
        assert!(g.ports.iter().any(|pg| pg.is_any));
        // Firefox bucket produces one flow per port token.
        let ff_idx = g.processes.iter().position(|pb| pb.name == "firefox.exe").unwrap();
        let ff_direct = g
            .flows
            .iter()
            .filter(|f| f.process_index == ff_idx && !g.ports[f.port_index].is_any)
            .count();
        assert!(
            ff_direct >= 2,
            "expected ≥2 Firefox Direct flows (port 443 + 80), got {}",
            ff_direct
        );
    }

    #[test]
    fn unlisted_bucket_with_direct_fallthrough_is_flagged() {
        let p = profile_with(vec![rule("Glob direct", RuleAction::Direct, &[], &["*.exe"], &[])]);
        let g = compute_exposure(&p);
        assert!(g.findings.iter().any(|f| f.kind == FindingKind::UnlistedReachesInternet));
    }

    #[test]
    fn shadowed_rule_is_surfaced() {
        let p = profile_with(vec![
            rule("Broad", RuleAction::Direct, &["*.example.com"], &[], &["443"]),
            rule("Narrow", RuleAction::Direct, &["api.example.com"], &[], &["443"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ]);
        let g = compute_exposure(&p);
        assert!(g.findings.iter().any(|f| f.kind == FindingKind::ShadowedRule));
    }

    #[test]
    fn breadth_ordering_is_monotonic() {
        let narrow =
            rule("N", RuleAction::Direct, &["api.example.com"], &["firefox.exe"], &["443"]);
        let medium = rule("M", RuleAction::Direct, &["*.example.com"], &["firefox.exe"], &[]);
        let wide = rule("W", RuleAction::Direct, &[], &[], &[]);
        assert!(breadth_score(&narrow) < breadth_score(&medium));
        assert!(breadth_score(&medium) < breadth_score(&wide));
        assert!((breadth_score(&wide) - 1.0).abs() < 0.001);
    }

    #[test]
    fn process_buckets_are_deduped_case_insensitively() {
        let p = profile_with(vec![
            rule("A", RuleAction::Direct, &[], &["Firefox.exe"], &["443"]),
            rule("B", RuleAction::Direct, &[], &[r"C:\Path\firefox.exe"], &["443"]),
        ]);
        let g = compute_exposure(&p);
        assert_eq!(g.processes.iter().filter(|p| p.name == "firefox.exe").count(), 1);
    }

    #[test]
    fn disabled_terminal_block_is_low_finding() {
        let mut r = rule("Default deny", RuleAction::Block, &[], &[], &[]);
        r.enabled = false;
        let p = profile_with(vec![r]);
        let g = compute_exposure(&p);
        let f = g
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::DisabledTerminalRule)
            .expect("DisabledTerminalRule");
        assert_eq!(f.severity, FindingSeverity::Low);
    }

    #[test]
    fn wide_breadth_direct_at_medium() {
        let p = profile_with(vec![
            rule("Wide FF", RuleAction::Direct, &[], &["firefox.exe"], &[]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ]);
        let g = compute_exposure(&p);
        let f = g.findings.iter().find(|f| f.kind == FindingKind::WideBreadthDirect);
        assert!(f.is_some(), "WideBreadthDirect expected");
        assert_eq!(f.unwrap().severity, FindingSeverity::Medium);
    }

    // ---- new: proxies + chains ---------------------------------------------

    #[test]
    fn orphan_proxy_reference_is_high() {
        let mut p = Profile::empty();
        // Profile has no proxy #3 defined but a rule targets it.
        p.rules = vec![
            rule("Via missing", RuleAction::Proxy { proxy_id: 3 }, &[], &["chrome.exe"], &["443"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ];
        let g = compute_exposure(&p);
        let orph = g
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::OrphanProxyReference)
            .expect("OrphanProxyReference");
        assert_eq!(orph.severity, FindingSeverity::High);
        assert_eq!(orph.proxy_ids, vec![3]);
        assert_eq!(orph.rule_indices, vec![0]);
    }

    #[test]
    fn broken_chain_is_high() {
        let mut p = Profile::empty();
        // Chain #7 references proxies 1 and 99; only 1 is defined.
        p.proxies = vec![proxy(1, ProxyType::Socks5, "10.0.0.1", 1080, Some("corp"))];
        p.chains = vec![Chain {
            id: 7,
            name: Some("vpn-chain".into()),
            members: vec![ChainMember { proxy_id: 1 }, ChainMember { proxy_id: 99 }],
        }];
        p.rules = vec![
            rule("Via chain", RuleAction::Chain { chain_id: 7 }, &[], &["chrome.exe"], &["443"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ];
        let g = compute_exposure(&p);
        let chain = g.chain_descriptors.iter().find(|c| c.chain_id == 7).unwrap();
        assert_eq!(chain.hop_proxy_indices.len(), 2);
        assert!(chain.hop_proxy_indices[0].is_some());
        assert!(chain.hop_proxy_indices[1].is_none());
        let f =
            g.findings.iter().find(|f| f.kind == FindingKind::BrokenChain).expect("BrokenChain");
        assert_eq!(f.severity, FindingSeverity::High);
        assert_eq!(f.chain_ids, vec![7]);
    }

    #[test]
    fn unencrypted_proxy_is_medium() {
        let mut p = Profile::empty();
        p.proxies = vec![
            proxy(1, ProxyType::Socks5, "10.0.0.1", 1080, Some("good")),
            proxy(2, ProxyType::Http, "10.0.0.2", 8080, Some("cleartext-dev")),
        ];
        p.rules = vec![
            rule("Via cleartext", RuleAction::Proxy { proxy_id: 2 }, &[], &["curl.exe"], &["80"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ];
        let g = compute_exposure(&p);
        let f = g
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::UnencryptedProxy)
            .expect("UnencryptedProxy");
        assert_eq!(f.severity, FindingSeverity::Medium);
        assert_eq!(f.proxy_ids, vec![2]);
        // The good proxy should not produce a finding.
        let cleartext_findings: Vec<_> =
            g.findings.iter().filter(|f| f.kind == FindingKind::UnencryptedProxy).collect();
        assert_eq!(cleartext_findings.len(), 1);
    }

    #[test]
    fn proxy_hops_emitted_even_for_unreferenced_proxies() {
        // A defined-but-unused proxy still appears in `proxy_hops` so the UI
        // can show the full pool.
        let mut p = Profile::empty();
        p.proxies = vec![proxy(5, ProxyType::Socks5, "10.0.0.5", 1080, Some("unused"))];
        p.rules = vec![rule("Deny", RuleAction::Block, &[], &[], &[])];
        let g = compute_exposure(&p);
        assert_eq!(g.proxy_hops.len(), 1);
        assert_eq!(g.proxy_hops[0].proxy_id, 5);
        assert!(g.proxy_hops[0].is_encrypted);
    }

    #[test]
    fn flows_reference_stable_indices() {
        let p = profile_with(vec![
            rule("FF", RuleAction::Direct, &[], &["firefox.exe"], &["443"]),
            rule("Deny", RuleAction::Block, &[], &[], &[]),
        ]);
        let g = compute_exposure(&p);
        for f in &g.flows {
            assert!(f.process_index < g.processes.len());
            assert!(f.rule_index < g.rules.len());
            assert!(f.port_index < g.ports.len());
            assert!(f.channel_index < g.channels.len());
        }
    }
}
