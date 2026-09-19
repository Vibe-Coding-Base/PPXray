//! The profile as plain text, for a language model.
//!
//! Renders the rule list in evaluation order with everything a reader needs
//! to judge what a rule lets out — and nothing else. Proxy addresses,
//! credentials and the master-password hash are not rendered: a proxy's type
//! is what matters to the policy, its address is the operator's
//! infrastructure.

use std::fmt::Write;

use crate::exposure::{FindingSeverity, compute_exposure};
use crate::model::{Profile, ProxyType, RuleAction};

/// Rules beyond this are summarised as a count. A profile this large is
/// resent with every turn of a conversation, and the model's judgement of a
/// policy does not improve past a few hundred lines of it.
const MAX_RULES: usize = 500;

/// Findings beyond this are summarised as a count, for the same reason.
const MAX_FINDINGS: usize = 80;

/// The rules followed by what the deterministic analysis found in them.
///
/// The findings are the part the model could not reliably derive on its own
/// — glob subsumption and CIDR containment are not things to trust a language
/// model with — and giving it the answers means it argues from them rather
/// than re-deriving them wrongly.
pub fn policy_context(profile: &Profile) -> String {
    let mut out = policy_text(profile);
    out.push('\n');
    out.push_str(&findings_text(profile));
    out
}

/// What `compute_exposure` and the shadow detector found, one line each.
pub fn findings_text(profile: &Profile) -> String {
    let mut findings = compute_exposure(profile).findings;
    findings.sort_by_key(|f| severity_rank(f.severity));

    let mut out = String::new();
    if findings.is_empty() {
        out.push_str("Deterministic analysis of the profile found nothing to report.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "Deterministic analysis of the profile ({} finding(s); rule numbers refer to the list above):",
        findings.len()
    );
    for f in findings.iter().take(MAX_FINDINGS) {
        let rules: Vec<String> = f.rule_indices.iter().map(|i| format!("#{}", i + 1)).collect();
        let _ = writeln!(
            out,
            "  [{}] {} — {}{}",
            severity(f.severity),
            f.title,
            f.detail,
            if rules.is_empty() { String::new() } else { format!(" (rules {})", rules.join(", ")) }
        );
    }
    if findings.len() > MAX_FINDINGS {
        let _ = writeln!(out, "  (+{} more findings not shown)", findings.len() - MAX_FINDINGS);
    }
    out
}

fn severity(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
    }
}

fn severity_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
    }
}

/// The rule list alone, in evaluation order.
pub fn policy_text(profile: &Profile) -> String {
    let mut out = String::new();

    if !profile.proxies.is_empty() {
        out.push_str("Proxies (referenced by rules as #id):\n");
        for p in &profile.proxies {
            let label = p.label.as_deref().unwrap_or("unlabelled");
            let _ = writeln!(out, "  #{} {} \"{}\"", p.id, proxy_type(p.proxy_type), label);
        }
    }
    if !profile.chains.is_empty() {
        out.push_str("Chains:\n");
        for c in &profile.chains {
            let hops: Vec<String> = c.members.iter().map(|m| format!("#{}", m.proxy_id)).collect();
            let _ = writeln!(
                out,
                "  chain #{} \"{}\": {}",
                c.id,
                c.name.as_deref().unwrap_or("unnamed"),
                hops.join(" -> ")
            );
        }
    }

    let _ = writeln!(
        out,
        "Rules, in evaluation order ({} total; first enabled match wins; \
         an empty field matches anything):",
        profile.rules.len()
    );
    for (i, r) in profile.rules.iter().enumerate().take(MAX_RULES) {
        let _ = writeln!(
            out,
            "  {}. {}\"{}\" -> {}; apps: {}; targets: {}; ports: {}",
            i + 1,
            if r.enabled { "" } else { "[disabled] " },
            r.name,
            action_label(&r.action),
            list(&r.applications),
            list(&r.targets),
            list(&r.ports),
        );
    }
    if profile.rules.len() > MAX_RULES {
        let _ = writeln!(out, "  (+{} more rules not shown)", profile.rules.len() - MAX_RULES);
    }
    out
}

/// `Direct`, `Block`, `Proxy #101`, `Chain #3`.
pub fn action_label(a: &RuleAction) -> String {
    match a {
        RuleAction::Direct => "Direct".into(),
        RuleAction::Block => "Block".into(),
        RuleAction::Proxy { proxy_id } => format!("Proxy #{proxy_id}"),
        RuleAction::Chain { chain_id } => format!("Chain #{chain_id}"),
    }
}

fn proxy_type(t: ProxyType) -> &'static str {
    match t {
        ProxyType::Socks4 => "SOCKS4",
        ProxyType::Socks5 => "SOCKS5",
        ProxyType::Https => "HTTPS",
        ProxyType::Http => "HTTP",
    }
}

fn list(items: &[String]) -> String {
    if items.is_empty() { "any".into() } else { items.join("; ") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Authentication, Options, Proxy, Rule};

    fn profile() -> Profile {
        Profile {
            version: 102,
            platform: "Windows".into(),
            product_id: "0".into(),
            product_minver: "400".into(),
            options: Options::default(),
            proxies: vec![Proxy {
                id: 101,
                proxy_type: ProxyType::Socks5,
                address: "203.0.113.11".into(),
                port: 1080,
                options: Some(48),
                label: Some("Egress".into()),
                authentication: Some(Authentication {
                    username: Some("operator".into()),
                    password: Some("hunter2".into()),
                }),
            }],
            chains: vec![],
            rules: vec![
                Rule {
                    enabled: true,
                    name: "Allow AV".into(),
                    action: RuleAction::Direct,
                    targets: vec![],
                    applications: vec!["ekrn.exe".into()],
                    ports: vec![],
                },
                Rule {
                    enabled: false,
                    name: "Old".into(),
                    action: RuleAction::Proxy { proxy_id: 101 },
                    targets: vec!["*.example".into(), "203.0.113.0/24".into()],
                    applications: vec![],
                    ports: vec!["443".into(), "8000-8100".into()],
                },
                Rule {
                    enabled: true,
                    name: "Default".into(),
                    action: RuleAction::Block,
                    targets: vec![],
                    applications: vec![],
                    ports: vec![],
                },
            ],
        }
    }

    #[test]
    fn renders_rules_in_order_with_empty_fields_spelled_out() {
        let t = policy_text(&profile());
        assert!(t.contains("1. \"Allow AV\" -> Direct; apps: ekrn.exe; targets: any; ports: any"));
        assert!(t.contains(
            "2. [disabled] \"Old\" -> Proxy #101; apps: any; targets: *.example; 203.0.113.0/24; ports: 443; 8000-8100"
        ));
        assert!(t.contains("3. \"Default\" -> Block; apps: any; targets: any; ports: any"));
        assert!(t.contains("first enabled match wins"));
    }

    #[test]
    fn proxy_addresses_and_credentials_never_appear() {
        let t = policy_text(&profile());
        assert!(t.contains("#101 SOCKS5 \"Egress\""));
        assert!(!t.contains("203.0.113.11"));
        assert!(!t.contains("1080"));
        assert!(!t.contains("operator"));
        assert!(!t.contains("hunter2"));
    }

    #[test]
    fn findings_name_rules_by_their_list_number() {
        // "Old" (rule 2) is disabled and "Default" (rule 3) is a terminal
        // Block, so the shadow of interest is the wide-open rule 1.
        let mut p = profile();
        p.rules.insert(
            1,
            Rule {
                enabled: true,
                name: "Narrower AV".into(),
                action: RuleAction::Direct,
                targets: vec!["*.example".into()],
                applications: vec!["ekrn.exe".into()],
                ports: vec![],
            },
        );
        let t = policy_context(&p);
        assert!(t.contains("2. \"Narrower AV\""));
        assert!(t.contains("Rule can never fire: Narrower AV"));
        assert!(t.contains("(rules #2, #1)"), "{t}");
    }

    #[test]
    fn a_clean_profile_says_so_rather_than_printing_nothing() {
        let mut p = profile();
        p.rules = vec![
            Rule {
                enabled: true,
                name: "One".into(),
                action: RuleAction::Direct,
                targets: vec!["api.example".into()],
                applications: vec!["app.exe".into()],
                ports: vec!["443".into()],
            },
            Rule {
                enabled: true,
                name: "Default".into(),
                action: RuleAction::Block,
                targets: vec![],
                applications: vec![],
                ports: vec![],
            },
        ];
        p.proxies.clear();
        let t = findings_text(&p);
        assert!(t.contains("found nothing to report"), "{t}");
    }

    #[test]
    fn very_large_profiles_are_capped() {
        let mut p = profile();
        p.rules = (0..MAX_RULES + 7)
            .map(|i| Rule { name: format!("r{i}"), ..Rule::new_default() })
            .collect();
        let t = policy_text(&p);
        assert!(t.contains(&format!("{}. \"r{}\"", MAX_RULES, MAX_RULES - 1)));
        assert!(!t.contains(&format!("\"r{}\"", MAX_RULES)));
        assert!(t.contains("(+7 more rules not shown)"));
    }
}
