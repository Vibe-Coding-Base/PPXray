//! Serialize a [`Profile`] to Proxifier-flavored XML.
//!
//! Format decisions:
//! - Tab indentation (matches stock Proxifier output).
//! - Self-closing tags for attribute-only elements.
//! - Lists (`Targets`, `Applications`, `Ports`) joined with `"; "` on a single
//!   line. Proxifier accepts both single- and multi-line variants; single-line
//!   keeps our output deterministic. Humans can still edit multi-line files
//!   and we'll reparse them correctly.
//! - `<?xml?>` declaration identical to Proxifier's.

use std::fmt::Write as _;

use crate::{error::PpxResult, model::*};

const DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

pub(crate) fn serialize(profile: &Profile) -> PpxResult<String> {
    let mut s = String::with_capacity(4096);
    s.push_str(DECL);

    writeln!(
        s,
        "<ProxifierProfile version=\"{}\" platform=\"{}\" product_id=\"{}\" product_minver=\"{}\">",
        profile.version,
        escape(&profile.platform),
        escape(&profile.product_id),
        escape(&profile.product_minver),
    )
    .unwrap();

    write_options(&mut s, &profile.options);
    write_proxy_list(&mut s, &profile.proxies);
    write_chain_list(&mut s, &profile.chains);
    write_rule_list(&mut s, &profile.rules);

    s.push_str("</ProxifierProfile>\n");
    Ok(s)
}

// ----------------------------------------------------------------------------
// Options
// ----------------------------------------------------------------------------

fn write_options(s: &mut String, o: &Options) {
    s.push_str("\t<Options>\n");
    write_resolve(s, &o.resolve);
    if let Some(enc) = &o.encryption {
        write_encryption(s, enc);
    }
    writeln!(
        s,
        "\t\t<ConnectionLoopDetection enabled=\"{}\" resolve=\"{}\" />",
        bool_str(o.connection_loop_detection.enabled),
        bool_str(o.connection_loop_detection.resolve),
    )
    .unwrap();
    writeln!(s, "\t\t<Udp mode=\"{}\" />", escape(&o.udp_mode)).unwrap();
    writeln!(s, "\t\t<LeakPreventionMode enabled=\"{}\" />", bool_str(o.leak_prevention_mode))
        .unwrap();
    writeln!(s, "\t\t<ProcessOtherUsers enabled=\"{}\" />", bool_str(o.process_other_users))
        .unwrap();
    writeln!(s, "\t\t<ProcessServices enabled=\"{}\" />", bool_str(o.process_services)).unwrap();
    writeln!(
        s,
        "\t\t<HandleDirectConnections enabled=\"{}\" />",
        bool_str(o.handle_direct_connections)
    )
    .unwrap();
    writeln!(s, "\t\t<HttpProxiesSupport enabled=\"{}\" />", bool_str(o.http_proxies_support))
        .unwrap();
    s.push_str("\t</Options>\n");
}

fn write_resolve(s: &mut String, r: &Resolve) {
    s.push_str("\t\t<Resolve>\n");
    writeln!(s, "\t\t\t<AutoModeDetection enabled=\"{}\" />", bool_str(r.auto_mode_detection))
        .unwrap();
    writeln!(s, "\t\t\t<ViaProxy enabled=\"{}\" />", bool_str(r.via_proxy)).unwrap();
    writeln!(s, "\t\t\t<BlockNonATypes enabled=\"{}\" />", bool_str(r.block_non_a_types)).unwrap();
    if r.exclusion_list.value.is_empty() {
        writeln!(
            s,
            "\t\t\t<ExclusionList OnlyFromListMode=\"{}\" />",
            bool_str(r.exclusion_list.only_from_list_mode)
        )
        .unwrap();
    } else {
        writeln!(
            s,
            "\t\t\t<ExclusionList OnlyFromListMode=\"{}\">{}</ExclusionList>",
            bool_str(r.exclusion_list.only_from_list_mode),
            escape(&r.exclusion_list.value),
        )
        .unwrap();
    }
    writeln!(s, "\t\t\t<DnsUdpMode>{}</DnsUdpMode>", r.dns_udp_mode).unwrap();
    s.push_str("\t\t</Resolve>\n");
}

fn write_encryption(s: &mut String, e: &Encryption) {
    match &e.hash {
        Some(h) => {
            writeln!(s, "\t\t<Encryption mode=\"{}\">", escape(&e.mode)).unwrap();
            writeln!(s, "\t\t\t<Hash>{}</Hash>", escape(h)).unwrap();
            s.push_str("\t\t</Encryption>\n");
        }
        None => {
            writeln!(s, "\t\t<Encryption mode=\"{}\" />", escape(&e.mode)).unwrap();
        }
    }
}

// ----------------------------------------------------------------------------
// ProxyList
// ----------------------------------------------------------------------------

fn write_proxy_list(s: &mut String, proxies: &[Proxy]) {
    if proxies.is_empty() {
        s.push_str("\t<ProxyList />\n");
        return;
    }
    s.push_str("\t<ProxyList>\n");
    for p in proxies {
        writeln!(s, "\t\t<Proxy id=\"{}\" type=\"{}\">", p.id, p.proxy_type.as_xml_str()).unwrap();
        if let Some(opts) = p.options {
            writeln!(s, "\t\t\t<Options>{}</Options>", opts).unwrap();
        }
        writeln!(s, "\t\t\t<Port>{}</Port>", p.port).unwrap();
        writeln!(s, "\t\t\t<Address>{}</Address>", escape(&p.address)).unwrap();
        if let Some(label) = &p.label {
            writeln!(s, "\t\t\t<Label>{}</Label>", escape(label)).unwrap();
        }
        if let Some(auth) = &p.authentication {
            s.push_str("\t\t\t<Authentication>\n");
            if let Some(u) = &auth.username {
                writeln!(s, "\t\t\t\t<Username>{}</Username>", escape(u)).unwrap();
            }
            if let Some(pw) = &auth.password {
                writeln!(s, "\t\t\t\t<Password>{}</Password>", escape(pw)).unwrap();
            }
            s.push_str("\t\t\t</Authentication>\n");
        }
        s.push_str("\t\t</Proxy>\n");
    }
    s.push_str("\t</ProxyList>\n");
}

// ----------------------------------------------------------------------------
// ChainList
// ----------------------------------------------------------------------------

fn write_chain_list(s: &mut String, chains: &[Chain]) {
    if chains.is_empty() {
        s.push_str("\t<ChainList />\n");
        return;
    }
    s.push_str("\t<ChainList>\n");
    for c in chains {
        writeln!(s, "\t\t<Chain id=\"{}\">", c.id).unwrap();
        if let Some(name) = &c.name {
            writeln!(s, "\t\t\t<Name>{}</Name>", escape(name)).unwrap();
        }
        for m in &c.members {
            writeln!(s, "\t\t\t<Proxy id=\"{}\" />", m.proxy_id).unwrap();
        }
        s.push_str("\t\t</Chain>\n");
    }
    s.push_str("\t</ChainList>\n");
}

// ----------------------------------------------------------------------------
// RuleList
// ----------------------------------------------------------------------------

fn write_rule_list(s: &mut String, rules: &[Rule]) {
    if rules.is_empty() {
        s.push_str("\t<RuleList />\n");
        return;
    }
    s.push_str("\t<RuleList>\n");
    for r in rules {
        writeln!(s, "\t\t<Rule enabled=\"{}\">", bool_str(r.enabled)).unwrap();
        match &r.action {
            RuleAction::Direct => s.push_str("\t\t\t<Action type=\"Direct\" />\n"),
            RuleAction::Block => s.push_str("\t\t\t<Action type=\"Block\" />\n"),
            RuleAction::Proxy { proxy_id } => {
                writeln!(s, "\t\t\t<Action type=\"Proxy\" proxy=\"{}\" />", proxy_id).unwrap();
            }
            RuleAction::Chain { chain_id } => {
                writeln!(s, "\t\t\t<Action type=\"Chain\" chain=\"{}\" />", chain_id).unwrap();
            }
        }
        if !r.ports.is_empty() {
            writeln!(s, "\t\t\t<Ports>{}</Ports>", escape(&join_list(&r.ports))).unwrap();
        }
        if !r.targets.is_empty() {
            writeln!(s, "\t\t\t<Targets>{}</Targets>", escape(&join_list(&r.targets))).unwrap();
        }
        if !r.applications.is_empty() {
            writeln!(
                s,
                "\t\t\t<Applications>{}</Applications>",
                escape(&join_list(&r.applications))
            )
            .unwrap();
        }
        writeln!(s, "\t\t\t<Name>{}</Name>", escape(&r.name)).unwrap();
        s.push_str("\t\t</Rule>\n");
    }
    s.push_str("\t</RuleList>\n");
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------

fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn join_list(items: &[String]) -> String {
    items.join("; ")
}

/// Escape XML text and attribute values. Covers `&`, `<`, `>`, `"`, `'`.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}
