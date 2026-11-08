//! Serialize a [`Profile`] to Proxifier-flavored XML.
//!
//! Format decisions:
//! - Tab indentation (matches stock Proxifier output).
//! - Self-closing tags for attribute-only elements.
//! - Lists (`Targets`, `Applications`, `Ports`) are written one entry per
//!   line, separated by `;` and CRLF — the form Proxifier itself writes when
//!   entries are typed on separate lines. Its rule editor shows the field's
//!   text verbatim, so a long target or application list stays readable
//!   there. The break must be CRLF: the Windows edit control does not break
//!   a line on a bare LF.
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
        escape_attr(&profile.platform),
        escape_attr(&profile.product_id),
        escape_attr(&profile.product_minver),
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
    writeln!(s, "\t\t<Udp mode=\"{}\" />", escape_attr(&o.udp_mode)).unwrap();
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
            escape_text(&r.exclusion_list.value),
        )
        .unwrap();
    }
    writeln!(s, "\t\t\t<DnsUdpMode>{}</DnsUdpMode>", r.dns_udp_mode).unwrap();
    s.push_str("\t\t</Resolve>\n");
}

fn write_encryption(s: &mut String, e: &Encryption) {
    match &e.hash {
        Some(h) => {
            writeln!(s, "\t\t<Encryption mode=\"{}\">", escape_attr(&e.mode)).unwrap();
            writeln!(s, "\t\t\t<Hash>{}</Hash>", escape_text(h)).unwrap();
            s.push_str("\t\t</Encryption>\n");
        }
        None => {
            writeln!(s, "\t\t<Encryption mode=\"{}\" />", escape_attr(&e.mode)).unwrap();
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
        writeln!(s, "\t\t\t<Address>{}</Address>", escape_text(&p.address)).unwrap();
        if let Some(label) = &p.label {
            writeln!(s, "\t\t\t<Label>{}</Label>", escape_text(label)).unwrap();
        }
        if let Some(auth) = &p.authentication {
            s.push_str("\t\t\t<Authentication>\n");
            if let Some(u) = &auth.username {
                writeln!(s, "\t\t\t\t<Username>{}</Username>", escape_text(u)).unwrap();
            }
            if let Some(pw) = &auth.password {
                writeln!(s, "\t\t\t\t<Password>{}</Password>", escape_text(pw)).unwrap();
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
            writeln!(s, "\t\t\t<Name>{}</Name>", escape_text(name)).unwrap();
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
            writeln!(s, "\t\t\t<Ports>{}</Ports>", escape_text(&join_list(&r.ports))).unwrap();
        }
        if !r.targets.is_empty() {
            writeln!(s, "\t\t\t<Targets>{}</Targets>", escape_text(&join_list(&r.targets)))
                .unwrap();
        }
        if !r.applications.is_empty() {
            writeln!(
                s,
                "\t\t\t<Applications>{}</Applications>",
                escape_text(&join_list(&r.applications))
            )
            .unwrap();
        }
        writeln!(s, "\t\t\t<Name>{}</Name>", escape_text(&r.name)).unwrap();
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

/// Separator between list entries: one entry per line in Proxifier's editor.
const LIST_SEP: &str = ";\r\n";

fn join_list(items: &[String]) -> String {
    items.join(LIST_SEP)
}

/// Escape element *text*: `&` and `<`, which is all XML requires there.
///
/// A double quote must stay literal. Proxifier quotes application names
/// containing spaces — `"Some App.exe"` — and its own reader does not decode
/// `&quot;`, so escaping it produced a profile Proxifier refuses to load:
/// "Error in application list: Unexpected blank space found". Our parser
/// still decodes `&quot;`, so a profile written by an earlier build repairs
/// itself when opened and saved.
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape an attribute value. Every attribute here is `"`-delimited.
fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::{parse_str, to_xml_string};

    /// Proxifier wraps an application name containing spaces in double
    /// quotes and does not decode `&quot;`. Writing the entity produced a
    /// profile it refused to load ("Error in application list: Unexpected
    /// blank space found"), so the quote has to survive as a literal.
    #[test]
    fn a_quoted_application_name_keeps_its_literal_quotes() {
        let src = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<ProxifierProfile version=\"102\" platform=\"Windows\" product_id=\"0\" ",
            "product_minver=\"400\">\n",
            "\t<ProxyList />\n\t<ChainList />\n\t<RuleList>\n",
            "\t\t<Rule enabled=\"true\">\n",
            "\t\t\t<Action type=\"Direct\" />\n",
            "\t\t\t<Applications>\"Some App.exe\";\r\n\"Other App.exe\"</Applications>\n",
            "\t\t\t<Name>R</Name>\n",
            "\t\t</Rule>\n\t</RuleList>\n</ProxifierProfile>\n",
        );
        let profile = parse_str(src).unwrap();
        assert_eq!(profile.rules[0].applications, ["\"Some App.exe\"", "\"Other App.exe\""]);

        let out = to_xml_string(&profile).unwrap();
        assert!(
            out.contains("<Applications>\"Some App.exe\";\r\n\"Other App.exe\"</Applications>")
        );
        assert!(!out.contains("&quot;"), "a quote was escaped into an entity:\n{out}");
        // Reparsing what we wrote gives the same rule back.
        assert_eq!(parse_str(&out).unwrap().rules[0], profile.rules[0]);
    }

    /// A profile written by an earlier build carries `&quot;`. Opening and
    /// saving it is the repair, so the parser must still decode the entity.
    #[test]
    fn an_entity_written_by_an_earlier_build_is_decoded_and_rewritten_literally() {
        let broken = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<ProxifierProfile version=\"102\" platform=\"Windows\" product_id=\"0\" ",
            "product_minver=\"400\">\n",
            "\t<ProxyList />\n\t<ChainList />\n\t<RuleList>\n",
            "\t\t<Rule enabled=\"true\">\n",
            "\t\t\t<Action type=\"Direct\" />\n",
            "\t\t\t<Applications>&quot;Some App.exe&quot;</Applications>\n",
            "\t\t\t<Name>R</Name>\n",
            "\t\t</Rule>\n\t</RuleList>\n</ProxifierProfile>\n",
        );
        let profile = parse_str(broken).unwrap();
        assert_eq!(profile.rules[0].applications, ["\"Some App.exe\""]);
        let out = to_xml_string(&profile).unwrap();
        assert!(out.contains("<Applications>\"Some App.exe\"</Applications>"));
        assert!(!out.contains("&quot;"));
    }

    #[test]
    fn an_ampersand_in_text_is_still_escaped() {
        let src = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<ProxifierProfile version=\"102\" platform=\"Windows\" product_id=\"0\" ",
            "product_minver=\"400\">\n",
            "\t<ProxyList />\n\t<ChainList />\n\t<RuleList>\n",
            "\t\t<Rule enabled=\"true\">\n",
            "\t\t\t<Action type=\"Direct\" />\n",
            "\t\t\t<Name>Telemetry &amp; analytics</Name>\n",
            "\t\t</Rule>\n\t</RuleList>\n</ProxifierProfile>\n",
        );
        let out = to_xml_string(&parse_str(src).unwrap()).unwrap();
        assert!(out.contains("<Name>Telemetry &amp; analytics</Name>"));
    }

    /// A list written on one line comes out one entry per line, so
    /// Proxifier's rule editor shows each value on its own row.
    #[test]
    fn a_single_line_list_is_written_one_entry_per_line() {
        let src = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
            "<ProxifierProfile version=\"102\" platform=\"Windows\" product_id=\"0\" ",
            "product_minver=\"400\">\n",
            "\t<ProxyList />\n\t<ChainList />\n\t<RuleList>\n",
            "\t\t<Rule enabled=\"true\">\n",
            "\t\t\t<Action type=\"Direct\" />\n",
            "\t\t\t<Ports>80; 443</Ports>\n",
            "\t\t\t<Targets>a.example; *.b.example;c.example</Targets>\n",
            "\t\t\t<Name>R</Name>\n",
            "\t\t</Rule>\n\t</RuleList>\n</ProxifierProfile>\n",
        );
        let profile = parse_str(src).unwrap();
        let out = to_xml_string(&profile).unwrap();
        assert!(out.contains("<Ports>80;\r\n443</Ports>"), "{out}");
        assert!(
            out.contains("<Targets>a.example;\r\n*.b.example;\r\nc.example</Targets>"),
            "{out}"
        );
        assert_eq!(parse_str(&out).unwrap(), profile);
    }
}
