//! Event-based XML parser for Proxifier `.ppx` files.
//!
//! We use [`quick_xml`]'s pull reader rather than a serde-mapped struct tree
//! because the format has several quirks: self-closing tags mixed with text
//! content, attribute-bearing text elements, empty container elements
//! (`<ChainList />`), and inconsistent whitespace in delimited lists. A
//! hand-written walker keeps the error messages precise and data lossless.

use quick_xml::{
    Reader,
    events::{BytesStart, Event},
    name::QName,
};

use crate::{
    error::{PpxError, PpxResult},
    model::*,
};

pub(crate) fn parse(xml: &str) -> PpxResult<Profile> {
    // Real Proxifier files contain bare `&` characters (e.g. in rule names)
    // which are technically invalid XML but which Proxifier itself tolerates.
    // We pre-escape them so a strict XML parser can proceed.
    let sanitized = escape_bare_ampersands(xml);
    parse_sanitized(&sanitized)
}

fn parse_sanitized(xml: &str) -> PpxResult<Profile> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"ProxifierProfile" => {
                return parse_profile(&mut reader, &e);
            }
            Event::Empty(e) if e.local_name().as_ref() == b"ProxifierProfile" => {
                return profile_from_root(&e);
            }
            Event::Eof => return Err(PpxError::MissingElement("ProxifierProfile")),
            _ => {}
        }
        buf.clear();
    }
}

fn profile_from_root(start: &BytesStart<'_>) -> PpxResult<Profile> {
    let mut p = Profile::empty();
    if let Some(v) = attr_string(start, b"version")? {
        p.version = v
            .parse()
            .map_err(|source| PpxError::InvalidInt { field: "ProxifierProfile.version", source })?;
    }
    if let Some(v) = attr_string(start, b"platform")? {
        p.platform = v;
    }
    if let Some(v) = attr_string(start, b"product_id")? {
        p.product_id = v;
    }
    if let Some(v) = attr_string(start, b"product_minver")? {
        p.product_minver = v;
    }
    Ok(p)
}

fn parse_profile(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<Profile> {
    let mut profile = profile_from_root(start)?;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"Options" => profile.options = parse_options(reader)?,
                b"ProxyList" => profile.proxies = parse_proxy_list(reader)?,
                b"ChainList" => profile.chains = parse_chain_list(reader)?,
                b"RuleList" => profile.rules = parse_rule_list(reader)?,
                other => return Err(PpxError::UnexpectedElement(qname_string(other), "Profile")),
            },
            Event::Empty(e) => match e.local_name().as_ref() {
                b"ChainList" => profile.chains = Vec::new(),
                b"ProxyList" => profile.proxies = Vec::new(),
                b"RuleList" => profile.rules = Vec::new(),
                b"Options" => profile.options = Options::default(),
                _ => {}
            },
            Event::End(e) if e.local_name().as_ref() == b"ProxifierProfile" => break,
            Event::Eof => return Err(PpxError::MissingElement("ProxifierProfile end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(profile)
}

// ----------------------------------------------------------------------------
// Options
// ----------------------------------------------------------------------------

fn parse_options(reader: &mut Reader<&[u8]>) -> PpxResult<Options> {
    let mut opts = Options::default();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"Resolve" => opts.resolve = parse_resolve(reader)?,
                b"Encryption" => opts.encryption = Some(parse_encryption(reader, &e)?),
                _ => skip_element(reader, &e)?,
            },
            Event::Empty(e) => match e.local_name().as_ref() {
                b"ConnectionLoopDetection" => {
                    opts.connection_loop_detection = ConnectionLoopDetection {
                        enabled: attr_bool(&e, b"enabled")?.unwrap_or(false),
                        resolve: attr_bool(&e, b"resolve")?.unwrap_or(false),
                    }
                }
                b"Udp" => {
                    opts.udp_mode =
                        attr_string(&e, b"mode")?.unwrap_or_else(|| "mode_block_all".into())
                }
                b"LeakPreventionMode" => {
                    opts.leak_prevention_mode = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"ProcessOtherUsers" => {
                    opts.process_other_users = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"ProcessServices" => {
                    opts.process_services = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"HandleDirectConnections" => {
                    opts.handle_direct_connections = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"HttpProxiesSupport" => {
                    opts.http_proxies_support = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"Encryption" => {
                    opts.encryption = Some(Encryption {
                        mode: attr_string(&e, b"mode")?.unwrap_or_default(),
                        hash: None,
                    })
                }
                _ => {}
            },
            Event::End(e) if e.local_name().as_ref() == b"Options" => break,
            Event::Eof => return Err(PpxError::MissingElement("Options end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(opts)
}

fn parse_resolve(reader: &mut Reader<&[u8]>) -> PpxResult<Resolve> {
    let mut r = Resolve::default();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"ExclusionList" => {
                    r.exclusion_list = ExclusionList {
                        only_from_list_mode: attr_bool(&e, b"OnlyFromListMode")?.unwrap_or(false),
                        value: read_text(reader, b"ExclusionList")?,
                    }
                }
                b"DnsUdpMode" => {
                    let text = read_text(reader, b"DnsUdpMode")?;
                    r.dns_udp_mode = text.trim().parse().map_err(|source| {
                        PpxError::InvalidInt { field: "Resolve.DnsUdpMode", source }
                    })?;
                }
                _ => skip_element(reader, &e)?,
            },
            Event::Empty(e) => match e.local_name().as_ref() {
                b"AutoModeDetection" => {
                    r.auto_mode_detection = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"ViaProxy" => r.via_proxy = attr_bool(&e, b"enabled")?.unwrap_or(false),
                b"BlockNonATypes" => {
                    r.block_non_a_types = attr_bool(&e, b"enabled")?.unwrap_or(false)
                }
                b"ExclusionList" => {
                    r.exclusion_list = ExclusionList {
                        only_from_list_mode: attr_bool(&e, b"OnlyFromListMode")?.unwrap_or(false),
                        value: String::new(),
                    }
                }
                _ => {}
            },
            Event::End(e) if e.local_name().as_ref() == b"Resolve" => break,
            Event::Eof => return Err(PpxError::MissingElement("Resolve end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(r)
}

fn parse_encryption(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<Encryption> {
    let mut enc = Encryption { mode: attr_string(start, b"mode")?.unwrap_or_default(), hash: None };
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"Hash" => {
                enc.hash = Some(read_text(reader, b"Hash")?);
            }
            Event::End(e) if e.local_name().as_ref() == b"Encryption" => break,
            Event::Eof => return Err(PpxError::MissingElement("Encryption end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(enc)
}

// ----------------------------------------------------------------------------
// ProxyList
// ----------------------------------------------------------------------------

fn parse_proxy_list(reader: &mut Reader<&[u8]>) -> PpxResult<Vec<Proxy>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"Proxy" => {
                out.push(parse_proxy(reader, &e)?)
            }
            Event::End(e) if e.local_name().as_ref() == b"ProxyList" => break,
            Event::Eof => return Err(PpxError::MissingElement("ProxyList end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn parse_proxy(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<Proxy> {
    let id =
        attr_u32(start, b"id")?.ok_or(PpxError::MissingAttribute { elem: "Proxy", attr: "id" })?;
    let type_str = attr_string(start, b"type")?
        .ok_or(PpxError::MissingAttribute { elem: "Proxy", attr: "type" })?;
    let proxy_type = ProxyType::from_xml_str(&type_str)
        .ok_or_else(|| PpxError::UnknownProxyType(type_str.clone()))?;

    let mut proxy = Proxy {
        id,
        proxy_type,
        address: String::new(),
        port: 0,
        options: None,
        label: None,
        authentication: None,
    };

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"Address" => proxy.address = read_text(reader, b"Address")?,
                b"Port" => {
                    let text = read_text(reader, b"Port")?;
                    proxy.port = text
                        .trim()
                        .parse()
                        .map_err(|source| PpxError::InvalidInt { field: "Proxy.Port", source })?;
                }
                b"Options" => {
                    let text = read_text(reader, b"Options")?;
                    proxy.options = Some(text.trim().parse().map_err(|source| {
                        PpxError::InvalidInt { field: "Proxy.Options", source }
                    })?);
                }
                b"Label" => proxy.label = Some(read_text(reader, b"Label")?),
                b"Authentication" => proxy.authentication = Some(parse_authentication(reader)?),
                _ => skip_element(reader, &e)?,
            },
            Event::End(e) if e.local_name().as_ref() == b"Proxy" => break,
            Event::Eof => return Err(PpxError::MissingElement("Proxy end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(proxy)
}

fn parse_authentication(reader: &mut Reader<&[u8]>) -> PpxResult<Authentication> {
    let mut a = Authentication { username: None, password: None };
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"Username" => a.username = Some(read_text(reader, b"Username")?),
                b"Password" => a.password = Some(read_text(reader, b"Password")?),
                _ => skip_element(reader, &e)?,
            },
            Event::End(e) if e.local_name().as_ref() == b"Authentication" => break,
            Event::Eof => return Err(PpxError::MissingElement("Authentication end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(a)
}

// ----------------------------------------------------------------------------
// ChainList
// ----------------------------------------------------------------------------

fn parse_chain_list(reader: &mut Reader<&[u8]>) -> PpxResult<Vec<Chain>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"Chain" => {
                out.push(parse_chain(reader, &e)?)
            }
            Event::End(e) if e.local_name().as_ref() == b"ChainList" => break,
            Event::Eof => return Err(PpxError::MissingElement("ChainList end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn parse_chain(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<Chain> {
    let id =
        attr_u32(start, b"id")?.ok_or(PpxError::MissingAttribute { elem: "Chain", attr: "id" })?;
    let mut chain = Chain { id, name: None, members: vec![] };
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => match e.local_name().as_ref() {
                b"Name" => chain.name = Some(read_text(reader, b"Name")?),
                b"Proxy" => {
                    // Chain references proxies; we capture the id.
                    if let Some(pid) = attr_u32(&e, b"id")? {
                        chain.members.push(ChainMember { proxy_id: pid });
                    }
                    skip_element(reader, &e)?;
                }
                _ => skip_element(reader, &e)?,
            },
            Event::Empty(e) if e.local_name().as_ref() == b"Proxy" => {
                if let Some(pid) = attr_u32(&e, b"id")? {
                    chain.members.push(ChainMember { proxy_id: pid });
                }
            }
            Event::End(e) if e.local_name().as_ref() == b"Chain" => break,
            Event::Eof => return Err(PpxError::MissingElement("Chain end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(chain)
}

// ----------------------------------------------------------------------------
// RuleList
// ----------------------------------------------------------------------------

fn parse_rule_list(reader: &mut Reader<&[u8]>) -> PpxResult<Vec<Rule>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.local_name().as_ref() == b"Rule" => {
                out.push(parse_rule(reader, &e)?)
            }
            Event::End(e) if e.local_name().as_ref() == b"RuleList" => break,
            Event::Eof => return Err(PpxError::MissingElement("RuleList end tag")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn parse_rule(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<Rule> {
    let enabled = attr_bool(start, b"enabled")?.unwrap_or(true);
    let mut name = String::new();
    let mut action: Option<RuleAction> = None;
    let mut targets = Vec::new();
    let mut apps = Vec::new();
    let mut ports = Vec::new();

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Empty(e) if e.local_name().as_ref() == b"Action" => {
                action = Some(parse_action_attrs(&e)?);
            }
            Event::Start(e) => match e.local_name().as_ref() {
                b"Action" => {
                    action = Some(parse_action_attrs(&e)?);
                    // Consume until </Action>
                    skip_to_end(reader, b"Action")?;
                }
                b"Name" => name = read_text(reader, b"Name")?,
                b"Targets" => targets = split_list(&read_text(reader, b"Targets")?),
                b"Applications" => apps = split_list(&read_text(reader, b"Applications")?),
                b"Ports" => ports = split_list(&read_text(reader, b"Ports")?),
                _ => skip_element(reader, &e)?,
            },
            Event::Empty(e) => match e.local_name().as_ref() {
                b"Targets" | b"Applications" | b"Ports" => {} // empty list
                _ => {}
            },
            Event::End(e) if e.local_name().as_ref() == b"Rule" => break,
            Event::Eof => return Err(PpxError::MissingElement("Rule end tag")),
            _ => {}
        }
        buf.clear();
    }

    Ok(Rule {
        enabled,
        name,
        action: action.ok_or(PpxError::MissingElement("Rule.Action"))?,
        targets,
        applications: apps,
        ports,
    })
}

fn parse_action_attrs(e: &BytesStart<'_>) -> PpxResult<RuleAction> {
    let ty = attr_string(e, b"type")?
        .ok_or(PpxError::MissingAttribute { elem: "Action", attr: "type" })?;

    match ty.as_str() {
        "Direct" => Ok(RuleAction::Direct),
        "Block" => Ok(RuleAction::Block),
        "Proxy" => {
            let pid = attr_u32(e, b"proxy")?
                .ok_or(PpxError::MissingAttribute { elem: "Action(Proxy)", attr: "proxy" })?;
            Ok(RuleAction::Proxy { proxy_id: pid })
        }
        "Chain" => {
            let cid = attr_u32(e, b"chain")?
                .ok_or(PpxError::MissingAttribute { elem: "Action(Chain)", attr: "chain" })?;
            Ok(RuleAction::Chain { chain_id: cid })
        }
        other => Err(PpxError::UnknownAction(other.to_string())),
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn attr_bytes(e: &BytesStart<'_>, name: &[u8]) -> PpxResult<Option<Vec<u8>>> {
    for attr in e.attributes() {
        let a = attr?;
        if a.key.local_name().as_ref() == name {
            return Ok(Some(a.value.into_owned()));
        }
    }
    Ok(None)
}

fn attr_string(e: &BytesStart<'_>, name: &[u8]) -> PpxResult<Option<String>> {
    match attr_bytes(e, name)? {
        Some(v) => {
            let raw = std::str::from_utf8(&v)?.to_string();
            let unescaped = quick_xml::escape::unescape(&raw)?;
            Ok(Some(unescaped.into_owned()))
        }
        None => Ok(None),
    }
}

fn attr_bool(e: &BytesStart<'_>, name: &[u8]) -> PpxResult<Option<bool>> {
    match attr_string(e, name)? {
        Some(s) => match s.as_str() {
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            _ => Err(PpxError::InvalidBool { field: "attribute", value: s }),
        },
        None => Ok(None),
    }
}

fn attr_u32(e: &BytesStart<'_>, name: &[u8]) -> PpxResult<Option<u32>> {
    match attr_string(e, name)? {
        Some(s) => Ok(Some(
            s.trim()
                .parse()
                .map_err(|source| PpxError::InvalidInt { field: "attribute", source })?,
        )),
        None => Ok(None),
    }
}

/// Read all text content until the matching `</name>` end tag. Returns the
/// concatenated, unescaped, but otherwise untrimmed text (callers may trim).
fn read_text(reader: &mut Reader<&[u8]>, end: &[u8]) -> PpxResult<String> {
    let mut out = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Text(t) => {
                let bytes = t.into_inner();
                let raw = std::str::from_utf8(&bytes)?;
                // `unescape` is still called in case of mixed-era files that
                // contain legitimate `&amp;` inside a text node; harmless if
                // no entities present.
                let unescaped = quick_xml::escape::unescape(raw)?;
                out.push_str(&unescaped);
            }
            Event::CData(t) => {
                let bytes = t.into_inner();
                out.push_str(std::str::from_utf8(&bytes)?);
            }
            Event::GeneralRef(r) => {
                let name = r.resolve_char_ref()?;
                if let Some(ch) = name {
                    out.push(ch);
                } else {
                    let name_bytes = r.into_inner();
                    let name_str = std::str::from_utf8(&name_bytes)?;
                    match name_str {
                        "amp" => out.push('&'),
                        "lt" => out.push('<'),
                        "gt" => out.push('>'),
                        "quot" => out.push('"'),
                        "apos" => out.push('\''),
                        other => {
                            return Err(PpxError::Custom(format!(
                                "unknown XML entity reference: &{other};"
                            )));
                        }
                    }
                }
            }
            Event::End(e) if e.local_name().as_ref() == end => break,
            Event::Eof => {
                return Err(PpxError::Custom(format!(
                    "unexpected EOF while reading text of <{}>",
                    std::str::from_utf8(end).unwrap_or("?")
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

/// Escape unescaped `&` characters while leaving valid entity references
/// (`&amp;`, `&lt;`, numeric refs, etc.) alone. Proxifier historically writes
/// rule names containing bare `&`; quick-xml's strict parser rejects these.
fn escape_bare_ampersands(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for (idx, c) in input.char_indices() {
        if c == '&' {
            let rest = &input[idx + 1..];
            if looks_like_entity_ref(rest) {
                out.push('&');
            } else {
                out.push_str("&amp;");
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn looks_like_entity_ref(rest: &str) -> bool {
    // A well-formed entity reference is `<name>;` where <name> is:
    //   - `amp`, `lt`, `gt`, `quot`, `apos` (predefined named refs), or
    //   - `#NNNN` or `#xNNNN` (numeric character refs)
    // We cap the scan at 10 chars — longer refs don't occur in .ppx.
    const MAX: usize = 10;
    let mut scanned = 0usize;
    let mut saw_semi = false;
    let mut semi_at = 0usize;
    for (i, c) in rest.char_indices() {
        if i >= MAX {
            break;
        }
        if c == ';' {
            saw_semi = true;
            semi_at = i;
            break;
        }
        scanned = i + c.len_utf8();
    }
    if !saw_semi || scanned == 0 {
        return false;
    }
    let name = &rest[..semi_at];
    match name {
        "amp" | "lt" | "gt" | "quot" | "apos" => true,
        s if s.starts_with('#') => {
            let body = &s[1..];
            if let Some(hex) = body.strip_prefix(['x', 'X']) {
                !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                !body.is_empty() && body.chars().all(|c| c.is_ascii_digit())
            }
        }
        _ => false,
    }
}

/// Skip forward until the closing tag for `start` is consumed. Handles nested
/// children of the same name.
fn skip_element(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> PpxResult<()> {
    let name = start.name().as_ref().to_vec();
    skip_to_end(reader, &name)
}

fn skip_to_end(reader: &mut Reader<&[u8]>, name: &[u8]) -> PpxResult<()> {
    let mut depth: u32 = 1;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) if e.name().as_ref() == name => depth += 1,
            Event::End(e) if e.name().as_ref() == name => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Event::Eof => {
                return Err(PpxError::Custom(format!(
                    "unexpected EOF while skipping <{}>",
                    std::str::from_utf8(name).unwrap_or("?")
                )));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn qname_string(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes).map(|s| s.to_string()).unwrap_or_else(|_| format!("{bytes:?}"))
}

/// Split a semicolon/newline-delimited list, trimming whitespace and
/// filtering empty entries. Mirrors Proxifier's tolerant parsing of `Targets`,
/// `Applications`, and `Ports`.
fn split_list(input: &str) -> Vec<String> {
    input
        .split(';')
        .map(|s| s.trim().trim_matches(|c: char| c == '\n' || c == '\r' || c == '\t').trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[allow(dead_code)]
fn _qname_kind(name: &QName<'_>) -> &'static str {
    // Placeholder: kept for potential future namespaced variants.
    if name.prefix().is_some() { "prefixed" } else { "unprefixed" }
}
