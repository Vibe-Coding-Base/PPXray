//! Streaming parser for Proxifier-format log lines.
//!
//! Observed line shapes (taken from real `.txt` logs):
//!
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid[, parent]) - <target>[:port] [(UDP)] [(IPv6)] matching <rule> rule : <action-phrase>
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <server>:<port> DNS-UDP request: AF=<n>, Type=<n>, Name=<qname>
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <qname> resolve via <server>:<port> : DNS
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <qname> DNS request type=<n> via <server>:<port> : DNS
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <server>:<port> DNS-UDP response: AF=<n>, Name=<qname>, IP=<ip>, ttl=<n>
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <server>:<port> DNS-UDP response: Type=<n>, Name=<qname>
//!   [YYYY.MM.DD HH:MM:SS] proc.exe (pid) - <server>:<port> DNS-UDP empty response: AF=<n>, Name=<qname>
//!
//! Target (the field after `-`) comes in four styles:
//!   host(ip):port                 e.g. `api.example.com(1.2.3.4):443`
//!   ip:port                        e.g. `198.51.100.254:53`
//!   [ipv6]:port                    e.g. `[::1]:443`
//!   host:port                      (legacy / rare)
//!
//! We parse by splitting on `]`, ` - `, and the keyword phrases (`matching`,
//! `DNS-UDP`, `resolve via`, `DNS request type=`). No per-line regex
//! allocation; target and process are the only sub-parses that require care.

use chrono::NaiveDateTime;

use crate::model::{Action, ConnectionEvent, DnsEvent, DnsKind, Event, Proto};

/// Parse a single line. Returns `None` for blank lines and lines that don't
/// match any known shape; the caller records these as [`Event::Other`] so
/// nothing is silently dropped.
pub fn parse_line(line: &str, raw_offset: u64) -> Option<Event> {
    let (ts, rest) = parse_header(line)?;
    let (process_part, body) = rest.split_once(" - ")?;
    let (process, pid, parent) = parse_process(process_part);

    // Branch on well-known keywords. Order matters: DNS- patterns are more
    // specific than the catch-all "matching … rule : …".
    if body.contains(" DNS-UDP request:") {
        return parse_dns_request(ts, process, pid, body, raw_offset).map(Event::Dns);
    }
    if body.contains(" DNS-UDP response:") {
        return parse_dns_response(ts, process, pid, body, raw_offset).map(Event::Dns);
    }
    if body.contains(" DNS-UDP empty response:") {
        return parse_dns_empty(ts, process, pid, body, raw_offset).map(Event::Dns);
    }
    if body.contains(" resolve via ") || body.contains(" DNS request type=") {
        return parse_dns_resolve(ts, process, pid, body, raw_offset).map(Event::Dns);
    }
    if body.contains(" matching ") && body.contains(" rule : ") {
        return parse_match(ts, process, pid, parent, body, raw_offset).map(Event::Connection);
    }

    // Unknown but timestamped line.
    Some(Event::Other { ts: Some(ts), raw_offset, len: line.len() as u32 })
}

// ---------------------------------------------------------------------------
// Header + process
// ---------------------------------------------------------------------------

/// Returns `(timestamp, remainder-starting-after "] ")`.
fn parse_header(line: &str) -> Option<(NaiveDateTime, &str)> {
    let line = line.strip_prefix('[')?;
    let (ts_part, rest) = line.split_once(']')?;
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let ts = NaiveDateTime::parse_from_str(ts_part, "%Y.%m.%d %H:%M:%S").ok()?;
    Some((ts, rest))
}

/// Parses e.g. `"gamingservices.exe (11796, System)"` or
/// `"svchost.exe (3044)"`. The closing `)` is guaranteed for well-formed
/// lines; for malformed ones we fall back to returning the raw string as
/// process name.
fn parse_process(s: &str) -> (String, Option<u32>, Option<String>) {
    let s = s.trim();
    let Some(paren) = s.rfind(" (") else {
        return (s.to_string(), None, None);
    };
    let name = s[..paren].to_string();
    let inside = &s[paren + 2..];
    let inside = inside.strip_suffix(')').unwrap_or(inside);

    match inside.split_once(", ") {
        Some((pid_str, parent)) => (name, pid_str.parse().ok(), Some(parent.to_string())),
        None => (name, inside.parse().ok(), None),
    }
}

// ---------------------------------------------------------------------------
// Connection matching
// ---------------------------------------------------------------------------

fn parse_match(
    ts: NaiveDateTime,
    process: String,
    pid: Option<u32>,
    parent: Option<String>,
    body: &str,
    raw_offset: u64,
) -> Option<ConnectionEvent> {
    let (target_section, rule_action) = body.split_once(" matching ")?;
    let (rule_part, action_part) = rule_action.split_once(" rule : ")?;

    let Target { host, ip, port, proto, ipv6 } = parse_target(target_section)?;
    let action = Action::parse(action_part);

    Some(ConnectionEvent {
        ts,
        process,
        pid,
        parent,
        proto,
        ipv6,
        dst_host: host,
        dst_ip: ip,
        dst_port: port,
        matched_rule: Some(rule_part.trim().to_string()),
        action,
        raw_offset,
    })
}

struct Target {
    host: Option<String>,
    ip: Option<String>,
    port: u16,
    proto: Proto,
    ipv6: bool,
}

/// Parse the target portion up to " matching …". Handles the four observed
/// shapes and the trailing ` (UDP)` / ` (IPv6)` annotations.
fn parse_target(raw: &str) -> Option<Target> {
    let raw = raw.trim();

    // Pull off optional annotations at the end.
    let mut proto = Proto::Tcp;
    let mut ipv6 = false;
    let mut t = raw;
    loop {
        let trimmed = t.trim_end();
        if let Some(rest) = trimmed.strip_suffix(" (UDP)") {
            proto = Proto::Udp;
            t = rest;
            continue;
        }
        if let Some(rest) = trimmed.strip_suffix(" (IPv6)") {
            ipv6 = true;
            t = rest;
            continue;
        }
        if let Some(rest) = trimmed.strip_suffix(" (ICMP)") {
            proto = Proto::Icmp;
            t = rest;
            continue;
        }
        break;
    }
    let t = t.trim();

    // IPv6 literal: `[...]:port`
    if let Some(close) = t.find("]:")
        && t.starts_with('[')
    {
        {
            let ip = t[1..close].to_string();
            let port: u16 = t[close + 2..].parse().ok()?;
            return Some(Target { host: None, ip: Some(ip), port, proto, ipv6: true });
        }
    }

    // Split off the `:port` at the end.
    let port_at = t.rfind(':')?;
    let port: u16 = t[port_at + 1..].parse().ok()?;
    let left = &t[..port_at];

    // `host(ip)` style?
    if let Some(paren) = left.rfind('(')
        && left.ends_with(')')
    {
        {
            let host = left[..paren].to_string();
            let ip = left[paren + 1..left.len() - 1].to_string();
            // We keep `0.0.0.0` as-is — it's a meaningful "unresolved"
            // sentinel from Proxifier, not a real IP.
            return Some(Target {
                host: if host.is_empty() { None } else { Some(host) },
                ip: Some(ip),
                port,
                proto,
                ipv6,
            });
        }
    }

    // Bare IP or host
    if looks_like_ipv4(left) {
        return Some(Target { host: None, ip: Some(left.to_string()), port, proto, ipv6 });
    }

    Some(Target { host: Some(left.to_string()), ip: None, port, proto, ipv6 })
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

fn parse_dns_request(
    ts: NaiveDateTime,
    process: String,
    pid: Option<u32>,
    body: &str,
    raw_offset: u64,
) -> Option<DnsEvent> {
    let (server_part, rest) = body.split_once(" DNS-UDP request:")?;
    let server = Some(server_part.trim().to_string());
    let qtype = extract_kv_u16(rest, "Type=");
    let qname = extract_kv(rest, "Name=")?;

    Some(DnsEvent {
        ts,
        process,
        pid,
        qname: qname.trim().to_string(),
        qtype,
        server,
        answer_ip: None,
        ttl: None,
        kind: DnsKind::Request,
        raw_offset,
    })
}

fn parse_dns_response(
    ts: NaiveDateTime,
    process: String,
    pid: Option<u32>,
    body: &str,
    raw_offset: u64,
) -> Option<DnsEvent> {
    let (server_part, rest) = body.split_once(" DNS-UDP response:")?;
    let qname = extract_kv(rest, "Name=")?;
    let answer_ip = extract_kv(rest, "IP=");
    let ttl = extract_kv_u32(rest, "ttl=");
    let qtype = extract_kv_u16(rest, "Type=");

    Some(DnsEvent {
        ts,
        process,
        pid,
        qname: qname.trim().to_string(),
        qtype,
        server: Some(server_part.trim().to_string()),
        answer_ip,
        ttl,
        kind: DnsKind::Response,
        raw_offset,
    })
}

fn parse_dns_empty(
    ts: NaiveDateTime,
    process: String,
    pid: Option<u32>,
    body: &str,
    raw_offset: u64,
) -> Option<DnsEvent> {
    let (server_part, rest) = body.split_once(" DNS-UDP empty response:")?;
    let qname = extract_kv(rest, "Name=")?;
    Some(DnsEvent {
        ts,
        process,
        pid,
        qname: qname.trim().to_string(),
        qtype: extract_kv_u16(rest, "Type="),
        server: Some(server_part.trim().to_string()),
        answer_ip: None,
        ttl: None,
        kind: DnsKind::EmptyResponse,
        raw_offset,
    })
}

fn parse_dns_resolve(
    ts: NaiveDateTime,
    process: String,
    pid: Option<u32>,
    body: &str,
    raw_offset: u64,
) -> Option<DnsEvent> {
    // Two shapes share the same "resolve via" / "DNS request type=" tail:
    //   <qname> resolve via <server>:<port> : DNS
    //   <qname> DNS request type=<n> via <server>:<port> : DNS
    let (qname, rest) = if let Some((qn, r)) = body.split_once(" DNS request type=") {
        (qn, r)
    } else if let Some((qn, r)) = body.split_once(" resolve via ") {
        (qn, r)
    } else {
        return None;
    };

    // Server is the token up to " :" or end.
    let server_end = rest.find(" :").unwrap_or(rest.len());
    let server_with_type = &rest[..server_end];
    // In the `DNS request type=NN via ...` shape, the qtype prefixes " via ".
    let (qtype, server) = if let Some((ty, sv)) = server_with_type.split_once(" via ") {
        (ty.trim().parse::<u16>().ok(), sv.trim().to_string())
    } else {
        (None, server_with_type.trim().to_string())
    };

    Some(DnsEvent {
        ts,
        process,
        pid,
        qname: qname.trim().to_string(),
        qtype,
        server: Some(server),
        answer_ip: None,
        ttl: None,
        kind: DnsKind::Resolve,
        raw_offset,
    })
}

// ---------------------------------------------------------------------------
// Tiny kv extractors
// ---------------------------------------------------------------------------

/// Find `key<value>` followed by `,` or end-of-string. Returns the raw value
/// trimmed of surrounding whitespace.
fn extract_kv(s: &str, key: &str) -> Option<String> {
    let idx = s.find(key)?;
    let rest = &s[idx + key.len()..];
    let end = rest.find(',').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn extract_kv_u16(s: &str, key: &str) -> Option<u16> {
    extract_kv(s, key).and_then(|v| v.parse().ok())
}

fn extract_kv_u32(s: &str, key: &str) -> Option<u32> {
    extract_kv(s, key).and_then(|v| v.parse().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(ev: Event) -> ConnectionEvent {
        match ev {
            Event::Connection(c) => c,
            other => panic!("expected Connection, got {other:?}"),
        }
    }

    fn dns(ev: Event) -> DnsEvent {
        match ev {
            Event::Dns(d) => d,
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    #[test]
    fn parses_hostname_target_match() {
        let line = "[2026.04.17 23:30:26] syncagent.exe (21264) - api.storage.example(203.0.113.43):443 matching Sync rule : direct connection";
        let c = conn(parse_line(line, 0).unwrap());
        assert_eq!(c.process, "syncagent.exe");
        assert_eq!(c.pid, Some(21264));
        assert_eq!(c.dst_host.as_deref(), Some("api.storage.example"));
        assert_eq!(c.dst_ip.as_deref(), Some("203.0.113.43"));
        assert_eq!(c.dst_port, 443);
        assert_eq!(c.proto, Proto::Tcp);
        assert!(!c.ipv6);
        assert_eq!(c.matched_rule.as_deref(), Some("Sync"));
        assert_eq!(c.action, Action::Direct);
    }

    #[test]
    fn parses_ipv6_udp_match() {
        let line = "[2026.04.17 23:30:21] chatapp.exe (81708) - [2001:db8::8888]:443 (UDP) (IPv6) matching Chat rule : direct connection";
        let c = conn(parse_line(line, 0).unwrap());
        assert_eq!(c.dst_ip.as_deref(), Some("2001:db8::8888"));
        assert_eq!(c.dst_port, 443);
        assert_eq!(c.proto, Proto::Udp);
        assert!(c.ipv6);
        assert!(c.dst_host.is_none());
    }

    #[test]
    fn parses_bare_ip_target() {
        let line = "[2026.04.17 23:30:17] System (4, System) - 10.0.0.91:137 (UDP) matching Localhost rule : direct connection";
        let c = conn(parse_line(line, 0).unwrap());
        assert_eq!(c.process, "System");
        assert_eq!(c.pid, Some(4));
        assert_eq!(c.parent.as_deref(), Some("System"));
        assert_eq!(c.dst_ip.as_deref(), Some("10.0.0.91"));
        assert_eq!(c.dst_port, 137);
        assert_eq!(c.proto, Proto::Udp);
    }

    #[test]
    fn parses_blocked_action() {
        let line = "[2026.04.17 23:31:37] deviceservice.exe (5668, System) - [fe80::1]:62078 (IPv6) matching Default rule : connection blocked";
        let c = conn(parse_line(line, 0).unwrap());
        assert_eq!(c.action, Action::Block);
        assert_eq!(c.matched_rule.as_deref(), Some("Default"));
        assert!(c.ipv6);
    }

    #[test]
    fn parses_dns_request() {
        let line = "[2026.04.17 23:30:16] svchost.exe (3044) - 198.51.100.254:53 DNS-UDP request: AF=2, Type=1, Name=telemetry.example";
        let d = dns(parse_line(line, 0).unwrap());
        assert_eq!(d.kind, DnsKind::Request);
        assert_eq!(d.qname, "telemetry.example");
        assert_eq!(d.qtype, Some(1));
        assert_eq!(d.server.as_deref(), Some("198.51.100.254:53"));
    }

    #[test]
    fn parses_dns_response_with_ip() {
        let line = "[2026.04.17 23:31:20] svchost.exe (3044) - 198.51.100.254:53 DNS-UDP response: AF=2, Name=catalog.example, IP=203.0.113.24, ttl=20";
        let d = dns(parse_line(line, 0).unwrap());
        assert_eq!(d.kind, DnsKind::Response);
        assert_eq!(d.qname, "catalog.example");
        assert_eq!(d.answer_ip.as_deref(), Some("203.0.113.24"));
        assert_eq!(d.ttl, Some(20));
    }

    #[test]
    fn parses_dns_empty_response() {
        let line = "[2026.04.17 23:30:19] svchost.exe (3044) - 198.51.100.254:53 DNS-UDP empty response: AF=2, Name=wpad.localdomain";
        let d = dns(parse_line(line, 0).unwrap());
        assert_eq!(d.kind, DnsKind::EmptyResponse);
        assert_eq!(d.qname, "wpad.localdomain");
    }

    #[test]
    fn parses_dns_resolve_via() {
        let line = "[2026.04.17 23:30:16] svchost.exe (3044) - telemetry.example resolve via 198.51.100.254:53 : DNS";
        let d = dns(parse_line(line, 0).unwrap());
        assert_eq!(d.kind, DnsKind::Resolve);
        assert_eq!(d.qname, "telemetry.example");
        assert_eq!(d.server.as_deref(), Some("198.51.100.254:53"));
    }

    #[test]
    fn parses_dns_resolve_typed() {
        let line = "[2026.04.17 23:31:05] chatapp.exe (81708) - ws.example DNS request type=65 via 198.51.100.254:53 : DNS";
        let d = dns(parse_line(line, 0).unwrap());
        assert_eq!(d.kind, DnsKind::Resolve);
        assert_eq!(d.qname, "ws.example");
        assert_eq!(d.qtype, Some(65));
    }

    #[test]
    fn unknown_line_returns_other() {
        let line = "[2026.04.17 23:31:37] weird.exe (1) - something totally unknown";
        match parse_line(line, 42).unwrap() {
            Event::Other { raw_offset, .. } => assert_eq!(raw_offset, 42),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn blank_line_returns_none() {
        assert!(parse_line("", 0).is_none());
        assert!(parse_line("   ", 0).is_none());
    }
}
