//! Reducing observed traffic to something that answers the question without
//! being a copy of the user's browsing history.
//!
//! At [`DataScope::Aggregates`] the model should see the shape of the
//! traffic, so the reduction keeps what makes a pattern recognisable and
//! drops what identifies it:
//!
//! * a hostname collapses to its registrable domain — `googlevideo.com` says
//!   "video CDN"; `rr5.sn-abcd1234.googlevideo.com` also says which session;
//! * a process collapses to its filename, since the path carries the username;
//! * a private address collapses to its RFC 1918 block;
//! * a public address is kept — a bare IP with no hostname is often the
//!   finding itself.
//!
//! None of this runs at [`DataScope::Raw`].

use crate::config::DataScope;

/// Approximate public-suffix handling: labels that are administrative
/// rather than registrable, so `bbc.co.uk` survives but `co.uk` does not.
///
/// `log_ingest::suggest` keeps its own copy for wildcard rollup. They are
/// deliberately separate: this one guards an egress boundary and must not
/// change because a suggestion heuristic was tuned.
const REGISTRY_LABELS: &[&str] =
    &["co", "com", "net", "org", "gov", "edu", "ac", "mil", "int", "biz", "info", "or", "ne", "gr"];

/// The shortest suffix of `host` that someone could have registered.
///
/// Returns the input unchanged when it is not a dotted name (an IP literal,
/// a single label, an empty string) — callers decide what to do with those.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_ascii_lowercase();
    }
    // Two labels is the normal answer; three when the second-to-last is a
    // registry label (`bbc.co.uk`, `example.ne.jp`).
    let take = if REGISTRY_LABELS.contains(&labels[labels.len() - 2]) { 3 } else { 2 };
    labels[labels.len() - take..].join(".").to_ascii_lowercase()
}

/// Drop the directory part of a process path.
///
/// Proxifier logs the program name, but user rules and some log formats
/// carry full paths, and a full path under `C:\Users\<name>` leaks the
/// account name into every aggregate.
pub fn process_basename(process: &str) -> String {
    process.rsplit(['\\', '/']).next().unwrap_or(process).trim().to_string()
}

/// Collapse private addresses to their block; leave public ones alone.
pub fn mask_ip(ip: &str) -> String {
    match ip.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            if v4.is_loopback() {
                "127.0.0.0/8".into()
            } else if o[0] == 10 {
                "10.0.0.0/8".into()
            } else if o[0] == 172 && (16..32).contains(&o[1]) {
                "172.16.0.0/12".into()
            } else if o[0] == 192 && o[1] == 168 {
                "192.168.0.0/16".into()
            } else if o[0] == 169 && o[1] == 254 {
                "169.254.0.0/16".into()
            } else {
                ip.trim().to_string()
            }
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                "::1".into()
            } else if v6.segments()[0] & 0xfe00 == 0xfc00 {
                "fc00::/7".into()
            } else if v6.segments()[0] & 0xffc0 == 0xfe80 {
                "fe80::/10".into()
            } else {
                ip.trim().to_string()
            }
        }
        // Not an address at all. Returning it unchanged would defeat the
        // point of calling a masking function, so treat it as a hostname.
        Err(_) => registrable_domain(ip),
    }
}

/// Apply the masking appropriate to `scope` to a destination, which in this
/// log format is either a hostname or a literal address.
pub fn mask_destination(dest: &str, scope: DataScope) -> String {
    if scope.allows_raw_rows() {
        return dest.to_string();
    }
    if dest.parse::<std::net::IpAddr>().is_ok() { mask_ip(dest) } else { registrable_domain(dest) }
}

/// Apply the masking appropriate to `scope` to a process identifier.
pub fn mask_process(process: &str, scope: DataScope) -> String {
    if scope.allows_raw_rows() { process.to_string() } else { process_basename(process) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_cdn_names_lose_the_session_specific_labels() {
        // The YouTube CDN case that drove the wildcard work in log-ingest:
        // the middle label is unique per session, so it is exactly the part
        // that must not travel.
        assert_eq!(registrable_domain("rr5.sn-abcd1234.googlevideo.com"), "googlevideo.com");
    }

    #[test]
    fn registry_suffixes_keep_the_registrable_label() {
        assert_eq!(registrable_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("shop.example.ne.jp"), "example.ne.jp");
        assert_eq!(registrable_domain("example.com"), "example.com");
    }

    #[test]
    fn degenerate_hosts_come_back_unchanged() {
        assert_eq!(registrable_domain(""), "");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("example.com."), "example.com");
    }

    #[test]
    fn addresses_are_not_treated_as_names() {
        // `1.2.3.4` has four dotted labels; the domain path would return
        // "3.4", which is both wrong and a plausible-looking domain.
        assert_eq!(registrable_domain("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn user_directories_do_not_survive_masking() {
        assert_eq!(process_basename(r"C:\Users\alice\AppData\Local\app.exe"), "app.exe");
        assert_eq!(process_basename("/home/alice/.local/bin/tool"), "tool");
        assert_eq!(process_basename("chrome.exe"), "chrome.exe");
    }

    #[test]
    fn private_ranges_collapse_and_public_ones_do_not() {
        assert_eq!(mask_ip("10.4.7.19"), "10.0.0.0/8");
        assert_eq!(mask_ip("172.20.1.1"), "172.16.0.0/12");
        // 172.15 and 172.32 are outside the /12 and are public.
        assert_eq!(mask_ip("172.15.1.1"), "172.15.1.1");
        assert_eq!(mask_ip("172.32.1.1"), "172.32.1.1");
        assert_eq!(mask_ip("192.168.0.5"), "192.168.0.0/16");
        assert_eq!(mask_ip("169.254.3.3"), "169.254.0.0/16");
        assert_eq!(mask_ip("127.0.0.1"), "127.0.0.0/8");
        assert_eq!(mask_ip("8.8.8.8"), "8.8.8.8");
        assert_eq!(mask_ip("fe80::1"), "fe80::/10");
        assert_eq!(mask_ip("2606:4700::1111"), "2606:4700::1111");
    }

    #[test]
    fn raw_scope_is_the_identity() {
        let host = "rr5.sn-abcd1234.googlevideo.com";
        assert_eq!(mask_destination(host, DataScope::Raw), host);
        let proc = r"C:\Users\alice\app.exe";
        assert_eq!(mask_process(proc, DataScope::Raw), proc);
    }

    #[test]
    fn aggregate_scope_masks_both_kinds_of_destination() {
        assert_eq!(
            mask_destination("cdn.assets.example.com", DataScope::Aggregates),
            "example.com"
        );
        assert_eq!(mask_destination("10.0.0.7", DataScope::Aggregates), "10.0.0.0/8");
    }
}
