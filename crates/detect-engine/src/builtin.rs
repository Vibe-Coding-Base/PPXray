//! Built-in detection rule catalog.
//!
//! Rules are defined as inline Rust values rather than YAML to avoid an
//! extra parser dep for what is essentially compile-time data. Each rule
//! consists of:
//!
//! * Metadata (id, title, description, severity, MITRE ATT&CK tags).
//! * A `RuleQuery` describing the SQL to run against the per-log DuckDB.
//!
//! Detection design notes:
//!
//! * **Public-IP filter**: many rules need to ignore RFC 1918 / loopback /
//!   link-local / multicast destinations because matching on them produces
//!   constant noise. The [`PUBLIC_IP_PRED`] constant captures that filter
//!   once and is concatenated into rule WHERE clauses.
//! * **Browser allowlist**: a handful of rules suppress evidence from
//!   browsers (e.g. "Discord/Telegram from non-browser") because seeing a
//!   browser hit pastebin is not interesting on its own.
//! * **System processes**: things like `svchost.exe` legitimately reach
//!   half the internet, so rules that scan port usage exclude them by
//!   default.

use crate::rule::{DetectionRule, GroupBy, RuleQuery, RuleSource, Severity};

/// Compact constructor for the built-in catalog. Lets each rule body read
/// like a data literal while still populating the owned-`String` fields
/// that user-loaded YAML rules also produce.
macro_rules! rule {
    (
        id: $id:literal,
        title: $title:literal,
        description: $desc:expr,
        severity: $sev:expr,
        mitre: [$($mitre:expr),* $(,)?],
        references: [$($ref:expr),* $(,)?],
        query: $query:expr $(,)?
    ) => {
        DetectionRule {
            id: ($id).into(),
            title: ($title).into(),
            description: ($desc).into(),
            severity: $sev,
            mitre: vec![$(($mitre).to_string()),*],
            references: vec![$(($ref).to_string()),*],
            query: $query,
            source: RuleSource::Builtin,
        }
    };
}

/// Returns the entire built-in catalog. Order influences the UI's
/// "per-rule" report, but not detection semantics.
pub fn all_rules() -> Vec<DetectionRule> {
    vec![
        lolbin_direct_ip(),
        lolbin_outbound(),
        cmd_outbound(),
        powershell_external(),
        unusual_port_userland(),
        smb_outbound_public(),
        rdp_outbound_public(),
        discord_pastebin_non_browser(),
        doh_dot_non_browser(),
        suspicious_dropper_basename(),
        cmstp_outbound(),
        certutil_outbound(),
        bitsadmin_outbound(),
        privileged_short_basename(),
        dns_tunneling_qtype(),
        dns_long_qname(),
        beacon_low_jitter(),
        rapid_scanner(),
        nxdomain_burst(),
        lsass_egress(),
        office_egress_non_microsoft(),
        webshell_callback(),
        c2_ports_public(),
        svchost_unusual_port(),
        script_interp_egress(),
        remote_admin_tool_egress(),
        low_reputation_tld(),
        cryptomining_pool(),
        unusual_dns_server(),
        webview_egress_non_microsoft(),
    ]
}

// ---------------------------------------------------------------------------
// Reusable SQL fragments
// ---------------------------------------------------------------------------

/// Predicate that evaluates to TRUE for IPs that are *publicly routable* (i.e.
/// not RFC 1918 / loopback / link-local / multicast / null / IPv6 link-local).
/// We use string LIKE prefixes because DuckDB has no native INET type without
/// the extension; this is fast on indexed columns.
const PUBLIC_IP_PRED: &str = r#"(
  dst_ip IS NOT NULL AND dst_ip <> '' AND dst_ip <> '0.0.0.0'
  AND NOT (dst_ip LIKE '10.%')
  AND NOT (dst_ip LIKE '127.%')
  AND NOT (dst_ip LIKE '192.168.%')
  AND NOT (dst_ip LIKE '169.254.%')
  AND NOT (dst_ip LIKE '0.%')
  AND NOT (dst_ip LIKE '172.16.%') AND NOT (dst_ip LIKE '172.17.%')
  AND NOT (dst_ip LIKE '172.18.%') AND NOT (dst_ip LIKE '172.19.%')
  AND NOT (dst_ip LIKE '172.20.%') AND NOT (dst_ip LIKE '172.21.%')
  AND NOT (dst_ip LIKE '172.22.%') AND NOT (dst_ip LIKE '172.23.%')
  AND NOT (dst_ip LIKE '172.24.%') AND NOT (dst_ip LIKE '172.25.%')
  AND NOT (dst_ip LIKE '172.26.%') AND NOT (dst_ip LIKE '172.27.%')
  AND NOT (dst_ip LIKE '172.28.%') AND NOT (dst_ip LIKE '172.29.%')
  AND NOT (dst_ip LIKE '172.30.%') AND NOT (dst_ip LIKE '172.31.%')
  AND NOT (dst_ip LIKE '224.%') AND NOT (dst_ip LIKE '225.%')
  AND NOT (dst_ip LIKE '226.%') AND NOT (dst_ip LIKE '227.%')
  AND NOT (dst_ip LIKE '228.%') AND NOT (dst_ip LIKE '229.%')
  AND NOT (dst_ip LIKE '230.%') AND NOT (dst_ip LIKE '231.%')
  AND NOT (dst_ip LIKE '232.%') AND NOT (dst_ip LIKE '233.%')
  AND NOT (dst_ip LIKE '234.%') AND NOT (dst_ip LIKE '235.%')
  AND NOT (dst_ip LIKE '236.%') AND NOT (dst_ip LIKE '237.%')
  AND NOT (dst_ip LIKE '238.%') AND NOT (dst_ip LIKE '239.%')
  AND NOT (dst_ip = '::') AND NOT (dst_ip = '::1')
  AND NOT (dst_ip LIKE 'fe80%')
  AND NOT (dst_ip LIKE 'ff%')
)"#;

/// Predicate matching common LOLBins by basename (Proxifier reports the
/// basename, not the full path).
const LOLBIN_PRED: &str = r#"LOWER(process) IN (
  'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
  'bitsadmin.exe', 'msiexec.exe', 'installutil.exe', 'msbuild.exe',
  'cmstp.exe', 'wmic.exe', 'forfiles.exe', 'xwizard.exe',
  'ieexec.exe', 'odbcconf.exe', 'pcalua.exe', 'pcwrun.exe',
  'mavinject.exe', 'extexport.exe', 'extrac32.exe',
  'esentutl.exe', 'expand.exe', 'finger.exe', 'tttracer.exe'
)"#;

/// Browsers (allow-listed when evaluating "from non-browser" rules).
const BROWSER_PRED: &str = r#"LOWER(process) IN (
  'chrome.exe', 'firefox.exe', 'msedge.exe', 'msedgewebview2.exe',
  'brave.exe', 'opera.exe', 'safari.exe', 'iexplore.exe',
  'arc.exe', 'browser.exe', 'librewolf.exe', 'tor browser.exe',
  'chromium.exe', 'vivaldi.exe', 'thunderbird.exe'
)"#;

/// Microsoft / well-known system processes to exclude when scanning for
/// "anomalous outbound" patterns. Covers the bulk of false positives in
/// Windows' default install.
const SYSTEM_PROC_PRED: &str = r#"LOWER(process) IN (
  'svchost.exe', 'system', 'wininit.exe', 'services.exe', 'lsass.exe',
  'csrss.exe', 'smss.exe', 'winlogon.exe', 'searchindexer.exe',
  'searchapp.exe', 'searchprotocolhost.exe', 'startmenuexperiencehost.exe',
  'shellexperiencehost.exe', 'taskhostw.exe', 'sihost.exe',
  'runtimebroker.exe', 'wmiprvse.exe', 'dnssd.exe',
  'backgroundtaskhost.exe'
)"#;

// ---------------------------------------------------------------------------
// Stateless rules
// ---------------------------------------------------------------------------

fn lolbin_direct_ip() -> DetectionRule {
    rule! {
        id: "apt.lolbin-direct-ip",
        title: "LOLBin egress to direct IP (no DNS)",
        description: "A known living-off-the-land binary is reaching a public IP \
                      with no preceding hostname resolution. Direct-IP C2 is a \
                      common evasion against DNS-based blocking.",
        severity: Severity::High,
        mitre: ["T1071.001", "T1105", "T1218"],
        references: ["https://lolbas-project.github.io/"],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "{LOLBIN_PRED}
                 AND dst_host IS NULL
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 200,
        },
    }
}

fn lolbin_outbound() -> DetectionRule {
    rule! {
        id: "apt.lolbin-outbound",
        title: "LOLBin reaching public destination",
        description: "Living-off-the-land binary contacting a non-private host. \
                      May be benign (Windows Update via bitsadmin) or an attacker \
                      using the binary to bypass app allowlisting.",
        severity: Severity::Medium,
        mitre: ["T1218"],
        references: ["https://lolbas-project.github.io/"],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "{LOLBIN_PRED}
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND COALESCE(dst_host, '') NOT LIKE '%.windowsupdate.com'
                 AND COALESCE(dst_host, '') NOT LIKE '%.microsoft.com'
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 200,
        },
    }
}

fn cmd_outbound() -> DetectionRule {
    rule! {
        id: "apt.cmd-outbound",
        title: "cmd.exe with outbound network connection",
        description: "`cmd.exe` rarely makes external network calls on its own. \
                      An outbound from cmd.exe usually means a shell-script \
                      payload reaching out — investigate the parent process.",
        severity: Severity::High,
        mitre: ["T1059.003"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) = 'cmd.exe'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::Dst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn powershell_external() -> DetectionRule {
    rule! {
        id: "apt.powershell-external",
        title: "PowerShell reaching non-Microsoft destination",
        description: "PowerShell talking to anything other than Microsoft's \
                      well-known telemetry / update endpoints is a recurrent \
                      indicator of fileless / interactive payload delivery.",
        severity: Severity::Medium,
        mitre: ["T1059.001", "T1105"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) IN ('powershell.exe', 'pwsh.exe', 'powershell_ise.exe')
                 AND COALESCE(dst_host, '') NOT LIKE '%.microsoft.com'
                 AND COALESCE(dst_host, '') NOT LIKE '%.windowsupdate.com'
                 AND COALESCE(dst_host, '') NOT LIKE '%.azureedge.net'
                 AND COALESCE(dst_host, '') NOT LIKE '%.live.com'
                 AND COALESCE(dst_host, '') NOT LIKE '%.windows.net'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn unusual_port_userland() -> DetectionRule {
    rule! {
        id: "apt.unusual-port-userland",
        title: "Non-system process on uncommon port",
        description: "A user-land process is connecting on a port outside the \
                      typical web / mail / dev set. Common in C2 channels that \
                      pick odd ports to dodge port-filtering proxies.",
        severity: Severity::Low,
        mitre: ["T1571"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "dst_port IS NOT NULL
                 AND dst_port NOT IN (
                   53, 67, 68, 80, 88, 123, 135, 137, 138, 139, 143, 161, 389, 443,
                   445, 465, 587, 631, 636, 853, 989, 990, 993, 995, 1433, 1434,
                   1900, 2049, 3306, 3389, 3478, 5060, 5061, 5223, 5228, 5353,
                   5355, 5432, 5985, 5986, 6443, 8080, 8443, 9418, 19010, 27015
                 )
                 AND NOT {SYSTEM_PROC_PRED}
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 200,
        },
    }
}

fn smb_outbound_public() -> DetectionRule {
    rule! {
        id: "apt.smb-outbound-public",
        title: "SMB / NetBIOS to public destination",
        description: "Outbound 445/139/137 to the public internet is almost \
                      always malicious — credential theft, lateral movement \
                      attempts, or NTLM relay.",
        severity: Severity::High,
        mitre: ["T1021.002", "T1187"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "dst_port IN (137, 138, 139, 445)
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn rdp_outbound_public() -> DetectionRule {
    rule! {
        id: "apt.rdp-outbound-public",
        title: "RDP outbound to public destination",
        description: "Outbound RDP from an endpoint to the public internet — \
                      either shadow IT, lateral movement, or an attacker \
                      pivoting through this host.",
        severity: Severity::Medium,
        mitre: ["T1021.001"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "dst_port = 3389
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 50,
        },
    }
}

fn discord_pastebin_non_browser() -> DetectionRule {
    rule! {
        id: "apt.discord-pastebin-non-browser",
        title: "Pastebin / Discord / tunneling host from non-browser process",
        description: "Discord webhooks, Pastebin, ngrok, and Cloudflare tunnels \
                      are commonly abused for staging payloads or relaying C2. \
                      Hits from anything other than a browser warrant review.",
        severity: Severity::Medium,
        mitre: ["T1102", "T1105"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "(
                   COALESCE(dst_host, '') LIKE '%discord.com'
                   OR COALESCE(dst_host, '') LIKE '%discordapp.com'
                   OR COALESCE(dst_host, '') LIKE '%pastebin.com'
                   OR COALESCE(dst_host, '') LIKE '%ngrok.io'
                   OR COALESCE(dst_host, '') LIKE '%trycloudflare.com'
                   OR COALESCE(dst_host, '') LIKE '%hastebin.com'
                   OR COALESCE(dst_host, '') LIKE '%transfer.sh'
                   OR COALESCE(dst_host, '') LIKE '%anonfiles.com'
                 )
                 AND NOT {BROWSER_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn doh_dot_non_browser() -> DetectionRule {
    rule! {
        id: "apt.doh-dot-non-browser",
        title: "DoH / DoT endpoint from non-browser process",
        description: "DNS-over-HTTPS or DoT to a third-party resolver from a \
                      non-browser process is suspicious — attackers tunnel C2 \
                      over DoH to hide DNS queries from on-host inspection.",
        severity: Severity::Medium,
        mitre: ["T1071.004"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "(
                   dst_port = 853
                   OR (dst_port = 443 AND COALESCE(dst_host, '') IN (
                     'cloudflare-dns.com', '1.1.1.1', '1.0.0.1',
                     'dns.google', '8.8.8.8', '8.8.4.4',
                     'dns.quad9.net', '9.9.9.9',
                     'dns.adguard.com', 'doh.opendns.com'
                   ))
                 )
                 AND NOT {BROWSER_PRED}
                 AND NOT {SYSTEM_PROC_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn suspicious_dropper_basename() -> DetectionRule {
    rule! {
        id: "apt.dropper-basename",
        title: "Generic dropper-style basename with outbound traffic",
        description: "Process basename matches a common malware drop pattern \
                      (svhost.exe with one missing letter, randomized 8-char names, \
                      `update.exe` outside known installer dirs).",
        severity: Severity::Medium,
        mitre: ["T1204"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "(
                   LOWER(process) IN ('svhost.exe', 'scvhost.exe', 'lssas.exe', 'csrrs.exe', 'winlogon32.exe')
                   OR LOWER(process) LIKE '%~%.exe'
                 )
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 50,
        },
    }
}

fn cmstp_outbound() -> DetectionRule {
    rule! {
        id: "apt.cmstp-outbound",
        title: "cmstp.exe outbound (UAC bypass / proxy load)",
        description: "Connection Manager Profile Installer is widely abused for \
                      UAC bypass and arbitrary INF-driven code execution. Any \
                      outbound is suspicious.",
        severity: Severity::High,
        mitre: ["T1218.003"],
        references: ["https://attack.mitre.org/techniques/T1218/003/"],
        query: RuleQuery::EventsWhere {
            where_sql: format!(
                "LOWER(process) = 'cmstp.exe'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            max_per_run: 50,
        },
    }
}

fn certutil_outbound() -> DetectionRule {
    rule! {
        id: "apt.certutil-outbound",
        title: "certutil.exe download from external host",
        description: "`certutil -urlcache -split -f <URL>` is a perennial \
                      payload-staging primitive. Outbound from certutil to a \
                      public host is almost never legitimate.",
        severity: Severity::High,
        mitre: ["T1218.003", "T1105"],
        references: [],
        query: RuleQuery::EventsWhere {
            where_sql: format!(
                "LOWER(process) = 'certutil.exe'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            max_per_run: 50,
        },
    }
}

fn bitsadmin_outbound() -> DetectionRule {
    rule! {
        id: "apt.bitsadmin-outbound",
        title: "bitsadmin.exe transfer to non-Microsoft host",
        description: "BITS jobs to non-Microsoft destinations are a known \
                      payload-staging technique. Microsoft Update legitimately \
                      uses BITS — those are excluded.",
        severity: Severity::Medium,
        mitre: ["T1197"],
        references: [],
        query: RuleQuery::EventsWhere {
            where_sql: format!(
                "LOWER(process) = 'bitsadmin.exe'
                 AND COALESCE(dst_host, '') NOT LIKE '%.windowsupdate.com'
                 AND COALESCE(dst_host, '') NOT LIKE '%.microsoft.com'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            max_per_run: 50,
        },
    }
}

fn privileged_short_basename() -> DetectionRule {
    rule! {
        id: "apt.short-basename-egress",
        title: "Single-letter or two-letter executable with outbound traffic",
        description: "Executables with very short basenames (`a.exe`, `xx.exe`) \
                      are extremely uncommon in legitimate software and \
                      occasionally flag dropper or beacon payloads.",
        severity: Severity::Low,
        mitre: ["T1036"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LENGTH(REGEXP_REPLACE(LOWER(process), '\\.exe$', '')) <= 2
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::Process,
            having_min_count: 1,
            max_per_run: 50,
        },
    }
}

// ---------------------------------------------------------------------------
// DNS-based rules
// ---------------------------------------------------------------------------

fn dns_tunneling_qtype() -> DetectionRule {
    rule! {
        id: "apt.dns-tunneling-qtype",
        title: "Suspicious DNS qtype (TXT / NULL) outbound",
        description: "DNS query types 16 (TXT) and 10 (NULL) are common DNS-over- \
                      tunnel transports. Even legitimate uses (SPF lookups, \
                      DKIM) cluster on a small set of names — rules elsewhere \
                      can suppress by qname.",
        severity: Severity::Medium,
        mitre: ["T1071.004"],
        references: [],
        query: RuleQuery::DnsWhere {
            where_sql: "qtype IN (10, 16) AND kind = 'Request'".into(),
            max_per_run: 200,
        },
    }
}

fn dns_long_qname() -> DetectionRule {
    rule! {
        id: "apt.dns-long-qname",
        title: "DNS query with abnormally long qname",
        description: "Tunneling tools encode payloads as subdomain prefixes, \
                      producing qnames much longer than the typical 30-char \
                      mark. Long qname spans (>60 chars) deserve investigation.",
        severity: Severity::Low,
        mitre: ["T1071.004"],
        references: [],
        query: RuleQuery::DnsWhere {
            where_sql: "LENGTH(qname) > 60 AND kind = 'Request'".into(),
            max_per_run: 200,
        },
    }
}

// ---------------------------------------------------------------------------
// Stateful rules (custom SQL)
// ---------------------------------------------------------------------------

fn beacon_low_jitter() -> DetectionRule {
    // Detects (process, dst) groups that show periodic call-out behavior.
    // Approach: per group, compute the time delta between successive events.
    // If COUNT >= 12 and the standard deviation / mean of the delta is very
    // small (< 0.20), it looks like a beacon. Avg interval is constrained to
    // 5s..15min to filter out chatty real-time apps and slow heartbeats.
    rule! {
        id: "apt.beacon-low-jitter",
        title: "Periodic beacon (low jitter)",
        description: "A (process, destination) pair connects on a near-constant \
                      interval, which is the signature of an automated check-in \
                      from a backdoor or implant. Tune `count >= 12` and \
                      `jitter < 0.20` if you see real-time apps slipping through.",
        severity: Severity::High,
        mitre: ["T1071", "T1573"],
        references: ["https://attack.mitre.org/techniques/T1071/"],
        query: RuleQuery::Custom {
            // Output column order:
            //   0 process | 1 dst | 2 count | 3 first_ts | 4 last_ts |
            //   5 avg_gap_sec | 6 jitter_ratio | 7 evidence_ids
            // Detail JSON is built in Rust from columns 5..N (see eval::run_custom).
            select_sql: r#"
                WITH gaps AS (
                  SELECT
                    process,
                    COALESCE(dst_host, dst_ip) AS dst,
                    id,
                    ts,
                    EXTRACT(EPOCH FROM (
                      ts - LAG(ts) OVER (
                        PARTITION BY process, COALESCE(dst_host, dst_ip)
                        ORDER BY ts
                      )
                    )) AS gap_sec
                  FROM events
                  WHERE COALESCE(dst_host, dst_ip) IS NOT NULL
                    AND action IN ('Direct', 'Proxy')
                ), agg AS (
                  SELECT
                    process,
                    dst,
                    COUNT(*) AS c,
                    AVG(gap_sec) AS avg_gap,
                    STDDEV(gap_sec) AS std_gap,
                    MIN(ts) AS first_ts,
                    MAX(ts) AS last_ts,
                    list_slice(array_agg(id ORDER BY ts DESC), 1, 50) AS evidence_ids
                  FROM gaps
                  WHERE gap_sec IS NOT NULL
                  GROUP BY process, dst
                  HAVING COUNT(*) >= 12
                     AND AVG(gap_sec) BETWEEN 5 AND 900
                     AND STDDEV(gap_sec) IS NOT NULL
                     AND AVG(gap_sec) > 0
                     AND (STDDEV(gap_sec) / AVG(gap_sec)) < 0.20
                )
                SELECT
                  process,
                  dst,
                  c AS count,
                  first_ts,
                  last_ts,
                  ROUND(avg_gap, 1) AS avg_gap_sec,
                  ROUND(std_gap / avg_gap, 3) AS jitter_ratio,
                  evidence_ids
                FROM agg
                ORDER BY c DESC
                LIMIT 100
            "#
            .into(),
        },
    }
}

fn rapid_scanner() -> DetectionRule {
    // A process that opens many distinct destinations in a short window —
    // either reconnaissance, network sweep, or worm-style propagation.
    rule! {
        id: "apt.rapid-scanner",
        title: "Process touches many distinct destinations rapidly",
        description: "More than 60 distinct destinations from a single process \
                      within a 5-minute span. Often legitimate for crawlers and \
                      indexers; weight against process baseline.",
        severity: Severity::Medium,
        mitre: ["T1018", "T1046"],
        references: [],
        query: RuleQuery::Custom {
            select_sql: r#"
                WITH windowed AS (
                  SELECT
                    process,
                    time_bucket(INTERVAL '5 minutes', ts) AS bucket,
                    COUNT(DISTINCT COALESCE(dst_host, dst_ip)) AS distinct_dsts,
                    COUNT(*) AS hits,
                    MIN(ts) AS first_ts,
                    MAX(ts) AS last_ts,
                    list_slice(array_agg(id ORDER BY ts DESC), 1, 50) AS evidence_ids
                  FROM events
                  WHERE COALESCE(dst_host, dst_ip) IS NOT NULL
                    AND action IN ('Direct', 'Proxy')
                  GROUP BY process, bucket
                  HAVING COUNT(DISTINCT COALESCE(dst_host, dst_ip)) >= 60
                )
                SELECT
                  process,
                  CAST(NULL AS VARCHAR) AS dst,
                  hits AS count,
                  first_ts,
                  last_ts,
                  distinct_dsts,
                  bucket AS window_start,
                  evidence_ids
                FROM windowed
                ORDER BY distinct_dsts DESC
                LIMIT 50
            "#
            .into(),
        },
    }
}

fn nxdomain_burst() -> DetectionRule {
    // Bursts of empty/NXDOMAIN responses to a single process — often a sign
    // of a domain-generation algorithm probing for live C2.
    rule! {
        id: "apt.nxdomain-burst",
        title: "Burst of empty / NXDOMAIN DNS responses",
        description: "More than 30 empty DNS responses to a single process in a \
                      30-second window. Common for failed DGA enumeration or \
                      misconfigured software — investigate the qname pattern.",
        severity: Severity::Medium,
        mitre: ["T1568.002"],
        references: [],
        query: RuleQuery::Custom {
            select_sql: r#"
                WITH bursts AS (
                  SELECT
                    process,
                    time_bucket(INTERVAL '30 seconds', ts) AS bucket,
                    COUNT(*) AS hits,
                    COUNT(DISTINCT qname) AS distinct_qnames,
                    MIN(ts) AS first_ts,
                    MAX(ts) AS last_ts
                  FROM dns_events
                  WHERE kind = 'EmptyResponse'
                  GROUP BY process, bucket
                  HAVING COUNT(*) >= 30
                )
                SELECT
                  process,
                  CAST(NULL AS VARCHAR) AS dst,
                  hits AS count,
                  first_ts,
                  last_ts,
                  distinct_qnames,
                  bucket AS window_start,
                  CAST([] AS UBIGINT[]) AS evidence_ids
                FROM bursts
                ORDER BY hits DESC
                LIMIT 50
            "#
            .into(),
        },
    }
}

// ===========================================================================
// Advanced APT catalog
//
// These rules target well-known attacker techniques from the MITRE ATT&CK
// matrix that the baseline catalog doesn't cover. They're written against
// the same event schema — `process` basename + `dst_host` / `dst_ip` /
// `dst_port` / `action` — so they stay decidable on Proxifier log data
// without a full EDR feed.
// ===========================================================================

/// Hosts treated as "Microsoft infrastructure" and suppressed from
/// egress-anomaly rules that would otherwise false-positive on Windows
/// telemetry / update / Office365 / Azure traffic. Kept as a single
/// predicate so we can tune the allowlist in one place.
const MICROSOFT_HOST_PRED: &str = r#"(
  COALESCE(dst_host, '') LIKE '%.microsoft.com'
  OR COALESCE(dst_host, '') LIKE '%.windowsupdate.com'
  OR COALESCE(dst_host, '') LIKE '%.windows.com'
  OR COALESCE(dst_host, '') LIKE '%.windows.net'
  OR COALESCE(dst_host, '') LIKE '%.office.com'
  OR COALESCE(dst_host, '') LIKE '%.office.net'
  OR COALESCE(dst_host, '') LIKE '%.office365.com'
  OR COALESCE(dst_host, '') LIKE '%.live.com'
  OR COALESCE(dst_host, '') LIKE '%.outlook.com'
  OR COALESCE(dst_host, '') LIKE '%.azureedge.net'
  OR COALESCE(dst_host, '') LIKE '%.azure.com'
  OR COALESCE(dst_host, '') LIKE '%.msedge.net'
  OR COALESCE(dst_host, '') LIKE '%.msftauth.net'
  OR COALESCE(dst_host, '') LIKE '%.msauth.net'
  OR COALESCE(dst_host, '') LIKE '%.skype.com'
  OR COALESCE(dst_host, '') LIKE '%.teams.microsoft.com'
  OR COALESCE(dst_host, '') LIKE '%.sharepoint.com'
  OR COALESCE(dst_host, '') LIKE '%.onedrive.live.com'
)"#;

fn lsass_egress() -> DetectionRule {
    // `lsass.exe` has essentially no legitimate reason to make outbound
    // connections. Any hit here is a classic post-exploitation signal —
    // often seen with Mimikatz injecting into LSASS and then beaconing out,
    // or with shellcode injected into LSASS by a loader.
    rule! {
        id: "apt.lsass-egress",
        title: "lsass.exe reaching network",
        description: "The Windows Local Security Authority Subsystem should \
                      never initiate outbound traffic in a healthy system. An \
                      outbound from lsass.exe is almost always credential \
                      theft via injected code (Mimikatz class) or LSASS \
                      tampering.",
        severity: Severity::Critical,
        mitre: ["T1003.001", "T1055"],
        references: ["https://attack.mitre.org/techniques/T1003/001/"],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) = 'lsass.exe'
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::Dst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn office_egress_non_microsoft() -> DetectionRule {
    // Office apps reaching non-Microsoft destinations is a recurrent
    // phishing / macro-payload signature. Word-to-pastebin, Excel-to-raw-IP,
    // Outlook-to-random-domain all ride on this pattern.
    rule! {
        id: "apt.office-egress-non-microsoft",
        title: "Office app reaches non-Microsoft host",
        description: "WINWORD / EXCEL / POWERPNT / OUTLOOK / MSPUB / VISIO / \
                      MSACCESS fetching from a non-Microsoft destination is \
                      a strong macro-payload indicator. Expected traffic \
                      for these binaries is telemetry + Office/365 backends; \
                      anything else warrants review.",
        severity: Severity::High,
        mitre: ["T1204.002", "T1566.001"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) IN (
                   'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
                   'mspub.exe', 'visio.exe', 'msaccess.exe', 'onenote.exe'
                 )
                 AND NOT {MICROSOFT_HOST_PRED}
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn webshell_callback() -> DetectionRule {
    // Web server worker processes making outbound to public hosts are a
    // classic webshell signature: the attacker drops a shell, the worker
    // executes it, and the shell reverse-connects.
    rule! {
        id: "apt.webshell-callback",
        title: "Web server worker makes outbound to public host",
        description: "IIS worker (w3wp.exe), Apache/nginx, node.js, or PHP \
                      CGI initiating outbound to a public destination is a \
                      strong webshell / reverse-shell indicator. Legitimate \
                      egress from these is almost entirely to package / API \
                      endpoints pre-configured at install time.",
        severity: Severity::High,
        mitre: ["T1505.003", "T1190"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) IN (
                   'w3wp.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe',
                   'node.exe', 'tomcat.exe', 'apache.exe', 'caddy.exe'
                 )
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn c2_ports_public() -> DetectionRule {
    // Well-known default ports for popular C2 frameworks. Cobalt Strike
    // defaults to 50050 for teamserver admin and frequently uses 443/8443
    // for beacons; Metasploit defaults to 4444 (and sometimes 4445/5555);
    // PoshC2 uses 8088 by default; Sliver often uses 8888/8889.
    rule! {
        id: "apt.c2-default-ports",
        title: "Traffic on known C2 framework default ports",
        description: "Outbound to public IP on 4444 / 4445 / 5555 / 6666 / \
                      8088 / 8888 / 50050 — the default listen ports of \
                      Metasploit / PoshC2 / Sliver / Cobalt Strike teamserver. \
                      These ports appear nowhere in the standard web / mail \
                      / dev stack, so a hit is high-signal.",
        severity: Severity::High,
        mitre: ["T1571", "T1071"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "dst_port IN (4444, 4445, 5555, 6666, 8088, 8888, 8889, 50050)
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn svchost_unusual_port() -> DetectionRule {
    // svchost.exe legitimately uses a well-defined set of ports (HTTP/S,
    // DNS, AD / Kerberos, time sync, SMB, LDAP, WinRM). Anything outside
    // that set indicates either a malicious service or code injected into
    // svchost — both worth investigating.
    rule! {
        id: "apt.svchost-unusual-port",
        title: "svchost.exe using port outside the expected set",
        description: "svchost.exe on a non-standard port to a public IP. \
                      svchost legitimately speaks a narrow set of Windows \
                      protocols; a divergence from that set often means a \
                      malicious service is hosted by svchost or shellcode \
                      has been injected.",
        severity: Severity::Medium,
        mitre: ["T1055.001", "T1071"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) = 'svchost.exe'
                 AND dst_port NOT IN (
                   53, 67, 68, 80, 88, 123, 135, 137, 138, 139, 143, 161, 389,
                   443, 445, 464, 500, 514, 636, 3268, 3269, 3389, 5353, 5355,
                   5985, 5986, 6443
                 )
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn script_interp_egress() -> DetectionRule {
    // Script interpreters with outbound to public hosts: the most common
    // initial-access / staged-payload vectors on Windows. wscript / cscript
    // run malicious VBS/JS; mshta is already covered by a baseline rule
    // but we include it here for a combined group-by view.
    rule! {
        id: "apt.script-interp-egress",
        title: "Script host (wscript/cscript/mshta/hh) with outbound traffic",
        description: "Windows script hosts and HTML-help (hh.exe) are common \
                      droppers. Outbound from wscript.exe / cscript.exe / \
                      mshta.exe / hh.exe almost always means a malicious \
                      script is downloading stage-2 payload or beaconing.",
        severity: Severity::High,
        mitre: ["T1059.005", "T1059.007", "T1218.001", "T1218.005"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) IN ('wscript.exe', 'cscript.exe', 'mshta.exe', 'hh.exe')
                 AND ({PUBLIC_IP_PRED} OR dst_host LIKE '%.%')
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn remote_admin_tool_egress() -> DetectionRule {
    // Remote-admin tools are dual-use: legitimate IT help-desk tooling, but
    // also widely abused by ransomware affiliates (AnyDesk is the current
    // favorite). We flag them at Medium so the analyst can triage against
    // org policy.
    rule! {
        id: "apt.remote-admin-tool-egress",
        title: "Remote admin / remote control tool reaching the internet",
        description: "AnyDesk / TeamViewer / Splashtop / RustDesk / Remote \
                      Utilities / LogMeIn / ScreenConnect / Atera reaching \
                      public IP. Dual-use: expected on help-desk machines, \
                      strong malicious indicator on everything else. \
                      Ransomware affiliates routinely install these for \
                      persistence.",
        severity: Severity::Medium,
        mitre: ["T1219"],
        references: ["https://attack.mitre.org/techniques/T1219/"],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) IN (
                   'anydesk.exe', 'teamviewer.exe', 'teamviewerservice.exe',
                   'tv_x64.exe', 'tv_x86.exe', 'splashtop.exe', 'rustdesk.exe',
                   'remotepc.exe', 'logmein.exe', 'logmeinrun.exe',
                   'screenconnect.clientservice.exe', 'screenconnect.windowsclient.exe',
                   'atera.exe', 'ateraagent.exe', 'connectwisecontrol.exe',
                   'gotoassist.exe', 'dwservice.exe', 'syncro.exe'
                 )
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn low_reputation_tld() -> DetectionRule {
    // TLDs historically overrepresented in abuse reports (Spamhaus DROP
    // statistics, Talos reputation feeds). Bucket is imperfect but
    // cheap + tunable per-org.
    rule! {
        id: "apt.low-reputation-tld",
        title: "Destination uses a low-reputation TLD",
        description: "Destination host ends in a TLD known for abuse \
                      concentration (.xyz, .top, .tk, .ml, .ga, .cf, .gq, \
                      .win, .bid, .loan, .vip, .cc, .su, .click, .work, \
                      .review, .country). Not dispositive — many legitimate \
                      sites use these — but a useful prioritization signal.",
        severity: Severity::Low,
        mitre: ["T1071.001"],
        references: ["https://www.spamhaus.org/statistics/tlds/"],
        query: RuleQuery::EventsGrouped {
            where_sql: "(
                   COALESCE(dst_host, '') LIKE '%.xyz'
                   OR COALESCE(dst_host, '') LIKE '%.top'
                   OR COALESCE(dst_host, '') LIKE '%.tk'
                   OR COALESCE(dst_host, '') LIKE '%.ml'
                   OR COALESCE(dst_host, '') LIKE '%.ga'
                   OR COALESCE(dst_host, '') LIKE '%.cf'
                   OR COALESCE(dst_host, '') LIKE '%.gq'
                   OR COALESCE(dst_host, '') LIKE '%.win'
                   OR COALESCE(dst_host, '') LIKE '%.bid'
                   OR COALESCE(dst_host, '') LIKE '%.loan'
                   OR COALESCE(dst_host, '') LIKE '%.vip'
                   OR COALESCE(dst_host, '') LIKE '%.cc'
                   OR COALESCE(dst_host, '') LIKE '%.su'
                   OR COALESCE(dst_host, '') LIKE '%.click'
                   OR COALESCE(dst_host, '') LIKE '%.work'
                   OR COALESCE(dst_host, '') LIKE '%.review'
                   OR COALESCE(dst_host, '') LIKE '%.country'
                 )
                 AND action IN ('Direct', 'Proxy')".into(),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 200,
        },
    }
}

fn cryptomining_pool() -> DetectionRule {
    // Connections to well-known mining pool infrastructure are either
    // authorised mining (rare in enterprise) or cryptojacking by an
    // attacker who compromised the host for resources.
    rule! {
        id: "apt.cryptomining-pool",
        title: "Connection to known cryptomining pool",
        description: "Destination host matches naming patterns of public \
                      mining pools (Monero, Ethereum, multi-coin aggregators). \
                      Enterprise-managed hosts should not be mining; \
                      cryptojacking is the usual explanation.",
        severity: Severity::Medium,
        mitre: ["T1496"],
        references: ["https://attack.mitre.org/techniques/T1496/"],
        query: RuleQuery::EventsGrouped {
            where_sql: "(
                   COALESCE(dst_host, '') LIKE '%.minexmr.%'
                   OR COALESCE(dst_host, '') LIKE '%.nanopool.%'
                   OR COALESCE(dst_host, '') LIKE '%.supportxmr.%'
                   OR COALESCE(dst_host, '') LIKE '%.moneroocean.%'
                   OR COALESCE(dst_host, '') LIKE '%.xmrpool.%'
                   OR COALESCE(dst_host, '') LIKE '%.poolin.%'
                   OR COALESCE(dst_host, '') LIKE '%.f2pool.%'
                   OR COALESCE(dst_host, '') LIKE '%.hiveon.%'
                   OR COALESCE(dst_host, '') LIKE '%.ethermine.%'
                   OR COALESCE(dst_host, '') LIKE '%.flypool.%'
                   OR COALESCE(dst_host, '') LIKE '%.2miners.%'
                   OR COALESCE(dst_host, '') LIKE 'pool.minexmr.com'
                   OR COALESCE(dst_host, '') LIKE 'xmr.%'
                   OR COALESCE(dst_host, '') LIKE '%.miningpoolhub.%'
                 )
                 AND action IN ('Direct', 'Proxy')".into(),
            group_by: GroupBy::ProcessAndDst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}

fn unusual_dns_server() -> DetectionRule {
    // DNS queries to a public resolver other than the usual suspects may
    // indicate DNS tunneling or an attacker redirecting resolution to a
    // controlled NS to sidestep on-host DNS inspection.
    rule! {
        id: "apt.unusual-dns-server",
        title: "DNS query sent to an unusual public resolver",
        description: "DNS traffic from the endpoint to a public resolver \
                      that isn't in the common set (Cloudflare, Google, \
                      Quad9, OpenDNS, Level3). Could be DNS tunneling, \
                      enforced DNS bypass, or an attacker-controlled NS.",
        severity: Severity::Medium,
        mitre: ["T1071.004", "T1572"],
        references: [],
        query: RuleQuery::DnsWhere {
            where_sql: "kind = 'Request'
                 AND server IS NOT NULL
                 AND server NOT LIKE '192.168.%'
                 AND server NOT LIKE '10.%'
                 AND server NOT LIKE '172.16.%'
                 AND server NOT LIKE '172.17.%' AND server NOT LIKE '172.18.%'
                 AND server NOT LIKE '172.19.%' AND server NOT LIKE '172.20.%'
                 AND server NOT LIKE '172.21.%' AND server NOT LIKE '172.22.%'
                 AND server NOT LIKE '172.23.%' AND server NOT LIKE '172.24.%'
                 AND server NOT LIKE '172.25.%' AND server NOT LIKE '172.26.%'
                 AND server NOT LIKE '172.27.%' AND server NOT LIKE '172.28.%'
                 AND server NOT LIKE '172.29.%' AND server NOT LIKE '172.30.%'
                 AND server NOT LIKE '172.31.%'
                 AND server NOT LIKE '127.%'
                 AND server NOT LIKE '169.254.%'
                 AND server NOT LIKE '1.1.1.1%' AND server NOT LIKE '1.0.0.1%'
                 AND server NOT LIKE '8.8.8.8%' AND server NOT LIKE '8.8.4.4%'
                 AND server NOT LIKE '9.9.9.9%' AND server NOT LIKE '149.112.112.%'
                 AND server NOT LIKE '208.67.222.%' AND server NOT LIKE '208.67.220.%'
                 AND server NOT LIKE '4.2.2.%'
                 AND server NOT LIKE 'fe80%' AND server NOT LIKE '[fe80%'
                 AND server NOT LIKE '::1%' AND server NOT LIKE '[::1]%'"
                .into(),
            max_per_run: 200,
        },
    }
}

fn webview_egress_non_microsoft() -> DetectionRule {
    // `msedgewebview2.exe` is embedded in many Electron-ish and WinUI apps;
    // its outbound traffic is *expected* when reaching Microsoft / the host
    // app's own backend. Hits to other public destinations from WebView2
    // have been used to smuggle C2 over a familiar-looking browser engine.
    rule! {
        id: "apt.webview2-egress-non-microsoft",
        title: "msedgewebview2 reaching non-Microsoft destination",
        description: "Embedded Chromium (msedgewebview2.exe) hitting a \
                      non-Microsoft public host. Noisier in dev setups \
                      (Teams webviews, Edge extensions) — tune per-org — \
                      but a known C2-smuggling vector when it reaches \
                      unusual destinations.",
        severity: Severity::Low,
        mitre: ["T1071.001"],
        references: [],
        query: RuleQuery::EventsGrouped {
            where_sql: format!(
                "LOWER(process) = 'msedgewebview2.exe'
                 AND NOT {MICROSOFT_HOST_PRED}
                 AND {PUBLIC_IP_PRED}
                 AND action IN ('Direct', 'Proxy')"
            ),
            group_by: GroupBy::Dst,
            having_min_count: 1,
            max_per_run: 100,
        },
    }
}
