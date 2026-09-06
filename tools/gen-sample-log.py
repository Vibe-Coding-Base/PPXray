"""Generate a synthetic Proxifier-format log fixture.

Every host, IP and process here is invented. IPs are drawn from the
documentation ranges reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and RFC 3849 (2001:db8::/32) so the fixture can never
collide with real infrastructure. Hostnames use .example / .invalid.

The fixture deliberately contains traffic that trips a good share of the
built-in detection catalog so `run_all_rules` has something to find.
"""

import datetime as dt

OUT = []
T0 = dt.datetime(2026, 4, 17, 23, 30, 0)


def ts(offset_secs):
    return (T0 + dt.timedelta(seconds=offset_secs)).strftime("[%Y.%m.%d %H:%M:%S]")


def conn(off, proc, pid, target, rule, action, parent=None, annot=""):
    who = f"{proc} ({pid}, {parent})" if parent else f"{proc} ({pid})"
    OUT.append(f"{ts(off)} {who} - {target}{annot} matching {rule} rule : {action}")


def dns_req(off, proc, pid, server, qtype, name):
    OUT.append(
        f"{ts(off)} {proc} ({pid}) - {server} DNS-UDP request: AF=2, Type={qtype}, Name={name}"
    )


def dns_resp(off, proc, pid, server, name, ip, ttl):
    OUT.append(
        f"{ts(off)} {proc} ({pid}) - {server} DNS-UDP response: AF=2, Name={name}, IP={ip}, ttl={ttl}"
    )


def dns_empty(off, proc, pid, server, name):
    OUT.append(
        f"{ts(off)} {proc} ({pid}) - {server} DNS-UDP empty response: AF=2, Name={name}"
    )


def dns_resolve(off, proc, pid, name, server):
    OUT.append(f"{ts(off)} {proc} ({pid}) - {name} resolve via {server} : DNS")


def dns_resolve_typed(off, proc, pid, name, qtype, server):
    OUT.append(
        f"{ts(off)} {proc} ({pid}) - {name} DNS request type={qtype} via {server} : DNS"
    )


DNS = "198.51.100.254:53"  # RFC 5737 TEST-NET-2, not a real LAN
t = 0

# --- Benign baseline: browser + system traffic ---------------------------
for i in range(40):
    t += 1
    dns_resolve(t, "svchost.exe", 3044, f"telemetry{i % 5}.example", DNS)
    dns_req(t, "svchost.exe", 3044, DNS, 1, f"telemetry{i % 5}.example")
    dns_resp(t, "svchost.exe", 3044, DNS, f"telemetry{i % 5}.example",
             f"192.0.2.{10 + (i % 5)}", 60)
    conn(t, "svchost.exe", 3044,
         f"telemetry{i % 5}.example(192.0.2.{10 + (i % 5)}):443", "Default",
         "direct connection")

for i in range(30):
    t += 1
    conn(t, "chrome.exe", 4120, f"cdn{i % 7}.example(198.51.100.{20 + (i % 7)}):443",
         "Browsers", "proxy HTTPS 203.0.113.9:8080")

for i in range(10):
    t += 1
    conn(t, "chrome.exe", 4120, f"[2001:db8:1::{i}]:443", "Browsers",
         "direct connection", annot=" (IPv6)")

# Local / private noise the PUBLIC_IP_PRED must filter out.
for i in range(12):
    t += 1
    conn(t, "System", 4, f"10.0.0.{50 + i}:137", "Localhost",
         "direct connection", parent="System", annot=" (UDP)")
    conn(t, "System", 4, f"198.51.100.{20 + i}:445", "Localhost",
         "direct connection", parent="System")

# Blocked traffic + IPv6 link-local (also filtered by PUBLIC_IP_PRED).
for i in range(8):
    t += 1
    conn(t, "applemobiledeviceservice.exe", 5668,
         f"[fe80::5efe:1:{i:04x}]:62078", "Default",
         "connection blocked", parent="System", annot=" (IPv6)")

# --- LOLBin egress: direct IP, no DNS (apt.lolbin-direct-ip) -------------
for i in range(6):
    t += 1
    conn(t, "rundll32.exe", 9001, f"203.0.113.{40 + i}:443", "Default",
         "direct connection")

# --- LOLBin to a hostname (apt.lolbin-outbound) -------------------------
for i in range(4):
    t += 1
    conn(t, "regsvr32.exe", 9002, f"payload-host.example(203.0.113.{60 + i}):80",
         "Default", "direct connection")

# --- certutil / bitsadmin / cmstp dedicated rules -----------------------
for i in range(3):
    t += 1
    conn(t, "certutil.exe", 9003, f"files.example(203.0.113.7{i}):443",
         "Default", "direct connection")
    conn(t, "bitsadmin.exe", 9004, f"drop.example(203.0.113.8{i}):80",
         "Default", "direct connection")
    conn(t, "cmstp.exe", 9005, f"203.0.113.9{i}:443", "Default",
         "direct connection")

# --- cmd.exe / powershell egress ----------------------------------------
for i in range(5):
    t += 1
    conn(t, "cmd.exe", 9100, f"stage.example(198.51.100.7{i}):8080", "Default",
         "direct connection")
    conn(t, "powershell.exe", 9101, f"raw.pastebin.invalid(198.51.100.8{i}):443",
         "Default", "direct connection")

# --- Suspicious dropper basename ----------------------------------------
for i in range(3):
    t += 1
    conn(t, "invoice_2026_scan.exe", 9200, f"203.0.113.15{i}:443", "Default",
         "direct connection")

# --- LSASS egress (apt.lsass-egress) ------------------------------------
t += 1
conn(t, "lsass.exe", 780, "203.0.113.200:443", "Default", "direct connection")

# --- Office egress to non-Microsoft -------------------------------------
for i in range(3):
    t += 1
    conn(t, "winword.exe", 9300, f"macro-cdn.example(203.0.113.21{i}):443",
         "Default", "direct connection")

# --- Unusual / C2 ports on public IPs -----------------------------------
for port in (4444, 8443, 1337, 9001, 5555, 6667):
    t += 1
    conn(t, "updater.exe", 9400, f"203.0.113.230:{port}", "Default",
         "direct connection")

# --- SMB / RDP to public ------------------------------------------------
t += 1
conn(t, "explorer.exe", 9500, "203.0.113.240:445", "Default", "direct connection")
t += 1
conn(t, "mstsc.exe", 9501, "203.0.113.241:3389", "Default", "direct connection")

# --- svchost on an unusual port -----------------------------------------
t += 1
conn(t, "svchost.exe", 3044, "203.0.113.242:8081", "Default", "direct connection")

# --- Script interpreter egress ------------------------------------------
for i in range(3):
    t += 1
    conn(t, "wscript.exe", 9600, f"203.0.113.25{i}:443", "Default",
         "direct connection")

# --- Remote admin tool egress -------------------------------------------
for i in range(3):
    t += 1
    conn(t, "anydesk.exe", 9700, f"relay{i}.example(198.51.100.9{i}):443",
         "Default", "direct connection")

# --- Low-reputation TLD -------------------------------------------------
for tld in ("tk", "top", "xyz", "gq", "cf"):
    t += 1
    conn(t, "svc-helper.exe", 9800, f"cdn-node.{tld}(198.51.100.110):443",
         "Default", "direct connection")

# --- Cryptomining pool --------------------------------------------------
for i in range(4):
    t += 1
    conn(t, "xmrig-worker.exe", 9900,
         f"pool.minexmr.example(198.51.100.12{i}):3333", "Default",
         "direct connection")

# --- Webshell callback --------------------------------------------------
for i in range(3):
    t += 1
    conn(t, "w3wp.exe", 9950, f"203.0.113.26{i}:443", "Default",
         "direct connection")

# --- WebView egress to non-Microsoft ------------------------------------
for i in range(3):
    t += 1
    conn(t, "msedgewebview2.exe", 9960,
         f"tracker.example(198.51.100.13{i}):443", "Default",
         "direct connection")

# --- DoH / DoT from a non-browser ---------------------------------------
t += 1
conn(t, "svc-helper.exe", 9800, "203.0.113.53:853", "Default", "direct connection")
t += 1
conn(t, "svc-helper.exe", 9800, "dns.example(203.0.113.54):443", "Default",
     "direct connection")

# --- Discord / pastebin from a non-browser ------------------------------
for i in range(3):
    t += 1
    conn(t, "svc-helper.exe", 9800,
         f"discord.invalid(198.51.100.14{i}):443", "Default",
         "direct connection")
    conn(t, "svc-helper.exe", 9800,
         f"pastebin.invalid(198.51.100.15{i}):443", "Default",
         "direct connection")

# --- Beaconing: exact 60s interval, no jitter (apt.beacon-low-jitter) ---
for i in range(30):
    conn(60 * i + 5, "beacon-svc.exe", 9990, "203.0.113.100:443", "Default",
         "direct connection")

# --- Rapid port scanner --------------------------------------------------
for i in range(60):
    t += 1
    conn(t, "scanner.exe", 9995, f"198.51.100.200:{1000 + i}", "Default",
         "direct connection")

# --- DNS tunneling: long qnames + TXT/NULL qtypes -----------------------
for i in range(25):
    t += 1
    label = ("a1b2c3d4e5f6a7b8c9d0" * 3) + f"{i:04d}"
    dns_resolve_typed(t, "tunnel-client.exe", 9997, f"{label}.tun.example", 16, DNS)
    dns_req(t, "tunnel-client.exe", 9997, DNS, 16, f"{label}.tun.example")

for i in range(10):
    t += 1
    dns_req(t, "tunnel-client.exe", 9997, DNS, 10, f"null-q{i}.tun.example")

# --- NXDOMAIN burst (DGA-ish) -------------------------------------------
for i in range(40):
    t += 1
    dns_empty(t, "dga-proc.exe", 9998, DNS, f"kq{i:03d}zxrv{i * 7 % 97:02d}.invalid")

# --- Unusual DNS server --------------------------------------------------
for i in range(5):
    t += 1
    dns_req(t, "svc-helper.exe", 9800, "203.0.113.53:53", 1,
            f"lookup{i}.example")

# --- Lines the parser should classify as Other / skip -------------------
OUT.append(f"{ts(t + 1)} weird.exe (1) - something totally unknown")
OUT.append("")
OUT.append("Proxifier log opened (this line has no timestamp)")

OUT.sort(key=lambda line: line[:21])

header = [
    "; Synthetic Proxifier log fixture — every host, IP and process is invented.",
    "; IPs come from the RFC 5737 / RFC 3849 documentation ranges; hostnames use",
    "; .example and .invalid. Safe to commit and to share in bug reports.",
    "; Regenerate with: python tools/gen-sample-log.py",
]

with open("testdata/synthetic-log.txt", "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(header + OUT) + "\n")

print(f"wrote testdata/synthetic-log.txt: {len(OUT)} log lines")
