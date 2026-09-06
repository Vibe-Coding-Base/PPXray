# Changelog

All notable changes to ppxray are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-06

First public release.

### Rules

Lossless `.ppx` parse and serialize, round-trip tested. Virtualized rule table
with resizable columns and drag-drop reorder, multi-select bulk operations,
undo/redo, a search DSL (`action:block host:*.nvidia.com app:chrome.exe`), a
rule tester, and an overshadow detector that reports per field why one rule
covers another (targets / applications / ports → `Any` / `Covers` /
`Identical`).

### Exposure

What the enabled rules actually let out, as a flow diagram: which rules reach
the internet, through which ports and proxies, and which findings deserve
attention.

### Log

Streaming parser into a local DuckDB store (~50 MB/s on a 33 MB log), a uPlot
timeline with drag-to-select time range, top-N panels for processes,
destinations and rule effectiveness, and a virtualized event table where every
cell pivots the filter. Panes can be shown and hidden individually.

**Suggested targets.** Pick a process in the top-processes panel and get the
destinations it actually reached, collapsed into entries ready to paste into a
rule's Targets field — for a process that was allowed to reach anything while
you worked out what it needed and is now due to be narrowed.

Hosts sharing a domain roll up to `*.example.com`, across as many levels as it
takes: YouTube's CDN gives every host a unique middle label, so 81 of them
collapse to one entry only because the roll-up looks past the immediate
parent. It stops short of registry suffixes — `*.co.uk` would hand a process
most of a country's internet, which is worse than the wide-open rule being
replaced. Being too narrow only costs a longer list.

### Hunt

Thirty built-in detections over that traffic — LOLBin egress, cmd/PowerShell
anomalies, SMB/RDP to public addresses, Discord and Pastebin webhooks,
non-browser DoH/DoT, low-jitter beaconing, rapid scanners, NXDOMAIN bursts,
LSASS egress, Office-macro payloads, webshell callbacks, C2 default ports,
svchost on unusual ports, script-host egress, remote-admin tools,
low-reputation TLDs, mining pools, unusual DNS servers, WebView2 egress —
plus any YAML rule dropped into the rule directory. Alerts land in a triage
inbox with evidence event IDs and MITRE ATT&CK tags. Built-in rules can be
viewed as generated YAML and cloned into editable user rules.

Every built-in runs against a fixture in CI, so a SQL typo fails the build
rather than silently disabling a rule at runtime.

### Assistant (opt-in, off by default)

A language model can help read a log: it asks questions of the DuckDB store,
explains Proxifier rules, and reviews a log for outliers. It is disabled on a
fresh install, and while it is disabled no code path opens a socket. It is
available as a drawer over any module and as its own tab; conversations live
for the session and are never written to disk.

The design question was not whether this is useful but what it costs. A
Proxifier log is a timestamped list of every host the machine contacted, keyed
by which program did it — for most people a more complete browsing history
than their browser keeps. So the boundary is a setting, and it defaults to the
tightest of three levels:

| Level | What leaves the machine |
|---|---|
| `schema-only` (default) | Table and column names, and the question. The model writes SQL, ppxray runs it locally, and the **rows are never sent** — they are rendered for the user, and the model is told only the row count and the column names. |
| `aggregates` | Query results, with hostnames reduced to their registrable domain, process paths to a filename, and private addresses to their RFC 1918 block. |
| `raw` | Query results unchanged. |

Supporting decisions, each of which is the reason a corresponding test exists:
the recommended provider is a local one (Ollama, llama.cpp, LM Studio —
Anthropic and any OpenAI-compatible endpoint also work), where nothing leaves
the machine at any level; API keys go to the OS credential store rather than
`settings.json`, which is plain text; the first send is gated on the user
reading the exact request body, produced by the same function the sender
serializes so the preview cannot drift from the payload; and every request —
sent, failed, or refused before sending — is appended to
`<app-data>/llm-audit.jsonl` with its endpoint, model, level, byte count and a
SHA-256 of the body. Changing the provider, endpoint or privacy level clears
both the approval and the conversation.

### Security

- **DuckDB is sandboxed against rule SQL.** Detection rules are SQL and rule
  packs are meant to be shared, so importing someone's `.yml` runs their SQL.
  Connections open with external file access and extension loading revoked and
  the configuration locked, and `crates/log-ingest/tests/sandbox.rs` fails the
  build if that stops holding.
- `llm_bridge::sql_guard` adds a lexical pass that accepts a single read-only
  statement and nothing else, and wraps the survivor in
  `SELECT * FROM ( … ) LIMIT n` — a position where `DROP TABLE` is a syntax
  error rather than a dropped table.
- A Content-Security-Policy is set for the webview, which renders hostnames
  and process names taken from log files.
- Settings and user rule YAML are written atomically.
- `safe_filename` rejects NTFS alternate data streams (`rule.yml:x`),
  drive-relative paths, reserved device names (`CON.yml`), trailing spaces and
  dots, and control characters.
- ppxray ships no sample profile or log. Test input is generated by
  `tools/gen-sample-log.py` using RFC 5737 / RFC 3849 documentation addresses,
  and `.gitignore` refuses `*.ppx` and Proxifier logs.

### Privacy

Zero telemetry, no analytics, no accounts. Out of the box the app makes one
network request, and only on an explicit **Settings → Check for updates**:
there is no background poll, and update bundles are verified against a key
compiled into the binary before installing. The assistant is the only other
thing that can open a socket, and it is off until turned on.

### Interface

- Mantine v7 dark and light themes with auto-swapping tokens.
- Interface font family and size are configurable, and every surface takes its
  size from that setting.
- Command palette (Ctrl+K), keyboard shortcut reference (`?`), About dialog
  reading its version from the build.
- Resizable panels across all modules, persisted to `localStorage`.
- Loading, error (with retry) and empty are distinct states everywhere. A
  failed read used to render as "No alerts", which in a security tool is the
  difference between "no threats found" and "the detector never ran".
- Clickable rows and cells are real controls (`role`, `tabIndex`,
  Enter/Space), there is a `:focus-visible` ring, the alert inbox is a proper
  listbox, and the log (`/`, `Esc`) and hunt (`R`, `T`/`F`/`S`, `Esc`) modules
  have keyboard paths for their whole drill-in loop.

### Architecture

- Tauri v2 host, React 19 + Mantine v7 UI, `ts-rs`-generated TypeScript types
  for every IPC struct.
- Rust crates: `ppx-core`, `log-ingest`, `detect-engine`, `llm-bridge`.
- DuckDB (bundled), one file per analysed log, versioned schema: a stale file
  is dropped and rebuilt rather than read with the wrong shape.
- The event tables carry no indexes. Every query is an aggregate DuckDB
  answers by scanning, so ART indexes only slowed bulk load and inflated
  memory.
- All DuckDB work runs on the blocking pool; frontend server state is TanStack
  Query.
- The release workflow refuses to build if the tag disagrees with the version
  in `package.json`, `Cargo.toml` or `tauri.conf.json`, and runs the full test
  suite first.

### Known limitations

- No GeoIP / ASN enrichment for log events.
- No threat-intel feed imports (URLhaus / Feodo / Emerging Threats).
- No STIX 2.1 alert export.
- No live log tail while Proxifier is writing.
- The rule directory is not watched; refresh manually after editing files
  outside the app.

[0.2.0]: https://github.com/Vibe-Coding-Base/PPXray/releases/tag/v0.2.0
