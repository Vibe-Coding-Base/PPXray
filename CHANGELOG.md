# Changelog

All notable changes to ppxray are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] — 2026-11-08

### Changed

- **Lists are saved one entry per line.** `Targets`, `Applications` and
  `Ports` used to be joined with `"; "` onto a single line, so a rule with a
  long target list showed as one unbroken line in Proxifier's rule editor.
  Each entry now ends with `;` and a CRLF — the form Proxifier writes itself
  when entries are typed on separate lines — so every value sits on its own
  row there. Open a profile and save it to reformat every rule.

### Fixed

- **A line break now separates list entries on its own**, as it does in
  Proxifier. A list typed one entry per line without semicolons was read as
  a single entry with line breaks inside it.

- **An ad-hoc query selecting a bare `NULL` no longer crashes.** The new
  DuckDB reports such a column with its own NULL type, which duckdb-rs
  panics on reading; the assistant's query tool now returns it as null, and
  the grouped hunt rules select a typed `CAST(NULL AS VARCHAR)`.

### Security

- quinn-proto 0.11.19 (RUSTSEC-2026-0338, -0340, -0343, high), rustls
  0.23.46 (RUSTSEC-2026-0346 to -0349), rustls-webpki 0.103.16
  (RUSTSEC-2026-0382), webpki-roots and webpki-root-certs 1.0.11
  (RUSTSEC-2026-0381, -0383), tokio 1.54.1 (RUSTSEC-2026-0386). These are
  the TLS and HTTP stack under the assistant's client and the updater.
- DuckDB 1.20000.1, which drops arrow 56 (RUSTSEC-2026-0442) and its
  build-time zip 6 (RUSTSEC-2026-0367 to -0369, -0429).
- The updater is built without its `zip` feature, removing zip 4 and the
  same four advisories. That feature only unpacks v1-style `.zip` and
  `.AppImage.tar.gz` update bundles, which this project does not ship.
- Rule YAML is parsed by `serde_norway` instead of `serde_yaml_ng`, whose
  `unsafe-libyaml` is unmaintained (RUSTSEC-2024-0449).
- zbus_names, zvariant and zvariant_derive are ignored in
  `.cargo/audit.toml`: unmaintained since their merge into zbus 6, Linux-only,
  and reached only through Tauri's opener plugin and keyring.

## [0.3.1] — 2026-09-23

### Fixed

- **Proxifier refused a profile saved by ppxray.** "Error in application
  list: Unexpected blank space found." Proxifier wraps an application name
  containing spaces in double quotes — `"Some App.exe"` — and its reader does
  not decode `&quot;`, which is what the serializer wrote. The escape set for
  element text is now the minimum XML requires, `&` and `<`; a quote stays
  literal. Attribute values keep their own escaper.

  A profile written by 0.2.0 or 0.3.0 repairs itself: the parser always
  decoded the entity, so nothing was lost on the way in. Open it and save it.

- **The rule list jumped back to the top** when the detail panel opened or
  closed. The module rendered a second copy of the table in the other branch
  of a ternary, so React unmounted the scroll container and built a new one.
  One table now stays mounted; only the detail panel comes and goes.

- rustls 0.23.45, for RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted
  across encryption level boundaries, medium). It is the TLS stack under the
  assistant's HTTP client and the updater.

## [0.3.0] — 2026-09-19

### Assistant sees the policy, and can test it

Asked whether a ruleset was tight enough, the assistant could only see the
`matched_rule` column of the log — the *name* of the rule that fired — and so
read a rule that names one process and no target as a domain allowlist
"contaminated" by whatever that process reached. The definition was never in
front of it.

- **The open profile travels with every question.** Rules in evaluation
  order with action, applications, targets and ports, followed by what the
  deterministic analysis found — shadowed rules, blanket Direct rules, missing
  default-deny, cleartext proxies — so the model argues from those findings
  rather than re-deriving glob subsumption on its own. Proxy addresses,
  credentials and the master-password hash are never rendered
  (`ppx_core::policy_text`, pinned by test).
- **A rule tester the model can call.** `test_rule_match` evaluates a
  hypothetical connection with the same matcher the Rules tab uses and
  reports which rule wins and why each earlier one did or did not match. The
  prompt tells the model to verify a claim about the policy before making
  it.
- **Tools follow from what is open.** `run_sql` only when a log is open,
  `test_rule_match` only when a profile is; the prompt says which is missing
  and tells the model to ask the user to open it, naming the tab. The panel
  shows the same two facts as badges — `profile · 13 rules`, `log · 276
  events` — so a question about the policy with no profile open is not a
  surprise afterwards.
- The profile is the user's own configuration rather than observed traffic,
  so it is shared at every privacy level, like the rule text the explainer
  already received. The scope descriptions in Settings and the payload
  preview say so.
- The drawer no longer sits a transparent overlay across the app: the rule
  list stays clickable while the answer is open beside it.
- Queries and rule tests are folded under one line by default — `3 queries,
  1 rule test · results stayed on this machine` — and open on click. The
  answer is what the reader came for; the evidence is one click away, never
  hidden.
- **Stop.** A question in flight can be stopped; the model gets one turn
  with no tools to answer from what it had gathered, and the reply says it
  was cut short. The per-question tool-call limit that used to end a
  question silently — showing the model's "let me verify…" and dropping the
  calls it wanted — is now a setting (default 100) that ends the same way:
  with an answer, and a note saying why.
- Dragging a rule no longer stacks every other row at the top of the table,
  and the rows below now slide out of the way as the drag passes them. Rows
  were positioned with a CSS transform, which dnd-kit ignores when it
  measures — so every row measured at the same place.
- **Change markers.** Each rule that differs from what is on disk is tagged
  `new`, `edited` or `moved` (a rule can be both of the last two), and the
  header counts them along with deletions. Cleared on save. A rule has no
  identity of its own in a `.ppx`, so each gets a client-side id that
  survives editing and reordering but never reaches the file; "moved" is
  computed as "not in the longest common subsequence with the saved order",
  so one move marks one rule rather than its neighbours too.

### Several log files in one analysis

Proxifier rotates its log to `Log.txt.1`, `Log.txt.2`, … and the picker did
not offer them. It now matches them with one `*.txt.*` pattern — no ceiling
on the archive number, one short entry in the file-type list — accepts
several at once, and reads them oldest-first so ids and timestamps agree. **Add logs** appends
more files to the analysis that is open — ids continue rather than restart,
so existing alerts keep pointing at the right rows — and the header shows
`Log.txt + 2 more files` with the full list on hover.

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

[0.3.2]: https://github.com/Vibe-Coding-Base/PPXray/releases/tag/v0.3.2
[0.3.1]: https://github.com/Vibe-Coding-Base/PPXray/releases/tag/v0.3.1
[0.3.0]: https://github.com/Vibe-Coding-Base/PPXray/releases/tag/v0.3.0
[0.2.0]: https://github.com/Vibe-Coding-Base/PPXray/releases/tag/v0.2.0
