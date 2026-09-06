# Security Policy

## Reporting a vulnerability

If you find a security issue in ppxray, **please do not open a
public GitHub issue**. Instead:

1. Open a private report via GitHub's Security Advisories tab
   (`https://github.com/Vibe-Coding-Base/PPXray/security/advisories/new`).
2. Or email the maintainer directly at `tony.nguyen.ai@gmail.com` with the
   subject line `[ppxray security]`.

Please include:

- Affected version (`git rev-parse HEAD` if you've built from source).
- Steps to reproduce.
- Impact assessment (what the vulnerability enables an attacker to do).
- Suggested fix, if any.

We'll acknowledge within 72 hours and aim to ship a patched release
within 14 days of confirming the report.

## Scope

In scope:

- Code execution / privilege escalation via crafted `.ppx` profile files.
- Code execution / privilege escalation via crafted Proxifier log files.
- Code execution / privilege escalation via crafted user-authored YAML
  detection rules.
- Memory-safety bugs in the Rust crates.
- SQL / command injection via UI-accepted inputs that propagate to the
  DuckDB store or shell.
- Credential or data leak from app-data directories.

Out of scope:

- Denial-of-service by feeding the app enormous (multi-GB) log files —
  that's a capacity consideration, not a vulnerability.
- False positives / negatives in the detection rule catalog — those are
  bugs but not security issues.
- Issues in dependencies without evidence of reachability from our code
  (please report upstream).

## Threat model

ppxray processes untrusted input in three places:

1. **`.ppx` profile files** — XML parsed by `ppx-core` (`quick-xml`).
2. **Proxifier log files** — line-by-line streaming parser in
   `log-ingest`.
3. **YAML detection rules** — parsed by `serde_yml`, then executed as SQL
   by DuckDB in-process.

That third one is the sharpest edge. Rule SQL is **not** trusted: rule
packs carry `id`, `mitre` and `references` precisely so analysts can trade
them, so importing someone's `.yml` means running their SQL. Left open,
that grants arbitrary file read (`read_text`), file write (`COPY … TO`)
and network egress (`INSTALL httpfs`).

Every connection therefore opens with external access and extension
loading revoked and the configuration locked, so a rule cannot re-enable
them (`log_ingest::store::harden`). Both halves of that — the escapes stay
blocked, the app keeps working — are pinned by
`crates/log-ingest/tests/sandbox.rs`. **A change that weakens the sandbox
is a security regression**, even if every test still passes.

All data processing is local. Two things can put a request on the wire, and
both are user-initiated:

**The update check.** Fetches a signed manifest from the GitHub release
channel and verifies it against the ed25519 public key compiled into the
binary (`src-tauri/tauri.conf.json → plugins.updater`). It runs only on an
explicit button press — there is no background poll.

**The assistant** (`crates/llm-bridge`), which is disabled on a fresh install
and sends nothing while it is. A Proxifier log is a record of every host the
machine contacted, so the boundary is a setting rather than a constant
(`llm_bridge::config::DataScope`) and it defaults to the tightest level:

- `schema-only` (default) — table and column names plus the question. The
  model writes SQL; ppxray executes it locally and hands back only the row
  count and column names. No value from the log is transmitted.
- `aggregates` — query results, with hostnames reduced to their registrable
  domain, process paths to a filename and private addresses to their block
  (`llm_bridge::redact`).
- `raw` — query results unchanged.

Model-written SQL is treated as untrusted, like a shared rule pack:
`llm_bridge::sql_guard` accepts a single read-only statement and nothing
else, the survivor is wrapped in `SELECT * FROM ( … ) LIMIT n` where no other
statement parses, and it runs on the same hardened connection described
above. API keys live in the OS credential store, never in `settings.json`.
The first send is gated on the user reading the exact payload
(`llm_bridge::client::preview`, which returns what the sender serializes),
and every request — sent, failed or refused — is appended to
`<app-data>/llm-audit.jsonl` with endpoint, model, level, byte count and a
SHA-256 of the body.

## Dependency audits

`cargo audit` and `pnpm audit` run on every PR (`.github/workflows/ci.yml`,
job `audit`). Known CVEs block the merge.

## Release integrity

Installers are **not** code-signed — commercial certificates are not worth
the cost for a free tool — so Windows SmartScreen and macOS Gatekeeper will
warn on first launch. Each release publishes a SHA-256 per artifact; verify
it before running.

Update bundles *are* signed, with a project-controlled ed25519 key whose
public half is compiled into every binary. A tampered update is rejected
before installation, so only the first install needs manual verification.

Release tags are not currently signed. Verify a release by its published
SHA-256 rather than by the tag.

[`docs/DISTRIBUTION.md`](docs/DISTRIBUTION.md) has the per-OS procedure, and
how to re-sign the artifacts with your own certificate for enterprise
deployment.
