# Architecture

Living document. Update it when a boundary moves, not when code moves.

## Shape

```
┌─────────────────────────────────────────────────────────────┐
│ WebView (React 19 + Mantine v7)                             │
│   apps/desktop/src/                                         │
│   - zustand stores      - modules/*                         │
│   - TanStack Query cache                                    │
│   - generated types from @ppxray/ipc-schema                 │
└───────────────▲──────────────────────────▲──────────────────┘
                │ invoke(cmd, args)        │ event stream
                │                          │
┌───────────────┴──────────────────────────┴──────────────────┐
│ Tauri v2 host (Rust, single process, tokio runtime)         │
│   src-tauri/src/                                            │
│   - commands/* (thin wrappers around crate fns)             │
│   - state.rs (AppState, shared behind tauri::Manager)       │
│   - error.rs (AppError, serializes to string for JS)        │
└───────────────▲──────────────────────────▲──────────────────┘
                │                          │
        ┌───────┴────────┐        ┌────────┴────────────┐
        │ ppx-core       │        │ log-ingest          │
        │ (pure, sync)   │        │ detect-engine       │
        └────────────────┘        │ llm-bridge (opt-in) │
                                  └─────────┬───────────┘
                                            │
                                     DuckDB (one file per log)
```

## Crate boundaries

- **`crates/ppx-core`** — parse and serialize `.ppx` profile files, plus the
  rule matcher, shadow detection, and exposure analysis. Pure and
  synchronous, no I/O beyond an input `&str`. Everything about the profile
  model lives here; `src-tauri` only wraps it in filesystem and IPC.
  Round-trip safety is the load-bearing invariant — see `tests/roundtrip.rs`.
- **`crates/log-ingest`** — streaming log parser, DuckDB loader, and the
  query layer. Owns the connection for a log DB, including the sandbox
  applied at open time (see *DuckDB sandbox* below).
- **`crates/detect-engine`** — the detection catalog, the rule runner, and
  alert storage. Reads the tables `log-ingest` writes, in the same file.
- **`crates/llm-bridge`** — the optional assistant: provider clients for the
  Anthropic and OpenAI-compatible dialects, the redaction that implements the
  privacy level, the read-only guard for model-written SQL, and the egress
  audit log. Disabled by default and free of Tauri, so the whole data
  boundary is unit-testable without a running app — see *Assistant data
  boundary* below.

New functionality lives in a crate, not in `src-tauri`. The host crate should
stay small and dedicated to IPC wiring, atomic file writes, and thread pools.

## IPC

Tauri `invoke` calls hit `#[tauri::command]` handlers under
`src-tauri/src/commands/`. Each handler returns `Result<T, AppError>`:

- Success: serialized `T` on the JS side.
- Failure: `AppError` serializes to a string, surfaces as a thrown Promise
  rejection on the JS side.

### Type sharing

Rust structs with `#[derive(ts_rs::TS)]` emit TypeScript declarations on
every `cargo test` run into `packages/ipc-schema/src/generated/`. The JS
side imports only through `@ppxray/ipc-schema`, never from the `generated/`
files directly — the re-export layer in `src/index.ts` is our stability
contract.

Adding a new shared type:
1. Add `#[derive(Serialize, Deserialize, TS)]` + `#[ts(export, export_to =
   "../../../packages/ipc-schema/src/generated/")]` to the Rust struct.
2. `cargo test -p ppx-core` (or any crate with the derive).
3. Add a `export type { Foo } from "./generated/Foo"` line in
   `packages/ipc-schema/src/index.ts`.

### Hand-written DTO types

A few JS-only envelopes live in `packages/ipc-schema/src/ipc.ts` — these are
response shapes for commands that don't correspond to a single Rust struct
(e.g. `OpenProfileResult { profile, path, modified_at }`). **Keep these in
sync** with the Rust-side `#[derive(Serialize)]` struct when you change it.

## DuckDB sandbox

Detection rules are SQL. Built-ins are Rust literals, but user rules are
YAML loaded from a directory, and rule packs are meant to be *shared* — so
importing someone's `.yml` means running their SQL. `store::harden` runs at
connection-open time and revokes DuckDB's access to everything outside the
database file (`enable_external_access = false`, extensions off,
`lock_configuration = true` last so a rule cannot undo it). Without it,
`read_text` / `COPY TO` / `INSTALL httpfs` give a rule file read, file write,
and network egress.

Nothing in the app needs SQL-level external access: ingest writes through the
Rust appender and every query reads tables in this file. Both halves are
pinned by `crates/log-ingest/tests/sandbox.rs` — the escapes stay blocked and
the app keeps working.

## Log DB schema policy

A log DB is a *cache*, derived from a `.txt` the user still has. So
`log_ingest::schema` does not migrate in place: if the file's stamped
`CURRENT_VERSION` differs from the build's, it drops every table and
rebuilds. Re-ingesting costs seconds; a subtly wrong column costs a wrong
answer in a security tool.

There are deliberately **no indexes**. Every query is an aggregate over a
large row range, which DuckDB answers by scanning with zonemaps; ART indexes
(what `CREATE INDEX` and `PRIMARY KEY` build) only pay for selective point
lookups and cost real time and memory during bulk load.

## Data-safety invariants

1. Every write to a file the user would miss goes through
   `src-tauri/src/atomic.rs` — `.ppx` profiles (with a `.bak`), settings, and
   user rule YAML:
   - optionally pre-copy to `<path>.bak`
   - write to a unique `<path>.tmp-<pid>-<n>`, `fsync`
   - rename over target
   If any step fails, the original file is untouched. Do not hand-roll
   `remove_file` + `rename` — that leaves a window where the file is gone.
2. `ppx_core::parse_str` → `to_xml_string` → `parse_str` must produce an
   equal `Profile`. Enforced by `crates/ppx-core/tests/roundtrip.rs`. Do not
   add fields to `Profile` without extending the round-trip coverage.
3. Bare `&` in XML (common in real profiles) is pre-escaped before parsing.
   Entity references (`&amp;`, `&#NN;`, …) are preserved.

## Frontend architecture

- **Routing/layout**: single `AppShell` with a left nav rail and top bar.
  Module switching is `useState`; there are no URLs to encode yet.
- **State**: `zustand` per domain holds *UI* state (filters, selection,
  the open log). Stores are provided via React Context so each test can
  mount with a fresh store.
- **Server state**: TanStack Query owns everything read over IPC. The log
  module's panels share one `log_dashboard` query rather than fetching per
  panel — see `modules/log/queries.ts`. Automatic refetching is off (the
  data is a local file with no other writer); caches are invalidated
  explicitly after an ingest.
- **Theme**: Mantine `createTheme` + a compact-first component config in
  `src/theme.ts`, dark by default. Interface font family and base size are
  user settings in `stores/ui-prefs.ts`; they live in `localStorage` rather
  than `settings.json` because they must be applied before the first paint.
- **Rendering conventions**: monospace for everything host/IP/path (use
  the `.mono` CSS class or Mantine `ff="monospace"`). Never wrap long host
  lists — use `lineClamp={1}` with a full list in `title` for hover tooltip.

## Why this is one binary

The question comes up as "split the crates into runtime DLLs to shrink the
executable, and load them safely". Loading them safely is solvable, and
DuckDB in particular exposes a C API — dropping the `bundled` feature links
a shared `libduckdb` with no Rust ABI boundary at all. The reason not to is
arithmetic, not risk.

Splitting relocates bytes; it does not remove them. The installer carries the
executable *and* the libraries, so the download is unchanged. It only shrinks
if a component becomes optional, and DuckDB is not: Log and Hunt are two of
the four modules and both read from it.

The other two hoped-for gains do not arrive either. Splitting *our* crates
would need a hand-written, hand-versioned C ABI across the query surface,
because Rust has no stable ABI — harder to maintain, not easier. And
per-component updates do not exist: the Tauri updater replaces the whole
bundle, so a second update path would have to be built, signed and verified
alongside the one that already works.

Where the size actually is, measured on a release build: the Windows installer is
9.6 MB, the macOS disk images 17–18 MB, the `.deb` 20 MB. The 92 MB AppImage
is the outlier, and 56% of it is the WebKit engine the format bundles for
portability — see `docs/DISTRIBUTION.md`. None of that moves by splitting
the executable.

## Build & release

- Dev: `pnpm dev` (frontend + Rust host, live-reloaded).
- Prod: `pnpm build` → unsigned installers under
  `target/release/bundle/`. See `docs/DISTRIBUTION.md`.
- CI (`.github/workflows/ci.yml`): `cargo fmt --check`,
  `cargo clippy -D warnings`, `cargo test`, `pnpm -r run check`,
  `pnpm -r run lint`, `pnpm -r run test`, plus a dependency audit.

## Assistant data boundary

The assistant is the only feature that can put user data on a network, so
its boundary is code rather than policy, and it lives in three named places:

1. **`llm_bridge::config::DataScope`** — the level, a persisted setting that
   defaults to `SchemaOnly`. `allows_values()` and `allows_raw_rows()` are
   the only two questions anything else asks it.
2. **`llm_bridge::table::tool_result`** — the single gate. The assistant's
   query runs locally and the rows always reach the *user*; this function
   decides what the *model* is told about them. At `SchemaOnly` that is the
   row count and the column names, and nothing else. Every level passes
   through here, so there is one place to audit rather than a call site per
   task.
3. **`llm_bridge::redact`** — how `Aggregates` masks: hostnames to their
   registrable domain, process paths to a filename, private addresses to
   their block. It carries its own copy of the registry-suffix list rather
   than sharing `log_ingest::suggest`'s, because that one is a suggestion
   heuristic and this one guards an egress boundary; they should not move
   together.

Two supporting invariants:

- **The preview is the payload.** `llm_bridge::client::preview` and
  `LlmClient::send` both call `provider::build_body`, which is pure. There is
  no second construction path that could send something the preview did not
  show, and `client::tests::the_preview_is_the_payload` compares the digests.
- **Model SQL is untrusted, like a rule pack.** `llm_bridge::sql_guard`
  accepts one read-only statement; the caller wraps it in `SELECT * FROM ( … )
  LIMIT n` so a non-query cannot parse; and it executes on the connection
  hardened by `log_ingest::store::harden`. The guard being incomplete is
  therefore not a breach on its own — which is the point of layering it that
  way, and why `sql_guard` has a test asserting that `read_csv` passes *it*
  and is stopped by the sandbox instead.

`crates/llm-bridge/tests/boundary.rs` walks a full question–query–result
round trip and asserts against the serialized bytes that no log value appears
at the default level. Byte-level on purpose: a refactor that relocated a
hostname into a new field would keep a structural assertion green.
