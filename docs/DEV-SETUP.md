# Dev setup

Quick-start for contributors.

## Prerequisites

| Tool   | Version      | Notes                                                                |
| ------ | ------------ | -------------------------------------------------------------------- |
| Rust   | `1.85+`      | install via [rustup](https://rustup.rs). `rustfmt` + `clippy` ship.  |
| Node   | `22+`        | any LTS works.                                                       |
| pnpm   | `10.23+`     | `corepack enable && corepack install` or `npm i -g pnpm`.            |
| Tauri v2 system deps | — | Windows: WebView2 Evergreen (ships with Win 11). macOS: Xcode Command Line Tools. Linux: see the [Tauri prereqs page](https://v2.tauri.app/start/prerequisites/). |

## First build

```bash
pnpm install                 # resolves JS deps
cargo build --workspace      # cold build compiles DuckDB from source (~3 min)
pnpm -r run check            # type-check all TS packages
cargo test --workspace       # includes the .ppx round-trip tests
```

Everything above should be green on a fresh clone. If `cargo test` fails, **do
not** commit — the round-trip invariant in `crates/ppx-core/tests/roundtrip.rs`
is the safety net that prevents the profile data-loss bug from reappearing.

## Running the app

```bash
pnpm dev                     # Tauri dev (runs Vite + Rust host + live-reload)
```

This opens the app window. Load your own `.ppx` with **Open profile**. Keep it
outside the repository — `.gitignore` refuses `*.ppx` for that reason, and
ppxray ships no sample profile.

## Production build

```bash
pnpm build                   # emits installers in target/release/bundle/ (unsigned)
```

## Proxifier dev-time note ⚠

Because Proxifier itself may be running on your machine and its default rule
set blocks outbound traffic from any unlisted process, **your Rust toolchain
may get blocked on the first `cargo fetch`**. Either:

1. Add a rule named e.g. `Rust Dev` with Action `Direct` and Applications:

   ```
   C:\Users\<you>\.cargo\bin\cargo.exe;
   C:\Users\<you>\.cargo\bin\rustc.exe;
   C:\Users\<you>\.cargo\bin\rustup.exe;
   C:\Users\<you>\.rustup\toolchains\*\bin\rustc.exe;
   C:\Users\<you>\.rustup\toolchains\*\bin\cargo.exe;
   ```

2. Or temporarily pause Proxifier.

This is one of the pain points we're building this tool to make manageable.

## Regenerating TS bindings from Rust

```bash
pnpm ts-gen                  # runs `cargo test -p ppx-core` which triggers ts-rs
```

Never edit files under `packages/ipc-schema/src/generated/` by hand — they are
regenerated on every `cargo test` run. See `docs/ARCHITECTURE.md` for details.

## Useful commands

```bash
cargo fmt --all              # format Rust
cargo clippy --workspace --all-targets -- -D warnings
pnpm lint                    # eslint (per package)
cargo test -p ppx-core       # parser/serializer tests only
cargo insta review           # review snapshot diffs (after test changes)
```

## Troubleshooting

- **`icons/icon.ico not found`** during `cargo build`: the icon set lives in
  `src-tauri/icons/`. Regenerate it from a square PNG with
  `pnpm tauri icon <path>`.
- **`IllFormed(UnclosedReference)` parsing a .ppx**: real Proxifier files
  contain bare `&` in rule names. Our parser strips these via
  `escape_bare_ampersands`; if you see this error, the sanitizer was bypassed
  somewhere.
- **Tauri webview is blank**: ensure `pnpm install` finished and WebView2 is
  installed on Windows (`reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"`).
