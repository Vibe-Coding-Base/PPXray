# Contributing to ppxray

Thanks for taking the time to contribute. This project is small enough
that heavy process would be a waste — a few pragmatic rules keep the
diff review quick.

## Dev setup

See [`docs/DEV-SETUP.md`](docs/DEV-SETUP.md).

TL;DR:

```bash
pnpm install
cargo build --workspace   # ~3 min first time (compiles DuckDB from source)
pnpm dev                  # launches Tauri + Vite dev server
```

## Quality gates

Every PR must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm -r run check         # TypeScript strict
pnpm -r run lint          # ESLint — react-hooks rules are errors
pnpm -r run test          # Vitest
```

These also run in CI (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Writing detection rules

The quickest way to contribute security value is to add detection rules.
Two paths:

1. **YAML-only user rules** — create a `.yml` file in your configured
   rule directory (`Settings → Detection rules directory`). Supported
   `kind` values: `events_where`, `events_grouped`, `dns_where`, `custom`.
   See [`crates/detect-engine/src/loader.rs`](crates/detect-engine/src/loader.rs)
   for the schema.

2. **Built-in Rust rules** — add a new `fn my_rule() -> DetectionRule`
   in [`crates/detect-engine/src/builtin.rs`](crates/detect-engine/src/builtin.rs)
   using the `rule!` macro, then register it in `all_rules()`. Include
   `mitre:` tags and a `description` that explains why the rule fires
   and what its false-positive profile looks like.

Every built-in rule is already executed against a fixture by
[`crates/detect-engine/tests/catalog.rs`](crates/detect-engine/tests/catalog.rs),
so a rule whose SQL does not run fails the build rather than silently
detecting nothing. Beyond that, add a test for anything subtle about *when*
the rule should and should not fire, and extend `tools/gen-sample-log.py`
if the fixture needs traffic that would trip it.

## Commit conventions

Conventional Commits, lightly:

- `feat(hunt): add apt.reverse-ssh rule`
- `fix(matcher): ipv4 wildcard + cidr equivalence`
- `refactor(log-ingest): share chrono helpers`
- `docs(README): screenshots + badges`
- `chore(deps): bump duckdb-rs to 1.4.5`

Prefix with module name when obvious. Body: explain *why*, not *what*
(the diff shows what).

## PR checklist

- [ ] Lint + tests pass locally.
- [ ] New public API surface has doc comments explaining intent.
- [ ] Tricky logic (shadow detection, parser edge cases) has a test
      that would have caught the absence of the logic.
- [ ] Changelog entry added under `## [Unreleased]`.
- [ ] No new deps without a short justification in the PR body.

## Performance

Ingest throughput is the number that matters for this tool. Measure it
before and after any change to the parser or the DuckDB load path:

```sh
cargo run --release -p log-ingest --example bench-ingest -- <path-to-log>
```

It reports parse-only and end-to-end MB/s separately, so it is clear which
half of the pipeline a change actually moved. Put the before/after numbers
in the PR body.

There is deliberately no benchmark job in CI: shared runners are too noisy
to distinguish a real regression from scheduling jitter, and a benchmark
that cannot fail is just a comment on every PR.

## Code style

- Rust: rustfmt defaults + `imports_granularity = "Crate"`, `group_imports = "StdExternalCrate"`
  (configured in `rustfmt.toml`).
- TypeScript: strict mode on, no implicit `any`, prefer `type` over
  `interface` for data-only shapes and `interface` for public props.
- Comments explain *why*, not *what*. Avoid comments that narrate what
  the next line obviously does.

## License

By contributing you agree that your contributions will be licensed under
the [MIT License](LICENSE) — same as the rest of the project.
