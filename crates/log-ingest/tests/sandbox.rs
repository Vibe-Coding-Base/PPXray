//! The DuckDB sandbox must hold against rule SQL.
//!
//! Detection rules are SQL supplied by shareable YAML files, so a rule pack
//! downloaded from someone else runs inside this connection. `store::harden`
//! revokes DuckDB's access to everything outside the database file; these
//! tests pin that down from both sides — the escapes stay blocked, and the
//! app's own legitimate work keeps functioning.

use std::path::PathBuf;

use log_ingest::{ingest_file, open_store, store_path_for};

/// A store over a scratch DB file, plus the synthetic log fixture loaded in.
struct Fixture {
    store: log_ingest::LogStore,
    _dir: tempfile::TempDir,
}

fn sample_log() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/synthetic-log.txt")
        .canonicalize()
        .expect("testdata/synthetic-log.txt should exist — run tools/gen-sample-log.py")
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = store_path_for(dir.path(), &sample_log());
    let store = open_store(&db).expect("open store");
    ingest_file(&sample_log(), &store, |_| {}).expect("ingest fixture");
    Fixture { store, _dir: dir }
}

/// Assert that `sql` is refused, *and* that it is refused by the sandbox.
///
/// The distinction matters: a typo, or a DuckDB build without the function,
/// also produces an error. Passing on those would leave us asserting nothing
/// while looking green, so we require the rejection to name a permission or
/// a locked configuration.
fn expect_blocked(store: &log_ingest::LogStore, what: &str, sql: &str) {
    let result = store.with_conn(|c| {
        c.execute_batch(sql)?;
        Ok(())
    });
    match result {
        Ok(()) => panic!("SANDBOX ESCAPE: {what} succeeded\n  sql: {sql}"),
        Err(e) => {
            let msg = e.to_string();
            let refused_by_sandbox = msg.contains("Permission Error")
                || msg.contains("configuration has been locked")
                || msg.contains("disabled through configuration");
            assert!(
                refused_by_sandbox,
                "{what} failed, but not because of the sandbox — this test would \
                 pass even with the sandbox removed.\n  sql: {sql}\n  error: {msg}"
            );
        }
    }
}

#[test]
fn blocks_arbitrary_file_read() {
    let f = fixture();
    expect_blocked(
        &f.store,
        "read_text of an arbitrary path",
        "SELECT content FROM read_text('/etc/passwd');",
    );
    expect_blocked(
        &f.store,
        "read_csv of an arbitrary path",
        "SELECT * FROM read_csv('/etc/passwd');",
    );
    expect_blocked(
        &f.store,
        "read_blob of an arbitrary path",
        "SELECT * FROM read_blob('/etc/passwd');",
    );
}

#[test]
fn blocks_arbitrary_file_write() {
    let f = fixture();
    expect_blocked(
        &f.store,
        "COPY TO an arbitrary path",
        "COPY (SELECT * FROM events) TO '/tmp/ppx-exfil.csv';",
    );
}

#[test]
fn blocks_extension_loading() {
    let f = fixture();
    // httpfs is the practical exfil path: load it and `COPY … TO 's3://…'`
    // or `read_csv('https://…')` reaches the network.
    expect_blocked(&f.store, "INSTALL httpfs", "INSTALL httpfs;");
    expect_blocked(&f.store, "LOAD httpfs", "LOAD httpfs;");
}

#[test]
fn blocks_attaching_another_database() {
    let f = fixture();
    expect_blocked(
        &f.store,
        "ATTACH another database file",
        "ATTACH '/tmp/ppx-other.duckdb' AS other;",
    );
}

/// The whole sandbox rests on this: if a rule can re-enable external access,
/// every other test here is decorative.
#[test]
fn configuration_cannot_be_unlocked() {
    let f = fixture();
    expect_blocked(&f.store, "re-enabling external access", "SET enable_external_access = true;");
    expect_blocked(
        &f.store,
        "re-enabling community extensions",
        "SET allow_community_extensions = true;",
    );
    expect_blocked(
        &f.store,
        "re-enabling extension autoloading",
        "SET autoload_known_extensions = true;",
    );

    // And the escape must still be blocked afterwards.
    expect_blocked(
        &f.store,
        "read_text after attempting to unlock",
        "SELECT content FROM read_text('/etc/passwd');",
    );
}

// ---------------------------------------------------------------------------
// The sandbox must not break the app
// ---------------------------------------------------------------------------

#[test]
fn ingest_and_query_still_work() {
    let f = fixture();

    let stats = log_ingest::query::stats(&f.store).expect("stats query");
    assert!(
        stats.total_events > 100,
        "fixture should have loaded a few hundred connection events, got {}",
        stats.total_events
    );
    assert!(stats.total_dns > 50, "fixture should have loaded DNS events, got {}", stats.total_dns);

    let filter = log_ingest::EventFilter::default();
    let rows = log_ingest::query_events(&f.store, &filter).expect("query events");
    assert!(!rows.is_empty(), "unfiltered query should return rows");
}

/// Aggregations spill to a temp directory when they outgrow memory. If the
/// sandbox blocked that, large logs would fail only in production — so
/// exercise the aggregate paths the UI actually runs.
#[test]
fn aggregates_and_grouping_still_work() {
    let f = fixture();
    let filter = log_ingest::EventFilter::default();

    let procs = log_ingest::query::top_processes(&f.store, &filter, 20).expect("top_processes");
    assert!(!procs.is_empty(), "top_processes should return rows");

    let hosts = log_ingest::query::top_hosts(&f.store, &filter, 20).expect("top_hosts");
    assert!(!hosts.is_empty(), "top_hosts should return rows");

    let rules = log_ingest::query::top_rules(&f.store, &filter, 20).expect("top_rules");
    assert!(!rules.is_empty(), "top_rules should return rows");

    let buckets = log_ingest::query::timeline(&f.store, &filter, 60).expect("timeline");
    assert!(!buckets.is_empty(), "timeline should return buckets");

    let facets = log_ingest::query::facets(&f.store).expect("facets");
    assert!(!facets.processes.is_empty(), "facets should list processes");
}

/// Re-ingesting into an existing store is the "open log → re-ingest" loop in
/// the UI; it truncates and reloads, all of which is DDL + appends.
#[test]
fn reingest_still_works() {
    let f = fixture();
    let before = log_ingest::query::stats(&f.store).expect("stats");
    ingest_file(&sample_log(), &f.store, |_| {}).expect("re-ingest");
    let after = log_ingest::query::stats(&f.store).expect("stats");
    assert_eq!(
        before.total_events, after.total_events,
        "re-ingesting the same file should yield the same event count"
    );
}
