//! Every built-in rule must actually run.
//!
//! The catalog is ~1100 lines of hand-written SQL interpolated into query
//! templates at runtime. Nothing in the type system checks that a `where:`
//! clause parses, that a `custom` SELECT returns the six columns
//! `eval::run_custom` requires, or that a rule id is unique. Before these
//! tests, a typo in any of the 30 rules compiled fine and surfaced only as a
//! per-rule error string in the Hunt panel — at which point the rule has
//! silently been detecting nothing.
//!
//! `run_all_rules` catches per-rule failures by design, so a broken rule does
//! not abort a hunt. That is right for production and useless for a test,
//! which is why these assert on the per-rule report rather than on the
//! call's `Result`.

use std::path::PathBuf;

use detect_engine::{
    RuleQuery, RuleSource, alert::AlertFilter, all_rules, list_alerts, list_evidence, run_all_rules,
};
use log_ingest::{LogStore, ingest_file, open_store, store_path_for};

struct Fixture {
    store: LogStore,
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

/// The load-bearing test: execute all 30 rules against a real ingested log
/// and fail loudly on any that error.
#[test]
fn every_builtin_rule_executes() {
    let f = fixture();
    let rules = all_rules();
    let report = run_all_rules(&f.store, &rules).expect("hunt run");

    assert_eq!(report.per_rule.len(), rules.len(), "report should carry one entry per rule");

    let failures: Vec<String> = report
        .per_rule
        .iter()
        .filter_map(|r| r.error.as_ref().map(|e| format!("  {}: {e}", r.rule_id)))
        .collect();

    assert!(
        failures.is_empty(),
        "{} of {} built-in rules failed to execute:\n{}",
        failures.len(),
        rules.len(),
        failures.join("\n")
    );
}

/// Rule ids address rules in the UI, in user overrides
/// (`load_combined_rules` drops a built-in when a user file reuses its id),
/// and in the `alerts.rule_id` column. Duplicates would make all three
/// ambiguous.
#[test]
fn builtin_rule_ids_are_unique() {
    let mut seen = std::collections::HashMap::<String, usize>::new();
    for rule in all_rules() {
        *seen.entry(rule.id.clone()).or_default() += 1;
    }
    let dupes: Vec<String> = seen
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(id, n)| format!("  {id} appears {n}×"))
        .collect();
    assert!(dupes.is_empty(), "duplicate rule ids:\n{}", dupes.join("\n"));
}

/// Metadata the UI renders unconditionally.
#[test]
fn builtin_rules_carry_required_metadata() {
    for rule in all_rules() {
        assert!(!rule.id.trim().is_empty(), "a rule has an empty id");
        assert!(!rule.title.trim().is_empty(), "rule `{}` has an empty title", rule.id);
        assert!(!rule.description.trim().is_empty(), "rule `{}` has an empty description", rule.id);
        assert_eq!(
            rule.source,
            RuleSource::Builtin,
            "rule `{}` is in the built-in catalog but not marked as such",
            rule.id
        );
    }
}

/// `eval::run_custom` rejects a SELECT with fewer than six columns at
/// runtime. Run each custom rule on its own so a violation names the rule
/// rather than showing up as one line in the combined report.
#[test]
fn custom_rules_satisfy_the_column_contract() {
    let f = fixture();
    for rule in all_rules() {
        if !matches!(rule.query, RuleQuery::Custom { .. }) {
            continue;
        }
        let single = vec![rule.clone()];
        let report = run_all_rules(&f.store, &single).expect("hunt run");
        let entry = &report.per_rule[0];
        assert!(
            entry.error.is_none(),
            "custom rule `{}` failed: {}",
            rule.id,
            entry.error.as_deref().unwrap_or("")
        );
    }
}

/// A catalog that runs but never fires would pass `every_builtin_rule_executes`
/// while detecting nothing. The fixture deliberately contains LOLBin egress,
/// beaconing, DNS tunnelling and port scanning, so a healthy catalog must
/// produce alerts — and the alerts must be readable back with their evidence.
#[test]
fn catalog_detects_the_planted_traffic() {
    let f = fixture();
    let report = run_all_rules(&f.store, &all_rules()).expect("hunt run");

    assert!(
        report.total_alerts > 0,
        "no rule fired on a fixture built to trip several — either the \
         catalog or the fixture has drifted"
    );

    let firing: Vec<&str> =
        report.per_rule.iter().filter(|r| r.alerts > 0).map(|r| r.rule_id.as_str()).collect();
    assert!(
        firing.len() >= 5,
        "expected several rules to fire on the fixture, got {}: {firing:?}",
        firing.len()
    );

    // `list_alerts` pages, so ask for more than the run produced before
    // comparing counts — otherwise this asserts on the page size.
    let all = AlertFilter { limit: Some(5000), ..AlertFilter::default() };
    let alerts = list_alerts(&f.store, &all).expect("list alerts");
    assert_eq!(
        alerts.len() as u64,
        report.total_alerts,
        "the alert table should hold exactly what the run reported"
    );

    // Evidence ids must resolve to rows in `events`; a rebuild of the event
    // table renumbers ids, which is why the schema drops alerts alongside it.
    let with_evidence = alerts.iter().find(|a| a.evidence_count > 0);
    if let Some(alert) = with_evidence {
        let ids = list_evidence(&f.store, alert.id, 50).expect("list evidence");
        assert!(!ids.is_empty(), "evidence_count > 0 but no ids came back");
    }
}

/// Re-running the catalog must replace the previous alerts, not append to
/// them — `run_all_rules` resets the tables first.
#[test]
fn rerunning_the_catalog_is_idempotent() {
    let f = fixture();
    let first = run_all_rules(&f.store, &all_rules()).expect("first run");
    let second = run_all_rules(&f.store, &all_rules()).expect("second run");
    assert_eq!(
        first.total_alerts, second.total_alerts,
        "a second hunt over unchanged data produced a different alert count"
    );

    let all = AlertFilter { limit: Some(5000), ..AlertFilter::default() };
    let alerts = list_alerts(&f.store, &all).expect("list alerts");
    assert_eq!(
        alerts.len() as u64,
        second.total_alerts,
        "alert table holds {} rows after a second run that reported {} — the \
         reset did not take, so alerts are accumulating across runs",
        alerts.len(),
        second.total_alerts
    );
}
