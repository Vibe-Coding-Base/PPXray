//! The promise, checked end to end.
//!
//! The unit tests in each module cover their own piece. These walk the whole
//! path a real question takes — settings, prompt, request body, tool result —
//! and assert the property the feature is sold on: at the default privacy
//! level, no value from the user's log is anywhere in what goes on the wire.
//!
//! They are deliberately written against *bytes*, not against structure. A
//! refactor that moved a hostname into a new field would keep every
//! structural assertion passing and still leak.

use llm_bridge::config::{DataScope, LlmSettings, ProviderKind};
use llm_bridge::provider::{ChatRequest, Turn, build_body};
use llm_bridge::table::{QueryTable, tool_result};
use llm_bridge::{prompt, sql_guard};
use serde_json::json;

/// Values that must never appear in a payload at the default level. Chosen
/// to be the kinds of thing a Proxifier log actually contains.
const SECRETS: &[&str] = &[
    "rr5.sn-abcd1234.googlevideo.com",
    "internal-jira.corp.example",
    "alice",
    "10.4.7.19",
    "chrome.exe",
];

fn sensitive_result() -> QueryTable {
    QueryTable {
        columns: vec!["process".into(), "dst_host".into(), "dst_ip".into(), "n".into()],
        rows: vec![
            vec![
                json!(r"C:\Users\alice\AppData\Local\chrome.exe"),
                json!("rr5.sn-abcd1234.googlevideo.com"),
                json!("10.4.7.19"),
                json!(9),
            ],
            vec![
                json!("java.exe"),
                json!("internal-jira.corp.example"),
                json!("10.4.7.20"),
                json!(3),
            ],
        ],
        truncated: false,
    }
}

fn settings(scope: DataScope) -> LlmSettings {
    LlmSettings {
        enabled: true,
        data_scope: scope,
        provider: ProviderKind::Anthropic,
        ..Default::default()
    }
}

/// The schema, as `log_ingest::schema_description` would produce it. Column
/// *names* are shared at every level; column *values* are the thing at issue.
const SCHEMA: &str = "CREATE TABLE events (\n  process VARCHAR,\n  dst_host VARCHAR\n);";

#[test]
fn at_the_default_level_a_full_round_trip_carries_no_log_values() {
    let cfg = settings(DataScope::SchemaOnly);
    let table = sensitive_result();

    // Turn 1: the question. Turn 2: the model's query. Turn 3: what we hand
    // back after running it. The third is the only one that could leak.
    let turns = vec![
        Turn::User("which process is noisiest?".into()),
        Turn::Assistant {
            text: "Let me count connections per process.".into(),
            calls: vec![llm_bridge::ToolCall {
                id: "toolu_1".into(),
                name: prompt::SQL_TOOL.into(),
                input: json!({"sql": "SELECT process, count(*) FROM events GROUP BY 1", "purpose": "rank processes"}),
            }],
        },
        Turn::ToolResult {
            id: "toolu_1".into(),
            name: prompt::SQL_TOOL.into(),
            content: tool_result(&table, cfg.data_scope),
            is_error: false,
        },
    ];

    let request = ChatRequest {
        system: prompt::log_assistant(cfg.data_scope, SCHEMA, "482 events over 3 days."),
        turns,
        tools: vec![prompt::sql_tool()],
    };

    let body = serde_json::to_string(&build_body(&cfg, &request)).unwrap();

    for secret in SECRETS {
        assert!(
            !body.contains(secret),
            "`{secret}` reached the request body at the schema-only level:\n{body}"
        );
    }

    // And the request is still useful: the schema and the question are there,
    // so this is not passing by sending nothing at all.
    assert!(body.contains("dst_host"), "the schema did not reach the model");
    assert!(body.contains("which process is noisiest?"), "the question did not reach the model");
    assert!(body.contains("2 row(s)"), "the model was not told the shape of the result");
}

#[test]
fn the_aggregate_level_shares_families_but_not_identities() {
    let cfg = settings(DataScope::Aggregates);
    let content = tool_result(&sensitive_result(), cfg.data_scope);

    // The domain survives, the session-specific labels do not.
    assert!(content.contains("googlevideo.com"));
    assert!(!content.contains("sn-abcd1234"));
    // The program survives, the account name does not.
    assert!(content.contains("chrome.exe"));
    assert!(!content.contains("alice"));
    // The network is internal; which host on it is not shared.
    assert!(content.contains("10.0.0.0/8"));
    assert!(!content.contains("10.4.7.19"));
    // A private-looking internal hostname still reduces to its domain.
    assert!(content.contains("corp.example"));
    assert!(!content.contains("internal-jira"));
}

#[test]
fn the_raw_level_does_what_it_says() {
    let content = tool_result(&sensitive_result(), DataScope::Raw);
    for secret in SECRETS {
        assert!(content.contains(secret), "`{secret}` was masked at the raw level");
    }
}

#[test]
fn explaining_a_rule_never_mentions_the_log() {
    // The rule explainer is the one task with no log access at all, which is
    // what makes it usable at every privacy level. Assert the prompt carries
    // no schema and no context.
    let cfg = settings(DataScope::SchemaOnly);
    let request = ChatRequest {
        system: prompt::rule_explainer(),
        turns: vec![Turn::User(
            "Explain this rule.\n\nRule #1: allow\nTargets: (any)\nAction: Direct".into(),
        )],
        tools: Vec::new(),
    };
    let body = serde_json::to_string(&build_body(&cfg, &request)).unwrap();

    assert!(!body.contains("CREATE TABLE"), "the rule explainer leaked the schema");
    assert!(!body.contains("dst_host"), "the rule explainer leaked column names");
    assert!(!body.contains("tools"), "the rule explainer offered a query tool");
    assert!(body.contains("Targets: (any)"));
}

#[test]
fn a_model_that_proposes_a_write_gets_nowhere() {
    // The shapes a compromised or confused model would produce, checked at
    // the boundary the caller actually uses.
    for hostile in [
        "DROP TABLE events",
        "SELECT 1; DELETE FROM events",
        "WITH x AS (SELECT 1) INSERT INTO events SELECT * FROM x",
        "SET enable_external_access = true",
        "ATTACH 'http://evil.example/x.db' AS e",
    ] {
        assert!(sql_guard::check(hostile).is_err(), "`{hostile}` was allowed through");
    }
}

#[test]
fn an_accepted_query_is_bounded_before_it_runs() {
    let statement = sql_guard::check("SELECT process FROM events ORDER BY ts DESC").unwrap();
    let wrapped = sql_guard::wrap(&statement, 50);

    // The wrap is what makes the guard's completeness non-critical: even a
    // statement that slipped past the lexical pass has to parse in a
    // subquery position.
    assert!(wrapped.starts_with("SELECT * FROM ("));
    assert!(wrapped.ends_with("LIMIT 50"));
    assert!(wrapped.contains("ORDER BY ts DESC"));
}

#[test]
fn a_disabled_assistant_has_no_configuration_worth_worrying_about() {
    let fresh = LlmSettings::default();
    assert!(!fresh.enabled);
    assert_eq!(fresh.data_scope, DataScope::SchemaOnly);
    assert!(!fresh.reviewed_payload);
}
