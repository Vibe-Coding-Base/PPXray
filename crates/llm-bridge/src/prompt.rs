//! The instructions that travel with every request.
//!
//! Two things are deliberately *not* hard-coded here. The database schema is
//! passed in, read from DuckDB at runtime, so it cannot drift from the
//! tables the query will actually run against. And the privacy paragraph is
//! generated from the live [`DataScope`], so what the model is told about
//! its own visibility is the same value that gates the data.

use serde_json::json;

use crate::config::DataScope;
use crate::provider::ToolSpec;

pub const SQL_TOOL: &str = "run_sql";
pub const MATCH_TOOL: &str = "test_rule_match";

/// The one tool the assistant gets.
///
/// Read-only by construction on the ppxray side; the description says so
/// mainly to stop the model wasting a turn proposing a write and being
/// refused.
pub fn sql_tool() -> ToolSpec {
    ToolSpec {
        name: SQL_TOOL,
        description: "Run one read-only DuckDB SELECT against the log database and \
                      return the rows. Only a single SELECT or WITH statement is \
                      accepted; anything that writes, attaches, installs or \
                      reconfigures is rejected before it reaches the database. \
                      Prefer aggregates over row dumps.",
        schema: json!({
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "A single DuckDB SELECT or WITH statement.",
                },
                "purpose": {
                    "type": "string",
                    "description": "One short line, shown to the user above the results, \
                                    saying what this query is meant to establish.",
                },
            },
            "required": ["sql", "purpose"],
            "additionalProperties": false,
        }),
    }
}

/// The deterministic rule tester, offered whenever a profile is open.
///
/// Evaluates a hypothetical connection against the open profile exactly as
/// Proxifier would, so the model can check "would ekrn.exe reaching
/// x.example be allowed, and by which rule?" instead of guessing from glob
/// syntax. No log data is involved.
pub fn match_tool() -> ToolSpec {
    ToolSpec {
        name: MATCH_TOOL,
        description: "Evaluate one hypothetical connection against the open Proxifier \
                      profile, top to bottom, and report which rule would win and \
                      why each earlier rule did or did not match. Use it to verify a \
                      claim about what the policy allows before making it. Leave a \
                      field empty to mean \"not constrained\".",
        schema: json!({
            "type": "object",
            "properties": {
                "application": {
                    "type": "string",
                    "description": "Process name or full path, e.g. `chrome.exe`. Empty = any.",
                },
                "host": {
                    "type": "string",
                    "description": "Destination hostname or IP. Empty = any.",
                },
                "port": {
                    "type": "integer",
                    "description": "Destination port. 0 or omitted = any.",
                },
                "purpose": {
                    "type": "string",
                    "description": "One short line, shown to the user, saying what this test \
                                    is meant to establish.",
                },
            },
            "required": ["purpose"],
            "additionalProperties": false,
        }),
    }
}

/// What the model is told about how much it can see.
fn visibility(scope: DataScope) -> &'static str {
    match scope {
        DataScope::SchemaOnly => {
            "PRIVACY LEVEL: schema-only (the default).\n\
             You can see table and column names and the user's questions. You \
             CANNOT see any values from the log. When you run a query, the rows \
             are displayed to the user on their own screen; you are told only \
             the row count and the column names. Work with that: explain what \
             the query establishes and what pattern the user should look for in \
             the output, and offer a refinement. Never invent example values or \
             pretend to have read the results. If a question genuinely cannot be \
             answered without seeing values, say so and mention that the privacy \
             level can be raised in Settings."
        }
        DataScope::Aggregates => {
            "PRIVACY LEVEL: aggregates.\n\
             Query results are shared with you, but hostnames are reduced to \
             their registrable domain (`rr5.sn-x.googlevideo.com` arrives as \
             `googlevideo.com`), process paths to a bare filename, and private \
             addresses to their RFC 1918 block. Reason about families and \
             patterns. If a conclusion would need an exact hostname or address, \
             say which one you would need and why, rather than guessing."
        }
        DataScope::Raw => {
            "PRIVACY LEVEL: raw.\n\
             The user has chosen to share unmasked event rows with you. Treat \
             them as sensitive: this is a record of every host their machine \
             contacted. Quote only what your conclusion needs."
        }
    }
}

const ROLE: &str = "\
You are the analysis assistant inside ppxray, a desktop tool that reads a \
Proxifier profile as an egress policy and a Proxifier log as per-process \
network telemetry.

The user may have a profile open, a log open, or both; what is open is stated \
below, and the tools you are given follow from it. A log is stored in a local \
DuckDB file, sandboxed so that no query can read files, install extensions or \
open a socket — which is why you are allowed to write SQL against it.

How to work:
* Answer with evidence. Run a query or a rule test rather than speculating.
* Prefer aggregates: counts, distinct hosts per process, time-bucketed rates. \
A row dump is rarely the answer.
* Proxifier logs what a process DID, never what it SHOULD be allowed to do. \
Do not describe traffic as approved, expected or benign because it is \
frequent; frequency is what beaconing looks like too.
* Say plainly when something is inconclusive. A confident wrong answer in a \
security tool is worse than no answer.
* Your output is advisory and is labelled unverified in the UI. The rule \
engine's alerts are the deterministic ones; do not present your conclusions \
as if they came from it.";

/// How Proxifier evaluates a profile. Shared by every prompt that sees rules,
/// so the explainer and the assistant cannot drift apart.
const RULE_SEMANTICS: &str = "\
Proxifier evaluates rules top to bottom and the first enabled match wins. A \
rule has Applications (process names or paths), Targets (a `;`-separated list \
of hosts, `*.wildcard` patterns, IPs and CIDRs), Ports, and an Action (Direct, \
Block, or a proxy / chain). An EMPTY field matches ANYTHING: a rule with \
Applications set and Targets empty lets that process reach every host, and a \
rule with Targets set and Applications empty lets every process reach those \
hosts. `*.example.com` and `example.com` are not the same set.";

/// The system prompt for the log assistant.
///
/// `policy` is the open profile rendered by `ppx_core::policy_text`, or
/// `None` when no profile is loaded. It is the user's own configuration, not
/// observed traffic, so it is included at every privacy level — the same
/// standing as the rule text `rule_explainer` receives.
pub fn log_assistant(
    scope: DataScope,
    schema: &str,
    context: &str,
    policy: Option<&str>,
) -> String {
    let mut s = String::with_capacity(ROLE.len() + schema.len() + 1024);
    s.push_str(ROLE);
    s.push_str("\n\n");
    s.push_str(visibility(scope));
    s.push_str("\n\nDATABASE SCHEMA\n");
    s.push_str(schema);
    if !context.trim().is_empty() {
        s.push_str("\n\nABOUT THE LOG CURRENTLY OPEN\n");
        s.push_str(context.trim());
    }
    match policy.map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => {
            s.push_str("\n\nTHE OPEN PROFILE (the egress policy the log was recorded under)\n");
            s.push_str(RULE_SEMANTICS);
            s.push_str(
                "\nThe `matched_rule` column in the log holds the Name of the rule that \
                 fired. Judge a rule by its definition below, not only by the traffic \
                 that matched it: traffic through a rule that names one process and no \
                 target tells you what that process did, not what the rule allows. \
                 Before claiming that the policy allows or blocks something, verify it \
                 with `test_rule_match`, which evaluates a connection exactly as \
                 Proxifier would.\n\n",
            );
            s.push_str(p);
        }
        None => s.push_str(
            "\n\nNo profile is open. You can see which rule name each event matched, but \
             not what any rule is defined to allow; say so if asked to judge the policy, \
             and ask the user to open the profile under Rules — it will then be given to \
             you here, together with a rule tester.",
        ),
    }
    s.push_str(
        "\n\nWHAT TO DO WHEN CONTEXT IS MISSING\n\
         You may use your tools as many times as it takes to be sure; a wrong answer is \
         worse than one more query. If a question about the policy needs evidence of \
         what actually happened and no log is open, answer what you can from the rules \
         and ask the user to open a log under Log (Proxifier keeps archives as \
         Log.txt.1, Log.txt.2 and so on, and several can be opened together). If a \
         question about the traffic needs the policy and no profile is open, ask them \
         to open it under Rules. Say which one you need and why.",
    );
    s
}

/// The system prompt for explaining a rule.
///
/// No log data is involved at any scope: a rule is the user's own
/// configuration, and explaining it needs nothing else. This prompt is the
/// reason the feature is usable at `schema-only` without compromise.
pub fn rule_explainer() -> String {
    format!(
        "You explain Proxifier rules and ppxray detection rules to a security \
         analyst.\n\n{RULE_SEMANTICS}\n\n\
         Given a rule, say: what traffic it matches, what it does with it, what it \
         lets through that the author may not have intended, and how an earlier \
         rule could shadow it.\n\n\
         You are given only the rule text. You have no visibility into what the \
         machine actually did, so do not claim any."
    )
}

/// The system prompt for a one-shot review of a log's aggregates.
pub fn anomaly_reviewer(scope: DataScope) -> String {
    format!(
        "You are reviewing a summary of one machine's outbound traffic, taken \
         from a Proxifier log, and looking for what does not belong.\n\n\
         {}\n\n\
         Report at most six findings, most suspicious first. For each: what you \
         saw, why it stands out, and the single check that would confirm or \
         dismiss it. Rank by how anomalous the pattern is, not by how alarming \
         the name sounds.\n\n\
         State explicitly when the summary is consistent with ordinary desktop \
         use. Returning \"nothing stands out\" is a valid and useful answer; \
         manufacturing six findings from a quiet log is not.",
        visibility(scope)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_schemas_are_strict_and_complete() {
        let t = sql_tool();
        assert_eq!(t.name, "run_sql");
        assert_eq!(t.schema["additionalProperties"], false);
        assert_eq!(t.schema["required"][0], "sql");
        assert_eq!(t.schema["required"][1], "purpose");

        let m = match_tool();
        assert_eq!(m.name, "test_rule_match");
        assert_eq!(m.schema["additionalProperties"], false);
        assert_eq!(m.schema["required"], json!(["purpose"]));
        for field in ["application", "host", "port"] {
            assert!(m.schema["properties"][field].is_object(), "{field}");
        }
    }

    #[test]
    fn the_assistant_is_told_how_to_ask_for_what_it_lacks() {
        let p = log_assistant(DataScope::SchemaOnly, "s", "", None);
        assert!(p.contains("WHAT TO DO WHEN CONTEXT IS MISSING"));
        assert!(p.contains("Log.txt.1"));
        assert!(p.contains("open it under Rules"));
        let with = log_assistant(DataScope::SchemaOnly, "s", "", Some("1. rule"));
        assert!(with.contains("verify it with `test_rule_match`"));
    }

    #[test]
    fn each_scope_states_its_own_limits() {
        let schema_only = log_assistant(DataScope::SchemaOnly, "events(...)", "", None);
        assert!(schema_only.contains("CANNOT see any values"));
        assert!(schema_only.contains("Never invent example values"));

        let aggregates = log_assistant(DataScope::Aggregates, "events(...)", "", None);
        assert!(aggregates.contains("registrable domain"));
        assert!(!aggregates.contains("CANNOT see any values"));

        let raw = log_assistant(DataScope::Raw, "events(...)", "", None);
        assert!(raw.contains("unmasked"));
    }

    #[test]
    fn the_schema_is_injected_not_hard_coded() {
        // Drift between this prompt and the real tables would have the model
        // writing queries against columns that do not exist, so the schema
        // has to arrive from the database itself.
        let p = log_assistant(DataScope::SchemaOnly, "CREATE TABLE zzz(a INT)", "", None);
        assert!(p.contains("CREATE TABLE zzz(a INT)"));
    }

    #[test]
    fn optional_context_is_omitted_when_absent() {
        assert!(!log_assistant(DataScope::SchemaOnly, "s", "   ", None).contains("ABOUT THE LOG"));
        assert!(log_assistant(DataScope::SchemaOnly, "s", "3M events", None).contains("3M events"));
    }

    #[test]
    fn the_policy_travels_with_its_semantics_or_its_absence_is_stated() {
        // A rule that names a process and nothing else was being read as a
        // domain allowlist from the traffic that matched it. The definition
        // and the "empty means any" rule have to arrive together.
        let with = log_assistant(
            DataScope::SchemaOnly,
            "s",
            "",
            Some("1. \"Allow AV\" -> Direct; apps: ekrn.exe; targets: any; ports: any"),
        );
        assert!(with.contains("THE OPEN PROFILE"));
        assert!(with.contains("apps: ekrn.exe; targets: any"));
        assert!(with.contains("EMPTY field matches ANYTHING"));
        assert!(with.contains("`matched_rule` column"));

        let without = log_assistant(DataScope::SchemaOnly, "s", "", None);
        assert!(without.contains("No profile is open"));
        assert!(!without.contains("THE OPEN PROFILE"));

        // Blank is the same as absent; it must not announce an empty policy.
        let blank = log_assistant(DataScope::SchemaOnly, "s", "", Some("  "));
        assert!(blank.contains("No profile is open"));
    }

    #[test]
    fn the_rule_explainer_claims_no_log_visibility() {
        let p = rule_explainer();
        assert!(p.contains("no visibility into what the machine actually did"));
    }

    #[test]
    fn the_reviewer_is_allowed_to_find_nothing() {
        let p = anomaly_reviewer(DataScope::Aggregates);
        assert!(p.contains("nothing stands out"));
    }
}
