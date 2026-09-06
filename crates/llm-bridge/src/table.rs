//! Query results, and the decision about which of them the model gets to see.
//!
//! This is where the scope setting stops being a label and starts costing
//! something. The assistant asks for a query; ppxray runs it locally and has
//! rows in hand. Handing those rows back is the moment traffic data would
//! leave the machine, and it is gated here rather than at the call site so
//! there is exactly one place to audit.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::config::DataScope;
use crate::redact::{mask_destination, mask_process};

/// A result set from a locally-executed query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct QueryTable {
    pub columns: Vec<String>,
    /// One entry per column, in `columns` order. Cells keep whatever JSON
    /// type DuckDB produced — a count stays a number so the UI can align it
    /// right without re-parsing.
    #[ts(type = "unknown[][]")]
    pub rows: Vec<Vec<Value>>,
    /// True when the row limit cut the result short, so the UI can say so
    /// instead of implying the query found exactly this many rows.
    pub truncated: bool,
}

impl QueryTable {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Columns whose values identify a person or a machine rather than describe
/// a behaviour.
///
/// Matched on the column *name* because the model writes the query, so the
/// projection is not known ahead of time. A model that aliases `dst_host AS
/// h` defeats this — which is why masking is a second line of defence and
/// [`DataScope::SchemaOnly`], where no rows travel at all, is the default.
type Masker = fn(&str, DataScope) -> String;

fn masker(column: &str) -> Option<Masker> {
    let c = column.to_ascii_lowercase();
    if c.contains("host") || c.contains("qname") || c.contains("domain") || c.contains("target") {
        return Some(mask_destination);
    }
    if c.contains("ip") || c.contains("server") || c.contains("address") || c.contains("answer") {
        return Some(mask_destination);
    }
    if c.contains("process") || c.contains("parent") || c.contains("app") || c.contains("exe") {
        return Some(mask_process);
    }
    None
}

/// Apply `scope` to a result set, returning what the model may be shown.
pub fn for_model(table: &QueryTable, scope: DataScope) -> QueryTable {
    if scope.allows_raw_rows() {
        return table.clone();
    }
    let maskers: Vec<Option<Masker>> = table.columns.iter().map(|c| masker(c)).collect();

    let rows = table
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(i, cell)| match (maskers.get(i).copied().flatten(), cell.as_str()) {
                    (Some(f), Some(s)) => Value::String(f(s, scope)),
                    _ => cell.clone(),
                })
                .collect()
        })
        .collect();

    QueryTable { columns: table.columns.clone(), rows, truncated: table.truncated }
}

/// What is sent back to the model as the tool result.
///
/// At [`DataScope::SchemaOnly`] this is a description of the result, not the
/// result: the rows go to the user's screen and stop there. The assistant
/// can still refine the query, because it knows the shape and the row count
/// — it just cannot read the values.
pub fn tool_result(table: &QueryTable, scope: DataScope) -> String {
    if !scope.allows_values() {
        return format!(
            "Query ran successfully. {} row(s){} across columns [{}]. \
             The results are displayed to the user; at the current privacy \
             level (schema-only) their values are not shared with you. \
             Summarise what the query does and what the user should look for \
             in it, or propose a refinement — do not guess at the values.",
            table.rows.len(),
            if table.truncated { " (truncated by the row limit)" } else { "" },
            table.columns.join(", "),
        );
    }

    let shown = for_model(table, scope);
    let payload = serde_json::json!({
        "columns": shown.columns,
        "rows": shown.rows,
        "truncated": shown.truncated,
        "masked": !scope.allows_raw_rows(),
    });
    let mut text = serde_json::to_string(&payload).unwrap_or_else(|e| format!("<{e}>"));
    if !scope.allows_raw_rows() {
        text.push_str(
            "\n\nHostnames are reduced to their registrable domain and process paths to a \
             filename before being shared with you. Treat them as families, not as exact \
             values, and say so if a conclusion would need the exact value.",
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table() -> QueryTable {
        QueryTable {
            columns: vec!["process".into(), "dst_host".into(), "dst_ip".into(), "n".into()],
            rows: vec![
                vec![
                    json!(r"C:\Users\alice\AppData\Local\app.exe"),
                    json!("rr5.sn-abcd1234.googlevideo.com"),
                    json!("10.0.0.5"),
                    json!(42),
                ],
                vec![json!("chrome.exe"), json!("api.github.com"), json!("140.82.121.5"), json!(7)],
            ],
            truncated: false,
        }
    }

    #[test]
    fn schema_only_shares_no_values_at_all() {
        let out = tool_result(&table(), DataScope::SchemaOnly);
        assert!(out.contains("2 row(s)"));
        assert!(out.contains("process, dst_host, dst_ip, n"));
        // Not one cell value may appear.
        assert!(!out.contains("googlevideo"));
        assert!(!out.contains("chrome.exe"));
        assert!(!out.contains("alice"));
        assert!(!out.contains("140.82"));
    }

    #[test]
    fn aggregates_share_values_but_not_identifying_ones() {
        let out = tool_result(&table(), DataScope::Aggregates);
        assert!(out.contains("googlevideo.com"));
        assert!(!out.contains("sn-abcd1234"));
        assert!(out.contains("app.exe"));
        assert!(!out.contains("alice"));
        assert!(out.contains("10.0.0.0/8"));
        // A public address is the finding, so it survives.
        assert!(out.contains("140.82.121.5"));
        // Counts are the point of an aggregate and are never touched.
        assert!(out.contains("42"));
    }

    #[test]
    fn raw_shares_everything_unchanged() {
        let out = tool_result(&table(), DataScope::Raw);
        assert!(out.contains("sn-abcd1234.googlevideo.com"));
        assert!(out.contains("alice"));
        assert!(!out.contains("registrable domain"));
    }

    #[test]
    fn masking_is_by_column_and_leaves_other_types_alone() {
        let masked = for_model(&table(), DataScope::Aggregates);
        assert_eq!(masked.columns, table().columns);
        // Numeric cells stay numbers, not stringified.
        assert_eq!(masked.rows[0][3], json!(42));
    }

    #[test]
    fn aliased_columns_still_match_when_the_name_carries_the_meaning() {
        let t = QueryTable {
            columns: vec!["top_host".into(), "parent_process".into()],
            rows: vec![vec![json!("a.b.example.com"), json!(r"C:\Windows\svchost.exe")]],
            truncated: false,
        };
        let masked = for_model(&t, DataScope::Aggregates);
        assert_eq!(masked.rows[0][0], json!("example.com"));
        assert_eq!(masked.rows[0][1], json!("svchost.exe"));
    }

    #[test]
    fn truncation_is_reported_rather_than_hidden() {
        let t = QueryTable { truncated: true, ..table() };
        assert!(tool_result(&t, DataScope::SchemaOnly).contains("truncated"));
        assert!(tool_result(&t, DataScope::Aggregates).contains("\"truncated\":true"));
    }

    #[test]
    fn an_empty_result_is_still_a_usable_answer() {
        let t = QueryTable { columns: vec!["n".into()], rows: vec![], truncated: false };
        assert!(t.is_empty());
        assert!(tool_result(&t, DataScope::SchemaOnly).contains("0 row(s)"));
    }
}
