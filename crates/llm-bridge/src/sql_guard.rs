//! Deciding whether a model-written query is allowed to run.
//!
//! Three layers stand between the model's text and the database, and they
//! fail in different ways on purpose:
//!
//! 1. **Structural** — the caller wraps the text in `SELECT * FROM ( … )
//!    LIMIT n`, where only a query expression parses. `DROP TABLE events`
//!    there is a syntax error. This layer does not depend on this file.
//! 2. **Lexical** — [`check`] rejects multiple statements and any
//!    statement-level keyword, so a rejection reads as a clear "no" rather
//!    than a DuckDB parse error.
//! 3. **Sandbox** — `log_ingest::store::harden` leaves external access,
//!    extensions and configuration changes off, so even a successful
//!    `SELECT` cannot read a file or open a socket.

use std::fmt;

/// Statement-level keywords. Anything that writes, attaches, installs,
/// exports or reconfigures. A read-only question needs none of them.
const FORBIDDEN: &[&str] = &[
    "alter",
    "attach",
    "begin",
    "call",
    "checkpoint",
    "commit",
    "copy",
    "create",
    "delete",
    "detach",
    "drop",
    "export",
    "force",
    "grant",
    "import",
    "insert",
    "install",
    "load",
    "pragma",
    "reset",
    "revoke",
    "rollback",
    "set",
    "truncate",
    "update",
    "use",
    "vacuum",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlRejection {
    Empty,
    /// More than one statement was supplied.
    MultipleStatements,
    /// The statement does not start with `SELECT` or `WITH`.
    NotAQuery,
    /// A statement-level keyword appeared outside a string literal.
    ForbiddenKeyword(String),
    /// A quote or comment was never closed, so the lexical pass cannot
    /// vouch for what follows it.
    Unterminated,
}

impl fmt::Display for SqlRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "the assistant returned an empty query"),
            Self::MultipleStatements => {
                write!(f, "only a single statement may be run; this one contains several")
            }
            Self::NotAQuery => write!(f, "only SELECT / WITH queries may be run"),
            Self::ForbiddenKeyword(k) => {
                write!(f, "`{}` modifies state and is not allowed here", k.to_uppercase())
            }
            Self::Unterminated => write!(f, "the query has an unterminated string or comment"),
        }
    }
}

impl std::error::Error for SqlRejection {}

/// Replace every string literal, quoted identifier and comment with spaces,
/// so keyword and separator scanning sees only code.
///
/// Keeping the length identical is not required, but it keeps offsets usable
/// if this ever needs to report a position.
fn blank_literals(sql: &str) -> Result<String, SqlRejection> {
    let bytes: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            '-' if bytes.get(i + 1) == Some(&'-') => {
                while i < bytes.len() && bytes[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            '/' if bytes.get(i + 1) == Some(&'*') => {
                let mut closed = false;
                out.push_str("  ");
                i += 2;
                while i < bytes.len() {
                    if bytes[i] == '*' && bytes.get(i + 1) == Some(&'/') {
                        out.push_str("  ");
                        i += 2;
                        closed = true;
                        break;
                    }
                    out.push(if bytes[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                if !closed {
                    return Err(SqlRejection::Unterminated);
                }
            }
            '\'' | '"' => {
                let quote = c;
                out.push(' ');
                i += 1;
                let mut closed = false;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        // Doubled quote is an escape, not a terminator.
                        if bytes.get(i + 1) == Some(&quote) {
                            out.push_str("  ");
                            i += 2;
                            continue;
                        }
                        out.push(' ');
                        i += 1;
                        closed = true;
                        break;
                    }
                    out.push(if bytes[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                if !closed {
                    return Err(SqlRejection::Unterminated);
                }
            }
            // DuckDB accepts `$$ … $$` dollar quoting, which would otherwise
            // hide an entire statement from the scan below.
            '$' if bytes.get(i + 1) == Some(&'$') => {
                out.push_str("  ");
                i += 2;
                let mut closed = false;
                while i < bytes.len() {
                    if bytes[i] == '$' && bytes.get(i + 1) == Some(&'$') {
                        out.push_str("  ");
                        i += 2;
                        closed = true;
                        break;
                    }
                    out.push(if bytes[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                if !closed {
                    return Err(SqlRejection::Unterminated);
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Accept `sql` only if it is a single read-only query.
///
/// Returns the trimmed statement with any trailing semicolon removed, ready
/// to be wrapped by the caller.
pub fn check(sql: &str) -> Result<String, SqlRejection> {
    // Both views of the same text, indexed by character so they stay aligned:
    // `blanked` has literals and comments replaced by spaces, `original` is
    // what actually runs.
    let blanked: Vec<char> = blank_literals(sql)?.chars().collect();
    let original: Vec<char> = sql.chars().collect();
    debug_assert_eq!(blanked.len(), original.len());

    // Where the statement ends, measured on the *original*.
    //
    // Measuring it on the blanked copy was a real bug: a statement ending in
    // a string literal - `WHERE matched_rule = ''` - has that literal blanked
    // to spaces, so trimming trailing whitespace ate the literal and handed
    // DuckDB `WHERE matched_rule =`. The parse error that produced then
    // poisoned the connection for the rest of the session.
    let mut end = original.len();
    let trim = |chars: &[char], mut n: usize| {
        while n > 0 && chars[n - 1].is_whitespace() {
            n -= 1;
        }
        n
    };
    end = trim(&original, end);

    // One trailing semicolon is allowed and dropped. Read from `blanked` so a
    // `;` inside a literal is not mistaken for a terminator.
    if end > 0 && blanked[end - 1] == ';' {
        end = trim(&original, end - 1);
    }

    if blanked[..end].contains(&';') {
        return Err(SqlRejection::MultipleStatements);
    }

    let statement: String = original[..end].iter().collect::<String>().trim().to_string();
    if statement.is_empty() {
        return Err(SqlRejection::Empty);
    }

    let mut words = blanked[..end]
        .iter()
        .collect::<String>()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .into_iter();

    match words.next().as_deref() {
        Some("select") | Some("with") => {}
        _ => return Err(SqlRejection::NotAQuery),
    }
    for word in words {
        if FORBIDDEN.contains(&word.as_str()) {
            return Err(SqlRejection::ForbiddenKeyword(word));
        }
    }

    Ok(statement)
}

/// Wrap a checked query so it can only ever produce rows, and never more
/// than `limit` of them.
pub fn wrap(statement: &str, limit: u32) -> String {
    format!("SELECT * FROM (\n{statement}\n) AS ppxray_llm_query LIMIT {limit}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_queries_pass() {
        assert!(check("SELECT process, count(*) FROM events GROUP BY 1").is_ok());
        assert!(check("with t as (select 1) select * from t").is_ok());
        assert!(check("  SELECT 1;  ").is_ok());
    }

    #[test]
    fn a_statement_ending_in_a_string_literal_survives_intact() {
        // Reported from a real session: the guard returned
        // `WHERE matched_rule =` with the literal cut off, DuckDB refused to
        // parse it, and the failed parse then poisoned the connection for
        // every query that followed.
        let sql = "SELECT COUNT(*) FROM events WHERE matched_rule IS NULL OR matched_rule = ''";
        assert_eq!(check(sql).unwrap(), sql);

        assert_eq!(check("SELECT 1 WHERE 'a' = 'a'").unwrap(), "SELECT 1 WHERE 'a' = 'a'");
        assert_eq!(check("SELECT 'x';").unwrap(), "SELECT 'x'");
        // Same for a trailing comment, which is blanked the same way.
        assert_eq!(check("SELECT 1 -- why").unwrap(), "SELECT 1 -- why",);
    }

    #[test]
    fn trailing_semicolon_is_stripped() {
        assert_eq!(check("SELECT 1;").unwrap(), "SELECT 1");
        assert_eq!(check("SELECT 1 ;\n").unwrap(), "SELECT 1");
    }

    #[test]
    fn a_second_statement_is_refused() {
        assert_eq!(
            check("SELECT 1; DROP TABLE events").unwrap_err(),
            SqlRejection::MultipleStatements
        );
    }

    #[test]
    fn writes_are_refused_even_alone() {
        assert_eq!(check("DROP TABLE events").unwrap_err(), SqlRejection::NotAQuery);
        assert_eq!(check("DELETE FROM events").unwrap_err(), SqlRejection::NotAQuery);
        assert_eq!(check("ATTACH 'x.db'").unwrap_err(), SqlRejection::NotAQuery);
    }

    #[test]
    fn writes_hidden_inside_a_query_are_refused() {
        // The shapes that would slip past a "starts with SELECT" check.
        assert_eq!(
            check("SELECT * FROM events; INSERT INTO events VALUES (1)").unwrap_err(),
            SqlRejection::MultipleStatements
        );
        assert_eq!(
            check("WITH x AS (SELECT 1) INSERT INTO events SELECT * FROM x").unwrap_err(),
            SqlRejection::ForbiddenKeyword("insert".into())
        );
        assert_eq!(
            check("SELECT 1 FROM (COPY events TO 'x.csv')").unwrap_err(),
            SqlRejection::ForbiddenKeyword("copy".into())
        );
        assert_eq!(
            check("SELECT 1 UNION SELECT 1; SET enable_external_access=true").unwrap_err(),
            SqlRejection::MultipleStatements
        );
    }

    #[test]
    fn file_reading_functions_are_the_sandbox_layer_not_this_one() {
        // `read_csv` is a table function, so it is a legal SELECT and this
        // guard passes it. It fails at execution because
        // `log_ingest::store::harden` sets enable_external_access = false
        // with the configuration locked, which is where that class of escape
        // is answered. Asserting it here records the division of labour: a
        // future reader must not delete the sandbox on the theory that this
        // file covers it.
        assert!(check("SELECT * FROM read_csv('/etc/passwd')").is_ok());
        // And the statement that would undo the sandbox is still refused,
        // whether it stands alone or trails a query.
        assert_eq!(check("SET enable_external_access=true").unwrap_err(), SqlRejection::NotAQuery);
    }

    #[test]
    fn keywords_inside_literals_are_not_keywords() {
        // A perfectly reasonable question about a process named after a
        // forbidden word must still run.
        assert!(check("SELECT * FROM events WHERE process = 'update.exe'").is_ok());
        assert!(check(r#"SELECT "drop" FROM events"#).is_ok());
        assert!(check("SELECT * FROM events -- drop table events\n").is_ok());
        assert!(check("SELECT * FROM events /* insert */ LIMIT 1").is_ok());
    }

    #[test]
    fn semicolons_inside_literals_are_not_separators() {
        assert!(check("SELECT * FROM events WHERE dst_host = 'a;b'").is_ok());
    }

    #[test]
    fn substrings_of_keywords_are_left_alone() {
        // OFFSET contains SET; RESET_ME contains RESET; a naive
        // `contains()` check would reject all of these.
        assert!(check("SELECT 1 LIMIT 10 OFFSET 5").is_ok());
        assert!(check("SELECT reset_me FROM events").is_ok());
        assert!(check("SELECT updated_at FROM events").is_ok());
    }

    #[test]
    fn dollar_quoting_cannot_hide_a_statement() {
        // Unterminated: the scan cannot see past it, so it is refused.
        assert_eq!(check("SELECT $$ ; DROP TABLE events").unwrap_err(), SqlRejection::Unterminated);
        // Terminated: the contents are literal text and stay harmless.
        assert!(check("SELECT $$ ; DROP TABLE events $$ AS note").is_ok());
    }

    #[test]
    fn unterminated_quotes_and_comments_are_refused() {
        assert_eq!(check("SELECT 'abc").unwrap_err(), SqlRejection::Unterminated);
        assert_eq!(check("SELECT 1 /* abc").unwrap_err(), SqlRejection::Unterminated);
    }

    #[test]
    fn empty_input_is_refused() {
        assert_eq!(check("   ").unwrap_err(), SqlRejection::Empty);
        assert_eq!(check(";").unwrap_err(), SqlRejection::Empty);
    }

    #[test]
    fn non_ascii_does_not_split_a_character() {
        // The blanking pass counts characters; slicing the original by that
        // count without converting would panic on any multi-byte input.
        assert!(check("SELECT * FROM events WHERE process = 'tệp.exe';").is_ok());
    }

    #[test]
    fn wrapping_bounds_the_result() {
        let wrapped = wrap("SELECT 1", 50);
        assert!(wrapped.starts_with("SELECT * FROM ("));
        assert!(wrapped.ends_with("LIMIT 50"));
    }
}
