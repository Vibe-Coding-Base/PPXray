//! Proxifier log ingest pipeline: parse + enrich + bulk load into DuckDB.
//!
//! Lifecycle:
//! 1. `ingest::ingest_file(path, callback)` streams a `.txt` log, parses each
//!    line into an [`Event`], and bulk-loads into a DuckDB file keyed by the
//!    log path. Progress is reported via the callback.
//! 2. [`query`] exposes filter / aggregation helpers on the resulting DB.
//!
//! The parser is designed for throughput — no regex allocation per line, byte
//! scanning where possible. Target: 50 MB/s on a single core.

pub mod adhoc;
pub mod error;
pub mod ingest;
pub mod model;
pub mod parser;
pub mod query;
pub mod schema;
pub mod store;
pub mod suggest;

pub use adhoc::{AdhocResult, schema_description};
pub use error::{IngestError, IngestResult};
pub use ingest::{IngestProgress, IngestStats, ingest_file};
pub use model::{Action, ConnectionEvent, DnsEvent, Event, Proto};
pub use parser::parse_line;
pub use query::{
    DashboardLimits, EventFilter, EventRow, LogDashboard, LogStats, ProcessCount, RuleCount,
    TimeBucket, count_events, dashboard, query_events,
};
pub use store::{LogStore, open_store, store_path_for};
pub use suggest::{
    HostSuggestion, SuggestOptions, SuggestionKind, TargetSuggestions, suggest_targets,
    to_targets_line,
};
