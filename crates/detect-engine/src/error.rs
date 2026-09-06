use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetectError {
    #[error("DuckDB error: {0}")]
    Duck(#[from] duckdb::Error),

    #[error("ingest layer error: {0}")]
    Ingest(#[from] log_ingest::IngestError),

    #[error("JSON encode error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error("rule `{rule_id}` failed: {message}")]
    RuleFailed { rule_id: String, message: String },

    #[error("{0}")]
    Custom(String),
}

pub type DetectResult<T> = Result<T, DetectError>;
