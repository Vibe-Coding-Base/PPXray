use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DuckDB error: {0}")]
    Duck(#[from] duckdb::Error),

    #[error("invalid timestamp `{0}`")]
    BadTimestamp(String),

    #[error("{0}")]
    Custom(String),
}

pub type IngestResult<T> = Result<T, IngestError>;
