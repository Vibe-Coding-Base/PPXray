//! Unified error type exposed to the renderer. Every Tauri command returns
//! `Result<T, AppError>`; on serialize, `AppError` flattens to a human-readable
//! string so the JS side can surface it without introspecting variants.

use serde::{Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("profile parse error: {0}")]
    Parse(#[from] ppx_core::PpxError),

    #[error("path is not valid UTF-8")]
    BadPath,

    #[error("{0}")]
    Other(String),
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}
