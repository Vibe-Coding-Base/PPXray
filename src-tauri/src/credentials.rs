//! API keys, in the OS credential store rather than in `settings.json`.
//!
//! `settings.json` is plain text under app-data. Anything running as the
//! user can read it, it lands in backups, and it shows up in a screen
//! recording of a settings page. The platform stores are not a vault, but
//! they are keyed to the account, encrypted at rest, and not sitting in a
//! file the user will one day paste into a bug report.
//!
//! A key is never returned to the renderer. It is read here, handed to the
//! HTTP client, and dropped; the UI is told only whether one exists.

use llm_bridge::ProviderKind;

use crate::error::AppError;

/// Service name in the platform store. Stable — changing it would orphan
/// every key users have already saved.
const SERVICE: &str = "ppxray";

fn entry(provider: ProviderKind) -> Result<keyring::Entry, AppError> {
    keyring::Entry::new(SERVICE, provider.credential_account())
        .map_err(|e| AppError::Other(format!("credential store unavailable: {e}")))
}

/// The stored key, or `None` when there is none.
///
/// A missing entry is not an error: local runtimes need no credential, so
/// "nothing stored" is a normal state rather than a misconfiguration.
pub fn get(provider: ProviderKind) -> Result<Option<String>, AppError> {
    match entry(provider)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AppError::Other(format!("read credential: {e}"))),
    }
}

pub fn set(provider: ProviderKind, key: &str) -> Result<(), AppError> {
    let key = key.trim();
    if key.is_empty() {
        // Saving an empty string would leave an entry that reads back as a
        // key and produces `Authorization: Bearer ` on every request.
        return delete(provider);
    }
    entry(provider)?
        .set_password(key)
        .map_err(|e| AppError::Other(format!("store credential: {e}")))
}

pub fn delete(provider: ProviderKind) -> Result<(), AppError> {
    match entry(provider)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Other(format!("delete credential: {e}"))),
    }
}

/// Whether a key exists, without moving it anywhere.
pub fn has(provider: ProviderKind) -> bool {
    matches!(get(provider), Ok(Some(_)))
}
