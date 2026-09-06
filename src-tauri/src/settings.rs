//! Minimal persistent settings stored as a JSON file in the Tauri app-data
//! directory. Read/written on demand; we don't bother with an in-memory
//! cache since calls are infrequent and the file is tiny.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::error::AppError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    /// Directory where user-authored YAML detection rules live.
    /// `None` = use the default path under app-data (`<appdata>/rules`).
    #[serde(default)]
    pub rule_dir: Option<String>,

    /// Assistant configuration. `#[serde(default)]` matters here beyond the
    /// usual convenience: it is what makes an existing install upgrade into
    /// a *disabled* assistant rather than failing to parse its own settings
    /// file. See `llm_bridge::config::LlmSettings::default`.
    ///
    /// The API key is deliberately absent — it lives in the OS credential
    /// store (`crate::credentials`), because this file is plain text.
    #[serde(default)]
    pub llm: llm_bridge::LlmSettings,
}

pub fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    let dir =
        app.path().app_data_dir().map_err(|e| AppError::Other(format!("app_data_dir: {e}")))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("settings.json"))
}

pub fn default_rule_dir(app: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    let root =
        app.path().app_data_dir().map_err(|e| AppError::Other(format!("app_data_dir: {e}")))?;
    Ok(root.join("rules"))
}

pub fn load(app: &tauri::AppHandle) -> Result<Settings, AppError> {
    let path = settings_path(app)?;
    if !path.exists() {
        return Ok(Settings::default());
    }
    let text = std::fs::read_to_string(&path)?;
    let s: Settings = serde_json::from_str(&text)
        .map_err(|e| AppError::Other(format!("settings.json parse: {e}")))?;
    Ok(s)
}

pub fn save(app: &tauri::AppHandle, s: &Settings) -> Result<(), AppError> {
    let path = settings_path(app)?;
    let text = serde_json::to_string_pretty(s)
        .map_err(|e| AppError::Other(format!("settings serialize: {e}")))?;
    crate::atomic::write(&path, text.as_bytes(), crate::atomic::Backup::Skip)
}

/// Resolve the effective rule directory: user override if present, else default.
pub fn effective_rule_dir(app: &tauri::AppHandle) -> Result<PathBuf, AppError> {
    let s = load(app)?;
    if let Some(path) = s.rule_dir {
        return Ok(PathBuf::from(path));
    }
    default_rule_dir(app)
}
