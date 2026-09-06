//! Profile I/O commands.
//!
//! All file writes are **atomic** (temp file + rename) and preceded by a `.bak`
//! backup of the existing file if present. This is the mitigation for the
//! data-loss bug that plagued the previous (Electron + xml2js) implementation.

use std::{fs, path::Path, time::SystemTime};

use ppx_core::{Profile, parse_str, to_xml_string};
use serde::Serialize;
use tauri::State;
use tracing::{info, instrument};

use crate::{atomic, error::AppError, state::AppState};

#[derive(Debug, Serialize)]
pub struct OpenProfileResult {
    pub profile: Profile,
    pub path: String,
    /// RFC 3339 timestamp of the file's `mtime` at read time.
    pub modified_at: String,
}

#[tauri::command]
#[instrument(skip(state))]
pub async fn profile_open_from_path(
    path: String,
    state: State<'_, AppState>,
) -> Result<OpenProfileResult, AppError> {
    let xml = fs::read_to_string(&path)?;
    let profile = parse_str(&xml)?;
    let modified_at = file_mtime(&path)?;

    *state
        .current_profile_path
        .lock()
        .map_err(|e| AppError::Other(format!("state lock poisoned: {e}")))? = Some(path.clone());

    info!(rules = profile.rules.len(), proxies = profile.proxies.len(), "profile opened");
    Ok(OpenProfileResult { profile, path, modified_at })
}

#[tauri::command]
#[instrument(skip(profile, state), fields(path = %path))]
pub async fn profile_save_to_path(
    path: String,
    profile: Profile,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    let xml = to_xml_string(&profile)?;
    atomic::write(Path::new(&path), xml.as_bytes(), atomic::Backup::Keep)?;

    *state
        .current_profile_path
        .lock()
        .map_err(|e| AppError::Other(format!("state lock poisoned: {e}")))? = Some(path.clone());

    info!("profile saved");
    Ok(())
}

/// Parse an XML string in memory. Useful for drag-drop / preview flows that
/// don't yet commit a file path.
#[tauri::command]
pub async fn profile_parse_xml(xml: String) -> Result<Profile, AppError> {
    Ok(parse_str(&xml)?)
}

/// Serialize a `Profile` to XML without touching the filesystem.
#[tauri::command]
pub async fn profile_serialize_to_xml(profile: Profile) -> Result<String, AppError> {
    Ok(to_xml_string(&profile)?)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn file_mtime(path: &str) -> Result<String, AppError> {
    let meta = fs::metadata(path)?;
    let mt: SystemTime = meta.modified()?;
    let duration = mt.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs() as i64;
    let nanos = duration.subsec_nanos();
    Ok(format_rfc3339(secs, nanos))
}

/// Minimal RFC 3339 formatter (UTC). Avoids pulling in a full date-time crate
/// for what is essentially a display string.
fn format_rfc3339(secs: i64, nanos: u32) -> String {
    // Days since 1970-01-01.
    let mut days = secs.div_euclid(86_400);
    let mut secs_of_day = secs.rem_euclid(86_400);

    let hour = secs_of_day / 3600;
    secs_of_day %= 3600;
    let minute = secs_of_day / 60;
    let second = secs_of_day % 60;

    // Civil date from days (Howard Hinnant's algorithm).
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z",
        y = y,
        m = m,
        d = d,
        hour = hour,
        minute = minute,
        second = second,
        nanos = nanos
    )
}
