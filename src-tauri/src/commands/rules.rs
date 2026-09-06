//! Rule matching / linting commands.
//!
//! These are all pure functions over in-memory state — the renderer uses them
//! to power the rule tester sandbox and the overshadow detector. No file I/O.

use ppx_core::{
    Candidate, ExposureGraph, Profile, Rule, ShadowPair, SimulationResult, compute_exposure,
    overshadow_pairs, simulate,
};

use crate::error::AppError;

#[tauri::command]
pub async fn rule_simulate_match(
    rules: Vec<Rule>,
    candidate: Candidate,
) -> Result<SimulationResult, AppError> {
    Ok(simulate(&rules, &candidate))
}

/// Returns a structured list of overshadow pairs with per-field reasoning
/// so the UI can explain which fields caused each conflict — e.g. "targets
/// are identical, ports are Any in earlier rule".
#[tauri::command]
pub async fn rule_overshadow_scan(rules: Vec<Rule>) -> Result<Vec<ShadowPair>, AppError> {
    Ok(overshadow_pairs(&rules))
}

/// Compute the Internet Exposure Surface graph for the current profile.
/// Pure + cheap → the renderer calls this on a debounced 400 ms timer
/// while the user edits rules.
#[tauri::command]
pub async fn profile_exposure(profile: Profile) -> Result<ExposureGraph, AppError> {
    Ok(compute_exposure(&profile))
}
