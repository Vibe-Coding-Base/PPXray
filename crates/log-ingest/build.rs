// DuckDB's bundled C++ source links against Windows' Restart Manager API
// (Rm{Start,End}Session etc.) via `libduckdb-sys`. Integration-test binaries
// under `tests/` don't inherit the linkage that the staticlib build of
// `src-tauri` does, so we restate it explicitly here — same as
// `crates/detect-engine/build.rs`.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=rstrtmgr");
    }
}
