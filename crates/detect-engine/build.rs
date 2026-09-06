// DuckDB's bundled C++ source links against Windows' Restart Manager API
// (Rm{Start,End}Session etc.) via `libduckdb-sys`. The `cargo test` binary
// for this crate doesn't inherit the linkage that the staticlib build of
// `src-tauri` does, so we restate it explicitly here.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=rstrtmgr");
    }
}
