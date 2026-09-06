//! Thin wrapper around the DuckDB handle for a specific log DB file.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use duckdb::Connection;

use crate::error::IngestResult;
use crate::schema;

/// A log-analysis DB. Internally wraps a single-writer DuckDB connection
/// behind a mutex. DuckDB 1.x supports concurrent readers, but we serialize
/// all writes through this handle to keep bulk-load and query code simple.
#[derive(Clone)]
pub struct LogStore {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl LogStore {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> IngestResult<R>) -> IngestResult<R> {
        // Recover from a poisoned mutex automatically: a panic inside a
        // previous `with_conn*` closure poisons the lock even though the
        // underlying DuckDB connection is perfectly usable. Treating the
        // poison as fatal would cascade a single broken rule into every
        // subsequent rule returning "store lock poisoned". We discard the
        // poison and proceed; the original panic was already reported by
        // whatever layer caught it (see detect_engine::eval).
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        f(&guard)
    }

    /// Run `f` on a short-lived connection, for SQL this crate did not write:
    /// detection rules and assistant queries.
    ///
    /// DuckDB leaves a connection unusable after certain parse failures —
    /// every later query returns "resource deadlock would occur" — so one bad
    /// statement must not take down the handle the rest of the app uses.
    ///
    /// The clone inherits the sandbox: `lock_configuration` is
    /// database-scoped, not session-scoped, so a sibling connection cannot
    /// re-enable external access. `tests/sandbox.rs` pins that.
    ///
    /// The main handle's mutex is held throughout, so scratch queries stay
    /// serialised against ingest.
    pub fn with_scratch_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> IngestResult<R>,
    ) -> IngestResult<R> {
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        let scratch = guard.try_clone()?;
        let result = f(&scratch);

        // Dropping a connection that hit a parse error aborts the process:
        // its C++ destructor throws and Rust cannot catch foreign exceptions.
        // Leak the few kilobytes instead. Only on failure — the success path
        // drops normally.
        if result.is_err() {
            std::mem::forget(scratch);
        }
        result
    }

    /// Executes a closure with a mutable connection — required by
    /// `Connection::appender` which takes `&mut self` on some API versions.
    pub fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> IngestResult<R>,
    ) -> IngestResult<R> {
        let mut guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        f(&mut guard)
    }
}

/// Open (or create) a `LogStore` at `path`. Applies pending migrations.
pub fn open_store(path: &Path) -> IngestResult<LogStore> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    harden(&conn)?;
    schema::init(&conn)?;
    Ok(LogStore { conn: Arc::new(Mutex::new(conn)), path: path.to_path_buf() })
}

/// Revoke DuckDB's access to anything outside this database file.
///
/// Detection rules are SQL and rule packs are meant to be shared, so
/// importing someone's `.yml` runs their SQL. Unsandboxed that grants
/// arbitrary file read (`read_text`), file write (`COPY … TO`) and network
/// egress (`INSTALL httpfs`). Assistant-written SQL is trusted no further and
/// lands in the same sandbox.
///
/// Nothing here needs SQL-level external access — ingest writes through the
/// Rust appender and every query reads tables in this file — so it is revoked
/// wholesale rather than filtered.
///
/// `lock_configuration` goes last; without it a rule's first statement is
/// `SET enable_external_access=true`.
///
/// `disabled_filesystems = 'LocalFileSystem'` is deliberately *not* set: it
/// also revokes access to the database file we just opened.
/// `tests/sandbox.rs` holds both halves.
fn harden(conn: &Connection) -> IngestResult<()> {
    conn.execute_batch(
        "SET autoinstall_known_extensions = false;
         SET autoload_known_extensions = false;
         SET allow_community_extensions = false;
         SET enable_external_access = false;
         SET lock_configuration = true;",
    )?;
    Ok(())
}

/// Compute a deterministic DB file path under `data_dir` for a given log
/// source path. We hash the source path so that identical re-opens map to
/// the same DB, while different logs stay isolated.
pub fn store_path_for(data_dir: &Path, source: &Path) -> PathBuf {
    let canonical = source.canonicalize().unwrap_or_else(|_| source.to_path_buf());
    let key = canonical.to_string_lossy().to_ascii_lowercase();
    let hash = blake3::hash(key.as_bytes()).to_hex();
    let short = &hash.as_str()[..16];
    let stem = canonical.file_stem().and_then(|s| s.to_str()).unwrap_or("log");
    data_dir.join(format!("{stem}.{short}.duckdb"))
}
