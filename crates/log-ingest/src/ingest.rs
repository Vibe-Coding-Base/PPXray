//! Orchestrates parsing + DB load. Designed for a worker thread spawned from
//! the Tauri host — takes a progress callback and returns final stats.
//!
//! Proxifier rotates its log: `Log.txt` is live, `Log.txt.1` the previous
//! one, `Log.txt.2` older still. One analysis can hold several of them, in
//! [`archive_order`], and more can be appended later.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use duckdb::params;
use serde::Serialize;
use ts_rs::TS;

use crate::error::IngestResult;
use crate::model::{DnsKind, Event};
use crate::parser::parse_line;
use crate::schema::truncate_events;
use crate::store::LogStore;

/// Streaming progress payload emitted every `PROGRESS_EVERY_BYTES`.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct IngestProgress {
    pub bytes_read: u64,
    pub total_bytes: u64,
    pub events_inserted: u64,
    pub dns_events_inserted: u64,
    pub elapsed_ms: u64,
    pub mb_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export, export_to = "../../../packages/ipc-schema/src/generated/")]
pub struct IngestStats {
    /// The primary file: the newest one, which is the live `Log.txt` when
    /// archives were opened alongside it.
    pub source_path: String,
    /// Every file this run read, in the order it read them.
    pub source_paths: Vec<String>,
    pub total_bytes: u64,
    pub total_events: u64,
    pub total_dns: u64,
    pub duration_ms: u64,
    pub mb_per_sec: f64,
    pub db_path: String,
}

/// Progress emits every 4 MB or every 500 ms of wall clock, whichever first.
const PROGRESS_EVERY_BYTES: u64 = 4 * 1024 * 1024;
const PROGRESS_EVERY_MS: u64 = 500;

/// Rows buffered inside DuckDB's appender before it writes a chunk out. This
/// is a flush cadence, not a batch size — rows stream into the appender one
/// at a time and never accumulate on the Rust side.
const FLUSH_EVERY_ROWS: u64 = 100_000;

/// Whether an ingest starts from an empty store or adds to what is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestMode {
    /// Drop whatever the store held and load these files.
    Replace,
    /// Keep existing rows and alerts; ids continue where they left off.
    Append,
}

/// Sort log files the way Proxifier wrote them: the highest archive number
/// is the oldest, and the file with no number is the live log.
///
/// Files that do not share a stem fall back to name order, after the ones
/// that do. `Log.txt`, `Log.txt.1`, `Log.txt.2` therefore become
/// `Log.txt.2, Log.txt.1, Log.txt`.
pub fn archive_order(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut keyed: Vec<(String, std::cmp::Reverse<u64>, PathBuf)> = paths
        .iter()
        .map(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            let (stem, n) = split_archive_suffix(&name);
            (stem.to_ascii_lowercase(), std::cmp::Reverse(n), p.clone())
        })
        .collect();
    keyed.sort();
    keyed.into_iter().map(|(_, _, p)| p).collect()
}

/// `Log.txt.3` -> (`Log.txt`, 3); `Log.txt` -> (`Log.txt`, 0).
fn split_archive_suffix(name: &str) -> (&str, u64) {
    match name.rsplit_once('.') {
        Some((stem, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            (stem, n.parse().unwrap_or(0))
        }
        _ => (name, 0),
    }
}

/// Ingest one file, replacing whatever the store held. See [`ingest_files`].
pub fn ingest_file(
    source: &Path,
    store: &LogStore,
    on_progress: impl FnMut(IngestProgress),
) -> IngestResult<IngestStats> {
    ingest_files(&[source.to_path_buf()], store, IngestMode::Replace, on_progress)
}

/// Ingest `sources` into `store`, in the order given.
///
/// `on_progress` is called on the ingest thread — keep it cheap (channel
/// send or event emit). Byte counts are cumulative across files, so a
/// progress bar reads naturally over the whole batch.
///
/// One appender per table, held open for the whole run, and the store lock
/// held throughout — so readers cannot observe a half-loaded table.
///
/// Single-threaded on purpose. On a 32 MB log the parse is 152 ms of a 544 ms
/// ingest; the rest is the single-threaded DuckDB append, so parallel parsing
/// could remove at most a quarter of the wall clock. Re-measure with
/// `cargo run --release -p log-ingest --example bench-ingest` before changing
/// this.
pub fn ingest_files(
    sources: &[PathBuf],
    store: &LogStore,
    mode: IngestMode,
    mut on_progress: impl FnMut(IngestProgress),
) -> IngestResult<IngestStats> {
    if sources.is_empty() {
        return Err(crate::error::IngestError::Custom("no log files given".into()));
    }
    let started = Instant::now();
    let total_bytes =
        sources.iter().map(|s| std::fs::metadata(s).map(|m| m.len())).sum::<Result<u64, _>>()?;

    // Cumulative across files.
    let mut bytes_done: u64 = 0;
    let mut events_inserted: u64 = 0;
    let mut dns_inserted: u64 = 0;

    store.with_conn(|conn| {
        match mode {
            IngestMode::Replace => truncate_events(conn)?,
            IngestMode::Append => {}
        }
        // Continue the id sequence rather than restart it: `alert_evidence`
        // points at ids, and a duplicate id would make evidence ambiguous.
        let mut next_event_id: u64 =
            conn.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
        let mut next_dns_id: u64 =
            conn.query_row("SELECT COALESCE(MAX(id), 0) FROM dns_events", [], |r| r.get(0))?;

        let mut ev_app = conn.appender("events")?;
        let mut dns_app = conn.appender("dns_events")?;

        let mut next_progress_at: u64 = PROGRESS_EVERY_BYTES;
        let mut next_progress_tick = Instant::now();
        let mut since_flush: u64 = 0;
        let mut line_buf = String::with_capacity(512);
        // Per file: (path, size, mtime, events, dns).
        let mut runs: Vec<(String, u64, Option<chrono::NaiveDateTime>, u64, u64)> = Vec::new();

        for source in sources {
            let file_bytes = std::fs::metadata(source)?.len();
            let source_mtime = std::fs::metadata(source)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| chrono::DateTime::<chrono::Utc>::from(t).naive_utc().into());
            let file = File::open(source)?;
            let mut reader = BufReader::with_capacity(1 << 20, file);
            let mut byte_pos: u64 = 0;
            let events_before = events_inserted;
            let dns_before = dns_inserted;

            loop {
                line_buf.clear();
                let raw_offset = byte_pos;
                let n = reader.read_line(&mut line_buf)?;
                if n == 0 {
                    break;
                }
                byte_pos += n as u64;

                let line = line_buf.trim_end_matches(['\n', '\r']);
                match parse_line(line, raw_offset) {
                    Some(Event::Connection(c)) => {
                        events_inserted += 1;
                        next_event_id += 1;
                        ev_app.append_row(params![
                            next_event_id,
                            c.ts,
                            c.process,
                            c.pid,
                            c.parent,
                            c.proto.as_str(),
                            c.ipv6,
                            c.dst_host,
                            c.dst_ip,
                            c.dst_port as i32,
                            c.matched_rule,
                            c.action.as_str(),
                            c.raw_offset,
                        ])?;
                        since_flush += 1;
                    }
                    Some(Event::Dns(d)) => {
                        dns_inserted += 1;
                        next_dns_id += 1;
                        dns_app.append_row(params![
                            next_dns_id,
                            d.ts,
                            d.process,
                            d.pid,
                            d.qname,
                            d.qtype.map(|v| v as i32),
                            d.server,
                            d.answer_ip,
                            d.ttl,
                            match d.kind {
                                DnsKind::Request => "Request",
                                DnsKind::Response => "Response",
                                DnsKind::EmptyResponse => "EmptyResponse",
                                DnsKind::Resolve => "Resolve",
                            },
                            d.raw_offset,
                        ])?;
                        since_flush += 1;
                    }
                    // Timestamped but unrecognised, or a blank/malformed line.
                    Some(Event::Other { .. }) | None => {}
                }

                if since_flush >= FLUSH_EVERY_ROWS {
                    ev_app.flush()?;
                    dns_app.flush()?;
                    since_flush = 0;
                }

                let read_so_far = bytes_done + byte_pos;
                if read_so_far >= next_progress_at
                    || next_progress_tick.elapsed().as_millis() as u64 >= PROGRESS_EVERY_MS
                {
                    let elapsed_ms = started.elapsed().as_millis() as u64;
                    on_progress(IngestProgress {
                        bytes_read: read_so_far,
                        total_bytes,
                        events_inserted,
                        dns_events_inserted: dns_inserted,
                        elapsed_ms,
                        mb_per_sec: throughput(read_so_far, elapsed_ms),
                    });
                    next_progress_at = read_so_far + PROGRESS_EVERY_BYTES;
                    next_progress_tick = Instant::now();
                }
            }

            bytes_done += byte_pos;
            runs.push((
                source.to_string_lossy().into_owned(),
                file_bytes,
                source_mtime,
                events_inserted - events_before,
                dns_inserted - dns_before,
            ));
        }

        ev_app.flush()?;
        dns_app.flush()?;
        // Release the appenders before issuing an ordinary statement on the
        // same connection, so `ingest_runs` observes the finished load.
        drop(ev_app);
        drop(dns_app);

        // One row per file. `id` is derived from the table rather than
        // hard-coded, so an append continues the sequence.
        let duration_ms = started.elapsed().as_millis() as u64;
        for (path, size, mtime, events, dns) in &runs {
            conn.execute(
                "INSERT INTO ingest_runs(
                     id, source_path, source_size, source_mtime,
                     total_events, total_dns, duration_ms)
                 SELECT COALESCE(MAX(id), 0) + 1, ?, ?, ?, ?, ?, ?
                 FROM ingest_runs",
                params![path, size, mtime, events, dns, duration_ms],
            )?;
        }
        Ok(())
    })?;

    let duration_ms = started.elapsed().as_millis() as u64;
    let mb_per_sec = throughput(bytes_done, duration_ms);

    // One last progress tick so the UI lands on 100%.
    on_progress(IngestProgress {
        bytes_read: bytes_done,
        total_bytes,
        events_inserted,
        dns_events_inserted: dns_inserted,
        elapsed_ms: duration_ms,
        mb_per_sec,
    });

    let source_paths: Vec<String> =
        sources.iter().map(|s| s.to_string_lossy().into_owned()).collect();
    Ok(IngestStats {
        // The last file in archive order is the newest.
        source_path: source_paths.last().cloned().unwrap_or_default(),
        source_paths,
        total_bytes,
        total_events: events_inserted,
        total_dns: dns_inserted,
        duration_ms,
        mb_per_sec,
        db_path: store.path().to_string_lossy().into_owned(),
    })
}

fn throughput(bytes: u64, elapsed_ms: u64) -> f64 {
    if elapsed_ms == 0 {
        return 0.0;
    }
    (bytes as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn archives_are_ordered_oldest_first_with_the_live_log_last() {
        let ordered = archive_order(&paths(&["Log.txt", "Log.txt.1", "Log.txt.10", "Log.txt.2"]));
        let names: Vec<&str> = ordered.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(names, ["Log.txt.10", "Log.txt.2", "Log.txt.1", "Log.txt"]);
    }

    #[test]
    fn a_dotted_stem_is_not_mistaken_for_an_archive_number() {
        assert_eq!(split_archive_suffix("Log.txt"), ("Log.txt", 0));
        assert_eq!(split_archive_suffix("Log.txt.7"), ("Log.txt", 7));
        assert_eq!(split_archive_suffix("2026.04.17.txt"), ("2026.04.17.txt", 0));
    }

    #[test]
    fn appending_keeps_ids_unique_and_rows_accumulating() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("Log.txt");
        std::fs::write(
            &log,
            "[2026.04.17 23:30:26] app.exe (1) - api.example(203.0.113.43):443 matching R rule : direct connection\n",
        )
        .unwrap();
        let store = crate::open_store(&dir.path().join("a.duckdb")).unwrap();

        let first =
            ingest_files(std::slice::from_ref(&log), &store, IngestMode::Replace, |_| {}).unwrap();
        assert_eq!(first.total_events, 1);
        let second =
            ingest_files(std::slice::from_ref(&log), &store, IngestMode::Append, |_| {}).unwrap();
        assert_eq!(second.total_events, 1, "stats describe this run, not the store");

        let (rows, distinct): (u64, u64) = store
            .with_conn(|c| {
                Ok(c.query_row("SELECT count(*), count(DISTINCT id) FROM events", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?)
            })
            .unwrap();
        assert_eq!((rows, distinct), (2, 2));

        let runs: u64 = store
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM ingest_runs", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(runs, 2);

        // Replace starts over.
        ingest_files(&[log], &store, IngestMode::Replace, |_| {}).unwrap();
        let rows: u64 = store
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(rows, 1);
    }
}
