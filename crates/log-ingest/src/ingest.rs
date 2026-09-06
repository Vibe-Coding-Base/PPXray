//! Orchestrates parsing + DB load. Designed for a worker thread spawned from
//! the Tauri host — takes a progress callback and returns final stats.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
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
    pub source_path: String,
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

/// Ingest `source` into `store`. Fully replaces any prior data in that store.
///
/// `on_progress` is called on the ingest thread — keep it cheap (channel
/// send or event emit).
///
/// One appender per table, held open for the whole run, and the store lock
/// held throughout — so readers cannot observe a half-loaded table.
///
/// Single-threaded on purpose. On a 32 MB log the parse is 152 ms of a 544 ms
/// ingest; the rest is the single-threaded DuckDB append, so parallel parsing
/// could remove at most a quarter of the wall clock. Re-measure with
/// `cargo run --release -p log-ingest --example bench-ingest` before changing
/// this.
pub fn ingest_file(
    source: &Path,
    store: &LogStore,
    mut on_progress: impl FnMut(IngestProgress),
) -> IngestResult<IngestStats> {
    let started = Instant::now();
    let total_bytes = std::fs::metadata(source)?.len();
    let source_mtime = std::fs::metadata(source)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| chrono::DateTime::<chrono::Utc>::from(t).naive_utc().into());

    let file = File::open(source)?;
    let mut reader = BufReader::with_capacity(1 << 20, file);

    let mut byte_pos: u64 = 0;
    let mut events_inserted: u64 = 0;
    let mut dns_inserted: u64 = 0;

    store.with_conn(|conn| {
        // One file = one DB = one analysis: drop whatever was here before.
        truncate_events(conn)?;

        let mut ev_app = conn.appender("events")?;
        let mut dns_app = conn.appender("dns_events")?;

        let mut next_progress_at: u64 = PROGRESS_EVERY_BYTES;
        let mut next_progress_tick = Instant::now();
        let mut since_flush: u64 = 0;
        let mut line_buf = String::with_capacity(512);

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
                    ev_app.append_row(params![
                        events_inserted,
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
                    dns_app.append_row(params![
                        dns_inserted,
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

            if byte_pos >= next_progress_at
                || next_progress_tick.elapsed().as_millis() as u64 >= PROGRESS_EVERY_MS
            {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                on_progress(IngestProgress {
                    bytes_read: byte_pos,
                    total_bytes,
                    events_inserted,
                    dns_events_inserted: dns_inserted,
                    elapsed_ms,
                    mb_per_sec: throughput(byte_pos, elapsed_ms),
                });
                next_progress_at = byte_pos + PROGRESS_EVERY_BYTES;
                next_progress_tick = Instant::now();
            }
        }

        ev_app.flush()?;
        dns_app.flush()?;
        // Release the appenders before issuing an ordinary statement on the
        // same connection, so `ingest_runs` observes the finished load.
        drop(ev_app);
        drop(dns_app);

        // `id` is derived from the table rather than hard-coded: nothing here
        // should depend on `truncate_events` having just emptied it.
        conn.execute(
            "INSERT INTO ingest_runs(
                 id, source_path, source_size, source_mtime,
                 total_events, total_dns, duration_ms)
             SELECT COALESCE(MAX(id), 0) + 1, ?, ?, ?, ?, ?, ?
             FROM ingest_runs",
            params![
                source.to_string_lossy().as_ref(),
                total_bytes,
                source_mtime,
                events_inserted,
                dns_inserted,
                started.elapsed().as_millis() as u64,
            ],
        )?;
        Ok(())
    })?;

    let duration_ms = started.elapsed().as_millis() as u64;
    let mb_per_sec = throughput(byte_pos, duration_ms);

    // One last progress tick so the UI lands on 100%.
    on_progress(IngestProgress {
        bytes_read: byte_pos,
        total_bytes,
        events_inserted,
        dns_events_inserted: dns_inserted,
        elapsed_ms: duration_ms,
        mb_per_sec,
    });

    Ok(IngestStats {
        source_path: source.to_string_lossy().into_owned(),
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
