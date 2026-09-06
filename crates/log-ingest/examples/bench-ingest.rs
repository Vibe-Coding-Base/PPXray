//! Ad-hoc ingest throughput probe.
//!
//!   cargo run --release -p log-ingest --example bench-ingest -- <path-to-log>
//!
//! Reports end-to-end MB/s (read + parse + DuckDB load) and, separately, the
//! parse-only rate, so it is clear which half a change actually moved.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let path: PathBuf = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/synthetic-log.txt")
    });

    let bytes = std::fs::metadata(&path).expect("stat log").len();
    let mb = bytes as f64 / 1_048_576.0;
    println!("log: {} ({mb:.1} MB)", path.display());

    // --- parse only -------------------------------------------------------
    let started = Instant::now();
    let mut parsed = 0u64;
    let mut offset = 0u64;
    let mut line = String::with_capacity(512);
    let mut reader = BufReader::with_capacity(1 << 20, std::fs::File::open(&path).unwrap());
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            break;
        }
        if log_ingest::parse_line(line.trim_end_matches(['\n', '\r']), offset).is_some() {
            parsed += 1;
        }
        offset += n as u64;
    }
    let parse_ms = started.elapsed().as_millis().max(1) as f64;
    println!(
        "parse only : {:>7.1} MB/s  ({parsed} events, {parse_ms:.0} ms)",
        mb / (parse_ms / 1000.0)
    );

    // --- full ingest ------------------------------------------------------
    let dir = std::env::temp_dir().join("ppx-bench-ingest");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = log_ingest::store_path_for(&dir, &path);
    let store = log_ingest::open_store(&db).expect("open store");

    let stats = log_ingest::ingest_file(&path, &store, |_| {}).expect("ingest");
    println!(
        "full ingest: {:>7.1} MB/s  ({} events + {} dns, {} ms)",
        stats.mb_per_sec, stats.total_events, stats.total_dns, stats.duration_ms
    );

    let db_size = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
    println!("db file    : {:.1} MB", db_size as f64 / 1_048_576.0);
    let _ = std::fs::remove_dir_all(&dir);
}
