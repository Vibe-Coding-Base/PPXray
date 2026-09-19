import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

import type {
  EventFilter,
  EventRow,
  FacetValues,
  IngestProgress,
  IngestStats,
  LogDashboard,
  LogStats,
  TargetSuggestions,
} from "@ppxray/ipc-schema";

export interface OpenLogResult {
  /** Every file in the store now, oldest first. */
  sources: string[];
  stats: IngestStats;
  counts: LogStats;
}

// --- Ingest / lifecycle ----------------------------------------------------

/**
 * Proxifier rotates its log as `Log.txt.1`, `Log.txt.2`, … — the extension a
 * file dialog sees is the number, so those are listed alongside `txt`. The
 * range is generous rather than exact; the last filter catches the rest.
 */
const ARCHIVE_NUMBERS = Array.from({ length: 50 }, (_, i) => String(i + 1));

/** One or more log files, or an empty list when the picker was cancelled. */
export async function pickLogFiles(): Promise<string[]> {
  const picked = await openDialog({
    multiple: true,
    filters: [
      { name: "Proxifier logs (Log.txt, Log.txt.1, …)", extensions: ["txt", "log", ...ARCHIVE_NUMBERS] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  if (picked === null) return [];
  return Array.isArray(picked) ? picked : [picked];
}

/** Open an analysis from these files, replacing the one for the same log. */
export function ingestLogs(paths: string[]): Promise<OpenLogResult> {
  return invoke<OpenLogResult>("log_ingest", { paths });
}

/** Add these files to the analysis that is open. */
export function appendLogs(paths: string[]): Promise<OpenLogResult> {
  return invoke<OpenLogResult>("log_ingest_append", { paths });
}

export function openExistingLog(path: string): Promise<LogStats> {
  return invoke<LogStats>("log_open_existing", { path });
}

export function closeLog(): Promise<void> {
  return invoke<void>("log_close");
}

export function onIngestProgress(cb: (p: IngestProgress) => void): Promise<UnlistenFn> {
  return listen<IngestProgress>("log:ingest-progress", (event) => cb(event.payload));
}

// --- Analysis queries ------------------------------------------------------

export function logStats(): Promise<LogStats> {
  return invoke<LogStats>("log_stats");
}

export function logFacets(): Promise<FacetValues> {
  return invoke<FacetValues>("log_facets");
}

export function queryEvents(filter: EventFilter): Promise<EventRow[]> {
  return invoke<EventRow[]>("log_query_events", { filter });
}






/**
 * Every filter-dependent panel in one round trip — see `queries.ts`.
 *
 * This replaced five per-panel commands (`log_count_events`,
 * `log_top_processes`, `log_top_hosts`, `log_top_rules`, `log_timeline`),
 * which were removed along with it rather than left as unused IPC surface.
 */
export function logDashboard(
  filter: EventFilter,
  bucketSecs: number,
  limits: { processes: number; hosts: number; rules: number },
): Promise<LogDashboard> {
  return invoke<LogDashboard>("log_dashboard", {
    filter,
    bucketSecs,
    processes: limits.processes,
    hosts: limits.hosts,
    rules: limits.rules,
  });
}

/**
 * Destinations a process actually reached, collapsed into entries that can be
 * pasted into a rule's Targets field. See `crates/log-ingest/src/suggest.rs`
 * for how subdomains roll up, and why they do not roll up further.
 */
export function suggestTargets(
  process: string,
  opts: { minEvents?: number; minHosts?: number; includeIps?: boolean } = {},
): Promise<TargetSuggestions> {
  return invoke<TargetSuggestions>("log_suggest_targets", {
    process,
    minEvents: opts.minEvents,
    minHostsForWildcard: opts.minHosts,
    includeIps: opts.includeIps,
  });
}
