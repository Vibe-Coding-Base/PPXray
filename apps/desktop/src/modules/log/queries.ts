// TanStack Query hooks for the log module.
//
// Every filter-dependent panel reads from a single `log_dashboard` query.
// Previously each panel ran its own `useEffect` + `useState` + `cancelled`
// flag and issued its own command, so one filter change fanned out into five
// independent round trips — five scans of `events`, five chances to render a
// panel against a filter the others had already moved past.
//
// One query key means React Query dedupes those five subscribers into one
// request, keeps the previous result on screen while the next one loads
// (`placeholderData`), and hands every panel the *same* snapshot.

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import type { EventFilter, LogDashboard } from "@ppxray/ipc-schema";
import { useEffectiveFilter, useLogStore } from "@/stores/log-store";
import { logDashboard, logFacets, logStats } from "./ipc";

/// Rows shown per panel. Server-side caps; the UI never renders more.
const PANEL_LIMITS = { processes: 20, hosts: 25, rules: 40 } as const;

/** Query keys, centralised so invalidation after a re-ingest is one call. */
export const logKeys = {
  all: ["log"] as const,
  stats: () => [...logKeys.all, "stats"] as const,
  facets: () => [...logKeys.all, "facets"] as const,
  dashboard: (filter: EventFilter, bucketSecs: number) =>
    [...logKeys.all, "dashboard", filter, bucketSecs] as const,
  events: (filter: EventFilter) => [...logKeys.all, "events", filter] as const,
};

/**
 * The shared read behind the timeline, the three breakdown panels, and the
 * events table's total. `enabled` is driven by whether a log is open, so the
 * hook is safe to call before ingest.
 */
export function useLogDashboard() {
  const filter = useEffectiveFilter();
  const bucketSecs = useLogStore((s) => s.bucketSecs);
  const sourcePath = useLogStore((s) => s.sourcePath);

  return useQuery<LogDashboard>({
    queryKey: logKeys.dashboard(filter, bucketSecs),
    queryFn: () => logDashboard(filter, bucketSecs, PANEL_LIMITS),
    enabled: sourcePath !== null,
    // Filter changes are rapid (typing, clicking a bar). Holding the last
    // good data avoids every panel blanking between keystrokes.
    placeholderData: keepPreviousData,
  });
}

/** Whole-log counts. Independent of the filter, so fetched once per log. */
export function useLogStats() {
  const sourcePath = useLogStore((s) => s.sourcePath);
  return useQuery({
    queryKey: logKeys.stats(),
    queryFn: logStats,
    enabled: sourcePath !== null,
    staleTime: Infinity,
  });
}

/** Filter-bar dropdown values. Fixed for a given ingest. */
export function useLogFacets() {
  const sourcePath = useLogStore((s) => s.sourcePath);
  return useQuery({
    queryKey: logKeys.facets(),
    queryFn: logFacets,
    enabled: sourcePath !== null,
    staleTime: Infinity,
  });
}
