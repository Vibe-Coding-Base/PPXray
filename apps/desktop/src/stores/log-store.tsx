import { createContext, useContext, useMemo, type ReactNode } from "react";
import { create, useStore as useZustandStore, type StoreApi } from "zustand";
import { useShallow } from "zustand/react/shallow";

import type {
  EventFilter,
  IngestProgress,
  IngestStats,
  LogStats,
} from "@ppxray/ipc-schema";
import { compileLogSearch, mergeFilters } from "@/modules/log/log-search-dsl";

export interface LogSlice {
  /** Absolute path of the source log file currently loaded. */
  sourcePath: string | null;
  /** Final stats emitted by `log_ingest`. */
  ingestStats: IngestStats | null;
  /** DuckDB-backed summary, kept fresh after every filter change. */
  counts: LogStats | null;
  /** Live ingest progress, only set while an ingest is running. */
  progress: IngestProgress | null;
  /** Manual filter (FilterBar multi-selects + clicks). */
  filter: EventFilter;
  /** Free-form search box query, compiled to a delta-filter at read time. */
  searchQuery: string;
  /** Timeline bucket width. Lives here, not in TimelineChart, because the
   *  combined dashboard read fetches the timeline alongside every other
   *  filter-dependent panel. */
  bucketSecs: number;

  // --- mutations ----------------------------------------------------------
  setLoaded: (path: string, stats: IngestStats, counts: LogStats) => void;
  setProgress: (p: IngestProgress | null) => void;
  setCounts: (c: LogStats) => void;
  setFilter: (patch: Partial<EventFilter>) => void;
  setSearchQuery: (q: string) => void;
  setBucketSecs: (secs: number) => void;
  clearFilter: () => void;
  unload: () => void;
}

const EMPTY_FILTER: EventFilter = {
  ts_from: null,
  ts_to: null,
  processes: null,
  matched_rules: null,
  actions: null,
  host_contains: null,
  protos: null,
  ipv6: null,
  limit: 500,
  offset: 0,
};

function createLogStore(): StoreApi<LogSlice> {
  return create<LogSlice>((set) => ({
    sourcePath: null,
    ingestStats: null,
    counts: null,
    progress: null,
    filter: EMPTY_FILTER,
    searchQuery: "",
    bucketSecs: 60,

    setLoaded: (path, stats, counts) =>
      set({
        sourcePath: path,
        ingestStats: stats,
        counts,
        progress: null,
        filter: EMPTY_FILTER,
        searchQuery: "",
      }),
    setProgress: (progress) => set({ progress }),
    setCounts: (counts) => set({ counts }),
    setFilter: (patch) =>
      set((s) => ({ filter: { ...s.filter, ...patch, offset: 0 } })),
    setSearchQuery: (q) => set({ searchQuery: q }),
    setBucketSecs: (bucketSecs) => set({ bucketSecs }),
    clearFilter: () => set({ filter: EMPTY_FILTER, searchQuery: "" }),
    unload: () =>
      set({
        sourcePath: null,
        ingestStats: null,
        counts: null,
        progress: null,
        filter: EMPTY_FILTER,
        searchQuery: "",
      }),
  }));
}

const LogStoreContext = createContext<StoreApi<LogSlice> | null>(null);

export function LogStoreProvider({ children }: { children: ReactNode }) {
  const store = useMemo(() => createLogStore(), []);
  return <LogStoreContext.Provider value={store}>{children}</LogStoreContext.Provider>;
}

export function useLogStore<T>(selector: (s: LogSlice) => T): T {
  const store = useContext(LogStoreContext);
  if (!store) throw new Error("useLogStore must be used inside <LogStoreProvider>");
  return useZustandStore(store, selector);
}

export function useLogStoreShallow<T>(selector: (s: LogSlice) => T): T {
  const store = useContext(LogStoreContext);
  if (!store) throw new Error("useLogStoreShallow must be used inside <LogStoreProvider>");
  return useZustandStore(store, useShallow(selector));
}

/**
 * Returns the **effective** filter — manual selections from the FilterBar
 * combined with whatever the search box compiled to. All consumers of the
 * log store should use this instead of `state.filter` so the search box
 * actually narrows their data.
 *
 * Implementation note: the merged filter is computed via `useMemo`, NOT
 * inside the zustand selector. A selector that returns `mergeFilters(...)`
 * produces a fresh object every call, which trips React 19's
 * `useSyncExternalStore` cache check ("getSnapshot should be cached")
 * and triggers an infinite re-render loop. By subscribing to the two
 * scalar slices separately and combining them via `useMemo`, every
 * subscription receives a stable reference and the merge runs once per
 * actual input change.
 */
export function useEffectiveFilter(): EventFilter {
  const filter = useLogStore((s) => s.filter);
  const searchQuery = useLogStore((s) => s.searchQuery);
  return useMemo(() => {
    const search = compileLogSearch(searchQuery).filter;
    return mergeFilters(filter, search);
  }, [filter, searchQuery]);
}
