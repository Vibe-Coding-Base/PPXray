import { createContext, useContext, useMemo, type ReactNode } from "react";
import { create, useStore as useZustandStore, type StoreApi } from "zustand";
import { useShallow } from "zustand/react/shallow";

import type { AlertFilter, HuntRunReport } from "@ppxray/ipc-schema";

/**
 * UI state for the hunt module.
 *
 * Alerts themselves are *not* here — they are server state owned by the
 * DuckDB file and live in the TanStack Query cache (`modules/hunt/queries.ts`).
 * Keeping a second copy in the store meant every mutation had to patch both,
 * and a failed read left the stale copy on screen looking authoritative.
 */
export interface HuntSlice {
  /** Most recent run report (per-rule timing + counts). */
  lastReport: HuntRunReport | null;
  filter: AlertFilter;
  selectedAlertId: bigint | null;

  setReport: (r: HuntRunReport) => void;
  setFilter: (patch: Partial<AlertFilter>) => void;
  selectAlert: (id: bigint | null) => void;
  reset: () => void;
}

const EMPTY_FILTER: AlertFilter = {
  severities: null,
  triage: ["new", "tp"],   // hide FP/suppressed by default
  rule_ids: null,
  limit: 1000,
  offset: 0,
};

function createHuntStore(): StoreApi<HuntSlice> {
  return create<HuntSlice>((set) => ({
    lastReport: null,
    filter: EMPTY_FILTER,
    selectedAlertId: null,

    setReport: (lastReport) => set({ lastReport }),
    setFilter: (patch) =>
      set((s) => ({ filter: { ...s.filter, ...patch }, selectedAlertId: null })),
    selectAlert: (id) => set({ selectedAlertId: id }),
    reset: () =>
      set({ lastReport: null, filter: EMPTY_FILTER, selectedAlertId: null }),
  }));
}

const HuntStoreContext = createContext<StoreApi<HuntSlice> | null>(null);

export function HuntStoreProvider({ children }: { children: ReactNode }) {
  const store = useMemo(() => createHuntStore(), []);
  return <HuntStoreContext.Provider value={store}>{children}</HuntStoreContext.Provider>;
}

export function useHuntStore<T>(selector: (s: HuntSlice) => T): T {
  const store = useContext(HuntStoreContext);
  if (!store) throw new Error("useHuntStore must be used inside <HuntStoreProvider>");
  return useZustandStore(store, selector);
}

export function useHuntStoreShallow<T>(selector: (s: HuntSlice) => T): T {
  const store = useContext(HuntStoreContext);
  if (!store) throw new Error("useHuntStoreShallow must be used inside <HuntStoreProvider>");
  return useZustandStore(store, useShallow(selector));
}
