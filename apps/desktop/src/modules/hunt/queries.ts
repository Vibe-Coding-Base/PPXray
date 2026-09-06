// TanStack Query hooks for the hunt module.
//
// These reads used to be `useEffect` + `.catch(() => {})`, which meant a
// failed `hunt_list_alerts` rendered as "No alerts. Run the catalog or relax
// the triage filter." — telling an analyst there is nothing to see when the
// truth was that nothing was looked at. Errors now reach the UI.
//
// Alerts live in the query cache rather than the zustand store: they are
// server state with a well-defined owner (the DuckDB file), and the two
// mutations that change them — running the catalog, triaging one — can then
// invalidate rather than hand-patch a second copy.

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
} from "@tanstack/react-query";

import type { Alert, AlertFilter, HuntRunReport } from "@ppxray/ipc-schema";
import { getRuleDir } from "@/modules/settings/ipc";
import { useLogStore } from "@/stores/log-store";
import {
  huntAlertEvidence,
  huntCatalog,
  huntListAlerts,
  huntRun,
  huntTriage,
  listUserRules,
} from "./ipc";

export const huntKeys = {
  all: ["hunt"] as const,
  catalog: () => [...huntKeys.all, "catalog"] as const,
  alerts: (filter: AlertFilter) => [...huntKeys.all, "alerts", filter] as const,
  evidence: (alertId: bigint) =>
    [...huntKeys.all, "evidence", String(alertId)] as const,
  userRules: () => [...huntKeys.all, "user-rules"] as const,
  ruleDir: () => [...huntKeys.all, "rule-dir"] as const,
};

/** Built-in catalog plus whatever parses from the user rule directory. */
export function useHuntCatalog() {
  return useQuery({
    queryKey: huntKeys.catalog(),
    queryFn: huntCatalog,
    staleTime: Infinity,
  });
}

/** Alerts for the current inbox filter. Requires an open log. */
export function useAlerts(filter: AlertFilter) {
  const sourcePath = useLogStore((s) => s.sourcePath);
  return useQuery<Alert[]>({
    queryKey: huntKeys.alerts(filter),
    queryFn: () => huntListAlerts(filter),
    enabled: sourcePath !== null,
  });
}

/** Evidence event ids behind one alert, for the detail drawer. */
export function useAlertEvidence(alertId: bigint) {
  return useQuery({
    queryKey: huntKeys.evidence(alertId),
    queryFn: () => huntAlertEvidence(alertId, 100),
  });
}

export function useUserRules() {
  return useQuery({ queryKey: huntKeys.userRules(), queryFn: listUserRules });
}

export function useRuleDir() {
  return useQuery({ queryKey: huntKeys.ruleDir(), queryFn: getRuleDir });
}

/**
 * Run the whole catalog. Invalidates everything under `hunt` — a run
 * rewrites the alert tables and may pick up rule files added since the
 * catalog was last read.
 */
export function useRunHunt(): UseMutationResult<HuntRunReport, unknown, void> {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: huntRun,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: huntKeys.all }),
  });
}

/**
 * Triage one alert.
 *
 * Optimistic: the analyst is clicking down a list, and a round trip per
 * click would make the inbox feel like it lags behind them. On failure the
 * previous cache is restored and the caller surfaces the error.
 */
export function useTriage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ alertId, triage }: { alertId: bigint; triage: string }) =>
      huntTriage(alertId, triage),
    onMutate: async ({ alertId, triage }) => {
      const key = [...huntKeys.all, "alerts"];
      await queryClient.cancelQueries({ queryKey: key });
      const previous = queryClient.getQueriesData<Alert[]>({ queryKey: key });
      queryClient.setQueriesData<Alert[]>({ queryKey: key }, (alerts) =>
        alerts?.map((a) =>
          a.id === alertId ? { ...a, triage: triage as Alert["triage"] } : a,
        ),
      );
      return { previous };
    },
    onError: (_err, _vars, context) => {
      for (const [key, data] of context?.previous ?? []) {
        queryClient.setQueryData(key, data);
      }
    },
    // The filter usually hides triaged alerts, so the row should disappear —
    // but only once the write is known to have landed.
    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: [...huntKeys.all, "alerts"] }),
  });
}

/** Rule files changed on disk; re-read the catalog and the file list. */
export function useInvalidateRules() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: huntKeys.catalog() });
    void queryClient.invalidateQueries({ queryKey: huntKeys.userRules() });
  };
}
