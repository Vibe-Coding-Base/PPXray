// TanStack Query hook for the exposure graph.
//
// The query key is a debounced `revision` counter, not the profile object:
// typing in a target field commits per keystroke, and React Query hashes keys
// with `JSON.stringify`, so keying on the profile would serialise the whole
// rule list on every render.
//
// Failures must surface rather than leaving the last good graph on screen —
// silently stale exposure is the one thing this view exists to get right.

import { useDebouncedValue } from "@mantine/hooks";
import { useQuery } from "@tanstack/react-query";

import type { ExposureGraph } from "@ppxray/ipc-schema";
import { useProfileStore } from "@/stores/profile-store";
import { computeExposure } from "./ipc";

export const exposureKeys = {
  all: ["exposure"] as const,
  graph: (revision: number) => [...exposureKeys.all, "graph", revision] as const,
};

const RECOMPUTE_DEBOUNCE_MS = 400;

export function useExposureGraph() {
  const profile = useProfileStore((s) => s.profile);
  const revision = useProfileStore((s) => s.revision);
  const [debouncedRevision] = useDebouncedValue(revision, RECOMPUTE_DEBOUNCE_MS);

  return useQuery<ExposureGraph>({
    queryKey: exposureKeys.graph(debouncedRevision),
    // `profile` is read at fetch time rather than captured in the key, so the
    // graph always reflects the current rules even though the key lags by
    // one debounce interval.
    queryFn: () => computeExposure(profile!),
    enabled: profile !== null,
    // The graph is a pure function of the profile, so a cached revision can
    // never go stale — undo/redo bumps the revision and gets its own entry.
    staleTime: Infinity,
    gcTime: 5 * 60_000,
  });
}
