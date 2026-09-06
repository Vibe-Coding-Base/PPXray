import { createContext, useContext, useMemo } from "react";
import { create, useStore as useZustandStore, type StoreApi } from "zustand";
import { useShallow } from "zustand/react/shallow";
import { produce } from "immer";

import type { Profile, Rule } from "@ppxray/ipc-schema";

/** A single rule mutation captured as an inverse snapshot. Only the `rules`
 *  array is kept: nothing else in the profile is editable from the UI. */
interface HistoryEntry {
  rules: Rule[];
  /** Short label shown in tooltips and the notifications the user sees. */
  label: string;
}

const MAX_HISTORY = 100;

export interface ProfileSlice {
  profile: Profile | null;
  path: string | null;
  dirty: boolean;

  /** Bumped on every change to `profile`.
   *
   *  A cheap, serialisable identity for the profile — the exposure view keys
   *  its query on this instead of the profile object, which would otherwise
   *  be JSON-hashed (155 rules deep) on every render. */
  revision: number;

  /** Row indices currently selected in the rule table. Persists across
   *  filter changes; the table UI intersects with the visible subset. */
  selectedIndices: Set<number>;

  /** Index of the rule whose detail panel is open. Null = no split panel. */
  detailIndex: number | null;

  undoStack: HistoryEntry[];
  redoStack: HistoryEntry[];

  // --- lifecycle -----------------------------------------------------------
  setLoaded: (profile: Profile, path: string) => void;
  markSaved: (path: string) => void;
  clear: () => void;

  // --- selection & split panel ---------------------------------------------
  setSelection: (indices: Iterable<number>) => void;
  toggleSelection: (index: number, mode: "single" | "toggle" | "range") => void;
  clearSelection: () => void;
  openDetail: (index: number | null) => void;

  // --- history -------------------------------------------------------------
  undo: () => string | null;
  redo: () => string | null;
  canUndo: () => boolean;
  canRedo: () => boolean;

  // --- rule CRUD (all go through `commit` so undo/dirty work uniformly) ----
  toggleRule: (index: number) => void;
  setEnabledMany: (indices: number[], enabled: boolean) => void;
  updateRule: (index: number, patch: Partial<Rule>) => void;
  deleteRules: (indices: number[]) => void;
  duplicateRules: (indices: number[]) => void;
  moveRules: (indices: number[], target: number) => void;
  moveRulesToTop: (indices: number[]) => void;
  moveRulesToBottom: (indices: number[]) => void;
  insertRule: (after: number | null, rule: Rule) => void;
}

function createProfileStore(): StoreApi<ProfileSlice> {
  let lastAnchor: number | null = null;

  return create<ProfileSlice>((set, get) => {
    /** Apply a mutation that produces a new rules array. Pushes the previous
     *  array to the undo stack, clears the redo stack, and flips dirty. */
    function commit(
      label: string,
      mutate: (rules: Rule[]) => Rule[],
      extra?: Partial<ProfileSlice>,
    ): void {
      const state = get();
      if (!state.profile) return;
      const nextRules = mutate(state.profile.rules);
      if (nextRules === state.profile.rules) return; // no-op

      const undo = state.undoStack.concat({ rules: state.profile.rules, label });
      if (undo.length > MAX_HISTORY) undo.shift();

      set({
        profile: { ...state.profile, rules: nextRules },
        revision: state.revision + 1,
        dirty: true,
        undoStack: undo,
        redoStack: [],
        ...extra,
      });
    }

    return {
      profile: null,
      path: null,
      dirty: false,
      revision: 0,
      selectedIndices: new Set<number>(),
      detailIndex: null,
      undoStack: [],
      redoStack: [],

      setLoaded: (profile, path) =>
        set((s) => ({
          profile,
          path,
          dirty: false,
          revision: s.revision + 1,
          selectedIndices: new Set(),
          detailIndex: null,
          undoStack: [],
          redoStack: [],
        })),
      markSaved: (path) => set((s) => ({ ...s, path, dirty: false })),
      clear: () =>
        set((s) => ({
          profile: null,
          path: null,
          dirty: false,
          revision: s.revision + 1,
          selectedIndices: new Set(),
          detailIndex: null,
          undoStack: [],
          redoStack: [],
        })),

      setSelection: (indices) => set({ selectedIndices: new Set(indices) }),

      toggleSelection: (index, mode) => {
        const current = new Set(get().selectedIndices);
        if (mode === "single") {
          current.clear();
          current.add(index);
          lastAnchor = index;
        } else if (mode === "toggle") {
          if (current.has(index)) current.delete(index);
          else current.add(index);
          lastAnchor = index;
        } else if (mode === "range") {
          if (lastAnchor == null) {
            current.add(index);
            lastAnchor = index;
          } else {
            const [lo, hi] = lastAnchor <= index
              ? [lastAnchor, index]
              : [index, lastAnchor];
            for (let i = lo; i <= hi; i++) current.add(i);
          }
        }
        set({ selectedIndices: current });
      },

      clearSelection: () => set({ selectedIndices: new Set() }),

      openDetail: (index) => set({ detailIndex: index }),

      undo: () => {
        const { undoStack, profile } = get();
        if (!profile || undoStack.length === 0) return null;
        const top = undoStack[undoStack.length - 1]!;
        set({
          profile: { ...profile, rules: top.rules },
          revision: get().revision + 1,
          undoStack: undoStack.slice(0, -1),
          redoStack: get().redoStack.concat({
            rules: profile.rules,
            label: top.label,
          }),
          dirty: true,
        });
        return top.label;
      },

      redo: () => {
        const { redoStack, profile } = get();
        if (!profile || redoStack.length === 0) return null;
        const top = redoStack[redoStack.length - 1]!;
        set({
          profile: { ...profile, rules: top.rules },
          revision: get().revision + 1,
          redoStack: redoStack.slice(0, -1),
          undoStack: get().undoStack.concat({
            rules: profile.rules,
            label: top.label,
          }),
          dirty: true,
        });
        return top.label;
      },

      canUndo: () => get().undoStack.length > 0,
      canRedo: () => get().redoStack.length > 0,

      // --- mutations ----------------------------------------------------------

      toggleRule: (index) => {
        commit(`Toggle "${get().profile?.rules[index]?.name ?? index}"`, (rules) =>
          produce(rules, (draft) => {
            const r = draft[index];
            if (r) r.enabled = !r.enabled;
          }),
        );
      },

      setEnabledMany: (indices, enabled) => {
        commit(`${enabled ? "Enable" : "Disable"} ${indices.length} rule(s)`, (rules) =>
          produce(rules, (draft) => {
            for (const i of indices) {
              const r = draft[i];
              if (r) r.enabled = enabled;
            }
          }),
        );
      },

      updateRule: (index, patch) => {
        const name = get().profile?.rules[index]?.name ?? index;
        commit(`Edit "${name}"`, (rules) =>
          produce(rules, (draft) => {
            const r = draft[index];
            if (r) Object.assign(r, patch);
          }),
        );
      },

      deleteRules: (indices) => {
        const set_ = new Set(indices);
        commit(`Delete ${indices.length} rule(s)`, (rules) =>
          rules.filter((_, i) => !set_.has(i)),
        );
      },

      duplicateRules: (indices) => {
        commit(`Duplicate ${indices.length} rule(s)`, (rules) =>
          produce(rules, (draft) => {
            // Insert copies immediately after each source, walking in reverse
            // order so indices remain stable during mutation.
            const sorted = [...indices].sort((a, b) => b - a);
            for (const i of sorted) {
              const r = draft[i];
              if (!r) continue;
              const copy: Rule = JSON.parse(JSON.stringify(r));
              copy.name = `${r.name} (copy)`;
              draft.splice(i + 1, 0, copy);
            }
          }),
        );
      },

      moveRules: (indices, target) => {
        commit(`Move ${indices.length} rule(s)`, (rules) =>
          reorderRules(rules, indices, target),
        );
      },

      moveRulesToTop: (indices) => {
        commit(`Move ${indices.length} rule(s) to top`, (rules) =>
          reorderRules(rules, indices, 0),
        );
      },

      moveRulesToBottom: (indices) => {
        commit(`Move ${indices.length} rule(s) to bottom`, (rules) =>
          reorderRules(rules, indices, rules.length),
        );
      },

      insertRule: (after, rule) => {
        commit("Insert rule", (rules) =>
          produce(rules, (draft) => {
            const at = after == null ? draft.length : after + 1;
            draft.splice(at, 0, rule);
          }),
        );
      },
    };
  });
}

/**
 * Move a set of rules (by their original indices) to before `target`. The
 * relative order of moved rules is preserved. `target` is interpreted in the
 * *original* array coordinate system, the same way TanStack Table's row
 * drag-drop emits reorder events.
 */
function reorderRules(rules: Rule[], indices: number[], target: number): Rule[] {
  if (indices.length === 0) return rules;
  const set_ = new Set(indices);
  const moving = [...indices].sort((a, b) => a - b).map((i) => rules[i]!);
  const remaining = rules.filter((_, i) => !set_.has(i));

  // Compute target in the `remaining` coordinate system: subtract the count
  // of moved entries strictly before `target`.
  let adjustedTarget = target;
  for (const i of indices) if (i < target) adjustedTarget--;
  if (adjustedTarget < 0) adjustedTarget = 0;
  if (adjustedTarget > remaining.length) adjustedTarget = remaining.length;

  return [
    ...remaining.slice(0, adjustedTarget),
    ...moving,
    ...remaining.slice(adjustedTarget),
  ];
}

// ---------------------------------------------------------------------------
// Context plumbing
// ---------------------------------------------------------------------------

const ProfileStoreContext = createContext<StoreApi<ProfileSlice> | null>(null);

export function ProfileStoreProvider({ children }: { children: React.ReactNode }) {
  const store = useMemo(() => createProfileStore(), []);
  return (
    <ProfileStoreContext.Provider value={store}>{children}</ProfileStoreContext.Provider>
  );
}

export function useProfileStore<T>(selector: (s: ProfileSlice) => T): T {
  const store = useContext(ProfileStoreContext);
  if (!store) throw new Error("useProfileStore must be used inside <ProfileStoreProvider>");
  return useZustandStore(store, selector);
}

/**
 * Object-selector variant. Components that need several slices in one call
 * MUST use this instead of plain `useProfileStore` — zustand v5 compares
 * with `Object.is`, so a fresh `{…}` per render triggers an infinite
 * re-render loop. `useShallow` compares keys/values element-wise.
 */
export function useProfileStoreShallow<T>(selector: (s: ProfileSlice) => T): T {
  const store = useContext(ProfileStoreContext);
  if (!store) throw new Error("useProfileStoreShallow must be used inside <ProfileStoreProvider>");
  return useZustandStore(store, useShallow(selector));
}

export function useProfileStoreApi(): StoreApi<ProfileSlice> {
  const store = useContext(ProfileStoreContext);
  if (!store) throw new Error("useProfileStoreApi must be used inside <ProfileStoreProvider>");
  return store;
}
