// What has changed since the profile was loaded or last saved, per rule.
//
// Rules have no identity of their own — a `.ppx` is positional — so each one
// gets a client-side id under a symbol key. Symbol keys survive object spread
// and immer, and are dropped by `JSON.stringify`, so the id never reaches the
// Rust side or the file. A rule that arrives without one (freshly parsed, or
// a copy made through JSON) is new by definition.

import type { Rule } from "@ppxray/ipc-schema";

const RULE_ID: unique symbol = Symbol("ppxray.rule-id");

type Tagged = Rule & { [RULE_ID]?: string };

let counter = 0;

export function ruleId(rule: Rule): string | undefined {
  return (rule as Tagged)[RULE_ID];
}

/** The same rules, every one carrying an id. Tagged rules keep their object. */
export function withIds(rules: Rule[]): Rule[] {
  let changed = false;
  const out = rules.map((r) => {
    if (ruleId(r) !== undefined) return r;
    changed = true;
    // Spread rather than assign: the store's rules are frozen by immer.
    const tagged: Tagged = { ...r, [RULE_ID]: `r${++counter}` };
    return tagged;
  });
  return changed ? out : rules;
}

export type RuleChange = "new" | "edited" | "moved";

export interface RuleChanges {
  /** Changes per rule id. A rule may be both edited and moved. */
  byId: Map<string, Set<RuleChange>>;
  counts: { new: number; edited: number; moved: number; deleted: number };
  total: number;
}

const NONE: RuleChanges = {
  byId: new Map(),
  counts: { new: 0, edited: 0, moved: 0, deleted: 0 },
  total: 0,
};

/** The fields a user can edit, in a fixed order, so equality is a string compare. */
function fingerprint(r: Rule): string {
  return JSON.stringify([r.enabled, r.name, r.action, r.targets, r.applications, r.ports]);
}

export function diffRules(baseline: Rule[], current: Rule[]): RuleChanges {
  const baseById = new Map<string, Rule>();
  for (const r of baseline) {
    const id = ruleId(r);
    if (id !== undefined) baseById.set(id, r);
  }
  const currentIds = new Set<string>();
  const byId = new Map<string, Set<RuleChange>>();
  const counts = { new: 0, edited: 0, moved: 0, deleted: 0 };

  const mark = (id: string, change: RuleChange) => {
    let set = byId.get(id);
    if (!set) byId.set(id, (set = new Set()));
    set.add(change);
    counts[change] += 1;
  };

  for (const r of current) {
    const id = ruleId(r);
    if (id === undefined) continue;
    currentIds.add(id);
    const before = baseById.get(id);
    if (!before) mark(id, "new");
    else if (fingerprint(before) !== fingerprint(r)) mark(id, "edited");
  }
  for (const id of baseById.keys()) if (!currentIds.has(id)) counts.deleted += 1;

  // A rule has moved when it is not part of the longest order-preserving
  // subsequence common to the two lists of surviving rules. Marking rules
  // whose neighbour changed instead would flag three rules for one move.
  const before = baseline.map(ruleId).filter((id): id is string => id !== undefined && currentIds.has(id));
  const after = current.map(ruleId).filter((id): id is string => id !== undefined && baseById.has(id));
  for (const id of movedIds(before, after)) mark(id, "moved");

  const total = byId.size + counts.deleted;
  return total === 0 ? NONE : { byId, counts, total };
}

/** Ids in `after` that are not in a longest common subsequence with `before`. */
function movedIds(before: string[], after: string[]): string[] {
  const n = before.length;
  const m = after.length;
  if (n === 0 || m === 0) return [];
  // lcs[i][j] = LCS length of before[i..] and after[j..].
  const lcs: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] =
        before[i] === after[j]
          ? lcs[i + 1]![j + 1]! + 1
          : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const kept = new Set<string>();
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (before[i] === after[j]) {
      kept.add(before[i]!);
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      i++;
    } else {
      j++;
    }
  }
  return after.filter((id) => !kept.has(id));
}
