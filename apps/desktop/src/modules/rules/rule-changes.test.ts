import { describe, expect, it } from "vitest";

import type { Rule } from "@ppxray/ipc-schema";
import { diffRules, ruleId, withIds } from "./rule-changes";

function rule(name: string): Rule {
  return { enabled: true, name, action: { kind: "direct" }, targets: [], applications: [], ports: [] };
}

function changesOf(rules: Rule[], base: Rule[]) {
  const d = diffRules(base, rules);
  return rules.map((r) => [r.name, [...(d.byId.get(ruleId(r)!) ?? [])].sort().join("+")]);
}

describe("rule change markers", () => {
  it("ids survive spread and immer-style copies but never reach JSON", () => {
    const [a] = withIds([rule("a")]);
    const copy = { ...a! };
    expect(ruleId(copy)).toBe(ruleId(a!));
    expect(JSON.stringify(a)).not.toContain(ruleId(a!));
    // A JSON round-trip is a new rule, which is what a duplicate should be.
    expect(ruleId(JSON.parse(JSON.stringify(a)))).toBeUndefined();
  });

  it("tags only what is untagged and keeps the array when nothing changes", () => {
    const tagged = withIds([rule("a"), rule("b")]);
    expect(withIds(tagged)).toBe(tagged);
    const mixed = withIds([...tagged, rule("c")]);
    expect(mixed[0]).toBe(tagged[0]);
    expect(ruleId(mixed[2]!)).toBeDefined();
  });

  it("reports nothing against itself", () => {
    const base = withIds([rule("a"), rule("b"), rule("c")]);
    expect(diffRules(base, base).total).toBe(0);
  });

  it("tells new, edited, moved and deleted apart", () => {
    const base = withIds([rule("a"), rule("b"), rule("c"), rule("d"), rule("e")]);
    const [a, b, c, d] = base as [Rule, Rule, Rule, Rule, Rule];
    // Edit b, move d to the top, add x, delete e.
    const current = withIds([d, a, { ...b, enabled: false }, c, rule("x")]);

    expect(changesOf(current, base)).toEqual([
      ["d", "moved"],
      ["a", ""],
      ["b", "edited"],
      ["c", ""],
      ["x", "new"],
    ]);
    const d2 = diffRules(base, current);
    expect(d2.counts).toEqual({ new: 1, edited: 1, moved: 1, deleted: 1 });
    expect(d2.total).toBe(4);
  });

  it("marks one rule for one move, not its neighbours", () => {
    const base = withIds([rule("a"), rule("b"), rule("c"), rule("d")]);
    const [a, b, c, d] = base as [Rule, Rule, Rule, Rule];
    expect(changesOf([a, c, d, b], base)).toEqual([
      ["a", ""],
      ["c", ""],
      ["d", ""],
      ["b", "moved"],
    ]);
  });

  it("a rule can be both edited and moved", () => {
    const base = withIds([rule("a"), rule("b"), rule("c")]);
    const [a, b, c] = base as [Rule, Rule, Rule];
    expect(changesOf([{ ...c, name: "c2" }, a, b], base)[0]).toEqual(["c2", "edited+moved"]);
  });
});
