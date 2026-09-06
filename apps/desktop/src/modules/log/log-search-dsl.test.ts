import { describe, expect, it } from "vitest";

import { compileLogSearch, mergeFilters } from "./log-search-dsl";

describe("log search DSL", () => {
  it("returns empty filter on empty input", () => {
    const r = compileLogSearch("");
    expect(r.filter).toEqual({});
    expect(r.unrecognized).toEqual([]);
  });

  it("parses a single key:value", () => {
    expect(compileLogSearch("process:chrome.exe").filter).toEqual({
      processes: ["chrome.exe"],
    });
  });

  it("aliases proc / dst", () => {
    const r1 = compileLogSearch("proc:foo");
    expect(r1.filter.processes).toEqual(["foo"]);
    const r2 = compileLogSearch("dst:1.2.3.4");
    expect(r2.filter.host_contains).toBe("1.2.3.4");
  });

  it("UNIONs same-key tokens", () => {
    const r = compileLogSearch("process:a process:b rule:R1 rule:R2");
    expect(r.filter.processes).toEqual(["a", "b"]);
    expect(r.filter.matched_rules).toEqual(["R1", "R2"]);
  });

  it("strips wildcard prefixes/suffixes from host", () => {
    const r = compileLogSearch("host:*.nvidia.com");
    expect(r.filter.host_contains).toBe("nvidia.com");
  });

  it("canonicalizes action names", () => {
    expect(compileLogSearch("action:block").filter.actions).toEqual(["Block"]);
    expect(compileLogSearch("action:BLOCKED").filter.actions).toEqual(["Block"]);
    expect(compileLogSearch("action:direct").filter.actions).toEqual(["Direct"]);
  });

  it("uppercases protos", () => {
    expect(compileLogSearch("proto:udp").filter.protos).toEqual(["UDP"]);
  });

  it("ipv6 boolean", () => {
    expect(compileLogSearch("ipv6:true").filter.ipv6).toBe(true);
    expect(compileLogSearch("ipv6:false").filter.ipv6).toBe(false);
  });

  it("ts comparators", () => {
    const r = compileLogSearch("ts>2026-04-17 ts<2026-04-18");
    expect(r.filter.ts_from).toBe("2026-04-17T00:00:00");
    expect(r.filter.ts_to).toBe("2026-04-18T00:00:00");
  });

  it("after/before aliases", () => {
    const r = compileLogSearch("after:2026-04-17T01:02 before:2026-04-17T05:00:00");
    expect(r.filter.ts_from).toBe("2026-04-17T01:02:00");
    expect(r.filter.ts_to).toBe("2026-04-17T05:00:00");
  });

  it("quoted values keep spaces", () => {
    const r = compileLogSearch('rule:"Default Block Telemetry"');
    expect(r.filter.matched_rules).toEqual(["Default Block Telemetry"]);
  });

  it("bare token becomes host_contains", () => {
    const r = compileLogSearch("nvidia");
    expect(r.filter.host_contains).toBe("nvidia");
  });

  it("flags unrecognized keys", () => {
    const r = compileLogSearch("foo:bar");
    expect(r.unrecognized.length).toBeGreaterThan(0);
  });

  it("merges manual + search filter (UNION lists, search wins single)", () => {
    const manual = {
      processes: ["a"],
      matched_rules: null,
      actions: null,
      protos: null,
      host_contains: "manual",
      ipv6: null,
      ts_from: null,
      ts_to: null,
      limit: 500,
      offset: 0,
    };
    const search = compileLogSearch("process:b host:search").filter;
    const merged = mergeFilters(manual, search);
    expect(merged.processes).toEqual(["a", "b"]);
    expect(merged.host_contains).toBe("search");
  });
});
