import { describe, expect, it } from "vitest";

import type { Rule } from "@ppxray/ipc-schema";
import { compileSearchDsl } from "./search-dsl";

function r(patch: Partial<Rule>): Rule {
  return {
    enabled: true,
    name: "Test",
    action: { kind: "direct" },
    targets: [],
    applications: [],
    ports: [],
    ...patch,
  };
}

describe("search DSL", () => {
  it("matches everything on empty input", () => {
    const f = compileSearchDsl("");
    expect(f(r({}))).toBe(true);
  });

  it("free text searches name, targets, and apps", () => {
    const f = compileSearchDsl("telegram");
    expect(f(r({ name: "Telegram" }))).toBe(true);
    expect(f(r({ name: "x", targets: ["91.108.56.0/22"], applications: ["Telegram.exe"] })))
      .toBe(true);
    expect(f(r({ name: "x" }))).toBe(false);
  });

  it("action: filters by action kind", () => {
    const f = compileSearchDsl("action:block");
    expect(f(r({ action: { kind: "block" } }))).toBe(true);
    expect(f(r({ action: { kind: "direct" } }))).toBe(false);
  });

  it("enabled: filter is boolean", () => {
    const on = compileSearchDsl("enabled:true");
    const off = compileSearchDsl("enabled:false");
    expect(on(r({ enabled: true }))).toBe(true);
    expect(on(r({ enabled: false }))).toBe(false);
    expect(off(r({ enabled: false }))).toBe(true);
  });

  it("port: matches explicit and range entries", () => {
    const f = compileSearchDsl("port:443");
    expect(f(r({ ports: ["443"] }))).toBe(true);
    expect(f(r({ ports: ["80"] }))).toBe(false);
    expect(f(r({ ports: ["8000-9000"] }))).toBe(false);
    expect(f(r({ ports: ["400-500"] }))).toBe(true);
  });

  it("host: supports globs and is case-insensitive", () => {
    const f = compileSearchDsl("host:*.NVIDIA.com");
    expect(f(r({ targets: ["telemetry.nvidia.com"] }))).toBe(true);
    expect(f(r({ targets: ["cool.nvidia.com.attacker.xyz"] }))).toBe(false);
  });

  it("app: supports quoted values with spaces", () => {
    const f = compileSearchDsl(`app:"Program Files"`);
    expect(f(r({ applications: [String.raw`C:\Program Files\Mozilla\firefox.exe`] }))).toBe(true);
  });

  it("combines multiple tokens as AND", () => {
    const f = compileSearchDsl("action:block enabled:true");
    expect(f(r({ action: { kind: "block" }, enabled: true }))).toBe(true);
    expect(f(r({ action: { kind: "block" }, enabled: false }))).toBe(false);
    expect(f(r({ action: { kind: "direct" }, enabled: true }))).toBe(false);
  });

  it("unknown key treated as free text", () => {
    const f = compileSearchDsl("foo:bar");
    expect(f(r({ name: "foo:bar" }))).toBe(true);
  });
});
