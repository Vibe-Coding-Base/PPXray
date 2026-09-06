// Client-side validators that mirror the Rust classifiers in
// `crates/ppx-core/src/validate.rs`. We duplicate (small) logic here so the
// UI can mark invalid chips instantly without a round-trip to the host.

export type TargetKind =
  | "hostname"
  | "wildcard"
  | "ipv4"
  | "ipv6"
  | "ipv4-cidr"
  | "ipv6-cidr"
  | "ipv4-range"
  | "env"
  | "invalid";

export function classifyTarget(entry: string): TargetKind {
  const e = entry.trim();
  if (!e) return "invalid";
  if (e.startsWith("%") && e.endsWith("%") && e.length > 2) return "env";

  if (e.includes(":") && !e.includes("/") && looksLikeIpv6(e)) return "ipv6";
  if (e.includes("/")) {
    const [net, pre] = e.split("/", 2);
    if (pre !== undefined) {
      const p = parseInt(pre, 10);
      if (!Number.isNaN(p)) {
        if (net && looksLikeIpv6(net) && p <= 128) return "ipv6-cidr";
        if (net && looksLikeIpv4(net) && p <= 32) return "ipv4-cidr";
      }
    }
  }

  if (e.endsWith("*")) {
    const parts = e.split(".");
    if (parts.length >= 2 && parts.length <= 4 && parts[parts.length - 1] === "*") {
      const head = parts.slice(0, -1);
      if (head.every((p) => /^\d+$/.test(p) && parseInt(p, 10) <= 255)) return "ipv4-range";
    }
  }

  if (e.includes("*") || e.includes("?")) return "wildcard";

  if (looksLikeIpv4(e)) return "ipv4";
  if (looksLikeHostname(e)) return "hostname";
  return "invalid";
}

export function validatePort(entry: string): boolean {
  const s = entry.trim();
  if (!s) return false;
  const parseU16 = (t: string): number | null => {
    const n = parseInt(t.trim(), 10);
    if (Number.isNaN(n) || n <= 0 || n > 65535) return null;
    return n;
  };
  if (s.includes("-")) {
    const [a, b] = s.split("-", 2);
    if (a === undefined || b === undefined) return false;
    return parseU16(a) !== null && parseU16(b) !== null;
  }
  return parseU16(s) !== null;
}

export function validateApplication(entry: string): boolean {
  const e = entry.trim();
  if (!e) return false;
  return !/[<>|\r\n\t]/.test(e);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function looksLikeIpv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => p.length > 0 && /^\d+$/.test(p) && parseInt(p, 10) <= 255);
}

function looksLikeIpv6(s: string): boolean {
  if (!s.includes(":")) return false;
  if ((s.match(/::/g) ?? []).length > 1) return false;
  const core = s.split("%", 1)[0] ?? s;
  const groups = core.split(":");
  if (groups.length < 2) return false;
  return groups.every((g) => g === "" || (g.length <= 4 && /^[0-9a-fA-F]+$/.test(g)));
}

function looksLikeHostname(s: string): boolean {
  if (!s || s.length > 253) return false;
  return s.split(".").every((label) => {
    if (!label || label.length > 63) return false;
    if (!/^[a-zA-Z0-9_-]+$/.test(label)) return false;
    return !label.startsWith("-") && !label.endsWith("-");
  });
}
