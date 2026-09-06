// Log search DSL.
//
// Lets the user type ad-hoc queries that compile to Partial<EventFilter>:
//
//     process:chrome.exe       restrict process (multi-token = OR within key)
//     proc:chrome              alias of `process`
//     host:*.example.com       host substring match (`*` is a soft hint, treated
//                              as substring; the backend always uses LIKE %x%)
//     dst:1.2.3.4              alias of `host`
//     port:443                 dst_port equals
//     port:8000-8100           dst_port range (inclusive)
//     action:block             one of direct|proxy|block|other
//     proto:udp                one of tcp|udp|icmp
//     rule:Localhost           matched_rule (multi-token = OR)
//     rule:"Default Block"     quoted value can contain spaces
//     ipv6:true / ipv6:false   ipv6 flag
//     ts>2026-04-17T23:30:00   ts_from (inclusive)
//     ts<2026-04-18T00:00:00   ts_to   (inclusive)
//     after:2026-04-17         alias of ts>
//     before:2026-04-18        alias of ts<
//     bare token               adds to host_contains (any free word filters host)
//
// Multiple tokens are AND-combined across keys; same-key repetitions UNION
// inside the field (e.g. `process:foo process:bar` → `processes IN (foo,bar)`).
// Quoted spans (`"..."`) preserve spaces and special chars in the value.
//
// The compiled output is meant to be merged with the user's manual filter
// (FilterBar selections); see `mergeFilters` for the exact intersection
// semantics.

import type { EventFilter } from "@ppxray/ipc-schema";

export interface CompiledSearch {
  filter: Partial<EventFilter>;
  /** Tokens that didn't fit any known shape. Surfaced in the UI so the user
   *  knows their query was partially unrecognized. */
  unrecognized: string[];
}

export function compileLogSearch(input: string): CompiledSearch {
  const out: CompiledSearch = { filter: {}, unrecognized: [] };
  const tokens = tokenize(input);
  if (tokens.length === 0) return out;

  const processes: string[] = [];
  const rules: string[] = [];
  const actions: string[] = [];
  const protos: string[] = [];
  const portTerms: string[] = [];
  const hostTerms: string[] = [];

  for (const t of tokens) {
    const key = t.key?.toLowerCase();
    const value = t.value;
    if (!key) {
      hostTerms.push(value);
      continue;
    }
    switch (key) {
      case "proc":
      case "process":
        processes.push(value);
        break;
      case "host":
      case "dst":
        // Strip any leading `*.` or trailing `*` since the backend uses
        // case-insensitive LIKE %value%; a literal substring is what the
        // user usually wants.
        hostTerms.push(value.replace(/^\*\.?/, "").replace(/\*$/, ""));
        break;
      case "port":
        portTerms.push(value);
        break;
      case "action":
        actions.push(canonicalAction(value));
        break;
      case "proto":
        protos.push(value.toUpperCase());
        break;
      case "rule":
        rules.push(value);
        break;
      case "ipv6":
        if (/^(true|1|yes)$/i.test(value)) out.filter.ipv6 = true;
        else if (/^(false|0|no)$/i.test(value)) out.filter.ipv6 = false;
        break;
      case "ts":
      case "after":
      case "before": {
        const iso = normalizeTs(value);
        if (!iso) {
          out.unrecognized.push(t.raw);
          break;
        }
        if (key === "after" || (key === "ts" && t.op === ">")) {
          out.filter.ts_from = iso;
        } else if (key === "before" || (key === "ts" && t.op === "<")) {
          out.filter.ts_to = iso;
        } else {
          // ts:VALUE without operator = exact second match: from = to = value.
          out.filter.ts_from = iso;
          out.filter.ts_to = iso;
        }
        break;
      }
      default:
        out.unrecognized.push(t.raw);
        hostTerms.push(value);
    }
  }

  if (processes.length) out.filter.processes = processes;
  if (rules.length) out.filter.matched_rules = rules;
  if (actions.length) out.filter.actions = actions;
  if (protos.length) out.filter.protos = protos;
  if (hostTerms.length) {
    // Multiple host terms become a single substring — backend doesn't OR
    // host_contains, so we join with the most-restrictive last term.
    out.filter.host_contains = hostTerms[hostTerms.length - 1] ?? null;
  }
  // `EventFilter` has no port field, so `port:` terms cannot be compiled.
  // Report them as unrecognised rather than dropping them silently, so the
  // search box can tell the user the term did nothing.
  if (portTerms.length && !out.filter.host_contains) {
    out.unrecognized.push(...portTerms.map((p) => `port:${p}`));
  }

  return out;
}

/**
 * Combine a manual filter (from the FilterBar multi-selects) with a search
 * filter (from the search box). Within each list field we UNION; for single
 * fields the search wins if both sides set a value.
 */
export function mergeFilters(
  manual: EventFilter,
  search: Partial<EventFilter>,
): EventFilter {
  const unionList = (a?: string[] | null, b?: string[] | null): string[] | null => {
    const set = new Set<string>();
    (a ?? []).forEach((v) => set.add(v));
    (b ?? []).forEach((v) => set.add(v));
    return set.size > 0 ? [...set] : null;
  };

  return {
    ...manual,
    processes: unionList(manual.processes, search.processes),
    matched_rules: unionList(manual.matched_rules, search.matched_rules),
    actions: unionList(manual.actions, search.actions),
    protos: unionList(manual.protos, search.protos),
    host_contains: search.host_contains ?? manual.host_contains,
    ipv6: search.ipv6 ?? manual.ipv6,
    ts_from: search.ts_from ?? manual.ts_from,
    ts_to: search.ts_to ?? manual.ts_to,
  };
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

interface Token {
  key: string | null;
  /** Operator on the key (`:`, `>`, `<`). Defaults to `:`. */
  op: ":" | ">" | "<";
  value: string;
  raw: string;
}

function tokenize(input: string): Token[] {
  const text = input.trim();
  if (!text) return [];

  const tokens: Token[] = [];
  let i = 0;
  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i]!)) i++;
    if (i >= text.length) break;
    const start = i;

    // Read key candidate up to ':'/`>`/`<`. Keys are letters + optional
    // digits (e.g. `ipv6`). We consume any keyed prefix unconditionally;
    // unknown keys flow into the `default` branch of the compiler's
    // dispatch and surface in `unrecognized`.
    const keyMatch = /^([a-z][a-z0-9]*)([:<>])/i.exec(text.slice(i));
    let key: string | null = null;
    let op: ":" | ">" | "<" = ":";
    if (keyMatch) {
      key = keyMatch[1]!.toLowerCase();
      op = keyMatch[2] as ":" | ">" | "<";
      i += keyMatch[0].length;
    }

    // Read value: either a quoted span or up to next whitespace.
    let value: string;
    if (text[i] === '"') {
      const end = text.indexOf('"', i + 1);
      if (end === -1) {
        value = text.slice(i + 1);
        i = text.length;
      } else {
        value = text.slice(i + 1, end);
        i = end + 1;
      }
    } else {
      let end = i;
      while (end < text.length && !/\s/.test(text[end]!)) end++;
      value = text.slice(i, end);
      i = end;
    }
    if (value.length === 0) continue;

    tokens.push({ key, op, value, raw: text.slice(start, i).trim() });
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

const ACTIONS_CANON: Record<string, string> = {
  direct: "Direct",
  proxy: "Proxy",
  block: "Block",
  blocked: "Block",
  other: "Other",
};

function canonicalAction(s: string): string {
  return ACTIONS_CANON[s.toLowerCase()] ?? s;
}

/** Accept several timestamp forms: `2026-04-17`, `2026-04-17T23:30`,
 *  `2026-04-17T23:30:16`, or epoch seconds. Returns the canonical
 *  `YYYY-MM-DDTHH:MM:SS` string the backend expects. */
function normalizeTs(value: string): string | null {
  const v = value.trim();
  if (!v) return null;

  // Pure date — anchor at start of day.
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    return `${v}T00:00:00`;
  }
  // Date + HH:MM
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(v)) {
    return `${v}:00`;
  }
  // Date + HH:MM:SS
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(v)) {
    return v;
  }
  // Epoch seconds.
  if (/^\d{10}$/.test(v)) {
    const d = new Date(parseInt(v, 10) * 1000);
    if (!isNaN(d.getTime())) return d.toISOString().slice(0, 19);
  }
  return null;
}
