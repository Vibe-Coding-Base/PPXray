// Simple search DSL for the rule list. Supports the following forms:
//
//     action:block                  rule action = block|direct|proxy|chain
//     enabled:true / enabled:false
//     port:443                      any listed port equals 443
//     host:*.nvidia.com             any target matches (glob, case-insensitive)
//     app:chrome.exe                any application matches (glob)
//     name:telemetry                rule name contains substring
//     <free text>                   matches name OR any target OR any app
//
// Tokens are whitespace-separated; a quoted span may contain spaces
// (e.g. `name:"apple iCloud"`). Unknown tokens fall back to free-text.
//
// The parser compiles to a single predicate `(rule) => boolean`. Missing the
// DSL is cheap — this file has no dependencies and no worker needed even
// for thousands of rules.

import type { Rule } from "@ppxray/ipc-schema";

export type RuleFilter = (rule: Rule) => boolean;

const KNOWN_KEYS = new Set([
  "action",
  "enabled",
  "port",
  "host",
  "target",
  "app",
  "application",
  "name",
]);

export function compileSearchDsl(input: string): RuleFilter {
  const tokens = tokenize(input);
  if (tokens.length === 0) return () => true;

  const predicates: RuleFilter[] = [];
  for (const token of tokens) {
    predicates.push(tokenToPredicate(token));
  }
  return (rule) => predicates.every((p) => p(rule));
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

interface Token {
  key: string | null;
  value: string;
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  const text = input.trim();
  if (!text) return tokens;

  let i = 0;
  while (i < text.length) {
    // Skip whitespace
    while (i < text.length && /\s/.test(text[i]!)) i++;
    if (i >= text.length) break;

    // Read key:value or bare value. Key is [a-z]+ then ':'
    const keyMatch = /^([a-z]+):/i.exec(text.slice(i));
    let key: string | null = null;
    if (keyMatch && KNOWN_KEYS.has(keyMatch[1]!.toLowerCase())) {
      key = keyMatch[1]!.toLowerCase();
      i += keyMatch[0].length;
    }

    // Value: quoted or bare
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
    if (value.length > 0) tokens.push({ key, value });
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Per-token predicate compilation
// ---------------------------------------------------------------------------

function tokenToPredicate(tok: Token): RuleFilter {
  switch (tok.key) {
    case "action":
      return actionPredicate(tok.value);
    case "enabled":
      return enabledPredicate(tok.value);
    case "port":
      return portPredicate(tok.value);
    case "host":
    case "target":
      return listGlobPredicate((r) => r.targets, tok.value);
    case "app":
    case "application":
      return listGlobPredicate((r) => r.applications, tok.value);
    case "name":
      return nameContainsPredicate(tok.value);
    default:
      return freeTextPredicate(tok.value);
  }
}

function actionPredicate(value: string): RuleFilter {
  const v = value.toLowerCase();
  return (r) => r.action.kind === v;
}

function enabledPredicate(value: string): RuleFilter {
  const truthy = /^(1|true|yes|on)$/i.test(value.trim());
  return (r) => r.enabled === truthy;
}

function portPredicate(value: string): RuleFilter {
  // value can be an exact port or a range
  return (r) =>
    r.ports.some((p) => portEntryMatches(p, value));
}

function listGlobPredicate(pick: (r: Rule) => string[], needle: string): RuleFilter {
  const lower = needle.toLowerCase();
  const usesGlob = needle.includes("*") || needle.includes("?");
  return (r) => {
    const items = pick(r);
    if (items.length === 0 && lower === "") return true;
    return items.some((entry) => {
      const e = entry.toLowerCase();
      if (usesGlob) return globMatch(lower, e);
      return e.includes(lower);
    });
  };
}

function nameContainsPredicate(value: string): RuleFilter {
  const needle = value.toLowerCase();
  return (r) => r.name.toLowerCase().includes(needle);
}

function freeTextPredicate(value: string): RuleFilter {
  const needle = value.toLowerCase();
  return (r) =>
    r.name.toLowerCase().includes(needle) ||
    r.targets.some((t) => t.toLowerCase().includes(needle)) ||
    r.applications.some((a) => a.toLowerCase().includes(needle));
}

// ---------------------------------------------------------------------------
// Helpers (kept local so this module has no runtime deps)
// ---------------------------------------------------------------------------

function portEntryMatches(entry: string, query: string): boolean {
  const q = query.trim();
  if (!q) return false;
  const rangeMatch = /^(\d+)\s*-\s*(\d+)$/.exec(entry.trim());
  if (rangeMatch) {
    const lo = parseInt(rangeMatch[1]!, 10);
    const hi = parseInt(rangeMatch[2]!, 10);
    // Allow exact numeric query or range-in-query
    const qRange = /^(\d+)\s*-\s*(\d+)$/.exec(q);
    if (qRange) {
      const qLo = parseInt(qRange[1]!, 10);
      const qHi = parseInt(qRange[2]!, 10);
      return lo <= qHi && hi >= qLo; // overlap
    }
    const qn = parseInt(q, 10);
    return !isNaN(qn) && qn >= lo && qn <= hi;
  }
  return entry.trim() === q;
}

/**
 * Shell-style glob: `*` = any run, `?` = one char. No escaping.
 * Both inputs expected in lowercase already.
 */
export function globMatch(pattern: string, text: string): boolean {
  const p = pattern;
  const t = text;
  let pi = 0;
  let ti = 0;
  let star = -1;
  let back = 0;
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === "?" || p[pi] === t[ti])) {
      pi++;
      ti++;
    } else if (pi < p.length && p[pi] === "*") {
      star = pi;
      back = ti;
      pi++;
    } else if (star !== -1) {
      pi = star + 1;
      back++;
      ti = back;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === "*") pi++;
  return pi === p.length;
}
