// Layout math for the Exposure Sankey. Separate from the React component so
// it can be unit-tested without a DOM.
//
// Columns, left to right: Rules, Ports, Exits, Proxy hops, Internet. Process
// context is a sublabel on each rule node rather than its own column — as a
// column it multiplied out to ~2000 overlapping flows on a 100-rule profile.
//
// Flows come in two tiers:
// - `ruleSegments`: one thin path per (rule, port), coloured by action and
//   port index so lanes sharing an exit stay distinguishable (~200).
// - `ribbons`: one thick band per (port, exit, hop_sequence), thickness being
//   the summed rule breadth, carrying its contributing rules for the popover
//   (~20-30).

import type {
  ExitChannel,
  ExposureGraph,
  PortGroup,
  ProcessBucket,
  ProxyHop,
  RuleRef,
} from "@ppxray/ipc-schema";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const COLUMN_LAYOUT = {
  rule: { x: 24, width: 240 },
  port: { x: 304, width: 96 },
  exit: { x: 440, width: 176 },
  hop: { x: 656, width: 208 },
  internet: { x: 904, width: 128 },
} as const;

export type ColumnId = keyof typeof COLUMN_LAYOUT;

const NODE_GAP = 8;
const RULE_NODE_HEIGHT = 44;
const SIMPLE_NODE_MIN_HEIGHT = 34;
const SIMPLE_NODE_MAX_HEIGHT = 90;
const TOP_PAD = 48;
const BOTTOM_PAD = 16;
export const HEADER_HEIGHT = 40;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface LaidOutNode {
  column: ColumnId;
  key: string;
  x: number;
  y: number;
  width: number;
  height: number;
  tag: NodeTag;
}

export type NodeTag =
  | { kind: "rule"; index: number; rule: RuleRef; context: RuleContext }
  | { kind: "port"; index: number; port: PortGroup }
  | { kind: "exit"; index: number; channel: ExitChannel }
  | { kind: "hop"; index: number; hop: ProxyHop }
  | { kind: "internet" };

/** Extra per-rule info computed from flows so the rule node label can show
 *  "applies to: firefox.exe, chrome.exe (+unlisted)" without needing to
 *  rescan the flow list. */
export interface RuleContext {
  matchingProcessLabels: string[];
  extraProcessCount: number;
  matchesUnlisted: boolean;
}

/** Thin per-rule segment from rule → port. One path per (rule, port). */
export interface RuleSegment {
  key: string;
  ruleRefIndex: number;
  portIndex: number;
  channelIndex: number;
  path: string;
  color: string;
  strokeWidth: number;
  opacity: number;
  isFirstMatch: boolean;
  touchedNodeKeys: string[];
}

/** Thick aggregated ribbon from port → exit → [hops →] internet. */
export interface Ribbon {
  key: string;
  portIndex: number;
  channelIndex: number;
  hopIndices: number[];
  /** Segments in order: port→exit, exit→hop[0], hop[i]→hop[i+1], last→internet.
   *  For Block channels the ribbon stops at the exit node (no internet hop). */
  segments: Array<{ path: string; width: number }>;
  color: string;
  opacity: number;
  totalBreadth: number;
  /** RuleRef indices (into graph.rules) contributing to this ribbon. */
  contributingRuleRefIndices: number[];
  terminatesAtBlock: boolean;
  touchedNodeKeys: string[];
}

export interface SankeyLayout {
  width: number;
  height: number;
  nodes: LaidOutNode[];
  ruleSegments: RuleSegment[];
  ribbons: Ribbon[];
  nodeByKey: Map<string, LaidOutNode>;
  /** Rule context map for external lookups (e.g. the rules table). */
  ruleContextByRefIndex: Map<number, RuleContext>;
}

// ---------------------------------------------------------------------------
// Node keys
// ---------------------------------------------------------------------------

export const nodeKey = {
  rule: (i: number) => `rule:${i}`,
  port: (i: number) => `port:${i}`,
  exit: (i: number) => `exit:${i}`,
  hop: (i: number) => `hop:${i}`,
  internet: () => `internet`,
};

// ---------------------------------------------------------------------------
// Layout entry point
// ---------------------------------------------------------------------------

export function layoutSankey(graph: ExposureGraph): SankeyLayout {
  const ruleContexts = buildRuleContexts(graph);

  // Per-column weights (sum of contributing flow breadths).
  const weights = columnWeights(graph);

  const ruleNodes = layoutColumn(
    "rule",
    graph.rules.map((rule, index) => ({
      key: nodeKey.rule(index),
      tag: {
        kind: "rule",
        index,
        rule,
        context: ruleContexts.get(index) ?? emptyRuleContext(),
      } as NodeTag,
      height: RULE_NODE_HEIGHT,
    })),
  );
  const portNodes = layoutColumn(
    "port",
    graph.ports.map((port, index) => ({
      key: nodeKey.port(index),
      tag: { kind: "port", index, port } as NodeTag,
      height: mapWeightToHeight(weights.port[index] ?? 0, weights.portMax),
    })),
  );
  const exitNodes = layoutColumn(
    "exit",
    graph.channels.map((channel, index) => ({
      key: nodeKey.exit(index),
      tag: { kind: "exit", index, channel } as NodeTag,
      height: mapWeightToHeight(weights.exit[index] ?? 0, weights.exitMax),
    })),
  );
  const hopNodes =
    graph.proxy_hops.length > 0
      ? layoutColumn(
          "hop",
          graph.proxy_hops.map((hop, index) => ({
            key: nodeKey.hop(index),
            tag: { kind: "hop", index, hop } as NodeTag,
            height: mapWeightToHeight(weights.hop[index] ?? 0, weights.hopMax),
          })),
        )
      : [];

  const maxColumnBottom = [ruleNodes, portNodes, exitNodes, hopNodes]
    .map((col) => (col.length === 0 ? TOP_PAD : col[col.length - 1].y + col[col.length - 1].height))
    .reduce((a, b) => Math.max(a, b), TOP_PAD);
  const sceneHeight = maxColumnBottom + BOTTOM_PAD;

  const internetNode: LaidOutNode = {
    column: "internet",
    key: nodeKey.internet(),
    x: COLUMN_LAYOUT.internet.x,
    y: TOP_PAD,
    width: COLUMN_LAYOUT.internet.width,
    height: sceneHeight - TOP_PAD - BOTTOM_PAD,
    tag: { kind: "internet" },
  };

  const nodes = [
    ...ruleNodes,
    ...portNodes,
    ...exitNodes,
    ...hopNodes,
    internetNode,
  ];
  const nodeByKey = new Map(nodes.map((n) => [n.key, n]));

  const ruleSegments = buildRuleSegments(graph, nodeByKey);
  const ribbons = buildRibbons(graph, nodeByKey);

  const width = COLUMN_LAYOUT.internet.x + COLUMN_LAYOUT.internet.width + 24;

  return {
    width,
    height: sceneHeight,
    nodes,
    ruleSegments,
    ribbons,
    nodeByKey,
    ruleContextByRefIndex: ruleContexts,
  };
}

// ---------------------------------------------------------------------------
// Rule context: which processes each rule matches.
// ---------------------------------------------------------------------------

function buildRuleContexts(graph: ExposureGraph): Map<number, RuleContext> {
  // rule_ref_index → set of process_index
  const perRule = new Map<number, Set<number>>();
  for (const f of graph.flows) {
    const set = perRule.get(f.rule_index) ?? new Set();
    set.add(f.process_index);
    perRule.set(f.rule_index, set);
  }

  const out = new Map<number, RuleContext>();
  for (const [ruleRefIdx, procSet] of perRule) {
    const indices = [...procSet];
    const listed: string[] = [];
    let matchesUnlisted = false;
    for (const i of indices) {
      const bucket = graph.processes[i];
      if (!bucket) continue;
      if (bucket.kind === "Unlisted") {
        matchesUnlisted = true;
      } else {
        listed.push(bucket.name);
      }
    }
    listed.sort();
    out.set(ruleRefIdx, {
      matchingProcessLabels: listed.slice(0, 3),
      extraProcessCount: Math.max(0, listed.length - 3),
      matchesUnlisted,
    });
  }
  return out;
}

function emptyRuleContext(): RuleContext {
  return { matchingProcessLabels: [], extraProcessCount: 0, matchesUnlisted: false };
}

/** Describe a rule context as a single label for UIs that can't do badges. */
export function describeRuleContext(ctx: RuleContext): string {
  const parts: string[] = [];
  if (ctx.matchingProcessLabels.length === 0 && !ctx.matchesUnlisted) {
    return "—";
  }
  if (ctx.matchingProcessLabels.length > 0) {
    parts.push(ctx.matchingProcessLabels.join(", "));
    if (ctx.extraProcessCount > 0) {
      parts.push(`+${ctx.extraProcessCount}`);
    }
  }
  if (ctx.matchesUnlisted) parts.push("+unlisted");
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// Column weights + node height mapping
// ---------------------------------------------------------------------------

interface ColumnWeights {
  port: number[];
  portMax: number;
  exit: number[];
  exitMax: number;
  hop: number[];
  hopMax: number;
}

function columnWeights(graph: ExposureGraph): ColumnWeights {
  const port = new Array<number>(graph.ports.length).fill(0);
  const exit = new Array<number>(graph.channels.length).fill(0);
  const hop = new Array<number>(graph.proxy_hops.length).fill(0);

  for (const f of graph.flows) {
    const contrib = Math.max(f.breadth, 0.1);
    if (port[f.port_index] != null) port[f.port_index] += contrib;
    if (exit[f.channel_index] != null) exit[f.channel_index] += contrib;
    const channel = graph.channels[f.channel_index];
    if (!channel) continue;
    const kind = channel.kind;
    if (kind.kind === "proxy") {
      const hi = graph.proxy_hops.findIndex((h) => h.proxy_id === kind.proxy_id);
      if (hi >= 0) hop[hi] += contrib;
    } else if (kind.kind === "chain") {
      const chain = graph.chain_descriptors.find((c) => c.chain_id === kind.chain_id);
      if (chain) {
        for (const idx of chain.hop_proxy_indices) {
          if (idx != null) hop[idx] += contrib;
        }
      }
    }
  }

  const max = (xs: number[]) => xs.reduce((a, b) => Math.max(a, b), 0);
  return {
    port,
    portMax: max(port),
    exit,
    exitMax: max(exit),
    hop,
    hopMax: max(hop),
  };
}

function mapWeightToHeight(weight: number, maxWeight: number): number {
  if (maxWeight <= 0) return SIMPLE_NODE_MIN_HEIGHT;
  const t = Math.min(1, weight / maxWeight);
  return SIMPLE_NODE_MIN_HEIGHT + (SIMPLE_NODE_MAX_HEIGHT - SIMPLE_NODE_MIN_HEIGHT) * t;
}

// ---------------------------------------------------------------------------
// Column layout — stack nodes top-down, natural heights.
// ---------------------------------------------------------------------------

interface ColumnNodeInput {
  key: string;
  tag: NodeTag;
  height: number;
}

function layoutColumn(column: ColumnId, nodes: ColumnNodeInput[]): LaidOutNode[] {
  if (nodes.length === 0) return [];
  const layout = COLUMN_LAYOUT[column];
  let cursor = TOP_PAD;
  return nodes.map((n) => {
    const h = Math.max(n.height, SIMPLE_NODE_MIN_HEIGHT);
    const laid: LaidOutNode = {
      column,
      key: n.key,
      x: layout.x,
      y: cursor,
      width: layout.width,
      height: h,
      tag: n.tag,
    };
    cursor += h + NODE_GAP;
    return laid;
  });
}

// ---------------------------------------------------------------------------
// Per-rule thin segments (rule → port)
// ---------------------------------------------------------------------------

function buildRuleSegments(
  graph: ExposureGraph,
  nodeByKey: Map<string, LaidOutNode>,
): RuleSegment[] {
  // Deduplicate by (rule_ref_index, port_index): the same rule-port pair can
  // appear multiple times across process buckets, but we already dropped the
  // processes column so we only want one thin line per (rule, port).
  const seen = new Set<string>();
  const out: RuleSegment[] = [];

  for (const flow of graph.flows) {
    const k = `${flow.rule_index}:${flow.port_index}`;
    if (seen.has(k)) continue;
    seen.add(k);

    const ruleNode = nodeByKey.get(nodeKey.rule(flow.rule_index));
    const portNode = nodeByKey.get(nodeKey.port(flow.port_index));
    if (!ruleNode || !portNode) continue;

    const rule = graph.rules[flow.rule_index];
    const actionKind = rule?.action.kind ?? "direct";
    const color = colorForFlow(actionKind, flow.port_index);
    const opacity = flow.is_first_match ? 0.7 : 0.22;
    const strokeWidth = Math.max(0.8, flow.breadth * 2.2 + 0.8);

    const seg = {
      x1: ruleNode.x + ruleNode.width,
      y1: ruleNode.y + ruleNode.height / 2,
      x2: portNode.x,
      y2: portNode.y + portNode.height / 2,
    };

    out.push({
      key: `rs-${k}`,
      ruleRefIndex: flow.rule_index,
      portIndex: flow.port_index,
      channelIndex: flow.channel_index,
      path: bezierHorizontal(seg),
      color,
      strokeWidth,
      opacity,
      isFirstMatch: flow.is_first_match,
      touchedNodeKeys: [ruleNode.key, portNode.key],
    });
  }

  return out;
}

// ---------------------------------------------------------------------------
// Aggregated ribbons (port → exit → hops → internet)
// ---------------------------------------------------------------------------

interface RibbonAggregate {
  portIndex: number;
  channelIndex: number;
  totalBreadth: number;
  contributingRules: Set<number>;
}

function buildRibbons(
  graph: ExposureGraph,
  nodeByKey: Map<string, LaidOutNode>,
): Ribbon[] {
  // Aggregate by (port, channel). Hop sequence is fully determined by channel,
  // so (port, channel) is enough.
  const agg = new Map<string, RibbonAggregate>();
  for (const flow of graph.flows) {
    // We only aggregate first-match flows into the ribbon. Shadowed flows
    // exist in the rule→port segment (to show the shadow) but don't
    // meaningfully contribute to "what actually reaches the Internet".
    if (!flow.is_first_match) continue;
    const k = `${flow.port_index}:${flow.channel_index}`;
    const entry =
      agg.get(k) ?? {
        portIndex: flow.port_index,
        channelIndex: flow.channel_index,
        totalBreadth: 0,
        contributingRules: new Set<number>(),
      };
    entry.totalBreadth += Math.max(flow.breadth, 0.1);
    entry.contributingRules.add(flow.rule_index);
    agg.set(k, entry);
  }

  const ribbons: Ribbon[] = [];
  const maxBreadth = [...agg.values()].reduce((a, b) => Math.max(a, b.totalBreadth), 0);

  for (const entry of agg.values()) {
    const portNode = nodeByKey.get(nodeKey.port(entry.portIndex));
    const exitNode = nodeByKey.get(nodeKey.exit(entry.channelIndex));
    const channel = graph.channels[entry.channelIndex];
    if (!portNode || !exitNode || !channel) continue;

    const hopIndices = resolveHopSequence(graph, channel);
    const terminatesAtBlock = channel.kind.kind === "block";
    const internetNode = nodeByKey.get(nodeKey.internet());

    const visited: LaidOutNode[] = [portNode, exitNode];
    for (const hi of hopIndices) {
      const hn = nodeByKey.get(nodeKey.hop(hi));
      if (hn) visited.push(hn);
    }
    if (!terminatesAtBlock && internetNode) visited.push(internetNode);

    // Ribbon width: 3..20 px mapped from breadth share.
    const widthBase = 3 + 17 * (maxBreadth > 0 ? entry.totalBreadth / maxBreadth : 0);

    const segments = [];
    for (let i = 0; i < visited.length - 1; i++) {
      const from = visited[i];
      const to = visited[i + 1];
      segments.push({
        path: bezierHorizontal({
          x1: from.x + from.width,
          y1: from.y + from.height / 2,
          x2: to.x,
          y2: to.y + to.height / 2,
        }),
        width: widthBase,
      });
    }

    ribbons.push({
      key: `ribbon-${entry.portIndex}-${entry.channelIndex}`,
      portIndex: entry.portIndex,
      channelIndex: entry.channelIndex,
      hopIndices,
      segments,
      color: colorForAction(channel.kind),
      opacity: 0.55,
      totalBreadth: entry.totalBreadth,
      contributingRuleRefIndices: [...entry.contributingRules].sort((a, b) => a - b),
      terminatesAtBlock,
      touchedNodeKeys: visited.map((v) => v.key),
    });
  }

  return ribbons;
}

function resolveHopSequence(graph: ExposureGraph, channel: ExitChannel): number[] {
  const kind = channel.kind;
  if (kind.kind === "proxy") {
    const target = graph.proxy_hops.findIndex((h) => h.proxy_id === kind.proxy_id);
    return target >= 0 ? [target] : [];
  }
  if (kind.kind === "chain") {
    const chain = graph.chain_descriptors.find((c) => c.chain_id === kind.chain_id);
    if (!chain) return [];
    const out: number[] = [];
    for (const idx of chain.hop_proxy_indices) {
      if (idx == null) break;
      out.push(idx);
    }
    return out;
  }
  return [];
}

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------

/** Base hue per action (HSL degrees). */
function baseHueForAction(kind: string): number {
  switch (kind) {
    case "direct":
      return 10; // red-orange
    case "block":
      return 210; // cool grey-blue
    case "proxy":
      return 35; // amber
    case "chain":
      return 280; // violet
    default:
      return 200;
  }
}

/** Per-rule thin segment colour: action hue + a small port-index shift so
 *  lanes sharing the same exit still look distinct. 6-step ladder; cycles
 *  every 6 ports, which is more than enough since typical profiles use
 *  <10 distinct port tokens. */
export function colorForFlow(actionKind: string, portIndex: number): string {
  const base = baseHueForAction(actionKind);
  const shift = (portIndex % 6) * 14;
  const hue = (base + shift) % 360;
  const sat = actionKind === "block" ? 10 : 68;
  const lightness = actionKind === "block" ? 52 : 58;
  return `hsl(${hue}, ${sat}%, ${lightness}%)`;
}

/** Aggregated ribbon colour: straight action colour, no port shift. */
export function colorForAction(kind: ExitChannel["kind"]): string {
  const hue = baseHueForAction(kind.kind);
  const sat = kind.kind === "block" ? 14 : 72;
  const lightness = kind.kind === "block" ? 48 : 58;
  return `hsl(${hue}, ${sat}%, ${lightness}%)`;
}

export function colorForProcess(bucket: ProcessBucket): string {
  return bucket.kind === "Unlisted" ? "#8a94a8" : "#6fb7ff";
}

export function colorForHop(hop: ProxyHop): string {
  return hop.is_encrypted ? "#ffb55a" : "#ff5c5c";
}

// ---------------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------------

function bezierHorizontal(seg: { x1: number; y1: number; x2: number; y2: number }): string {
  const midX = (seg.x1 + seg.x2) / 2;
  return `M${seg.x1},${seg.y1} C${midX},${seg.y1} ${midX},${seg.y2} ${seg.x2},${seg.y2}`;
}
