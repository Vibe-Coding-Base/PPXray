// Flat tabular view of "which rule reaches Internet via which port + exit?"
//
// Direct answer to the question the Sankey only gestures at. Grouped by
// (exit channel, port). Click a row → pivot to the Rules tab with a
// `port:<N>` DSL filter so the user sees every rule sharing that port.
//
// One row per (rule × port-token × exit) lane. A rule with `[443, 80]`
// reaches Internet on two different ports → two distinct lanes shown.
//
// Layout uses CSS Grid with the shared `useColumnWidths` hook (same one
// driving the Rules + Log tables) so columns are user-resizable and the
// widths persist across launches.

import {
  Badge,
  Box,
  Checkbox,
  Group,
  ScrollArea,
  Stack,
  Text,
  TextInput,
  Tooltip,
  UnstyledButton,
} from "@mantine/core";
import { IconSearch } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import type { ExposureGraph } from "@ppxray/ipc-schema";

import {
  ColumnResizeHandle,
  useColumnWidths,
  type ColumnSpec,
} from "@/components/shell/ResizableColumns";
import { requestRulesSearch } from "@/modules/rules/cross-tab-search";

export interface RulesToInternetTableProps {
  graph: ExposureGraph;
  onFocusRule?: (ruleProfileIndex: number) => void;
}

/** Jump to the Rules tab with an applied DSL search.
 *
 *  We DON'T use `window.dispatchEvent` for the search query — RuleModule
 *  isn't mounted while we're sitting in the Exposure tab, so an event
 *  dispatched here would be consumed by no listener. The cross-tab-search
 *  module queues the query so the next mount of RuleModule picks it up.
 *  See `modules/rules/cross-tab-search.ts` for the full handoff. */
function pivotToRulesTab(dslQuery: string) {
  requestRulesSearch(dslQuery);
  window.dispatchEvent(new CustomEvent("proxifier:nav", { detail: "rules" }));
}

/** DSL-safe port token: ranges like `8000-8100` work as literal port
 *  matches in the search DSL (see `search-dsl.ts`). Empty / "any" tokens
 *  pivot without a port filter. */
function portToDslQuery(portLabel: string, isAny: boolean): string {
  if (isAny) return "";
  return `port:${portLabel.trim()}`;
}

// ---------------------------------------------------------------------------
// Column spec — shared across header + every body row + every group, so
// resizing once updates the whole table consistently.
// ---------------------------------------------------------------------------

const COLUMN_SPEC: ColumnSpec[] = [
  { id: "rule", label: "Rule", defaultWidth: 240, minWidth: 120 },
  { id: "port", label: "Port", defaultWidth: 96, minWidth: 60, maxWidth: 200 },
  { id: "apps", label: "Applications", defaultWidth: 320, minWidth: 120, fixed: true },
];

const ROW_PADDING_X = 8;
const ROW_PADDING_Y = 4;

// ---------------------------------------------------------------------------
// Data shape
// ---------------------------------------------------------------------------

interface TableRow {
  key: string;
  /** Rule index into `profile.rules` (not `graph.rules`). */
  ruleProfileIndex: number;
  ruleName: string;
  actionLabel: string;
  portLabel: string;
  portIsAny: boolean;
  exitLabel: string;
  exitKind: "direct" | "block" | "proxy" | "chain";
  reachesInternet: boolean;
  applications: string[];
  isFirstMatch: boolean;
}

// ---------------------------------------------------------------------------
// Top-level component
// ---------------------------------------------------------------------------

export function RulesToInternetTable({ graph, onFocusRule }: RulesToInternetTableProps) {
  const [q, setQ] = useState("");
  // Default: show every enabled rule. Heavily-shadowed profiles otherwise
  // hide ~90% of their rules and leave the user wondering where they went.
  const [hideShadowed, setHideShadowed] = useState(false);

  const cols = useColumnWidths("exposure-rules-table", COLUMN_SPEC);

  // Always build the full row set so count badges show real numbers; the
  // `hideShadowed` flag only filters what's rendered.
  const allRows = useMemo(() => buildRows(graph), [graph]);
  const visibleRows = useMemo(
    () => (hideShadowed ? allRows.filter((r) => r.isFirstMatch) : allRows),
    [allRows, hideShadowed],
  );

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return visibleRows;
    return visibleRows.filter(
      (r) =>
        r.ruleName.toLowerCase().includes(needle) ||
        r.portLabel.toLowerCase().includes(needle) ||
        r.exitLabel.toLowerCase().includes(needle) ||
        r.applications.some((a) => a.toLowerCase().includes(needle)),
    );
  }, [visibleRows, q]);

  const grouped = useMemo(() => groupByExit(filtered), [filtered]);

  const totalLanes = allRows.length;
  const effectiveLanes = allRows.filter((r) => r.isFirstMatch).length;
  const shadowedLanes = totalLanes - effectiveLanes;

  return (
    <Stack gap={6} p="xs" style={{ height: "100%", minHeight: 0 }}>
      <Group gap={6} wrap="nowrap">
        <Badge size="sm" variant="default">
          {totalLanes} lane{totalLanes === 1 ? "" : "s"}
        </Badge>
        <Badge size="sm" color="teal" variant="light">
          {effectiveLanes} effective
        </Badge>
        <Badge
          size="sm"
          color={shadowedLanes > 0 ? "yellow" : "gray"}
          variant="light"
          title={
            shadowedLanes > 0
              ? "Shadowed: rule is enabled but an earlier rule already covers this (rule, port) — it never wins a match."
              : "No shadowed rules in this profile."
          }
        >
          {shadowedLanes} shadowed
        </Badge>
      </Group>

      <Group gap="xs" wrap="nowrap">
        <TextInput
          size="xs"
          leftSection={<IconSearch size="1rem" />}
          placeholder="Filter rules / ports / apps…"
          value={q}
          onChange={(e) => setQ(e.currentTarget.value)}
          style={{ flex: 1 }}
        />
        <Checkbox
          size="xs"
          label="Hide shadowed"
          checked={hideShadowed}
          onChange={(e) => setHideShadowed(e.currentTarget.checked)}
        />
      </Group>
      <Text size="10" c="dimmed">
        Click a row → Rules tab filtered by that port - Click the position
        badge → open just that one rule - Drag the column borders to resize
      </Text>

      {/* Table area: shared header + scrollable body. */}
      <Box
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          border: "1px solid var(--ppxray-border)",
          borderRadius: 6,
          overflow: "hidden",
        }}
      >
        <HeaderRow cols={cols} />
        <ScrollArea
          type="auto"
          scrollbarSize={8}
          style={{ flex: 1, minHeight: 0 }}
        >
          <Box style={{ minWidth: cols.minRowWidth }}>
            {grouped.length === 0 && (
              <Text c="dimmed" size="xs" ta="center" py="md">
                No rules match this filter.
              </Text>
            )}
            {grouped.map((g) => (
              <GroupSection
                key={g.exitKey}
                group={g}
                template={cols.flexTemplate}
                onFocusRule={onFocusRule}
              />
            ))}
          </Box>
        </ScrollArea>
      </Box>
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// Header row — sticky at the top of the table area, owns the resize handles.
// ---------------------------------------------------------------------------

interface HeaderRowProps {
  cols: ReturnType<typeof useColumnWidths>;
}

function HeaderRow({ cols }: HeaderRowProps) {
  return (
    <Box
      style={{
        display: "grid",
        gridTemplateColumns: cols.flexTemplate,
        minWidth: cols.minRowWidth,
        background: "var(--ppxray-surface-strong)",
        borderBottom: "1px solid var(--ppxray-border-strong)",
        fontSize: "var(--ppxray-text-dense)",
        fontWeight: 600,
        color: "var(--ppxray-node-text-dim)",
        position: "sticky",
        top: 0,
        zIndex: 2,
      }}
    >
      {COLUMN_SPEC.map((spec, i) => (
        <Box
          key={spec.id}
          style={{
            position: "relative",
            padding: `${ROW_PADDING_Y + 2}px ${ROW_PADDING_X}px`,
            borderRight:
              i < COLUMN_SPEC.length - 1
                ? "1px solid var(--ppxray-border)"
                : undefined,
            userSelect: "none",
          }}
        >
          {spec.label}
          {!spec.fixed && (
            <ColumnResizeHandle
              className="ppxray-col-resize"
              currentWidth={cols.widths[i]}
              onResize={(w) => cols.setWidth(i, w)}
            />
          )}
        </Box>
      ))}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Group section — exit-channel group label + its rows.
// ---------------------------------------------------------------------------

interface GroupSectionProps {
  group: TableGroup;
  template: string;
  onFocusRule?: (ruleProfileIndex: number) => void;
}

function GroupSection({ group, template, onFocusRule }: GroupSectionProps) {
  const effective = group.rows.filter((r) => r.isFirstMatch).length;
  const shadowed = group.rows.length - effective;
  return (
    <Box>
      <Group
        gap={6}
        px={ROW_PADDING_X}
        py={6}
        style={{
          background: "var(--ppxray-surface)",
          borderTop: "1px solid var(--ppxray-row-divider)",
          borderBottom: "1px solid var(--ppxray-row-divider)",
          position: "sticky",
          top: 26, // sits below the column header
          zIndex: 1,
        }}
      >
        <Badge
          size="sm"
          color={badgeColor(group.exitKind)}
          variant={group.exitKind === "block" ? "light" : "filled"}
        >
          {group.exitLabel}
        </Badge>
        <Text size="xs" c="dimmed">
          {effective} effective
          {shadowed > 0 ? ` - ${shadowed} shadowed` : ""}
          {group.reachesInternet ? " → Internet" : " - terminates"}
        </Text>
      </Group>
      {group.rows.map((row) => (
        <RowView
          key={row.key}
          row={row}
          template={template}
          onFocusRule={onFocusRule}
        />
      ))}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Body row — one (rule × port × exit) lane.
// ---------------------------------------------------------------------------

interface RowViewProps {
  row: TableRow;
  template: string;
  onFocusRule?: (ruleProfileIndex: number) => void;
}

function RowView({ row, template, onFocusRule }: RowViewProps) {
  /** Row click → jump to Rules tab with `port:<N>` DSL filter applied so
   *  the user sees every rule touching that port. This is the primary
   *  use case: "show me all rules reaching Internet on port 80".
   *
   *  Position badge → open just that one rule (escape hatch for when the
   *  user wants to drill into a single rule from the lane). Stays on the
   *  Exposure tab so the map context is preserved. */
  const pivotByPort = (e: React.MouseEvent) => {
    e.stopPropagation();
    pivotToRulesTab(portToDslQuery(row.portLabel, row.portIsAny));
  };
  const focusSingleRule = (e: React.MouseEvent) => {
    e.stopPropagation();
    onFocusRule?.(row.ruleProfileIndex);
  };

  const appsTooltip =
    row.applications.length > 0 ? row.applications.join("\n") : "any process";

  return (
    <UnstyledButton
      component="div"
      onClick={pivotByPort}
      style={{
        display: "grid",
        gridTemplateColumns: template,
        alignItems: "center",
        cursor: "pointer",
        borderBottom: "1px solid var(--ppxray-row-divider)",
        fontSize: "var(--ppxray-text-dense)",
      }}
      title="Click anywhere → Rules tab filtered by this port - Click the # badge → open just this rule"
    >
      {/* Rule cell */}
      <Box
        style={{
          padding: `${ROW_PADDING_Y}px ${ROW_PADDING_X}px`,
          display: "flex",
          alignItems: "center",
          gap: 6,
          minWidth: 0,
        }}
      >
        <Tooltip label="Open just this rule (no port filter)" withArrow openDelay={300}>
          <Badge
            variant="default"
            onClick={focusSingleRule}
            style={{
              fontVariantNumeric: "tabular-nums",
              flexShrink: 0,
              cursor: "pointer",
            }}
          >
            {row.ruleProfileIndex + 1}
          </Badge>
        </Tooltip>
        <Text
          size="xs"
          lineClamp={1}
          style={{
            color: row.isFirstMatch
              ? "var(--ppxray-node-text)"
              : "var(--ppxray-node-text-dim)",
            textDecoration: row.isFirstMatch ? "none" : "line-through",
            flex: 1,
            minWidth: 0,
          }}
        >
          {row.ruleName}
        </Text>
        {!row.isFirstMatch && (
          <Tooltip
            label="An earlier rule already covers this (rule, port) — this rule never wins a match"
            multiline
            maw={260}
            position="left"
            withArrow
          >
            <Badge
              color="yellow"
              variant="light"
              style={{ flexShrink: 0 }}
            >
              shadowed
            </Badge>
          </Tooltip>
        )}
      </Box>

      {/* Port cell */}
      <Box
        style={{
          padding: `${ROW_PADDING_Y}px ${ROW_PADDING_X}px`,
          fontVariantNumeric: "tabular-nums",
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {row.portLabel}
      </Box>

      {/* Applications cell */}
      <Box
        style={{
          padding: `${ROW_PADDING_Y}px ${ROW_PADDING_X}px`,
          minWidth: 0,
        }}
      >
        <Tooltip
          label={appsTooltip}
          multiline
          maw={320}
          position="left"
          openDelay={200}
          withArrow
          style={{ whiteSpace: "pre-line" }}
        >
          <Text size="xs" c="dimmed" lineClamp={1}>
            {row.applications.length > 0
              ? row.applications.join(", ")
              : "any process"}
          </Text>
        </Tooltip>
      </Box>
    </UnstyledButton>
  );
}

// ---------------------------------------------------------------------------
// Data construction
// ---------------------------------------------------------------------------

function buildRows(graph: ExposureGraph): TableRow[] {
  // Emit one row per (rule × port × exit) lane. A lane is considered
  // EFFECTIVE if at least one of its underlying per-process flows has
  // is_first_match=true — that means there exists some process for which
  // this rule wins on this port. Otherwise the lane is dead (fully
  // shadowed across every process bucket that even reaches it).
  const byKey = new Map<string, TableRow>();

  for (const flow of graph.flows) {
    const rule = graph.rules[flow.rule_index];
    const port = graph.ports[flow.port_index];
    const channel = graph.channels[flow.channel_index];
    if (!rule || !port || !channel) continue;

    const key = `${rule.index}:${flow.port_index}:${flow.channel_index}`;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.isFirstMatch && flow.is_first_match) {
        existing.isFirstMatch = true;
      }
      continue;
    }

    const procNames = collectProcesses(
      graph,
      rule.index,
      flow.port_index,
      flow.channel_index,
    );
    byKey.set(key, {
      key,
      ruleProfileIndex: rule.index,
      ruleName: rule.name,
      actionLabel: actionWord(rule.action.kind),
      portLabel: port.label,
      portIsAny: port.is_any,
      exitLabel: channel.label,
      exitKind: channel.kind.kind,
      reachesInternet: channel.kind.kind !== "block",
      applications: procNames,
      isFirstMatch: flow.is_first_match,
    });
  }

  const rows = [...byKey.values()];
  rows.sort((a, b) => {
    if (a.ruleProfileIndex !== b.ruleProfileIndex) {
      return a.ruleProfileIndex - b.ruleProfileIndex;
    }
    if (a.portLabel !== b.portLabel) return a.portLabel.localeCompare(b.portLabel);
    return a.exitLabel.localeCompare(b.exitLabel);
  });

  return rows;
}

function collectProcesses(
  graph: ExposureGraph,
  ruleProfileIndex: number,
  portIndex: number,
  channelIndex: number,
): string[] {
  const ruleRefPos = graph.rules.findIndex((r) => r.index === ruleProfileIndex);
  if (ruleRefPos < 0) return [];
  const names: string[] = [];
  let unlisted = false;
  for (const f of graph.flows) {
    if (
      f.rule_index === ruleRefPos &&
      f.port_index === portIndex &&
      f.channel_index === channelIndex
    ) {
      const b = graph.processes[f.process_index];
      if (!b) continue;
      if (b.kind === "Unlisted") unlisted = true;
      else if (!names.includes(b.name)) names.push(b.name);
    }
  }
  names.sort();
  if (unlisted) names.push("(unlisted)");
  return names;
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

interface TableGroup {
  exitKey: string;
  exitLabel: string;
  exitKind: "direct" | "block" | "proxy" | "chain";
  reachesInternet: boolean;
  rows: TableRow[];
}

function groupByExit(rows: TableRow[]): TableGroup[] {
  const map = new Map<string, TableGroup>();
  const order = ["direct", "proxy", "chain", "block"] as const;

  for (const r of rows) {
    const key = `${r.exitKind}:${r.exitLabel}`;
    let g = map.get(key);
    if (!g) {
      g = {
        exitKey: key,
        exitLabel: r.exitLabel,
        exitKind: r.exitKind,
        reachesInternet: r.reachesInternet,
        rows: [],
      };
      map.set(key, g);
    }
    g.rows.push(r);
  }

  return [...map.values()].sort((a, b) => {
    const ai = order.indexOf(a.exitKind);
    const bi = order.indexOf(b.exitKind);
    if (ai !== bi) return ai - bi;
    return a.exitLabel.localeCompare(b.exitLabel);
  });
}

function badgeColor(kind: "direct" | "block" | "proxy" | "chain"): string {
  switch (kind) {
    case "direct":
      return "orange";
    case "block":
      return "gray";
    case "proxy":
      return "yellow";
    case "chain":
      return "violet";
  }
}

function actionWord(kind: string): string {
  switch (kind) {
    case "direct":
      return "Direct";
    case "block":
      return "Block";
    case "proxy":
      return "Proxy";
    case "chain":
      return "Chain";
    default:
      return kind;
  }
}
