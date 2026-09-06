// SVG Sankey visualisation for the Exposure Surface tab.
//
// Two render layers:
//  1. Ribbons — thick aggregated bands for port → exit → hops → internet.
//     One per unique path (typically ~20-30 for a 100-rule profile).
//  2. Rule segments — thin per-rule lines for rule → port.
//     One per (rule, port) — typically ~200 for a 100-rule profile.
//
// Interaction:
//  • Wheel            — zoom around cursor
//  • Drag background  — pan
//  • Hover node/line  — cross-highlight; unrelated lines dim
//  • Click rule node  — pivot to rule editor + isolate
//  • Click ribbon     — popover listing the contributing rules
//  • Toolbar          — zoom in/out, fit-to-screen, reset
//
// Colours are CSS custom properties (see `styles/global.css`) so the scene
// follows the Mantine light/dark theme.

import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";

import {
  ActionIcon,
  Anchor,
  Group,
  Popover,
  Stack,
  Text,
  Tooltip,
  rem,
} from "@mantine/core";
import {
  IconArrowsMaximize,
  IconExternalLink,
  IconRefresh,
  IconZoomIn,
  IconZoomOut,
} from "@tabler/icons-react";

import type { ExposureGraph } from "@ppxray/ipc-schema";

import {
  COLUMN_LAYOUT,
  HEADER_HEIGHT,
  colorForAction,
  colorForHop,
  colorForProcess,
  describeRuleContext,
  layoutSankey,
  nodeKey,
  type LaidOutNode,
  type NodeTag,
  type Ribbon,
  type SankeyLayout,
} from "./sankey-layout";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ExposureSankeyProps {
  graph: ExposureGraph;
  isolatedNodeKey?: string;
  onHover?: (node: LaidOutNode | null) => void;
  onPickRule?: (ruleProfileIndex: number) => void;
  onPickIsolation?: (key: string | undefined) => void;
}

interface Transform {
  k: number;
  tx: number;
  ty: number;
}

const MIN_ZOOM = 0.15;
const MAX_ZOOM = 4;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ExposureSankey({
  graph,
  isolatedNodeKey,
  onHover,
  onPickRule,
  onPickIsolation,
}: ExposureSankeyProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ w: 800, h: 600 });
  const [transform, setTransform] = useState<Transform>({ k: 1, tx: 0, ty: 0 });
  const [hoverKey, setHoverKey] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [ribbonPopover, setRibbonPopover] = useState<{
    ribbon: Ribbon;
    clientX: number;
    clientY: number;
  } | null>(null);

  useLayoutEffect(() => {
    const el = wrapperRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        setViewport({
          w: Math.max(300, Math.round(e.contentRect.width)),
          h: Math.max(200, Math.round(e.contentRect.height)),
        });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const layout = useMemo(() => layoutSankey(graph), [graph]);

  const fingerprint = `${layout.width}x${layout.height}|${viewport.w}x${viewport.h}|${graph.flows.length}`;
  const lastFitFingerprint = useRef<string>("");
  useLayoutEffect(() => {
    if (lastFitFingerprint.current === fingerprint) return;
    lastFitFingerprint.current = fingerprint;
    setTransform(fitTransform(layout, viewport));
  }, [fingerprint, layout, viewport]);

  const highlightKey = isolatedNodeKey ?? hoverKey;

  const relatedKeys = useMemo(() => {
    if (!highlightKey) return null;
    const set = new Set<string>([highlightKey]);
    for (const rs of layout.ruleSegments) {
      if (rs.touchedNodeKeys.includes(highlightKey)) {
        rs.touchedNodeKeys.forEach((k) => set.add(k));
      }
    }
    for (const rb of layout.ribbons) {
      if (rb.touchedNodeKeys.includes(highlightKey)) {
        rb.touchedNodeKeys.forEach((k) => set.add(k));
      }
    }
    return set;
  }, [highlightKey, layout.ribbons, layout.ruleSegments]);

  const isRelated = useCallback(
    (key: string): boolean => (relatedKeys == null ? true : relatedKeys.has(key)),
    [relatedKeys],
  );
  const anyTouchedRelated = useCallback(
    (keys: string[]): boolean =>
      relatedKeys == null ? true : keys.some((k) => relatedKeys.has(k)),
    [relatedKeys],
  );

  // --- pan + zoom ---------------------------------------------------------

  const onWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    e.preventDefault();
    const rect = wrapperRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    setTransform((t) => {
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
      const newK = clamp(t.k * factor, MIN_ZOOM, MAX_ZOOM);
      const wx = (mx - t.tx) / t.k;
      const wy = (my - t.ty) / t.k;
      return { k: newK, tx: mx - wx * newK, ty: my - wy * newK };
    });
  }, []);

  const dragRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const onMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const target = e.target as SVGElement | HTMLElement;
      if ((target as HTMLElement).dataset?.pan !== "bg") return;
      dragRef.current = { x: e.clientX, y: e.clientY, tx: transform.tx, ty: transform.ty };
      setDragging(true);
    },
    [transform.tx, transform.ty],
  );
  const onMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const d = dragRef.current;
    if (!d) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    setTransform((t) => ({ ...t, tx: d.tx + dx, ty: d.ty + dy }));
  }, []);
  const endDrag = useCallback(() => {
    dragRef.current = null;
    setDragging(false);
  }, []);

  const zoomAtCentre = (factor: number) => {
    const cx = viewport.w / 2;
    const cy = viewport.h / 2;
    setTransform((t) => {
      const newK = clamp(t.k * factor, MIN_ZOOM, MAX_ZOOM);
      const wx = (cx - t.tx) / t.k;
      const wy = (cy - t.ty) / t.k;
      return { k: newK, tx: cx - wx * newK, ty: cy - wy * newK };
    });
  };
  const zoomIn = () => zoomAtCentre(1.2);
  const zoomOut = () => zoomAtCentre(1 / 1.2);
  const fitToScreen = () => setTransform(fitTransform(layout, viewport));
  const resetZoom = () => setTransform({ k: 1, tx: 8, ty: 8 });

  // --- render -------------------------------------------------------------

  return (
    <div
      ref={wrapperRef}
      onWheel={onWheel}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={endDrag}
      onMouseLeave={endDrag}
      style={{
        position: "relative",
        height: "100%",
        width: "100%",
        background: "var(--ppxray-scene-bg)",
        overflow: "hidden",
        cursor: dragging ? "grabbing" : "grab",
        userSelect: "none",
      }}
    >
      <svg
        width={viewport.w}
        height={viewport.h}
        viewBox={`0 0 ${viewport.w} ${viewport.h}`}
        // Set explicitly rather than relying on inheritance: every <text> in
        // here is sized in rem and has to pick up the same family the rest of
        // the app uses, or this tab reads as a different program.
        style={{ display: "block", fontFamily: "var(--ppxray-font)" }}
      >
        <rect
          x={0}
          y={0}
          width={viewport.w}
          height={viewport.h}
          fill="transparent"
          data-pan="bg"
        />
        <defs>
          <linearGradient id="internet-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--ppxray-internet-grad-start)" />
            <stop offset="60%" stopColor="var(--ppxray-internet-grad-mid)" />
            <stop offset="100%" stopColor="var(--ppxray-internet-grad-end)" />
          </linearGradient>
        </defs>

        <g transform={`translate(${transform.tx} ${transform.ty}) scale(${transform.k})`}>
          <rect
            x={COLUMN_LAYOUT.internet.x - 20}
            y={0}
            width={COLUMN_LAYOUT.internet.width + 40}
            height={layout.height}
            fill="url(#internet-grad)"
            data-pan="bg"
          />
          <ColumnHeaders />

          {/* Ribbon layer — drawn first, behind everything else. */}
          <g>
            {layout.ribbons.map((ribbon) => {
              const related = anyTouchedRelated(ribbon.touchedNodeKeys);
              const opacity = related ? ribbon.opacity : ribbon.opacity * 0.15;
              return (
                <g
                  key={ribbon.key}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() =>
                    setHoverKey(nodeKey.exit(ribbon.channelIndex))
                  }
                  onMouseLeave={() => setHoverKey(null)}
                  onClick={(e) => {
                    e.stopPropagation();
                    const rect = wrapperRef.current?.getBoundingClientRect();
                    setRibbonPopover({
                      ribbon,
                      clientX: e.clientX - (rect?.left ?? 0),
                      clientY: e.clientY - (rect?.top ?? 0),
                    });
                  }}
                >
                  {ribbon.segments.map((seg, j) => (
                    <path
                      key={`${ribbon.key}-s${j}`}
                      d={seg.path}
                      fill="none"
                      stroke={ribbon.color}
                      strokeWidth={seg.width}
                      strokeOpacity={opacity}
                      strokeLinecap="round"
                    />
                  ))}
                </g>
              );
            })}
          </g>

          {/* Rule-to-port thin segments. */}
          <g style={{ pointerEvents: "none" }}>
            {layout.ruleSegments.map((rs) => {
              const related = anyTouchedRelated(rs.touchedNodeKeys);
              const opacity = related ? rs.opacity : rs.opacity * 0.15;
              return (
                <path
                  key={rs.key}
                  d={rs.path}
                  fill="none"
                  stroke={rs.color}
                  strokeWidth={rs.strokeWidth}
                  strokeOpacity={opacity}
                  strokeLinecap="round"
                />
              );
            })}
          </g>

          {/* Nodes on top. */}
          <g>
            {layout.nodes.map((node) => (
              <NodeView
                key={node.key}
                node={node}
                dim={!isRelated(node.key)}
                emphasized={highlightKey === node.key}
                onHover={(n) => {
                  setHoverKey(n?.key ?? null);
                  onHover?.(n);
                }}
                onClick={(n) => {
                  if (n.tag.kind === "rule") onPickRule?.(n.tag.rule.index);
                  onPickIsolation?.(n.key);
                }}
              />
            ))}
          </g>
        </g>
      </svg>

      {/* Ribbon popover — lists contributing rules. */}
      {ribbonPopover && (
        <RibbonPopover
          ribbon={ribbonPopover.ribbon}
          graph={graph}
          x={ribbonPopover.clientX}
          y={ribbonPopover.clientY}
          layout={layout}
          onClose={() => setRibbonPopover(null)}
          onPickRule={(idx) => {
            onPickRule?.(idx);
            setRibbonPopover(null);
          }}
        />
      )}

      {/* Zoom toolbar — bottom-right. */}
      <Group
        gap={4}
        style={{
          position: "absolute",
          right: 12,
          bottom: 12,
          padding: 4,
          borderRadius: 6,
          background: "var(--ppxray-surface-elevated)",
          border: "1px solid var(--ppxray-border)",
        }}
      >
        <Tooltip label="Zoom in" withArrow>
          <ActionIcon variant="subtle" onClick={zoomIn} aria-label="Zoom in">
            <IconZoomIn size="1.1rem" />
          </ActionIcon>
        </Tooltip>
        <Tooltip label="Zoom out" withArrow>
          <ActionIcon variant="subtle" onClick={zoomOut} aria-label="Zoom out">
            <IconZoomOut size="1.1rem" />
          </ActionIcon>
        </Tooltip>
        <Tooltip label="Fit to screen" withArrow>
          <ActionIcon variant="subtle" onClick={fitToScreen} aria-label="Fit to screen">
            <IconArrowsMaximize size="1.1rem" />
          </ActionIcon>
        </Tooltip>
        <Tooltip label="Reset zoom (1×)" withArrow>
          <ActionIcon variant="subtle" onClick={resetZoom} aria-label="Reset zoom">
            <IconRefresh size="1.1rem" />
          </ActionIcon>
        </Tooltip>
        <span
          style={{
            fontSize: "var(--ppxray-text-dense)",
            color: "var(--ppxray-scene-header-sub)",
            padding: "0 6px",
            minWidth: rem(40),
            textAlign: "right",
          }}
        >
          {Math.round(transform.k * 100)}%
        </span>
      </Group>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Ribbon popover — click a ribbon to see the rules feeding it.
// ---------------------------------------------------------------------------

interface RibbonPopoverProps {
  ribbon: Ribbon;
  graph: ExposureGraph;
  layout: SankeyLayout;
  x: number;
  y: number;
  onClose: () => void;
  onPickRule: (ruleProfileIndex: number) => void;
}

function RibbonPopover({
  ribbon,
  graph,
  layout,
  x,
  y,
  onClose,
  onPickRule,
}: RibbonPopoverProps) {
  const port = graph.ports[ribbon.portIndex];
  const channel = graph.channels[ribbon.channelIndex];
  const contributing = ribbon.contributingRuleRefIndices
    .map((i) => graph.rules[i])
    .filter(Boolean);

  return (
    <Popover
      opened
      onClose={onClose}
      position="right"
      withArrow
      shadow="md"
      withinPortal
    >
      <Popover.Target>
        <div
          style={{
            position: "absolute",
            left: x,
            top: y,
            width: rem(1),
            height: rem(1),
            pointerEvents: "none",
          }}
        />
      </Popover.Target>
      <Popover.Dropdown p="xs" style={{ maxWidth: rem(360) }}>
        <Stack gap={6}>
          <Text size="xs" c="dimmed">
            Port <b>{port?.label ?? "?"}</b> → <b>{channel?.label ?? "?"}</b>
            {ribbon.terminatesAtBlock ? " (blocks)" : " → Internet"}
          </Text>
          <Text size="xs" fw={600}>
            {contributing.length} rule{contributing.length === 1 ? "" : "s"} feed
            this lane
          </Text>
          <Stack gap={2}>
            {contributing.slice(0, 12).map((r) => {
              const ctx = layout.ruleContextByRefIndex.get(
                ribbon.contributingRuleRefIndices.find(
                  (ri) => graph.rules[ri] === r,
                ) ?? -1,
              );
              return (
                <Anchor
                  key={r.index}
                  size="xs"
                  onClick={() => onPickRule(r.index)}
                  style={{ cursor: "pointer" }}
                >
                  <Group gap={4} wrap="nowrap">
                    <IconExternalLink size="0.8rem" />
                    <span>
                      #{r.index + 1} {r.name}
                    </span>
                    {ctx && (
                      <Text span size="xs" c="dimmed">
                        - {describeRuleContext(ctx)}
                      </Text>
                    )}
                  </Group>
                </Anchor>
              );
            })}
            {contributing.length > 12 && (
              <Text size="xs" c="dimmed">
                + {contributing.length - 12} more
              </Text>
            )}
          </Stack>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}

// ---------------------------------------------------------------------------
// Fit-to-screen math
// ---------------------------------------------------------------------------

function fitTransform(layout: SankeyLayout, viewport: { w: number; h: number }): Transform {
  const margin = 24;
  const kx = (viewport.w - margin * 2) / layout.width;
  const ky = (viewport.h - margin * 2) / layout.height;
  const k = clamp(Math.min(kx, ky), MIN_ZOOM, 1);
  const tx = (viewport.w - layout.width * k) / 2;
  const ty = (viewport.h - layout.height * k) / 2;
  return { k, tx, ty };
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

// ---------------------------------------------------------------------------
// Column headers inside the transform group
// ---------------------------------------------------------------------------

function ColumnHeaders() {
  const headers: { id: keyof typeof COLUMN_LAYOUT; label: string; sub: string }[] = [
    { id: "rule", label: "Rules", sub: "what catches traffic" },
    { id: "port", label: "Ports", sub: "target port" },
    { id: "exit", label: "Exits", sub: "Direct / Block / Proxy" },
    { id: "hop", label: "Proxy hops", sub: "if any" },
    { id: "internet", label: "Internet", sub: "outside" },
  ];
  return (
    <g>
      {headers.map((h) => {
        const c = COLUMN_LAYOUT[h.id];
        const cx = c.x + c.width / 2;
        return (
          <g key={h.id} transform={`translate(${cx}, 0)`} pointerEvents="none">
            <text
              x={0}
              y={HEADER_HEIGHT / 2 - 4}
              textAnchor="middle"
              fontSize="var(--ppxray-text-dense)"
              fontWeight={600}
              fill="var(--ppxray-scene-header-title)"
            >
              {h.label}
            </text>
            <text
              x={0}
              y={HEADER_HEIGHT / 2 + 10}
              textAnchor="middle"
              fontSize="var(--ppxray-text-caption)"
              fill="var(--ppxray-scene-header-sub)"
            >
              {h.sub}
            </text>
          </g>
        );
      })}
    </g>
  );
}

// ---------------------------------------------------------------------------
// Node renderer
// ---------------------------------------------------------------------------

interface NodeViewProps {
  node: LaidOutNode;
  dim: boolean;
  emphasized: boolean;
  onHover: (n: LaidOutNode | null) => void;
  onClick: (n: LaidOutNode) => void;
}

function NodeView({ node, dim, emphasized, onHover, onClick }: NodeViewProps) {
  const { stroke, warn } = strokeFor(node.tag);
  const opacity = dim ? 0.35 : 1;
  const strokeWidth = emphasized ? 2.5 : 1.2;
  const { primary, secondary } = labelsFor(node.tag);
  const isInternet = node.tag.kind === "internet";

  return (
    <g
      transform={`translate(${node.x}, ${node.y})`}
      style={{ cursor: isInternet ? "default" : "pointer" }}
      onMouseEnter={() => onHover(node)}
      onMouseLeave={() => onHover(null)}
      onClick={(e) => {
        if (isInternet) return;
        e.stopPropagation();
        onClick(node);
      }}
      opacity={opacity}
    >
      <rect
        width={node.width}
        height={node.height}
        rx={6}
        ry={6}
        fill={isInternet ? "transparent" : "var(--ppxray-node-fill)"}
        stroke={warn ? "#ffce4a" : stroke}
        strokeWidth={strokeWidth}
      />
      <foreignObject x={0} y={0} width={node.width} height={node.height}>
        <div
          style={{
            width: "100%",
            height: "100%",
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            padding: "2px 8px",
            fontFamily: "var(--ppxray-font)",
            overflow: "hidden",
            textAlign: node.tag.kind === "port" ? "center" : "left",
            pointerEvents: "none",
          }}
        >
          <div
            style={{
              color: "var(--ppxray-node-text)",
              fontSize: "var(--ppxray-text-dense)",
              fontWeight: 600,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {primary}
          </div>
          {secondary && (
            <div
              style={{
                color: "var(--ppxray-node-text-dim)",
                fontSize: "var(--ppxray-text-caption)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {secondary}
            </div>
          )}
        </div>
      </foreignObject>
    </g>
  );
}

interface NodeStroke {
  stroke: string;
  warn: boolean;
}

function strokeFor(tag: NodeTag): NodeStroke {
  switch (tag.kind) {
    case "rule": {
      const warn = tag.rule.applies_to_any_process && tag.rule.action.kind !== "block";
      return { stroke: colorForAction(tag.rule.action), warn };
    }
    case "port":
      return {
        stroke: tag.port.is_any ? "#ff9a5c" : "#5c7aa8",
        warn: tag.port.is_any,
      };
    case "exit":
      return { stroke: colorForAction(tag.channel.kind), warn: false };
    case "hop":
      return { stroke: colorForHop(tag.hop), warn: !tag.hop.is_encrypted };
    case "internet":
      return { stroke: "var(--ppxray-border-strong)", warn: false };
  }
}

function labelsFor(tag: NodeTag): { primary: string; secondary: string | null } {
  switch (tag.kind) {
    case "rule": {
      const ctx = tag.context;
      const parts: string[] = [];
      if (ctx.matchingProcessLabels.length > 0) {
        parts.push(ctx.matchingProcessLabels.join(", "));
        if (ctx.extraProcessCount > 0) parts.push(`+${ctx.extraProcessCount}`);
      }
      if (ctx.matchesUnlisted) parts.push("+unlisted");
      const procBit = parts.length > 0 ? ` - ${parts.join(" ")}` : "";
      return {
        primary: tag.rule.name,
        secondary: `#${tag.rule.index + 1} - ${actionLabel(tag.rule.action.kind)}${procBit}`,
      };
    }
    case "port":
      return {
        primary: tag.port.label,
        secondary: tag.port.is_any ? "any port" : null,
      };
    case "exit":
      return {
        primary: tag.channel.label,
        secondary: tag.channel.kind.kind === "block" ? "traffic stops here" : null,
      };
    case "hop":
      return {
        primary: tag.hop.label ?? `Proxy #${tag.hop.proxy_id}`,
        secondary: `${tag.hop.proxy_type} - ${tag.hop.address}:${tag.hop.port}${
          tag.hop.is_encrypted ? "" : " - cleartext"
        }`,
      };
    case "internet":
      return { primary: "Internet", secondary: "outside the host" };
  }
}

function actionLabel(kind: string): string {
  switch (kind) {
    case "direct":
      return "Direct";
    case "block":
      return "Block";
    case "proxy":
      return "via Proxy";
    case "chain":
      return "via Chain";
    default:
      return kind;
  }
}

// Re-exports for consumers (module, findings panel, table).
export { colorForProcess, nodeKey };
