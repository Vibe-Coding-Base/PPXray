// Thin wrapper over `react-resizable-panels` v4, re-exported under v3-style
// names (`Group` → `SplitGroup`, `Separator` → `SplitHandle`).
//
// Hide a pane by not rendering it, never with the library's `collapsible`: a
// pane collapsed to size 0 is still in the group, and the layout engine
// redistributed the space it gave up — pushing one sibling past its collapse
// threshold and squeezing another below its minimum.

import type { ReactNode } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";

interface SplitGroupProps {
  /** Layout direction: `"horizontal"` stacks panels left-to-right; the
   *  drag handle becomes a vertical bar. `"vertical"` stacks top-to-bottom
   *  with horizontal drag handles. Mirrors v3 semantics for code clarity. */
  direction: "horizontal" | "vertical";
  /** Persists panel sizes under this key in `localStorage`. */
  autoSaveId?: string;
  children: ReactNode;
  style?: React.CSSProperties;
}

export function SplitGroup({ direction, autoSaveId, children, style }: SplitGroupProps) {
  return (
    <Group
      orientation={direction}
      id={autoSaveId}
      style={{ height: "100%", width: "100%", ...style }}
    >
      {children}
    </Group>
  );
}

interface SplitPanelProps {
  defaultSize?: number;
  /**
   * Percentage, or a CSS length such as `"180px"`.
   *
   * A pixel floor is what stops a pane being squeezed below the height its
   * contents need: at percentages alone, a short window left the timeline
   * with no room for its canvas and the breakdown panels showing half a row,
   * which reads as the panel below drawing over them.
   */
  minSize?: number | string;
  maxSize?: number | string;
  /** Stable identity, so sizes survive a sibling being hidden and shown. */
  id?: string;
  children: ReactNode;
  style?: React.CSSProperties;
}

export function SplitPanel({
  defaultSize,
  minSize,
  maxSize,
  id,
  children,
  style,
}: SplitPanelProps) {
  return (
    <Panel
      defaultSize={defaultSize}
      minSize={minSize}
      maxSize={maxSize}
      id={id}
      style={{ overflow: "hidden", ...style }}
    >
      {children}
    </Panel>
  );
}

interface SplitHandleProps {
  /** Visual orientation of the handle bar (kept for API compatibility with
   *  the previous wrapper; v4's `Separator` figures it out from the parent
   *  `Group.orientation`, so we just pass through the styling here). */
  orientation?: "horizontal" | "vertical";
}

export function SplitHandle({ orientation = "vertical" }: SplitHandleProps) {
  // The bar is 8px of hit area around a 2px line, not a 2px line you have to
  // hit exactly. `flexShrink: 0` matters as much: as a shrinkable flex item
  // the handle was squeezed towards nothing by its neighbours, leaving
  // nothing to grab even though the divider was still drawn.
  const style: React.CSSProperties =
    orientation === "horizontal"
      ? { height: 8, width: "100%", flexShrink: 0, cursor: "row-resize" }
      : { width: 8, height: "100%", flexShrink: 0, cursor: "col-resize" };

  return (
    <Separator
      className={`ppxray-splitter ppxray-splitter-${orientation}`}
      style={{ ...style, touchAction: "none" }}
    />
  );
}
