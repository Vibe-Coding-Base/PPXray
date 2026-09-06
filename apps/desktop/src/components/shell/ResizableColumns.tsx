// Pure-React resizable-column model for the rule table (and any future
// dense table). We avoid pulling TanStack Table just for resize handling —
// the table body is virtualized via `react-virtual` and uses CSS Grid, so
// all we need is a stateful column-width array + a drag handle that mutates
// it.
//
// Width persistence: caller passes `storageKey`; widths are saved to
// `localStorage` keyed by `proxifier:cols:<storageKey>`. Resetting widths
// (e.g. on column-set change) is the caller's job.

import { useCallback, useEffect, useRef, useState } from "react";

export interface ColumnSpec {
  /** Stable identifier — used as React key and in localStorage. */
  id: string;
  /** Initial width in px when no saved value exists. */
  defaultWidth: number;
  /** Lower bound when dragging. */
  minWidth?: number;
  /** Upper bound when dragging. Omit for "no cap". */
  maxWidth?: number;
  /** Display label shown in header cell. */
  label: string;
  /** Whether this column should NOT show a resize handle on its right edge.
   *  Use for the LAST column or for non-content columns like grip / checkbox. */
  fixed?: boolean;
}

export function useColumnWidths(
  storageKey: string,
  spec: ColumnSpec[],
): {
  widths: number[];
  setWidth: (index: number, w: number) => void;
  resetWidths: () => void;
  /** Fixed-pixel grid template (row width = sum of column widths). */
  template: string;
  /** Flex grid template: last column is `minmax(Npx, 1fr)` so it fills
   *  available slack when the container is wider than the sum of widths. */
  flexTemplate: string;
  /** Sum of all configured widths; use as row `min-width` to prevent
   *  collapse below defaults on narrow viewports. */
  minRowWidth: number;
} {
  const lsKey = `proxifier:cols:${storageKey}`;

  const [widths, setWidths] = useState<number[]>(() => {
    if (typeof window !== "undefined") {
      try {
        const saved = window.localStorage.getItem(lsKey);
        if (saved) {
          const parsed = JSON.parse(saved) as number[];
          if (Array.isArray(parsed) && parsed.length === spec.length) {
            return parsed;
          }
        }
      } catch {
        /* fallthrough to defaults */
      }
    }
    return spec.map((c) => c.defaultWidth);
  });

  // Persist on change. Throttled-by-requestIdleCallback would be nicer but
  // a 0-ms timeout is good enough for a 9-column table.
  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(lsKey, JSON.stringify(widths));
    } catch {
      /* localStorage full / unavailable — silently drop */
    }
  }, [widths, lsKey]);

  const setWidth = useCallback(
    (index: number, w: number) => {
      const col = spec[index];
      if (!col) return;
      const min = col.minWidth ?? 32;
      const max = col.maxWidth ?? 4000;
      const clamped = Math.max(min, Math.min(max, w));
      setWidths((current) => {
        if (current[index] === clamped) return current;
        const next = current.slice();
        next[index] = clamped;
        return next;
      });
    },
    [spec],
  );

  const resetWidths = useCallback(() => {
    setWidths(spec.map((c) => c.defaultWidth));
  }, [spec]);

  // Fixed-pixel template: every column sized exactly to its stored width.
  // Combined with `width: <sum>px` on the row, the table is exactly as wide
  // as the columns — use this when the caller wants horizontal scrolling.
  const template = widths.map((w) => `${w}px`).join(" ");

  // Flex template: every column except the LAST is a fixed pixel width,
  // and the last is `minmax(<its stored width>px, 1fr)`. Combined with
  // `min-width: <sum>px` + `width: 100%` on the row:
  //   - container wider than sum  → last column stretches into the slack
  //     (no right whitespace)
  //   - container narrower        → horizontal scrollbar appears; columns
  //     don't collapse below their defaults
  const minRowWidth = widths.reduce((s, w) => s + w, 0);
  const flexTemplate = widths
    .map((w, i) => (i === widths.length - 1 ? `minmax(${w}px, 1fr)` : `${w}px`))
    .join(" ");

  return { widths, setWidth, resetWidths, template, flexTemplate, minRowWidth };
}

interface ColumnResizeHandleProps {
  /** Current width of the column, used as the drag baseline. */
  currentWidth: number;
  /** Called with the new width on every mousemove. */
  onResize: (newWidth: number) => void;
  /** Optional classname for additional styling. */
  className?: string;
}

/**
 * 4-pixel-wide vertical handle absolutely positioned at the right edge of
 * a header cell. Listens for pointerdown + window pointermove/pointerup so
 * the drag isn't lost when the cursor leaves the cell.
 */
export function ColumnResizeHandle({ currentWidth, onResize, className }: ColumnResizeHandleProps) {
  const startRef = useRef<{ x: number; w: number } | null>(null);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      e.stopPropagation();
      startRef.current = { x: e.clientX, w: currentWidth };

      const move = (ev: PointerEvent) => {
        if (!startRef.current) return;
        const dx = ev.clientX - startRef.current.x;
        onResize(startRef.current.w + dx);
      };
      const up = () => {
        startRef.current = null;
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        document.body.style.cursor = "";
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      document.body.style.cursor = "col-resize";
    },
    [currentWidth, onResize],
  );

  return (
    <div
      onPointerDown={onPointerDown}
      className={className}
      style={{
        position: "absolute",
        top: 0,
        right: -2,
        width: 6,
        height: "100%",
        cursor: "col-resize",
        zIndex: 6,
        // Visible-on-hover via the .ppxray-col-resize:hover rule in
        // global.css.
      }}
    />
  );
}
