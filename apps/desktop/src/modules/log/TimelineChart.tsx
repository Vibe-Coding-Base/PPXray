// Stacked timeseries of events-per-bucket, colored by action. uPlot is
// deliberately chosen over a React-wrapped library: it renders with 1 canvas,
// handles 10k+ points at 60fps, and supports brush-to-zoom for drill-in.
//
// State contract: we take the filter from the store, pick a sensible bucket
// size, fetch via `log_timeline`, and render. Dragging a horizontal range
// sets `ts_from` / `ts_to` on the store filter (bi-directional binding).

import {
  Box,
  Card,
  Group,
  SegmentedControl,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import { useEffect, useMemo, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";

import type { TimeBucket } from "@ppxray/ipc-schema";
import { EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/shell/States";
import { useLogStore, useLogStoreShallow } from "@/stores/log-store";
import { useLogDashboard } from "./queries";

/**
 * Resolve a CSS custom property to a concrete colour.
 *
 * uPlot draws to a canvas, and canvas `strokeStyle` does not understand
 * `var(--x)` or `color-mix(...)` — it silently keeps whatever was set before,
 * which is black. That is why the axis ticks and grid were rendering as solid
 * black bars across the plot on a dark background: the strings looked like
 * valid CSS but never reached CSS.
 */
function cssColor(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

/**
 * The four actions, in back-to-front draw order.
 *
 * Stacked areas must be drawn tallest-first with opaque fills, so each band
 * shows only the segment between its own total and the next one down. The
 * legend reads this same list, so swatches cannot drift from the series.
 */
const ACTION_SERIES = [
  { key: "other", label: "Other", stroke: "#adb5bd", fill: "#5c636a" },
  { key: "block", label: "Block", stroke: "#ff8787", fill: "#c92a2a" },
  { key: "proxy", label: "Proxy", stroke: "#74c0fc", fill: "#1971c2" },
  // Direct is the common case and sits in front, so it gets the calmest
  // colour; green also reads as "went straight out" against the red of Block.
  { key: "direct", label: "Direct", stroke: "#8ce99a", fill: "#2f9e44" },
] as const;

const BUCKET_PRESETS: { label: string; secs: number }[] = [
  { label: "5s", secs: 5 },
  { label: "30s", secs: 30 },
  { label: "1m", secs: 60 },
  { label: "5m", secs: 300 },
  { label: "1h", secs: 3600 },
];

export function TimelineChart() {
  const { setFilter, setBucketSecs } = useLogStoreShallow((s) => ({
    setFilter: s.setFilter,
    setBucketSecs: s.setBucketSecs,
  }));
  const bucket = useLogStore((s) => s.bucketSecs);
  const { colorScheme } = useMantineColorScheme();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const plotRef = useRef<uPlot | null>(null);

  // Shared with the breakdown panels — see `queries.ts`. Changing the bucket
  // size changes the query key, so the refetch is automatic.
  const dashboard = useLogDashboard();
  const data = useMemo<TimeBucket[]>(
    () => dashboard.data?.timeline ?? [],
    [dashboard.data],
  );
  const plotData = useMemo(() => toUplotData(data), [data]);

  // Rebuilt whenever the palette changes, because uPlot bakes colours into
  // the canvas; `plotDataRef` lets that rebuild seed itself with the data
  // already on screen instead of waiting for the next query result.
  const plotDataRef = useRef(plotData);
  plotDataRef.current = plotData;

  useEffect(() => {
    if (!containerRef.current) return;
    const el = containerRef.current;
    const width = el.clientWidth || 800;
    // 80px left roughly 30px of plot area once the axis and padding were
    // taken out, so every series collapsed onto the zero line. The floor now
    // clears the axis with something left over, but stays below the pane's
    // minimum so the canvas shrinks rather than overflowing into the panels
    // underneath.
    const height = Math.max(110, el.clientHeight || 160);

    const axisColor = cssColor("--mantine-color-dimmed", "#909296");
    const gridColor =
      colorScheme === "light" ? "rgba(0,0,0,0.08)" : "rgba(255,255,255,0.08)";
    const tickColor =
      colorScheme === "light" ? "rgba(0,0,0,0.18)" : "rgba(255,255,255,0.18)";

    const opts: uPlot.Options = {
      width,
      height,
      padding: [4, 8, 4, 0],
      cursor: {
        drag: { x: true, y: false, uni: 20 },
        points: { show: false },
      },
      scales: {
        x: { time: true },
        y: { min: 0 },
      },
      legend: { show: false },
      series: [
        {},
        ...ACTION_SERIES.map((s) => ({
          label: s.label,
          stroke: s.stroke,
          fill: s.fill,
          width: 1,
          points: { show: false },
          paths: uPlot.paths.stepped!({ align: 1 }),
        })),
      ],
      // Concrete colours only — see `cssColor` above.
      axes: [
        {
          stroke: axisColor,
          grid: { stroke: gridColor, width: 1 },
          ticks: { stroke: tickColor, width: 1, size: 4 },
        },
        {
          stroke: axisColor,
          grid: { stroke: gridColor, width: 1 },
          ticks: { stroke: tickColor, width: 1, size: 4 },
          size: 44,
        },
      ],
      hooks: {
        setSelect: [
          (u) => {
            const sel = u.select;
            if (!sel || sel.width <= 2) return;
            const left = u.posToVal(sel.left, "x");
            const right = u.posToVal(sel.left + sel.width, "x");
            if (!isFinite(left) || !isFinite(right)) return;
            setFilter({
              ts_from: new Date(left * 1000).toISOString().slice(0, 19),
              ts_to: new Date(right * 1000).toISOString().slice(0, 19),
            });
            // Clear selection immediately so the user's next drag is clean.
            u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
          },
        ],
      },
    };

    plotRef.current = new uPlot(opts, plotDataRef.current, el);

    // Leaving this module unmounts the chart; coming back re-runs this effect
    // while the split panes are still settling, so `clientWidth` can be 0 and
    // the canvas gets built at the 800x160 fallback. It then sat there empty
    // until something else changed the data - which is why the timeline came
    // back only after clicking a bucket button. ResizeObserver fires once on
    // observe, so this both corrects that first guess and tracks later
    // resizes.
    const ro = new ResizeObserver(() => {
      const plot = plotRef.current;
      if (!plot) return;
      const w = el.clientWidth;
      const h = Math.max(110, el.clientHeight);
      if (w > 0) {
        plot.setSize({ width: w, height: h });
      }
    });
    ro.observe(el);

    // One frame later the split panes have restored their sizes and the
    // container has its real box. ResizeObserver alone was not enough: when
    // the pane comes back at exactly the width it had before, the browser
    // reports no resize, so nothing corrects the canvas built at the
    // fallback size - and the chart stayed blank until something else
    // changed the data. Re-applying size and data here is cheap and does not
    // depend on which of those two went wrong.
    const settle = requestAnimationFrame(() => {
      const plot = plotRef.current;
      if (!plot) return;
      const w = el.clientWidth;
      if (w > 0) {
        plot.setSize({ width: w, height: Math.max(110, el.clientHeight) });
      }
      plot.setData(plotDataRef.current);
    });

    return () => {
      cancelAnimationFrame(settle);
      ro.disconnect();
      plotRef.current?.destroy();
      plotRef.current = null;
    };
    // Data is pushed separately below; the chart is rebuilt only when the
    // palette changes, because the colours are baked into the canvas.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [colorScheme]);

  useEffect(() => {
    plotRef.current?.setData(plotData);
  }, [plotData]);

  return (
    <Card withBorder radius="sm" p="xs" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <Group justify="space-between" gap="xs">
        <Text size="xs" fw={600} tt="uppercase" c="dimmed">
          Timeline - stacked by action
        </Text>
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            bucket
          </Text>
          <SegmentedControl
            size="xs"
            value={String(bucket)}
            onChange={(v) => setBucketSecs(parseInt(v, 10))}
            data={BUCKET_PRESETS.map((p) => ({ value: String(p.secs), label: p.label }))}
          />
        </Group>
      </Group>
      <Box style={{ position: "relative", width: "100%", flex: 1, minHeight: 0, overflow: "hidden", marginTop: 6 }}>
        <Box ref={containerRef} style={{ width: "100%", height: "100%" }} />
        {/* Overlaid rather than swapped in, so the bucket control above stays
            usable while a query is loading or failing. */}
        {(dashboard.isError || dashboard.isLoading || data.length === 0) && (
          <Box
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "var(--ppxray-surface)",
            }}
          >
            {dashboard.isError ? (
              <ErrorBlock
                compact
                error={dashboard.error}
                onRetry={() => void dashboard.refetch()}
              />
            ) : dashboard.isLoading ? (
              <LoadingBlock compact label="Bucketing events…" />
            ) : (
              <EmptyBlock compact title="No events in this range" />
            )}
          </Box>
        )}
      </Box>
      <Group gap="sm" mt={4}>
        {/* Reversed: drawn back-to-front, read front-to-back. */}
        {[...ACTION_SERIES].reverse().map((s) => (
          <LegendSwatch key={s.key} color={s.fill} label={s.label} />
        ))}
        <Text size="xs" c="dimmed" ml="auto">
          drag horizontally to filter by time range
        </Text>
      </Group>
    </Card>
  );
}

function LegendSwatch({ color, label }: { color: string; label: string }) {
  return (
    <Group gap={4}>
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: 2,
          background: color,
          display: "inline-block",
        }}
      />
      <Text size="xs" c="dimmed">
        {label}
      </Text>
    </Group>
  );
}

/** Convert server buckets into uPlot's column-major `AlignedData`. Totals are
 *  converted to a cumulative running sum so the stacked overlay renders
 *  correctly (uPlot stacks via explicit per-series offsets). */
function toUplotData(buckets: TimeBucket[]): uPlot.AlignedData {
  if (buckets.length === 0) {
    return [[], [], [], [], []] as unknown as uPlot.AlignedData;
  }
  const xs: number[] = new Array(buckets.length);
  const direct: number[] = new Array(buckets.length);
  const proxy: number[] = new Array(buckets.length);
  const block: number[] = new Array(buckets.length);
  const other: number[] = new Array(buckets.length);

  for (let i = 0; i < buckets.length; i++) {
    const b = buckets[i]!;
    xs[i] = Math.floor(new Date(b.ts).getTime() / 1000);
    const d = Number(b.direct);
    const p = Number(b.proxy);
    const bl = Number(b.block);
    const o = Number(b.other);
    // Cumulative totals: each series is the sum of everything at or below
    // it, so the bands sit on top of one another rather than overlapping.
    direct[i] = d;
    proxy[i] = d + p;
    block[i] = d + p + bl;
    other[i] = d + p + bl + o;
  }
  // Ordered to match `ACTION_SERIES`: tallest first, so it is drawn at the
  // back and the shorter bands paint in front of it.
  return [xs, other, block, proxy, direct];
}
