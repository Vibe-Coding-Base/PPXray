// Virtualized events table, paged server-side via `useInfiniteQuery`:
// scrolling near the bottom loads the next 500 rows. DuckDB answers a page in
// under 50 ms even on multi-million-row logs.

import { Badge, Box, Group, Text, rem } from "@mantine/core";
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef } from "react";

import type { EventRow } from "@ppxray/ipc-schema";
import {
  EmptyBlock,
  ErrorBlock,
  LoadingBlock,
  clickable,
} from "@/components/shell/States";
import { useRem } from "@/hooks/use-row-height";
import { useEffectiveFilter, useLogStore, useLogStoreShallow } from "@/stores/log-store";
import { queryEvents } from "./ipc";
import { logKeys, useLogDashboard } from "./queries";

const PAGE_SIZE = 500;
/** 28px at the original 16px base, kept proportional as the user
 *  changes the interface size (see `hooks/use-row-height.ts`). */
const ROW_HEIGHT_REM = 1.75;

export function EventTable() {
  const filter = useEffectiveFilter();
  const sourcePath = useLogStore((s) => s.sourcePath);
  const { setFilter } = useLogStoreShallow((s) => ({ setFilter: s.setFilter }));
  const parentRef = useRef<HTMLDivElement | null>(null);

  // The matching-row count comes from the shared dashboard read rather than
  // a second `log_count_events` round trip over the same filter.
  const { data: dash } = useLogDashboard();
  const total = Number(dash?.total_matching ?? 0);

  const {
    data,
    error,
    fetchNextPage,
    hasNextPage,
    isError,
    isFetchingNextPage,
    isLoading,
    refetch,
  } = useInfiniteQuery({
    queryKey: logKeys.events(filter),
    queryFn: ({ pageParam }) =>
      queryEvents({ ...filter, limit: PAGE_SIZE, offset: pageParam }),
    initialPageParam: 0,
    // A short page means we reached the end; otherwise resume at the number
    // of rows already held. `ORDER BY ts DESC, id DESC` is a total order, so
    // offset paging cannot duplicate or skip a row.
    getNextPageParam: (lastPage, allPages) =>
      lastPage.length < PAGE_SIZE
        ? undefined
        : allPages.reduce((n, page) => n + page.length, 0),
    enabled: sourcePath !== null,
    placeholderData: keepPreviousData,
  });

  const rows = useMemo<EventRow[]>(() => data?.pages.flat() ?? [], [data]);
  const rowHeight = useRem(ROW_HEIGHT_REM);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 20,
  });

  // A new filter is a new query key, so the list restarts at page 0 — scroll
  // back to the top to match.
  useEffect(() => {
    parentRef.current?.scrollTo({ top: 0 });
  }, [filter]);

  // Infinite scroll: when we're near the bottom, pull the next page.
  const lastVisible = virtualizer.getVirtualItems().at(-1)?.index;
  useEffect(() => {
    if (lastVisible === undefined) return;
    if (lastVisible >= rows.length - 10 && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage();
    }
  }, [lastVisible, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage]);

  return (
    <Box style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: rem(0) }}>
      <TitleBar total={total} />
      <HeaderRow total={total} loaded={rows.length} />
      <Box
        ref={parentRef}
        style={{
          flex: 1,
          overflow: "auto",
          border: "1px solid var(--ppxray-border)",
          borderTop: "none",
          background: "var(--ppxray-surface)",
        }}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((v) => {
            const row = rows[v.index];
            if (!row) return null;
            return (
              <Row
                key={row.id}
                row={row}
                top={v.start}
                rowHeight={rowHeight}
                onFilterHost={(host) => setFilter({ host_contains: host })}
                onFilterProcess={(proc) => setFilter({ processes: [proc] })}
                onFilterRule={(rule) => setFilter({ matched_rules: [rule] })}
              />
            );
          })}
          {isError && (
            <ErrorBlock error={error} onRetry={() => void refetch()} />
          )}
          {!isError && isLoading && <LoadingBlock label="Querying events…" />}
          {!isError && !isLoading && rows.length === 0 && (
            <EmptyBlock
              title="No events match the current filter"
              hint="Clear a chip in the filter bar, widen the timeline selection, or empty the search box."
            />
          )}
          {isFetchingNextPage && <LoadingBlock compact label="Loading more…" />}
        </div>
      </Box>
    </Box>
  );
}

/** Names the pane, so the row of pane toggles below has something to name. */
function TitleBar({ total }: { total: number }) {
  return (
    <Group
      justify="space-between"
      wrap="nowrap"
      px="xs"
      py={4}
      style={{
        flexShrink: 0,
        borderTop: "1px solid var(--ppxray-border)",
        background: "var(--ppxray-surface-strong)",
      }}
    >
      <Text size="sm" fw={600}>
        Events{total > 0 ? ` (${total.toLocaleString()})` : ""}
      </Text>
    </Group>
  );
}

function HeaderRow({ total, loaded }: { total: number; loaded: number }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: COLUMNS,
        padding: "6px 8px",
        fontSize: "var(--ppxray-text-caption)",
        textTransform: "uppercase",
        color: "var(--mantine-color-dimmed)",
        background: "var(--ppxray-row-divider)",
        border: "1px solid var(--ppxray-border)",
        borderBottom: "none",
        letterSpacing: 0.3,
        fontWeight: 600,
      }}
    >
      <div>Timestamp</div>
      <div>Process</div>
      <div>Dst</div>
      <div>Port</div>
      <div>Proto</div>
      <div>Rule</div>
      {/* The loaded/total count is table metadata rather than part of the
          column name, and this column is narrow — so it sits on its own line
          instead of being joined on with a separator that then wraps. */}
      <div>
        Action
        <Text component="span" size="xs" c="dimmed" fw={400} tt="none" display="block">
          {loaded.toLocaleString()} / {total.toLocaleString()}
        </Text>
      </div>
    </div>
  );
}

const COLUMNS =
  "170px minmax(160px,1fr) minmax(220px,2fr) 60px 54px minmax(120px,1fr) 80px";

const CELL_PLAIN = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
} as const;

/** A cell that pivots the filter when activated. */
const CELL_BUTTON = { ...CELL_PLAIN, cursor: "pointer" } as const;

interface RowProps {
  row: EventRow;
  top: number;
  rowHeight: number;
  onFilterHost: (s: string) => void;
  onFilterProcess: (s: string) => void;
  onFilterRule: (s: string) => void;
}

function Row({ row, top, rowHeight, onFilterHost, onFilterProcess, onFilterRule }: RowProps) {
  const dst = row.dst_host ?? row.dst_ip ?? "—";
  const dstSuffix = row.dst_host && row.dst_ip && row.dst_host !== row.dst_ip
    ? ` (${row.dst_ip})` : "";
  return (
    <div
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        transform: `translateY(${top}px)`,
        height: rowHeight,
        width: "100%",
        display: "grid",
        gridTemplateColumns: COLUMNS,
        alignItems: "center",
        padding: "0 8px",
        borderBottom: "1px solid var(--ppxray-row-divider)",
        fontSize: "var(--ppxray-text-dense)",
      }}
    >
      {/* Not dimmed: in a log viewer the timestamp is the primary key of the
          row, not secondary chrome. It read as near-invisible against the
          dark surface. */}
      <Text size="xs" className="mono">
        {formatTs(row.ts)}
      </Text>
      <Text
        size="xs"
        className="mono"
        title="Filter by this process"
        style={CELL_BUTTON}
        {...clickable(
          () => onFilterProcess(row.process),
          `Filter by process ${row.process}`,
        )}
      >
        {row.process}
      </Text>
      <Text
        size="xs"
        className="mono"
        title="Filter by this destination"
        style={CELL_BUTTON}
        {...clickable(() => onFilterHost(dst), `Filter by destination ${dst}`)}
      >
        {dst}
        <Text component="span" c="dimmed">
          {dstSuffix}
        </Text>
      </Text>
      <Text size="xs" className="mono">
        {row.dst_port ?? "—"}
      </Text>
      <Text size="xs" className="mono" c="dimmed">
        {row.ipv6 ? "v6/" : ""}
        {row.proto}
      </Text>
      <Text
        size="xs"
        title={row.matched_rule ? "Filter by this rule" : undefined}
        style={row.matched_rule ? CELL_BUTTON : CELL_PLAIN}
        {...clickable(
          // Events with no matched rule have nothing to pivot to, so the
          // cell stays inert rather than becoming a dead tab stop.
          row.matched_rule ? () => onFilterRule(row.matched_rule!) : undefined,
          row.matched_rule ? `Filter by rule ${row.matched_rule}` : undefined,
        )}
      >
        {row.matched_rule ?? "—"}
      </Text>
      <Group gap={0} wrap="nowrap">
        <ActionChip action={row.action} />
      </Group>
    </div>
  );
}

function ActionChip({ action }: { action: string }) {
  switch (action) {
    case "Direct":
      return <Badge color="teal" variant="light">Direct</Badge>;
    case "Block":
      return <Badge color="red" variant="light">Block</Badge>;
    case "Proxy":
      return <Badge color="blue" variant="light">Proxy</Badge>;
    default:
      return <Badge color="gray" variant="light">{action}</Badge>;
  }
}

function formatTs(ts: string): string {
  // "2026-04-17T23:30:16" → "04-17 23:30:16"
  const m = /^(\d{4})-(\d{2})-(\d{2})T(.+)$/.exec(ts);
  if (!m) return ts;
  return `${m[2]}-${m[3]} ${m[4]}`;
}
