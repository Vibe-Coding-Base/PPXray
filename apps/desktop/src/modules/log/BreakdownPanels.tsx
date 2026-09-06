// Top-N summary panels that pivot the current filter. Clicking a row narrows
// the global filter — the core interaction loop of the log analyzer.
//
// All three panels read from the one `useLogDashboard()` query rather than
// fetching independently, so they always render the same snapshot of the
// same filter — and the same loading / error state.

import { ActionIcon, Badge, Card, Group, ScrollArea, Stack, Text, Tooltip,
  rem,
} from "@mantine/core";
import { IconListSearch } from "@tabler/icons-react";
import { useState } from "react";

import {
  EmptyBlock,
  ErrorBlock,
  LoadingBlock,
  clickable,
  rows as panelRows,
} from "@/components/shell/States";
import { useLogStoreShallow } from "@/stores/log-store";
import { TargetSuggestionModal } from "./TargetSuggestionModal";
import { useLogDashboard } from "./queries";

export function ProcessPanel() {
  const { setFilter } = useLogStoreShallow((s) => ({ setFilter: s.setFilter }));
  const q = useLogDashboard();
  const items = panelRows(q.data?.top_processes);
  const max = items[0]?.count ?? 1;
  const [suggestFor, setSuggestFor] = useState<string | null>(null);

  return (
    <>
      <Panel title="Top processes" subtitle="click a row to filter - ⌕ suggests a Targets list">
        <PanelBody query={q} count={items.length} what="process">
          {items.map((r) => (
            <BarRow
              key={r.process}
              label={r.process}
              mono
              count={Number(r.count)}
              max={Number(max)}
              badge={`${r.distinct_hosts} dsts`}
              onClick={() => setFilter({ processes: [r.process] })}
              clickLabel={`Filter events to process ${r.process}`}
              action={
                <Tooltip
                  label={`Build a Targets list from the ${r.distinct_hosts} destinations ${r.process} reached`}
                  withArrow
                  openDelay={200}
                >
                  <ActionIcon
                    size="md"
                    variant="light"
                    color="blue"
                    aria-label={`Suggest targets for ${r.process}`}
                    onClick={(e) => {
                      // The row itself filters; this is a second action on it.
                      e.stopPropagation();
                      setSuggestFor(r.process);
                    }}
                  >
                    <IconListSearch size="1.1rem" />
                  </ActionIcon>
                </Tooltip>
              }
            />
          ))}
        </PanelBody>
      </Panel>
      <TargetSuggestionModal process={suggestFor} onClose={() => setSuggestFor(null)} />
    </>
  );
}

export function HostPanel() {
  const { setFilter } = useLogStoreShallow((s) => ({ setFilter: s.setFilter }));
  const q = useLogDashboard();
  const items = panelRows(q.data?.top_hosts);
  const max = items[0]?.count ?? 1;

  return (
    <Panel title="Top destinations" subtitle="click to drill in">
      <PanelBody query={q} count={items.length} what="destination">
        {items.map((r) => (
          <BarRow
            key={r.host}
            label={r.host}
            mono
            count={Number(r.count)}
            max={Number(max)}
            badge={`${r.distinct_processes} procs`}
            onClick={() => setFilter({ host_contains: r.host })}
            clickLabel={`Filter events to destination ${r.host}`}
          />
        ))}
      </PanelBody>
    </Panel>
  );
}

export function RulePanel() {
  const { setFilter } = useLogStoreShallow((s) => ({ setFilter: s.setFilter }));
  const q = useLogDashboard();
  const items = panelRows(q.data?.top_rules);
  const max = items[0]?.count ?? 1;

  return (
    <Panel title="Rule effectiveness" subtitle="match counts per rule">
      <PanelBody query={q} count={items.length} what="rule">
        {items.map((r) => {
          // "(none)" is the bucket for events no rule matched — there is
          // nothing to filter to, so it stays non-interactive.
          const pivotable = r.rule !== "(none)";
          return (
            <BarRow
              key={r.rule}
              label={r.rule}
              count={Number(r.count)}
              max={Number(max)}
              badge={`${r.distinct_processes} procs`}
              onClick={pivotable ? () => setFilter({ matched_rules: [r.rule] }) : undefined}
              clickLabel={`Filter events to rule ${r.rule}`}
              tooltip={r.last_match ? `Last match: ${r.last_match}` : undefined}
            />
          );
        })}
      </PanelBody>
    </Panel>
  );
}

/**
 * Maps the shared dashboard query onto the four things a panel can be
 * showing. `isLoading` rather than `isPending` so a disabled query (no log
 * open) doesn't spin forever, and `keepPreviousData` means a refetch keeps
 * the old rows on screen instead of flashing this.
 */
function PanelBody({
  query,
  count,
  what,
  children,
}: {
  query: ReturnType<typeof useLogDashboard>;
  count: number;
  what: string;
  children: React.ReactNode;
}) {
  if (query.isError) {
    return <ErrorBlock compact error={query.error} onRetry={() => void query.refetch()} />;
  }
  if (query.isLoading) {
    return <LoadingBlock compact />;
  }
  if (count === 0) {
    return (
      <EmptyBlock
        compact
        title={`No ${what} matches this filter`}
        hint="Widen the time range or clear a filter chip above."
      />
    );
  }
  return (
    <ScrollArea h="100%" type="auto" scrollbarSize={6}>
      <Stack gap={2} p={4}>
        {children}
      </Stack>
    </ScrollArea>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <Card
      withBorder
      radius="sm"
      p={0}
      // `height: 100%` is what makes the list scroll rather than run past
      // the bottom of the pane: without it the card sizes to its content and
      // the pane simply clips whatever did not fit, so the last few rows
      // disappeared with no scrollbar to reach them.
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        minHeight: rem(0),
        overflow: "hidden",
      }}
    >
      <Group
        justify="space-between"
        px="sm"
        py={4}
        style={{ borderBottom: "1px solid var(--ppxray-border)" }}
      >
        <Text size="xs" fw={600} tt="uppercase">
          {title}
        </Text>
        <Text size="xs" c="dimmed">
          {subtitle}
        </Text>
      </Group>
      <div style={{ flex: 1, minHeight: rem(0), overflow: "hidden" }}>{children}</div>
    </Card>
  );
}

interface BarRowProps {
  label: string;
  count: number;
  max: number;
  badge?: string;
  mono?: boolean;
  onClick?: () => void;
  /** Screen-reader description of what clicking does. */
  clickLabel?: string;
  tooltip?: string;
  /** Secondary control rendered at the row's trailing edge. */
  action?: React.ReactNode;
}

function BarRow({
  label,
  count,
  max,
  badge,
  mono,
  onClick,
  clickLabel,
  tooltip,
  action,
}: BarRowProps) {
  const pct = max > 0 ? Math.max(2, (count / max) * 100) : 0;
  const body = (
    <div
      {...clickable(onClick, clickLabel ?? label)}
      className={onClick ? "ppxray-bar-row" : undefined}
      style={{
        position: "relative",
        padding: "3px 6px",
        borderRadius: 3,
        cursor: onClick ? "pointer" : "default",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          width: `${pct}%`,
          background:
            "linear-gradient(90deg, rgba(77,171,247,0.22), rgba(77,171,247,0.08))",
          borderRadius: 3,
        }}
      />
      <Group justify="space-between" wrap="nowrap" style={{ position: "relative" }}>
        <Text
          size="xs"
          className={mono ? "mono" : undefined}
          style={{
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: "75%",
          }}
          title={label}
        >
          {label}
        </Text>
        <Group gap={4} wrap="nowrap">
          {badge && (
            <Badge variant="default" color="gray">
              {badge}
            </Badge>
          )}
          <Text size="xs" fw={600} className="mono">
            {count.toLocaleString()}
          </Text>
          {action}
        </Group>
      </Group>
    </div>
  );
  if (tooltip) {
    return (
      <Tooltip label={tooltip} withArrow openDelay={400}>
        {body}
      </Tooltip>
    );
  }
  return body;
}

