// Alert inbox with virtualized list. Selection drives the detail panel.
//
// This is the list an analyst works top to bottom, so it is keyboard-first:
// ↑/↓ move the selection and scroll it into view, Enter opens the detail
// panel, and each row is a real focus target rather than a bare `onClick`.

import { Badge, Box, Group, MultiSelect, Stack, Text,
  rem,
} from "@mantine/core";
import { IconShieldCheck } from "@tabler/icons-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useRef } from "react";

import type { Alert } from "@ppxray/ipc-schema";
import {
  EmptyBlock,
  ErrorBlock,
  LoadingBlock,
  clickable,
  rows,
} from "@/components/shell/States";
import { useRem } from "@/hooks/use-row-height";
import { useHuntStore, useHuntStoreShallow } from "@/stores/hunt-store";
import { useAlerts } from "./queries";

/** 56px at the original 16px base, kept proportional as the user
 *  changes the interface size (see `hooks/use-row-height.ts`). */
const ROW_HEIGHT_REM = 3.5;

export function AlertInbox() {
  const selectedAlertId = useHuntStore((s) => s.selectedAlertId);
  const filter = useHuntStore((s) => s.filter);
  const { selectAlert, setFilter } = useHuntStoreShallow((s) => ({
    selectAlert: s.selectAlert,
    setFilter: s.setFilter,
  }));

  const query = useAlerts(filter);
  const alerts = rows(query.data);

  const parentRef = useRef<HTMLDivElement | null>(null);
  const rowHeight = useRem(ROW_HEIGHT_REM);
  const virtualizer = useVirtualizer({
    count: alerts.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });

  const selectedIndex = alerts.findIndex((a) => a.id === selectedAlertId);

  /** Move the selection by `delta`, clamped, and keep it on screen. */
  const move = useCallback(
    (delta: number) => {
      if (alerts.length === 0) return;
      // Nothing selected yet: ↓ starts at the top, ↑ at the bottom.
      const from = selectedIndex >= 0 ? selectedIndex : delta > 0 ? -1 : alerts.length;
      const next = Math.min(Math.max(from + delta, 0), alerts.length - 1);
      const alert = alerts[next];
      if (!alert) return;
      selectAlert(alert.id);
      virtualizer.scrollToIndex(next, { align: "auto" });
    },
    [alerts, selectedIndex, selectAlert, virtualizer],
  );

  // Scoped to the list: a global hotkey would fight the rule table's own
  // arrow handling when both are mounted.
  const onListKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        move(1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        move(-1);
      } else if (e.key === "Home") {
        e.preventDefault();
        move(-alerts.length);
      } else if (e.key === "End") {
        e.preventDefault();
        move(alerts.length);
      }
    },
    [move, alerts.length],
  );

  // Re-run once the virtualizer has rendered the window containing the new
  // selection, otherwise the row we want to focus is not in the DOM yet.
  const renderedCount = virtualizer.getVirtualItems().length;

  // Keep the focus ring with the selection when it moves by keyboard.
  useEffect(() => {
    if (selectedIndex < 0) return;
    const el = parentRef.current?.querySelector<HTMLElement>(
      `[data-alert-index="${selectedIndex}"]`,
    );
    if (el && parentRef.current?.contains(document.activeElement)) el.focus();
  }, [selectedIndex, renderedCount]);

  return (
    <Stack gap={0} h="100%">
      <Group gap="sm" px="sm" py="xs" wrap="nowrap" align="flex-end">
        <MultiSelect
          label="Severity"
          placeholder="Any"
          aria-label="Filter by severity"
          value={filter.severities ?? []}
          onChange={(v) => setFilter({ severities: v.length ? v : null })}
          data={["Critical", "High", "Medium", "Low"]}
          clearable
          style={{ width: rem(230) }}
        />
        <MultiSelect
          label="Triage"
          placeholder="Any"
          aria-label="Filter by triage state"
          value={filter.triage ?? []}
          onChange={(v) => setFilter({ triage: v.length ? v : null })}
          data={[
            { value: "new", label: "New" },
            { value: "tp", label: "True positive" },
            { value: "fp", label: "False positive" },
            { value: "suppressed", label: "Suppressed" },
          ]}
          clearable
          style={{ width: rem(270) }}
        />
        <Text size="sm" c="dimmed" ml="auto" pb={6}>
          {alerts.length.toLocaleString()} shown
        </Text>
      </Group>

      <Box
        ref={parentRef}
        role="listbox"
        aria-label="Alerts"
        tabIndex={-1}
        onKeyDown={onListKeyDown}
        style={{
          flex: 1,
          overflow: "auto",
          borderTop: "1px solid var(--ppxray-border)",
        }}
      >
        {query.isError ? (
          <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
        ) : query.isLoading ? (
          <LoadingBlock label="Loading alerts…" />
        ) : alerts.length === 0 ? (
          <EmptyBlock
            icon={<IconShieldCheck size="1.5rem" stroke={1.4} color="var(--mantine-color-dimmed)" />}
            title="No alerts to review"
            hint="Run the catalog, or widen the severity and triage filters above — triaged alerts are hidden by default."
          />
        ) : (
          <div
            style={{
              height: `${virtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative",
            }}
          >
            {virtualizer.getVirtualItems().map((vi) => {
              const a = alerts[vi.index];
              if (!a) return null;
              return (
                <Row
                  key={String(a.id)}
                  alert={a}
                  index={vi.index}
                  top={vi.start}
                  selected={selectedAlertId === a.id}
                  onClick={() => selectAlert(a.id)}
                />
              );
            })}
          </div>
        )}
      </Box>
    </Stack>
  );
}

interface RowProps {
  alert: Alert;
  index: number;
  top: number;
  selected: boolean;
  onClick: () => void;
}

function Row({ alert, index, top, selected, onClick }: RowProps) {
  const rowHeight = useRem(ROW_HEIGHT_REM);
  return (
    <div
      {...clickable(onClick, `${alert.severity} alert: ${alert.rule_title}`)}
      role="option"
      aria-selected={selected}
      data-alert-index={index}
      data-row-focus
      // Only the selected row is a tab stop; ↑/↓ move within the list. This
      // is the standard listbox pattern — without it, tabbing out of the
      // inbox would take one press per alert.
      tabIndex={selected ? 0 : -1}
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        transform: `translateY(${top}px)`,
        height: rowHeight,
        padding: "6px 10px",
        background: selected ? "var(--mantine-color-blue-light)" : "transparent",
        borderBottom: "1px solid var(--ppxray-row-divider)",
        cursor: "pointer",
      }}
    >
      <Group justify="space-between" gap="xs" wrap="nowrap">
        <Group gap={6} wrap="nowrap" style={{ minWidth: rem(0), flex: 1 }}>
          <SeverityChip severity={alert.severity} />
          <Text
            size="sm"
            fw={500}
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {alert.rule_title}
          </Text>
        </Group>
        <TriageChip triage={alert.triage} />
      </Group>
      <Group gap={6} wrap="nowrap" mt={2}>
        {alert.process && (
          <Text size="sm" c="dimmed" className="mono">
            {alert.process}
          </Text>
        )}
        {alert.dst && (
          <Text
            size="xs"
            c="dimmed"
            className="mono"
            style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          >
            → {alert.dst}
          </Text>
        )}
        <Text size="sm" c="dimmed" ml="auto">
          {alert.ts}
        </Text>
      </Group>
    </div>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  const color = severityColor(severity);
  return (
    <Badge size="sm" variant="filled" color={color} style={{ minWidth: rem(70), textAlign: "center" }}>
      {severity}
    </Badge>
  );
}

function severityColor(s: string): string {
  switch (s) {
    case "Critical":
      return "red.9";
    case "High":
      return "red";
    case "Medium":
      return "orange";
    case "Low":
      return "yellow";
    default:
      return "gray";
  }
}

function TriageChip({ triage }: { triage: string }) {
  switch (triage) {
    case "tp":
      return (
        <Badge size="sm" color="red" variant="light">
          TP
        </Badge>
      );
    case "fp":
      return (
        <Badge size="sm" color="gray" variant="light">
          FP
        </Badge>
      );
    case "suppressed":
      return (
        <Badge size="sm" color="gray" variant="outline">
          SUP
        </Badge>
      );
    default:
      return null;
  }
}
