import { Card, Group, ScrollArea, Text, Tooltip, rem } from "@mantine/core";
import {
  IconArrowsJoin,
  IconClock,
  IconNetwork,
  IconShieldOff,
  IconTimeline,
  IconUser,
} from "@tabler/icons-react";
import type { LogStats } from "@ppxray/ipc-schema";

export function StatsCards({ stats }: { stats: LogStats }) {
  const spanLabel = useSpanLabel(stats);
  return (
    // A wrapping grid inside a `overflow: hidden` column meant that on a
    // narrow window the second and third rows of cards were simply cut off,
    // with no way to reach them. One row that scrolls sideways keeps every
    // figure reachable and the header a predictable height.
    <ScrollArea type="auto" scrollbarSize={6} offsetScrollbars="x" px="sm">
      {/* `max-content` so the row really is wider than the viewport when the
          cards do not fit - a nowrap flex row on its own just squeezes and
          the ScrollArea has nothing to scroll. `minWidth: 100%` keeps them
          filling the bar on a wide window. */}
      <Group
        gap="xs"
        wrap="nowrap"
        align="stretch"
        style={{ width: "max-content", minWidth: "100%" }}
      >
        <Stat
          icon={<IconTimeline size="1rem" />}
          label="Events"
          value={Number(stats.total_events).toLocaleString()}
          tooltip="Connection matching events in the current analysis"
        />
        <Stat
          icon={<IconArrowsJoin size="1rem" />}
          label="DNS"
          value={Number(stats.total_dns).toLocaleString()}
        />
        <Stat
          icon={<IconUser size="1rem" />}
          label="Processes"
          value={Number(stats.distinct_processes).toLocaleString()}
        />
        <Stat
          icon={<IconNetwork size="1rem" />}
          label="Destinations"
          value={Number(stats.distinct_hosts).toLocaleString()}
        />
        <Stat
          icon={<IconShieldOff size="1rem" />}
          label="Blocked"
          value={Number(stats.blocked_count).toLocaleString()}
          tone={stats.blocked_count > 0n ? "red" : undefined}
        />
        <Stat icon={<IconClock size="1rem" />} label="Time span" value={spanLabel} />
      </Group>
    </ScrollArea>
  );
}

interface StatProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  tooltip?: string;
  tone?: "red" | "yellow" | "teal";
}

function Stat({ icon, label, value, tooltip, tone }: StatProps) {
  const content = (
    <Card
      withBorder
      radius="sm"
      padding="xs"
      // In a nowrap row the cards would otherwise squeeze until the labels
      // wrapped; a floor keeps them legible and lets the strip scroll instead.
      miw={rem(150)}
      style={{
        flex: "1 0 auto",
        borderColor: tone ? `var(--mantine-color-${tone}-7)` : undefined,
      }}
    >
      <Group gap={6} align="center" wrap="nowrap">
        <span style={{ color: "var(--mantine-color-dimmed)", display: "flex" }}>{icon}</span>
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          {label}
        </Text>
      </Group>
      <Text fw={700} size="md" className="mono" style={{ lineHeight: 1.1, marginTop: 4 }}>
        {value}
      </Text>
    </Card>
  );
  if (tooltip) {
    return (
      <Tooltip label={tooltip} withArrow openDelay={300}>
        {content}
      </Tooltip>
    );
  }
  return content;
}

function useSpanLabel(stats: LogStats): string {
  if (!stats.span_start || !stats.span_end) return "—";
  const start = new Date(stats.span_start);
  const end = new Date(stats.span_end);
  const durMs = end.getTime() - start.getTime();
  return humanDuration(durMs);
}

function humanDuration(ms: number): string {
  if (ms < 0) return "—";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}
