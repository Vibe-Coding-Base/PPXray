import { Box, Button, Group, Stack, Text, rem } from "@mantine/core";
import { IconEye, IconEyeOff } from "@tabler/icons-react";
import { useHotkeys } from "@mantine/hooks";
import { useState } from "react";

import {
  SplitGroup,
  SplitHandle,
  SplitPanel,
} from "@/components/shell/Splitter";
import { useLogStore, useLogStoreShallow } from "@/stores/log-store";
import { HostPanel, ProcessPanel, RulePanel } from "./BreakdownPanels";
import { EventTable } from "./EventTable";
import { FilterBar } from "./FilterBar";
import { IngestPanel } from "./IngestPanel";
import { SearchBox } from "./SearchBox";
import { StatsCards } from "./StatsCards";
import { TimelineChart } from "./TimelineChart";
import { useLogStats } from "./queries";

export function LogModule() {
  const sourcePath = useLogStore((s) => s.sourcePath);
  const storedCounts = useLogStore((s) => s.counts);
  // Prefer the freshly-queried stats; fall back to whatever the ingest
  // returned so the cards render immediately after a load.
  const { data: queriedCounts } = useLogStats();
  const counts = queriedCounts ?? storedCounts;
  const { clearFilter } = useLogStoreShallow((s) => ({ clearFilter: s.clearFilter }));

  // Which panes are on screen. Kept here rather than in the splitter because
  // a hidden pane is not rendered at all, so React owns the decision.
  const [showTimeline, setShowTimeline] = useState(true);
  const [showBreakdowns, setShowBreakdowns] = useState(true);
  const [showTable, setShowTable] = useState(true);

  // The log view's whole interaction loop is filtering, so it gets the same
  // `/` and `Esc` the rule table has.
  useHotkeys([
    [
      "/",
      (e) => {
        e.preventDefault();
        document.getElementById("log-search-input")?.focus();
      },
    ],
    [
      "Escape",
      () => {
        // Only meaningful while a filter is active; otherwise let Escape
        // fall through to whatever modal or popover is open.
        const el = document.activeElement as HTMLElement | null;
        if (el?.tagName === "INPUT" || el?.tagName === "TEXTAREA") return;
        clearFilter();
      },
    ],
  ]);

  if (!sourcePath) {
    return <IngestPanel />;
  }

  // Fixed header, then Timeline / Breakdowns / Events in a resizable column
  // whose sizes persist under `autoSaveId`. A hidden pane is left out of the
  // group rather than collapsed inside it — see the note in `Splitter.tsx`.
  return (
    <Stack gap={0} h="calc(100vh - 40px)" style={{ overflow: "hidden" }}>
      {/* The header keeps its natural height. Without `flexShrink: 0` the
          flex column shrank it to make room for the split panes below, so
          the stats cards were clipped from underneath and looked as though
          the events table was drawn over them. */}
      <Box style={{ flexShrink: 0 }}>
        <IngestPanel />
        {counts && <StatsCards stats={counts} />}

        <Group gap="xs" px="sm" py="xs" wrap="nowrap" align="center">
          <SearchBox />
        </Group>
        <FilterBar />
      </Box>

      <Box
        style={{
          flex: 1,
          minHeight: rem(0),
          padding: "0 8px 8px 8px",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <Box style={{ flex: 1, minHeight: rem(0) }}>
          <SplitGroup direction="vertical" autoSaveId="log-vertical">
            {/* Pixel floors, not percentages: a percentage minimum leaves the
                chart with no room for its canvas on a short window. */}
            {showTimeline && (
              <SplitPanel id="timeline" defaultSize={30} minSize="150px">
                <TimelineChart />
              </SplitPanel>
            )}

            {showTimeline && showBreakdowns && <SplitHandle orientation="horizontal" />}

            {showBreakdowns && (
              <SplitPanel
                id="breakdowns"
                defaultSize={28}
                minSize="130px"
                style={{ display: "flex", flexDirection: "column" }}
              >
                <Text size="xs" fw={600} tt="uppercase" c="dimmed" px="xs" py={2}>
                  Breakdowns
                </Text>
                <Box style={{ flex: 1, minHeight: rem(0) }}>
                  <SplitGroup direction="horizontal" autoSaveId="log-breakdowns">
                    <SplitPanel defaultSize={33} minSize={15}>
                      <ProcessPanel />
                    </SplitPanel>
                    <SplitHandle orientation="vertical" />
                    <SplitPanel defaultSize={33} minSize={15}>
                      <HostPanel />
                    </SplitPanel>
                    <SplitHandle orientation="vertical" />
                    <SplitPanel defaultSize={34} minSize={15}>
                      <RulePanel />
                    </SplitPanel>
                  </SplitGroup>
                </Box>
              </SplitPanel>
            )}

            {(showTimeline || showBreakdowns) && showTable && (
              <SplitHandle orientation="horizontal" />
            )}

            {showTable && (
              <SplitPanel id="events" defaultSize={50} minSize="120px">
                <Box style={{ height: "100%", display: "flex", paddingTop: 8 }}>
                  <EventTable />
                </Box>
              </SplitPanel>
            )}
          </SplitGroup>
        </Box>

        {/* Always present and always the same height, so nothing below moves
            when a pane is hidden. */}
        <Group gap={6} wrap="nowrap" align="center" style={{ flexShrink: 0, paddingTop: 6 }}>
          <Text size="xs" c="dimmed">
            Panes
          </Text>
          <PaneToggle label="Timeline" shown={showTimeline} onToggle={setShowTimeline} />
          <PaneToggle label="Breakdowns" shown={showBreakdowns} onToggle={setShowBreakdowns} />
          <PaneToggle label="Events table" shown={showTable} onToggle={setShowTable} />
        </Group>
      </Box>
    </Stack>
  );
}

/** One pane's visibility. Filled means on screen; the icon states which,
 *  rather than claiming a direction the pane will move in. */
function PaneToggle({
  label,
  shown,
  onToggle,
}: {
  label: string;
  shown: boolean;
  onToggle: (shown: boolean) => void;
}) {
  return (
    <Button
      size="compact-sm"
      variant={shown ? "light" : "default"}
      color={shown ? "blue" : "gray"}
      leftSection={shown ? <IconEye size="0.85rem" /> : <IconEyeOff size="0.85rem" />}
      aria-pressed={shown}
      onClick={() => onToggle(!shown)}
    >
      {label}
    </Button>
  );
}
