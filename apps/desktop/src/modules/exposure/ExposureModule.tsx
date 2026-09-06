// Top-level module for the Exposure Surface tab.
//
// Left pane: `ExposureSankey` (SVG flow diagram — Processes → Rules → Ports
// → Exits → Proxy hops → Internet). Right pane: `FindingsPanel`.
//
// The Sankey and the findings panel cross-link via the `isolatedNodeKey`
// string — clicking a finding resolves to a node key and pipes it back in
// as isolation. Hover also bubbles up so the top status strip can show
// "Hovered: firefox.exe → Allow HTTPS → 443 → Direct → Internet".
//
// We recompute the graph on profile change with a 400 ms debounce — safe
// to run on every keystroke (pure over in-memory state) but we still
// debounce to avoid excess SVG re-layouts during drag-reorders.

import {
  Badge,
  Box,
  Button,
  Code,
  Group,
  SegmentedControl,
  Stack,
  Tabs,
  Title,
  Tooltip,
  rem,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconAtom,
  IconEye,
  IconFolderOpen,
  IconEyeOff,
  IconListDetails,
  IconRefresh,
} from "@tabler/icons-react";
import { useCallback, useMemo, useState } from "react";

import type { ExposureGraph } from "@ppxray/ipc-schema";
import {
  ErrorBlock,
  LoadingBlock,
  ModuleEmptyState,
} from "@/components/shell/States";
import { useOpenProfile } from "@/modules/rules/use-open-profile";
import { SplitGroup, SplitHandle, SplitPanel } from "@/components/shell/Splitter";
import { useProfileStoreShallow } from "@/stores/profile-store";

import { ExposureSankey, nodeKey } from "./ExposureSankey";
import { FindingsPanel } from "./FindingsPanel";
import { RulesToInternetTable } from "./RulesToInternetTable";
import { useExposureGraph } from "./queries";
import type { LaidOutNode } from "./sankey-layout";

type FlowFilter = "all" | "first-match";

export function ExposureModule({
  onPivotToRules,
}: {
  onPivotToRules?: (ruleIndex: number) => void;
}) {
  const { open: openProfile, opening } = useOpenProfile();
  const { profile, openDetail } = useProfileStoreShallow((s) => ({
    profile: s.profile,
    openDetail: s.openDetail,
  }));
  const [isolatedKey, setIsolatedKey] = useState<string | undefined>(undefined);
  const [hoverLabel, setHoverLabel] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<FlowFilter>("all");

  // Debounced recompute keyed on the profile revision — see `queries.ts`.
  const graphQuery = useExposureGraph();
  const graph = graphQuery.data ?? null;

  const displayGraph = useMemo(() => {
    if (!graph) return null;
    if (filterMode === "all") return graph;
    return {
      ...graph,
      flows: graph.flows.filter((f) => f.is_first_match),
    };
  }, [graph, filterMode]);

  const onPickRule = useCallback(
    (ruleProfileIndex: number) => {
      openDetail(ruleProfileIndex);
      onPivotToRules?.(ruleProfileIndex);
    },
    [onPivotToRules, openDetail],
  );

  /** Translate a finding's (rule_indices / proxy_ids / chain_ids) into a
   *  node key the Sankey can isolate on. Rules win when present — they're
   *  the most specific lever. `processIndex` findings have no dedicated
   *  node since the processes column was dropped; those fall back to the
   *  first rule that matches the process bucket. */
  const isolateFromFinding = useCallback(
    (
      params: {
        ruleProfileIndex?: number;
        processIndex?: number;
        proxyId?: number;
        chainId?: number;
      },
    ) => {
      if (!graph) return;
      if (params.ruleProfileIndex != null) {
        const refIdx = graph.rules.findIndex((r) => r.index === params.ruleProfileIndex);
        if (refIdx >= 0) {
          setIsolatedKey(nodeKey.rule(refIdx));
          return;
        }
      }
      if (params.processIndex != null) {
        // No processes column anymore — isolate on the first rule that
        // matches this process bucket (typically the unlisted-reaches-
        // internet case).
        const flow = graph.flows.find(
          (f) => f.process_index === params.processIndex && f.is_first_match,
        );
        if (flow) {
          setIsolatedKey(nodeKey.rule(flow.rule_index));
          return;
        }
      }
      if (params.proxyId != null) {
        const hopIdx = graph.proxy_hops.findIndex((h) => h.proxy_id === params.proxyId);
        if (hopIdx >= 0) {
          setIsolatedKey(nodeKey.hop(hopIdx));
          return;
        }
      }
      if (params.chainId != null) {
        const exitIdx = graph.channels.findIndex(
          (c) => c.kind.kind === "chain" && c.kind.chain_id === params.chainId,
        );
        if (exitIdx >= 0) {
          setIsolatedKey(nodeKey.exit(exitIdx));
        }
      }
    },
    [graph],
  );

  if (!profile) {
    return (
      <ModuleEmptyState
        icon={<IconAtom size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
        title="No profile loaded"
        description={
          <>
            This view maps what a profile&apos;s enabled rules actually let out
            to the Internet. Open a <Code>.ppx</Code> profile to see its
            exposure surface.
          </>
        }
        actions={
          <Button
            size="sm"
            leftSection={<IconFolderOpen size="1rem" />}
            onClick={() => void openProfile()}
            loading={opening}
          >
            Open profile
          </Button>
        }
      />
    );
  }

  return (
    <Stack gap={0} h="calc(100vh - 40px)">
      <Group justify="space-between" align="center" px="sm" py="xs">
        <Group gap="sm">
          <Title order={5}>Exposure surface</Title>
          {displayGraph && (
            <>
              <Badge variant="default">
                {displayGraph.rules.length} enabled rules
              </Badge>
              <Badge
                color={displayGraph.summary.has_default_deny ? "teal" : "red"}
                variant="light"
              >
                {displayGraph.summary.has_default_deny
                  ? "Default-deny ✓"
                  : "No default-deny"}
              </Badge>
              <Badge color="gray" variant="default">
                Exposure {displayGraph.summary.aggregate_breadth.toFixed(1)}
              </Badge>
              {displayGraph.proxy_hops.length > 0 && (
                <Badge color="orange" variant="light">
                  {displayGraph.proxy_hops.length} proxy hop
                  {displayGraph.proxy_hops.length === 1 ? "" : "s"}
                </Badge>
              )}
              {hoverLabel && (
                <Badge color="blue" variant="light">
                  {hoverLabel}
                </Badge>
              )}
            </>
          )}
        </Group>

        <Group gap="xs">
          <SegmentedControl
            size="xs"
            value={filterMode}
            onChange={(v) => setFilterMode(v as FlowFilter)}
            data={[
              { value: "all", label: "All flows" },
              { value: "first-match", label: "First match only" },
            ]}
          />
          <Tooltip
            label={isolatedKey ? "Clear isolation" : "Nothing isolated"}
            withArrow
          >
            <Button
              size="xs"
              variant={isolatedKey ? "filled" : "default"}
              color={isolatedKey ? "blue" : undefined}
              leftSection={isolatedKey ? <IconEyeOff size="1rem" /> : <IconEye size="1rem" />}
              onClick={() => setIsolatedKey(undefined)}
              disabled={!isolatedKey}
            >
              {isolatedKey ? "Clear" : "No isolation"}
            </Button>
          </Tooltip>
          <Tooltip label="Recompute now" withArrow>
            <Button
              size="xs"
              variant="default"
              leftSection={<IconRefresh size="1rem" />}
              onClick={() => void graphQuery.refetch()}
              loading={graphQuery.isFetching}
            >
              Refresh
            </Button>
          </Tooltip>
        </Group>
      </Group>

      <Box style={{ flex: 1, minHeight: rem(0) }}>
        <SplitGroup direction="horizontal" autoSaveId="exposure-split">
          <SplitPanel defaultSize={68} minSize={40}>
            <Box style={{ height: "100%", minHeight: rem(0) }}>
              {displayGraph ? (
                <ExposureSankey
                  graph={displayGraph}
                  isolatedNodeKey={isolatedKey}
                  onHover={(n) => setHoverLabel(n ? hoverDescription(n) : null)}
                  onPickRule={onPickRule}
                  onPickIsolation={(k) => setIsolatedKey(k)}
                />
              ) : (
                <SceneMessage>
                  {graphQuery.isError ? (
                    <ErrorBlock
                      error={graphQuery.error}
                      onRetry={() => void graphQuery.refetch()}
                    />
                  ) : (
                    <LoadingBlock label="Computing exposure graph…" />
                  )}
                </SceneMessage>
              )}
            </Box>
          </SplitPanel>
          <SplitHandle orientation="vertical" />
          <SplitPanel defaultSize={32} minSize={25}>
            {displayGraph && (
              <Tabs
                defaultValue="rules"
                keepMounted={false}
                styles={{
                  root: { display: "flex", flexDirection: "column", height: "100%" },
                  panel: { flex: 1, minHeight: rem(0), overflow: "hidden" },
                }}
              >
                <Tabs.List>
                  <Tabs.Tab
                    value="rules"
                    leftSection={<IconListDetails size="1rem" />}
                  >
                    Rules → Internet
                    <Badge ml={6} variant="default">
                      {countRuleLanes(displayGraph)}
                    </Badge>
                  </Tabs.Tab>
                  <Tabs.Tab
                    value="findings"
                    leftSection={<IconAlertTriangle size="1rem" />}
                  >
                    Findings
                    {displayGraph.findings.length > 0 && (
                      <Badge
                        ml={6}
                        color={
                          displayGraph.summary.finding_counts.critical > 0
                            ? "red"
                            : displayGraph.summary.finding_counts.high > 0
                              ? "orange"
                              : "yellow"
                        }
                      >
                        {displayGraph.findings.length}
                      </Badge>
                    )}
                  </Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="rules">
                  <RulesToInternetTable
                    graph={displayGraph}
                    onFocusRule={onPickRule}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="findings">
                  <FindingsPanel
                    graph={displayGraph}
                    onFocusRule={onPickRule}
                    onIsolate={(params) => isolateFromFinding(params)}
                  />
                </Tabs.Panel>
              </Tabs>
            )}
          </SplitPanel>
        </SplitGroup>
      </Box>
    </Stack>
  );
}

/** Centred overlay on the Sankey's own backdrop, so a failure or a slow
 *  recompute reads as part of the scene rather than a blank panel. */
function SceneMessage({ children }: { children: React.ReactNode }) {
  return (
    <Stack
      align="center"
      justify="center"
      style={{ height: "100%", background: "var(--ppxray-scene-bg)" }}
    >
      {children}
    </Stack>
  );
}


function hoverDescription(node: LaidOutNode): string {
  switch (node.tag.kind) {
    case "rule":
      return `Rule #${node.tag.rule.index + 1}: ${node.tag.rule.name}`;
    case "port":
      return `Port: ${node.tag.port.label}`;
    case "exit":
      return `Exit: ${node.tag.channel.label}`;
    case "hop":
      return `Proxy hop: ${node.tag.hop.label ?? `#${node.tag.hop.proxy_id}`} (${node.tag.hop.proxy_type})`;
    case "internet":
      return "Internet";
  }
}

/** Count of distinct (rule × port × exit) lanes — matches the number of
 *  first-match rows the table shows by default. Used for the tab badge. */
function countRuleLanes(graph: ExposureGraph): number {
  const seen = new Set<string>();
  for (const f of graph.flows) {
    if (!f.is_first_match) continue;
    const ruleRef = graph.rules[f.rule_index];
    if (!ruleRef) continue;
    seen.add(`${ruleRef.index}:${f.port_index}:${f.channel_index}`);
  }
  return seen.size;
}

export default ExposureModule;
