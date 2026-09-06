import {
  ActionIcon,
  Badge,
  Button,
  Card,
  Code,
  Group,
  ScrollArea,
  Stack,
  Tabs,
  Text,
  Title,
  Tooltip,
  rem,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconBolt,
  IconList,
  IconRefresh,
  IconShieldCheck,
  IconShieldSearch,
  IconUpload,
} from "@tabler/icons-react";
import { useHotkeys } from "@mantine/hooks";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";

import { SplitGroup, SplitHandle, SplitPanel } from "@/components/shell/Splitter";
import { useLogStore, useLogStoreShallow } from "@/stores/log-store";
import { ModuleEmptyState } from "@/components/shell/States";
import { useHuntStore, useHuntStoreShallow } from "@/stores/hunt-store";
import { ingestLog, pickLogFile } from "@/modules/log/ipc";
import { logKeys } from "@/modules/log/queries";
import { AlertDetail } from "./AlertDetail";
import { AlertInbox } from "./AlertInbox";
import { RulesPanel } from "./RulesPanel";
import { useAlerts, useHuntCatalog, useRunHunt, useTriage } from "./queries";

type HuntTab = "alerts" | "rules";

export function HuntModule() {
  const sourcePath = useLogStore((s) => s.sourcePath);
  const lastReport = useHuntStore((s) => s.lastReport);
  const filter = useHuntStore((s) => s.filter);
  const selectedAlertId = useHuntStore((s) => s.selectedAlertId);
  const { setReport, selectAlert } = useHuntStoreShallow((s) => ({
    setReport: s.setReport,
    selectAlert: s.selectAlert,
  }));

  const catalogQuery = useHuntCatalog();
  const catalog = catalogQuery.data ?? [];
  const alertsQuery = useAlerts(filter);
  const alerts = alertsQuery.data ?? [];
  const runHunt = useRunHunt();
  const running = runHunt.isPending;

  const [tab, setTab] = useState<HuntTab>("alerts");
  const [openingLog, setOpeningLog] = useState(false);

  const queryClient = useQueryClient();
  const { setLogLoaded } = useLogStoreShallow((s) => ({
    setLogLoaded: s.setLoaded,
  }));

  // Inline "Open log" entry point — surfaces here so a user who landed on
  // Hunt first (and doesn't realise the Log module is a separate step) can
  // bootstrap the analysis without leaving the panel. The TopBar's "Open
  // profile" button is explicitly for .ppx files and caused confusion when
  // clicked from Hunt expecting log-open behaviour.
  async function onOpenLog() {
    setOpeningLog(true);
    try {
      const path = await pickLogFile();
      if (!path) return;
      const result = await ingestLog(path);
      setLogLoaded(path, result.stats, result.counts);
      await queryClient.invalidateQueries({ queryKey: logKeys.all });
      notifications.show({
        title: "Log ingested",
        message: `${Number(result.stats.total_events).toLocaleString()} events - ${(
          Number(result.stats.duration_ms) / 1000
        ).toFixed(1)}s`,
        color: "teal",
      });
    } catch (e) {
      notifications.show({
        title: "Ingest failed",
        message: String(e),
        color: "red",
      });
    } finally {
      setOpeningLog(false);
    }
  }

  // `useRunHunt` invalidates every hunt query on success, so the catalog
  // count and the inbox both pick up the run without extra plumbing.
  const onRunHunt = useCallback(() => {
    if (!sourcePath || running) return;
    runHunt.mutate(undefined, {
      onSuccess: (report) => {
        setReport(report);
        const errored = report.per_rule.filter((r) => r.error).length;
        notifications.show({
          title: "Hunt complete",
          message: `${Number(report.total_alerts).toLocaleString()} alerts in ${Number(
            report.duration_ms,
          )}ms${errored > 0 ? ` - ${errored} rule(s) errored` : ""}`,
          color: errored > 0 ? "yellow" : "teal",
        });
      },
      onError: (e) =>
        notifications.show({ title: "Hunt failed", message: String(e), color: "red" }),
    });
  }, [sourcePath, running, runHunt, setReport]);

  const selectedAlert = selectedAlertId != null
    ? alerts.find((a) => a.id === selectedAlertId)
    : undefined;

  // Triage is a keyboard loop: ↑/↓ walk the inbox (handled inside
  // `AlertInbox`), then t / f / s mark the alert without reaching for the
  // detail panel's buttons. `r` re-runs the catalog.
  const triageSelected = useTriage();
  const triageShortcut = useCallback(
    (value: "tp" | "fp" | "suppressed") => () => {
      if (selectedAlertId == null) return;
      triageSelected.mutate({ alertId: selectedAlertId, triage: value });
    },
    [selectedAlertId, triageSelected],
  );

  useHotkeys([
    ["r", () => onRunHunt()],
    ["t", triageShortcut("tp")],
    ["f", triageShortcut("fp")],
    ["s", triageShortcut("suppressed")],
    ["Escape", () => selectAlert(null)],
  ]);

  return (
    <Stack gap={0} h="calc(100vh - 40px)" style={{ overflow: "hidden" }}>
      <Group justify="space-between" px="sm" py="xs" wrap="nowrap">
        <Group gap="sm">
          <Title order={5}>Threat hunting</Title>
          <Badge variant="default">
            {catalog.length} rules
          </Badge>
          {lastReport && (
            <>
              <Badge color="blue" variant="light">
                {Number(lastReport.total_alerts).toLocaleString()} alerts
              </Badge>
              <Text size="xs" c="dimmed" className="mono">
                last run - {Number(lastReport.duration_ms)}ms
              </Text>
            </>
          )}
        </Group>
        <Group gap="xs">
          {!sourcePath && (
            <Button
              size="xs"
              variant="default"
              leftSection={<IconUpload size="1rem" />}
              onClick={onOpenLog}
              loading={openingLog}
            >
              Open log
            </Button>
          )}
          <Tooltip label="Re-run all rules" withArrow>
            <ActionIcon
              variant="subtle"
              onClick={onRunHunt}
              disabled={running || !sourcePath}
              aria-label="Re-run"
            >
              <IconRefresh size="1rem" />
            </ActionIcon>
          </Tooltip>
          <Button
            size="xs"
            leftSection={<IconBolt size="1rem" />}
            onClick={onRunHunt}
            loading={running}
            disabled={!sourcePath}
          >
            Run hunt
          </Button>
        </Group>
      </Group>

      {lastReport && lastReport.per_rule.some((r) => r.error) && (
        <Card
          withBorder
          radius="sm"
          p="xs"
          mx="sm"
          mb="xs"
          style={{ borderColor: "var(--mantine-color-yellow-7)" }}
        >
          <Text size="xs" fw={600} c="yellow.5">
            Some rules errored
          </Text>
          <ScrollArea h={rem(80)} type="auto">
            {lastReport.per_rule
              .filter((r) => r.error)
              .map((r) => (
                <Text key={r.rule_id} size="xs" c="dimmed" className="mono">
                  {r.rule_id}: {r.error}
                </Text>
              ))}
          </ScrollArea>
        </Card>
      )}

      <Tabs
        value={tab}
        onChange={(v) => v && setTab(v as HuntTab)}
        keepMounted={false}
        style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: rem(0) }}
      >
        <Tabs.List>
          <Tabs.Tab value="alerts" leftSection={<IconShieldCheck size="1rem" />}>
            Alerts
          </Tabs.Tab>
          <Tabs.Tab value="rules" leftSection={<IconList size="1rem" />}>
            Rules
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="alerts" style={{ flex: 1, minHeight: rem(0) }}>
          {!sourcePath ? (
            <NoLogPrompt onOpenLog={onOpenLog} busy={openingLog} />
          ) : selectedAlert ? (
            <SplitGroup direction="horizontal" autoSaveId="hunt-split">
              <SplitPanel defaultSize={56} minSize={30}>
                <AlertInbox />
              </SplitPanel>
              <SplitHandle orientation="vertical" />
              <SplitPanel defaultSize={44} minSize={25}>
                <AlertDetail alert={selectedAlert} onClose={() => selectAlert(null)} />
              </SplitPanel>
            </SplitGroup>
          ) : (
            <AlertInbox />
          )}
        </Tabs.Panel>

        <Tabs.Panel value="rules" style={{ flex: 1, minHeight: rem(0) }}>
          <RulesPanel />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}

function NoLogPrompt({
  onOpenLog,
  busy,
}: {
  onOpenLog: () => void;
  busy: boolean;
}) {
  return (
    <ModuleEmptyState
      icon={<IconShieldSearch size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
      title="No log loaded"
      description={
        <>
          Open a Proxifier <Code>.txt</Code> log to start hunting. The engine
          runs the built-in and user catalog over the loaded analysis store.
        </>
      }
      actions={
        <Button
          size="sm"
          leftSection={<IconUpload size="1rem" />}
          onClick={onOpenLog}
          loading={busy}
        >
          Open log file
        </Button>
      }
      footnote={
        <>
          You can still manage rules in the <b>Rules</b> tab without a log.
        </>
      }
    />
  );
}
