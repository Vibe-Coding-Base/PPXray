import { Button, Card, Code, Group, Progress, Stack, Text, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconFolderOpen, IconPlug, IconPlus, IconRefresh } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { ModuleEmptyState } from "@/components/shell/States";
import { useLogStoreShallow } from "@/stores/log-store";
import { appendLogs, ingestLogs, onIngestProgress, pickLogFiles, type OpenLogResult } from "./ipc";
import { logKeys } from "./queries";

export function IngestPanel() {
  const {
    sourcePath,
    sources,
    ingestStats,
    progress,
    setLoaded,
    setProgress,
    unload,
  } = useLogStoreShallow((s) => ({
    sourcePath: s.sourcePath,
    sources: s.sources,
    ingestStats: s.ingestStats,
    progress: s.progress,
    setLoaded: s.setLoaded,
    setProgress: s.setProgress,
    unload: s.unload,
  }));

  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  // An ingest rebuilds `events` / `dns_events` outright, so every cached log
  // read is stale by definition. Nothing else invalidates these — the app
  // deliberately has no background refetching (see `App.tsx`).
  const invalidateLogQueries = () =>
    queryClient.invalidateQueries({ queryKey: logKeys.all });

  // Subscribe to progress events for the lifetime of the module.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onIngestProgress((p) => setProgress(p)).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, [setProgress]);

  /** Every way of loading runs through here: open, add, re-ingest. */
  async function load(title: string, run: () => Promise<OpenLogResult>) {
    try {
      setBusy(true);
      setProgress({
        bytes_read: 0n,
        total_bytes: 0n,
        events_inserted: 0n,
        dns_events_inserted: 0n,
        elapsed_ms: 0n,
        mb_per_sec: 0,
      });
      const result = await run();
      setLoaded(result.stats.source_path, result.stats, result.counts, result.sources);
      await invalidateLogQueries();
      const files = result.stats.source_paths.length;
      notifications.show({
        title,
        message: `${Number(result.stats.total_events).toLocaleString()} events${
          files > 1 ? ` from ${files} files` : ""
        } - ${(Number(result.stats.duration_ms) / 1000).toFixed(1)}s - ${result.stats.mb_per_sec.toFixed(1)} MB/s`,
        color: "teal",
      });
    } catch (err) {
      notifications.show({ title: `${title} failed`, message: String(err), color: "red" });
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  async function onOpen() {
    const paths = await pickLogFiles();
    // A cancelled picker is not a failure.
    if (paths.length === 0) return;
    await load("Log ingested", () => ingestLogs(paths));
  }

  async function onAdd() {
    const paths = await pickLogFiles();
    if (paths.length === 0) return;
    await load("Logs added", () => appendLogs(paths));
  }

  async function onReingest() {
    if (sources.length === 0) return;
    await load("Re-ingested", () => ingestLogs(sources));
  }

  if (!sourcePath && !progress) {
    return (
      <ModuleEmptyState
        icon={<IconPlug size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
        title="No log loaded"
        description={
          <>
            Open a Proxifier <Code>Log.txt</Code> to stream-parse it into a
            local DuckDB analysis store. Select its archives
            (<Code>Log.txt.1</Code>, <Code>Log.txt.2</Code>, …) with it to
            analyse them as one. First ingest of a 30&nbsp;MB file completes
            in a few seconds.
          </>
        }
        actions={
          <Button
            size="sm"
            leftSection={<IconFolderOpen size="1rem" />}
            onClick={onOpen}
            loading={busy}
          >
            Open log files
          </Button>
        }
      />
    );
  }

  if (progress) {
    const bytesRead = Number(progress.bytes_read);
    const totalBytes = Number(progress.total_bytes);
    const pct = totalBytes > 0
      ? Math.min(100, Math.round((bytesRead / totalBytes) * 100))
      : 0;
    return (
      <Card withBorder radius="sm" p="sm" m="sm">
        <Stack gap={6}>
          <Group justify="space-between">
            <Text size="sm" fw={600}>
              Ingesting…
            </Text>
            <Text size="xs" c="dimmed" className="mono">
              {progress.mb_per_sec.toFixed(1)} MB/s -{" "}
              {(Number(progress.elapsed_ms) / 1000).toFixed(1)}s
            </Text>
          </Group>
          <Progress value={pct} animated striped />
          <Group gap="lg">
            <Text size="xs" c="dimmed">
              {formatBytes(bytesRead)} / {formatBytes(totalBytes)}
            </Text>
            <Text size="xs" c="dimmed">
              {Number(progress.events_inserted).toLocaleString()} connection events
            </Text>
            <Text size="xs" c="dimmed">
              {Number(progress.dns_events_inserted).toLocaleString()} DNS events
            </Text>
          </Group>
        </Stack>
      </Card>
    );
  }

  const archives = sources.length - 1;
  return (
    <Group gap="sm" px="sm" py="xs" wrap="nowrap" style={{ overflow: "hidden" }}>
      <Tooltip
        withArrow
        multiline
        disabled={sources.length <= 1}
        label={
          <Stack gap={2}>
            {sources.map((s) => (
              <Text key={s} size="xs" className="mono">
                {s}
              </Text>
            ))}
          </Stack>
        }
      >
        <Text
          size="xs"
          c="dimmed"
          className="mono"
          style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
          title={sources.length <= 1 ? (sourcePath ?? undefined) : undefined}
        >
          {sourcePath}
          {archives > 0 ? ` + ${archives} more file${archives === 1 ? "" : "s"}` : ""}
        </Text>
      </Tooltip>
      {ingestStats && (
        <Text size="xs" c="dimmed" className="mono">
          {Number(ingestStats.total_events).toLocaleString()} events - {(Number(ingestStats.duration_ms) / 1000).toFixed(1)}s
        </Text>
      )}
      <Button
        size="xs"
        variant="subtle"
        leftSection={<IconRefresh size="0.85rem" />}
        onClick={onReingest}
        loading={busy}
      >
        Re-ingest
      </Button>
      <Tooltip label="Add more files to this analysis, such as older archives" withArrow>
        <Button
          size="xs"
          variant="subtle"
          leftSection={<IconPlus size="0.85rem" />}
          onClick={onAdd}
          loading={busy}
        >
          Add logs
        </Button>
      </Tooltip>
      <Button
        size="xs"
        variant="subtle"
        leftSection={<IconFolderOpen size="0.85rem" />}
        onClick={onOpen}
        loading={busy}
      >
        Open other
      </Button>
      <Button size="xs" variant="subtle" color="gray" onClick={() => {
          unload();
          void invalidateLogQueries();
        }}>
        Unload
      </Button>
    </Group>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
