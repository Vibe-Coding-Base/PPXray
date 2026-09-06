import {
  Button,
  Card,
  Code,
  Group,
  Progress,
  Stack,
  Text,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconFolderOpen,
  IconPlug,
  IconRefresh,
} from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { ModuleEmptyState } from "@/components/shell/States";
import { useLogStoreShallow } from "@/stores/log-store";
import { ingestLog, onIngestProgress, pickLogFile } from "./ipc";
import { logKeys } from "./queries";

export function IngestPanel() {
  const {
    sourcePath,
    ingestStats,
    progress,
    setLoaded,
    setProgress,
    unload,
  } = useLogStoreShallow((s) => ({
    sourcePath: s.sourcePath,
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

  /**
   * Ingest a specific file. Split out of `onOpen` so the bundled-sample
   * button runs the identical path rather than a second copy of it.
   */
  async function onIngestPath(path: string) {
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
      const result = await ingestLog(path);
      setLoaded(path, result.stats, result.counts);
      await invalidateLogQueries();
      notifications.show({
        title: "Log ingested",
        message: `${Number(result.stats.total_events).toLocaleString()} events - ${(
          Number(result.stats.duration_ms) / 1000
        ).toFixed(1)}s - ${result.stats.mb_per_sec.toFixed(1)} MB/s`,
        color: "teal",
      });
    } catch (err) {
      notifications.show({ title: "Ingest failed", message: String(err), color: "red" });
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  async function onOpen() {
    const path = await pickLogFile();
    // A cancelled picker is not a failure.
    if (!path) return;
    await onIngestPath(path);
  }

  async function onReingest() {
    if (!sourcePath) return;
    setBusy(true);
    try {
      const result = await ingestLog(sourcePath);
      setLoaded(sourcePath, result.stats, result.counts);
      await invalidateLogQueries();
      notifications.show({
        title: "Re-ingested",
        message: `${Number(result.stats.total_events).toLocaleString()} events`,
        color: "teal",
      });
    } catch (err) {
      notifications.show({ title: "Re-ingest failed", message: String(err), color: "red" });
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  if (!sourcePath && !progress) {
    return (
      <ModuleEmptyState
        icon={<IconPlug size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
        title="No log loaded"
        description={
          <>
            Open a Proxifier <Code>.txt</Code> log to stream-parse it into a
            local DuckDB analysis store. First ingest of a 30&nbsp;MB file
            completes in a few seconds.
          </>
        }
        actions={
          <Button
            size="sm"
            leftSection={<IconFolderOpen size="1rem" />}
            onClick={onOpen}
            loading={busy}
          >
            Open log file
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

  return (
    <Group gap="sm" px="sm" py="xs" wrap="nowrap" style={{ overflow: "hidden" }}>
      <Text size="xs" c="dimmed" className="mono" style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={sourcePath ?? undefined}>
        {sourcePath}
      </Text>
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
