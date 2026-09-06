// "This process reached these hosts — here is the Targets field for it."
//
// The workflow: someone allowed a process to reach anything while they
// worked out what it needed, and now wants to narrow the rule. The log
// already holds the answer, so this reads it back in the shape Proxifier's
// Targets field takes.
//
// Entries are selectable because the suggestion is a starting point, not a
// verdict — the log records what the process *did*, which includes anything
// it did that the user is about to go and investigate.

import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Group,
  Modal,
  NumberInput,
  ScrollArea,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  Tooltip,
  rem,
} from "@mantine/core";
import { useClipboard } from "@mantine/hooks";
import { IconAlertTriangle, IconCheck, IconCopy } from "@tabler/icons-react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import type { HostSuggestion } from "@ppxray/ipc-schema";
import { EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/shell/States";
import { suggestTargets } from "./ipc";
import { logKeys } from "./queries";

interface Props {
  /** Process to suggest for; `null` keeps the modal closed. */
  process: string | null;
  onClose: () => void;
}

export function TargetSuggestionModal({ process, onClose }: Props) {
  const [minEvents, setMinEvents] = useState(2);
  const [minHosts, setMinHosts] = useState(3);
  const [includeIps, setIncludeIps] = useState(false);
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const clipboard = useClipboard({ timeout: 1500 });

  const query = useQuery({
    queryKey: [...logKeys.all, "suggest", process, minEvents, minHosts, includeIps],
    queryFn: () => suggestTargets(process!, { minEvents, minHosts, includeIps }),
    enabled: process !== null,
    placeholderData: keepPreviousData,
  });

  const rows = useMemo<HostSuggestion[]>(() => query.data?.suggestions ?? [], [query.data]);

  // A new process is a new set of entries; a stale exclusion list would
  // silently drop rows the user never saw.
  useEffect(() => setExcluded(new Set()), [process]);

  const targetsLine = useMemo(
    () =>
      rows
        .filter((r) => !excluded.has(r.value))
        .map((r) => r.value)
        .join("; "),
    [rows, excluded],
  );

  const toggle = (value: string) =>
    setExcluded((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });

  const selected = rows.length - excluded.size;

  return (
    <Modal
      opened={process !== null}
      onClose={onClose}
      title={
        <Group gap="xs">
          <Text fw={600}>Suggested targets</Text>
          <Code>{process}</Code>
        </Group>
      }
      size="xl"
    >
      <Stack gap="sm">
        <Group gap="lg" wrap="nowrap" align="flex-end">
          <NumberInput
            size="xs"
            label="Min connections"
            description="Drops one-off noise"
            min={1}
            value={minEvents}
            onChange={(v) => setMinEvents(Number(v) || 1)}
            style={{ width: rem(150) }}
          />
          <NumberInput
            size="xs"
            label="Hosts per wildcard"
            description="Before *.domain is offered"
            min={2}
            value={minHosts}
            onChange={(v) => setMinHosts(Math.max(2, Number(v) || 2))}
            style={{ width: rem(170) }}
          />
          <Switch
            size="xs"
            label="Include bare IPs"
            checked={includeIps}
            onChange={(e) => setIncludeIps(e.currentTarget.checked)}
            mb={6}
          />
        </Group>

        {query.isError ? (
          <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
        ) : query.isLoading ? (
          <LoadingBlock label="Reading destinations…" />
        ) : rows.length === 0 ? (
          <EmptyBlock
            title="No destinations recorded for this process"
            hint="Lower the minimum connection count, or check the process reached anything in this log."
          />
        ) : (
          <>
            <Group gap="xs">
              <Text size="xs" c="dimmed">
                {query.data?.distinct_destinations} destinations seen -{" "}
                {rows.length} entries - {selected} selected
              </Text>
            </Group>

            <ScrollArea h={rem(320)} type="auto">
              <Table stickyHeader highlightOnHover verticalSpacing={4}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th w={rem(36)} />
                    <Table.Th>Target</Table.Th>
                    <Table.Th w={rem(90)}>Conns</Table.Th>
                    <Table.Th w={rem(160)}>Last seen</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {rows.map((r) => (
                    <Table.Tr key={r.value}>
                      <Table.Td>
                        <Checkbox
                          size="xs"
                          checked={!excluded.has(r.value)}
                          onChange={() => toggle(r.value)}
                          aria-label={`Include ${r.value}`}
                        />
                      </Table.Td>
                      <Table.Td>
                        <Group gap={6} wrap="nowrap">
                          <Text size="xs" className="mono">
                            {r.value}
                          </Text>
                          {r.kind === "Wildcard" && (
                            <Tooltip
                              withArrow
                              multiline
                              w={rem(320)}
                              label={`Stands in for: ${r.covered_hosts.join(", ")}`}
                            >
                              <Badge variant="light" color="blue">
                                {r.covers} hosts
                              </Badge>
                            </Tooltip>
                          )}
                          {r.kind === "Ip" && (
                            <Badge variant="light" color="gray">
                              IP
                            </Badge>
                          )}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" className="mono">
                          {Number(r.events).toLocaleString()}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" c="dimmed" className="mono">
                          {r.last_seen ?? "—"}
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>

            <Alert
              variant="light"
              color="yellow"
              icon={<IconAlertTriangle size="1rem" />}
              p="xs"
            >
              <Text size="xs">
                This is what the process <b>did</b>, not what it{" "}
                <b>should be allowed</b> to do. Read the list before pasting
                it — anything unexpected in here is worth investigating rather
                than allowing.
              </Text>
            </Alert>

            <Textarea
              label="Targets field"
              description="Paste into the rule's Targets box"
              value={targetsLine}
              readOnly
              autosize
              minRows={2}
              maxRows={6}
              className="mono"
              styles={{ input: { fontSize: "var(--ppxray-text-dense)" } }}
            />

            <Group justify="flex-end">
              <Button size="xs" variant="default" onClick={onClose}>
                Close
              </Button>
              <Button
                size="xs"
                leftSection={
                  clipboard.copied ? <IconCheck size="0.85rem" /> : <IconCopy size="0.85rem" />
                }
                onClick={() => clipboard.copy(targetsLine)}
                disabled={targetsLine.length === 0}
              >
                {clipboard.copied ? "Copied" : "Copy"}
              </Button>
            </Group>
          </>
        )}
      </Stack>
    </Modal>
  );
}
