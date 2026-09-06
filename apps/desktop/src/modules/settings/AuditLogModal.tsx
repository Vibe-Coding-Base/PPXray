// Every request the assistant has made, and every one it refused to make.
//
// A privacy claim you cannot check is a marketing claim. This reads back the
// same JSONL file the user can open in any editor, so the UI is a
// convenience rather than the source of truth — and the digest column lets
// them tie a line here to a payload they read in the preview.

import {
  Badge,
  Button,
  Group,
  Modal,
  ScrollArea,
  Stack,
  Table,
  Text,
  Tooltip,
  rem,
} from "@mantine/core";
import { IconTrash } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import type { AuditEntry, AuditOutcome } from "@ppxray/ipc-schema";
import { EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/shell/States";
import { llmAuditEntries, llmClearAudit } from "@/modules/assistant/ipc";

const OUTCOME_COLOR: Record<AuditOutcome, string> = {
  ok: "teal",
  failed: "red",
  blocked: "gray",
};

export function AuditLogModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["llm", "audit"],
    queryFn: () => llmAuditEntries(500),
    enabled: opened,
    staleTime: 0,
  });

  const rows = query.data ?? [];

  return (
    <Modal opened={opened} onClose={onClose} size="xl" title={<Text fw={600}>Egress log</Text>}>
      <Stack gap="sm">
        <Text size="xs" c="dimmed">
          One line per request the assistant made, newest first, including the
          ones that were refused before sending. Request bodies are not stored
          — only their SHA-256, which is enough to match a line here against a
          payload you read in the preview, without keeping a second copy of
          your log on disk.
        </Text>

        {query.isError ? (
          <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
        ) : query.isLoading ? (
          <LoadingBlock label="Reading the log…" />
        ) : rows.length === 0 ? (
          <EmptyBlock
            title="No requests recorded"
            hint="Nothing has been sent to a model provider from this machine."
          />
        ) : (
          <ScrollArea h={rem(420)} type="auto">
            <Table stickyHeader highlightOnHover verticalSpacing={3} style={{ fontSize: "var(--ppxray-text-dense)" }}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={rem(150)}>When</Table.Th>
                  <Table.Th w={rem(90)}>Result</Table.Th>
                  <Table.Th w={rem(90)}>For</Table.Th>
                  <Table.Th>Endpoint</Table.Th>
                  <Table.Th w={rem(100)}>Level</Table.Th>
                  <Table.Th w={rem(80)}>Bytes</Table.Th>
                  <Table.Th w={rem(90)}>Tokens</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((e, i) => (
                  <Row key={`${e.at}-${i}`} entry={e} />
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        )}

        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            {rows.length > 0 && `${rows.length} entries`}
          </Text>
          <Group gap="xs">
            {rows.length > 0 && (
              <Button
                size="xs"
                variant="subtle"
                color="red"
                leftSection={<IconTrash size="0.85rem" />}
                onClick={async () => {
                  await llmClearAudit();
                  await qc.invalidateQueries({ queryKey: ["llm", "audit"] });
                }}
              >
                Clear
              </Button>
            )}
            <Button size="xs" variant="default" onClick={onClose}>
              Close
            </Button>
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}

function Row({ entry }: { entry: AuditEntry }) {
  return (
    <Table.Tr>
      <Table.Td className="mono">{entry.at.replace("T", " ").replace(/\..*$/, "")}</Table.Td>
      <Table.Td>
        <Tooltip
          withArrow
          multiline
          w={rem(300)}
          disabled={!entry.detail}
          label={entry.detail ?? ""}
        >
          <Badge variant="light" color={OUTCOME_COLOR[entry.outcome]}>
            {entry.outcome}
          </Badge>
        </Tooltip>
      </Table.Td>
      <Table.Td>{entry.purpose}</Table.Td>
      <Table.Td className="mono" style={{ wordBreak: "break-all" }}>
        <Tooltip withArrow label={`sha256 ${entry.request_sha256 || "(nothing sent)"}`}>
          <span>
            {entry.endpoint} - {entry.model}
          </span>
        </Tooltip>
      </Table.Td>
      <Table.Td>{entry.data_scope}</Table.Td>
      <Table.Td className="mono" style={{ textAlign: "right" }}>
        {Number(entry.request_bytes).toLocaleString()}
      </Table.Td>
      <Table.Td className="mono" style={{ textAlign: "right" }}>
        {entry.input_tokens == null && entry.output_tokens == null
          ? "—"
          : `${entry.input_tokens ?? 0}/${entry.output_tokens ?? 0}`}
      </Table.Td>
    </Table.Tr>
  );
}
