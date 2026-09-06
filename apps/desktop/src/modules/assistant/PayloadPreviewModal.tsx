// "Here is the request. Read it, then decide."
//
// The first send is gated on this dialog because no summary of a privacy
// boundary is as convincing as the bytes. What is shown is not a rendering
// of the payload — it is the payload: the Rust side builds it with the same
// function the sender serializes, so the two cannot drift.

import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  ScrollArea,
  Stack,
  Table,
  Text,
  rem,
} from "@mantine/core";
import { useClipboard } from "@mantine/hooks";
import {
  IconCheck,
  IconCopy,
  IconDeviceDesktop,
  IconWorldUpload,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";

import { ErrorBlock, LoadingBlock } from "@/components/shell/States";
import { llmPreview, type Task } from "./ipc";

interface Props {
  opened: boolean;
  onClose: () => void;
  task: Task;
  /** The question or rule text that would be sent. */
  input: string;
  /** Shown only when this is the gate before the first send. */
  onApprove?: () => void;
  approving?: boolean;
}

export function PayloadPreviewModal({
  opened,
  onClose,
  task,
  input,
  onApprove,
  approving,
}: Props) {
  const clipboard = useClipboard({ timeout: 1500 });

  const query = useQuery({
    queryKey: ["llm", "preview", task, input],
    queryFn: () => llmPreview(task, input),
    enabled: opened,
    // The payload depends on the open log's schema and on settings, both of
    // which can change between openings. Never serve a stale one.
    gcTime: 0,
    staleTime: 0,
  });

  const preview = query.data;

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      size="xl"
      title={<Text fw={600}>What would be sent</Text>}
    >
      <Stack gap="sm">
        {query.isError ? (
          <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
        ) : query.isLoading || !preview ? (
          <LoadingBlock label="Building the request…" />
        ) : (
          <>
            <Alert
              variant="light"
              color={preview.local_endpoint ? "teal" : "yellow"}
              icon={
                preview.local_endpoint ? (
                  <IconDeviceDesktop size="1rem" />
                ) : (
                  <IconWorldUpload size="1rem" />
                )
              }
              p="xs"
            >
              <Text size="xs">
                {preview.local_endpoint ? (
                  <>
                    This endpoint is on <b>your machine</b>. Nothing below
                    leaves it.
                  </>
                ) : (
                  <>
                    This request goes to <b>{hostOf(preview.url)}</b>, a third
                    party. Everything in the body below leaves your machine and
                    is subject to that provider&apos;s retention policy.
                  </>
                )}
              </Text>
            </Alert>

            <Table withRowBorders={false} verticalSpacing={2}>
              <Table.Tbody>
                <Row label="URL">
                  <Text size="xs" className="mono">
                    POST {preview.url}
                  </Text>
                </Row>
                {preview.headers.map(([name, value]) => (
                  <Row key={name} label={name}>
                    <Text size="xs" className="mono" c="dimmed">
                      {value}
                    </Text>
                  </Row>
                ))}
                <Row label="Size">
                  <Group gap={6}>
                    <Text size="xs" className="mono">
                      {Number(preview.bytes).toLocaleString()} bytes
                    </Text>
                    <Badge variant="light" color="gray">
                      sha256 {preview.sha256.slice(0, 16)}…
                    </Badge>
                  </Group>
                </Row>
              </Table.Tbody>
            </Table>

            <Text size="xs" c="dimmed">
              The digest above is recorded in the audit log for every request,
              so you can check afterwards that what was sent is what you read
              here.
            </Text>

            <ScrollArea h={rem(340)} type="auto">
              <Code block style={{ fontSize: "var(--ppxray-text-dense)", whiteSpace: "pre-wrap" }}>
                {preview.body}
              </Code>
            </ScrollArea>

            <Group justify="space-between">
              <Button
                size="xs"
                variant="subtle"
                leftSection={
                  clipboard.copied ? <IconCheck size="0.85rem" /> : <IconCopy size="0.85rem" />
                }
                onClick={() => clipboard.copy(preview.body)}
              >
                {clipboard.copied ? "Copied" : "Copy body"}
              </Button>
              <Group gap="xs">
                <Button size="xs" variant="default" onClick={onClose}>
                  {onApprove ? "Cancel" : "Close"}
                </Button>
                {onApprove && (
                  <Button size="xs" onClick={onApprove} loading={approving}>
                    Send this
                  </Button>
                )}
              </Group>
            </Group>
          </>
        )}
      </Stack>
    </Modal>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Table.Tr>
      <Table.Td w={rem(140)} style={{ verticalAlign: "top" }}>
        <Text size="xs" c="dimmed">
          {label}
        </Text>
      </Table.Td>
      <Table.Td style={{ wordBreak: "break-all" }}>{children}</Table.Td>
    </Table.Tr>
  );
}

/** Scheme and host, for the sentence above — not for any security decision. */
function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
