// Right-hand detail panel for the selected alert.
// Shows: title, severity, MITRE chips, the JSON detail, and a paginated list
// of evidence event ids (clickable to drill into the events table).

import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Code,
  Group,
  ScrollArea,
  Stack,
  Text,
  Tooltip,
  rem,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconShieldX, IconX } from "@tabler/icons-react";
import type { Alert } from "@ppxray/ipc-schema";
import { useHuntStore } from "@/stores/hunt-store";
import { useAlertEvidence, useTriage } from "./queries";

interface Props {
  alert: Alert;
  onClose: () => void;
}

export function AlertDetail({ alert, onClose }: Props) {
  const evidenceQuery = useAlertEvidence(alert.id);
  const evidence = evidenceQuery.data ?? [];
  const triageMutation = useTriage();

  // The mutation applies an optimistic patch to the alert cache and rolls it
  // back on failure, so this only has to report the outcome.
  function triage(value: "tp" | "fp" | "suppressed" | "new") {
    triageMutation.mutate(
      { alertId: alert.id, triage: value },
      {
        onSuccess: () =>
          notifications.show({
            message: `Triaged as ${value.toUpperCase()}`,
            color: "teal",
          }),
        onError: (e) =>
          notifications.show({
            title: "Triage failed",
            message: String(e),
            color: "red",
          }),
      },
    );
  }

  return (
    <Stack
      gap="sm"
      h="100%"
      p="sm"
      style={{ borderLeft: "1px solid var(--ppxray-border)", overflow: "hidden" }}
    >
      <Group justify="space-between" wrap="nowrap" align="flex-start">
        <Stack gap={2} style={{ minWidth: rem(0) }}>
          <Group gap={6} wrap="nowrap">
            <SeverityBadge severity={alert.severity} />
            <Text size="xs" c="dimmed" className="mono">
              {alert.rule_id}
            </Text>
          </Group>
          <Text size="md" fw={600} style={{ wordBreak: "break-word" }}>
            {alert.rule_title}
          </Text>
        </Stack>
        <Tooltip label="Close" withArrow>
          <ActionIcon variant="subtle" onClick={onClose}>
            <IconX size="1rem" />
          </ActionIcon>
        </Tooltip>
      </Group>

      {alert.mitre && (
        <Group gap={4}>
          {alert.mitre.split(",").map((m) => (
            <Badge key={m} variant="default">
              {m.trim()}
            </Badge>
          ))}
        </Group>
      )}

      <ScrollArea h="100%" type="auto" scrollbarSize={6}>
        <Stack gap="md" pr="xs">
          <Group gap="md">
            <Field label="Process" value={alert.process ?? "—"} mono />
            <Field label="Destination" value={alert.dst ?? "—"} mono />
          </Group>
          <Field label="Time" value={alert.ts} mono />

          {alert.detail && (
            <Stack gap={4}>
              <Text size="xs" fw={600} c="dimmed" tt="uppercase">
                Evidence detail
              </Text>
              <Code block style={{ whiteSpace: "pre-wrap" }}>
                {prettyJson(alert.detail)}
              </Code>
            </Stack>
          )}

          <Stack gap={4}>
            <Text size="xs" fw={600} c="dimmed" tt="uppercase">
              Evidence event IDs ({alert.evidence_count})
            </Text>
            {evidence.length === 0 ? (
              <Text size="xs" c="dimmed">
                None recorded for this alert (DNS-only or stateful rule).
              </Text>
            ) : (
              <Group gap={4}>
                {evidence.slice(0, 50).map((eid) => (
                  <Badge
                    key={String(eid)}
                    variant="default"
                    className="mono"
                    title={`Open event #${eid} in the log table`}
                  >
                    #{String(eid)}
                  </Badge>
                ))}
                {evidence.length > 50 && (
                  <Text size="xs" c="dimmed">
                    +{evidence.length - 50} more
                  </Text>
                )}
              </Group>
            )}
          </Stack>
        </Stack>
      </ScrollArea>

      <Group gap="xs">
        <Button
          size="xs"
          color="red"
          leftSection={<IconShieldX size="0.85rem" />}
          onClick={() => triage("tp")}
        >
          True positive
        </Button>
        <Button
          size="xs"
          variant="default"
          leftSection={<IconCheck size="0.85rem" />}
          onClick={() => triage("fp")}
        >
          False positive
        </Button>
        <Button
          size="xs"
          variant="subtle"
          color="gray"
          onClick={() => triage("suppressed")}
        >
          Suppress
        </Button>
        {alert.triage !== "new" && (
          <Button size="xs" variant="subtle" onClick={() => triage("new")}>
            Reset
          </Button>
        )}
      </Group>
    </Stack>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <Box>
      <Text size="xs" fw={600} c="dimmed" tt="uppercase">
        {label}
      </Text>
      <Text size="sm" className={mono ? "mono" : undefined}>
        {value}
      </Text>
    </Box>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = severity === "Critical"
    ? "red.9"
    : severity === "High"
      ? "red"
      : severity === "Medium"
        ? "orange"
        : "yellow";
  return <Badge color={color} size="sm" variant="filled">{severity}</Badge>;
}

function prettyJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

// Avoid an unused-import warning for the typed alias used elsewhere.
export const _useHuntStore = useHuntStore;
