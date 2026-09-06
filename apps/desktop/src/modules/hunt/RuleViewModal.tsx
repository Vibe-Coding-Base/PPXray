// Read-only preview of any rule in the catalog (built-in or user). Renders
// the detection metadata + the generated YAML body, with a "Clone" button
// that pre-fills the editor for built-ins so the analyst can customize.

import {
  Badge,
  Button,
  Code,
  CopyButton,
  Divider,
  Group,
  Modal,
  ScrollArea,
  Stack,
  Text,
  rem,
} from "@mantine/core";
import {
  IconCheck,
  IconCopy,
  IconCopyPlus,
  IconExternalLink,
} from "@tabler/icons-react";

import type { HuntCatalogEntry } from "./ipc";
import { entryToYaml } from "./rule-yaml";

interface Props {
  opened: boolean;
  onClose: () => void;
  entry: HuntCatalogEntry | null;
  onClone: (entry: HuntCatalogEntry) => void;
}

export function RuleViewModal({ opened, onClose, entry, onClone }: Props) {
  if (!entry) {
    return <Modal opened={opened} onClose={onClose} title="Rule" />;
  }

  const yaml = entryToYaml(entry);
  const isBuiltin = entry.source === "builtin";

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      size="xl"
      title={
        <Group gap="xs">
          <SeverityBadge severity={entry.severity} />
          <Text fw={600}>{entry.title}</Text>
        </Group>
      }
    >
      <Stack gap="sm">
        <Group gap={4} wrap="wrap">
          <Text size="xs" c="dimmed" className="mono">
            {entry.id}
          </Text>
          <Divider orientation="vertical" />
          {isBuiltin ? (
            <Badge color="teal" variant="light">
              built-in
            </Badge>
          ) : (
            <Badge color="blue" variant="light" className="mono">
              {entry.source}
            </Badge>
          )}
          {entry.mitre.map((m) => (
            <Badge key={m} variant="default">
              {m}
            </Badge>
          ))}
        </Group>

        {entry.description.trim() && (
          <Text size="sm" c="dimmed" style={{ whiteSpace: "pre-wrap" }}>
            {entry.description}
          </Text>
        )}

        {entry.references.length > 0 && (
          <Stack gap={2}>
            <Text size="xs" fw={600} c="dimmed" tt="uppercase">
              References
            </Text>
            {entry.references.map((r) => (
              <Group key={r} gap={4} wrap="nowrap">
                <IconExternalLink size="0.85rem" color="var(--mantine-color-dimmed)" />
                <Text size="xs" className="mono">
                  {r}
                </Text>
              </Group>
            ))}
          </Stack>
        )}

        <Stack gap={2}>
          <Group justify="space-between">
            <Text size="xs" fw={600} c="dimmed" tt="uppercase">
              Detection
            </Text>
            <CopyButton value={yaml} timeout={1500}>
              {({ copied, copy }) => (
                <Button
                  size="compact-sm"
                  variant="subtle"
                  leftSection={
                    copied ? (
                      <IconCheck size="0.85rem" color="var(--mantine-color-teal-5)" />
                    ) : (
                      <IconCopy size="0.85rem" />
                    )
                  }
                  onClick={copy}
                >
                  {copied ? "Copied" : "Copy YAML"}
                </Button>
              )}
            </CopyButton>
          </Group>
          <ScrollArea.Autosize mah={rem(420)} type="auto">
            <Code block style={{ whiteSpace: "pre" }}>
              {yaml}
            </Code>
          </ScrollArea.Autosize>
        </Stack>

        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            {isBuiltin
              ? "Built-in rules are read-only. Use Clone to customize."
              : "Editing opens the YAML editor."}
          </Text>
          <Group gap="xs">
            <Button size="xs" variant="subtle" onClick={onClose}>
              Close
            </Button>
            {isBuiltin && (
              <Button
                size="xs"
                leftSection={<IconCopyPlus size="0.85rem" />}
                onClick={() => onClone(entry)}
              >
                Clone to user rule
              </Button>
            )}
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color =
    severity === "Critical"
      ? "red.9"
      : severity === "High"
        ? "red"
        : severity === "Medium"
          ? "orange"
          : "yellow";
  return (
    <Badge color={color} size="sm" variant="filled">
      {severity}
    </Badge>
  );
}
