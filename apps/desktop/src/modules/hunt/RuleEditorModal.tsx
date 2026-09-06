// Simple YAML rule editor. We deliberately avoid pulling Monaco: textarea
// + backend parse-on-save gives the analyst instant validation feedback
// (Rust parses the same YAML the engine will load) for a fraction of the
// bundle cost.

import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  ScrollArea,
  Stack,
  Text,
  TextInput,
  Textarea,
  rem,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconDeviceFloppy, IconTemplate } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import { saveUserRule } from "./ipc";

const EDITOR_TEMPLATES: { label: string; yaml: string }[] = [
  {
    label: "events_where",
    yaml: `id: org.yourteam.example
title: Example detection
description: >
  What the rule looks for and why.
severity: medium
mitre:
  - T1071
detection:
  kind: events_where
  where: "process = 'suspicious.exe' AND dst_port = 443"
  max_per_run: 100
`,
  },
  {
    label: "events_grouped",
    yaml: `id: org.yourteam.grouped
title: Grouped detection
severity: medium
mitre: []
detection:
  kind: events_grouped
  where: "process IN ('foo.exe') AND dst_ip IS NOT NULL"
  group_by: process_and_dst
  min_count: 5
  max_per_run: 100
`,
  },
  {
    label: "dns_where",
    yaml: `id: org.yourteam.dns
title: Suspicious DNS pattern
severity: low
detection:
  kind: dns_where
  where: "qtype IN (10, 16) AND kind = 'Request'"
  max_per_run: 200
`,
  },
];

interface Props {
  opened: boolean;
  onClose: () => void;
  /** When editing an existing file, pass its metadata so the filename field
   *  is locked and we don't accidentally save a duplicate. */
  existing?: { filename: string; yaml: string } | null;
  /** Pre-seed a new file with a suggested filename + YAML body (e.g. when
   *  cloning a built-in). Ignored if `existing` is set. */
  seed?: { filename: string; yaml: string } | null;
  onSaved: () => void;
}

export function RuleEditorModal({ opened, onClose, existing, seed, onSaved }: Props) {
  const [filename, setFilename] = useState("");
  const [yaml, setYaml] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Seed when opened / when editing a different rule.
  useEffect(() => {
    if (!opened) return;
    setError(null);
    if (existing) {
      setFilename(existing.filename);
      setYaml(existing.yaml);
    } else if (seed) {
      setFilename(seed.filename);
      setYaml(seed.yaml);
    } else {
      setFilename("new-rule.yml");
      setYaml(EDITOR_TEMPLATES[0]!.yaml);
    }
  }, [opened, existing, seed]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await saveUserRule(filename, yaml);
      notifications.show({
        title: "Rule saved",
        message: filename,
        color: "teal",
      });
      onSaved();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={existing ? `Edit ${existing.filename}` : "New detection rule"}
      size="xl"
    >
      <Stack gap="sm">
        <Group gap="sm" align="flex-end">
          <TextInput
            label="Filename"
            size="xs"
            value={filename}
            onChange={(e) => setFilename(e.currentTarget.value)}
            disabled={!!existing}
            className="mono"
            style={{ flex: 1 }}
            description={
              existing
                ? "Cannot rename — delete and recreate instead."
                : "Must end in .yml or .yaml. No path separators."
            }
          />
          {!existing && (
            <Group gap={4}>
              <Text size="xs" c="dimmed">
                Template:
              </Text>
              {EDITOR_TEMPLATES.map((t) => (
                <Badge
                  key={t.label}
                  variant="default"
                  size="sm"
                  leftSection={<IconTemplate size="0.72rem" />}
                  style={{ cursor: "pointer" }}
                  onClick={() => setYaml(t.yaml)}
                >
                  {t.label}
                </Badge>
              ))}
            </Group>
          )}
        </Group>

        <Textarea
          label="Rule YAML"
          value={yaml}
          onChange={(e) => setYaml(e.currentTarget.value)}
          autosize
          minRows={18}
          maxRows={28}
          spellCheck={false}
          styles={{
            input: {
              fontFamily: "var(--mono)",
              fontSize: "var(--ppxray-text-dense)",
              lineHeight: 1.5,
            },
          }}
        />

        <ScrollArea.Autosize mah={rem(80)}>
          {error && (
            <Alert
              color="red"
              variant="light"
              icon={<IconAlertCircle size="1rem" />}
              title="Save blocked — YAML did not validate"
              styles={{ message: { fontFamily: "var(--mono)", fontSize: "var(--ppxray-text-dense)" } }}
            >
              {error}
            </Alert>
          )}
        </ScrollArea.Autosize>

        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            The backend parses your YAML with the same loader the engine uses,
            so validation errors here are exactly what <Code>hunt_run</Code>{" "}
            would see.
          </Text>
          <Group gap="xs">
            <Button size="xs" variant="subtle" onClick={onClose}>
              Cancel
            </Button>
            <Button
              size="xs"
              leftSection={<IconDeviceFloppy size="0.85rem" />}
              onClick={save}
              loading={busy}
              disabled={!filename.trim() || !yaml.trim()}
            >
              Save
            </Button>
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}
