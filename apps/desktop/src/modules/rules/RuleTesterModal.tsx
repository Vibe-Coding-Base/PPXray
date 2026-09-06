import {
  Badge,
  Box,
  Button,
  Group,
  Modal,
  NumberInput,
  ScrollArea,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
  rem,
} from "@mantine/core";
import {
  IconArrowRight,
  IconCheck,
  IconMinus,
  IconTargetArrow,
  IconX,
} from "@tabler/icons-react";
import { useState } from "react";

import type {
  FieldOutcome,
  Rule,
  RuleEvaluation,
  SimulationResult,
  WinnerAction,
} from "@ppxray/ipc-schema";
import { useProfileStore } from "@/stores/profile-store";
import { simulateMatch } from "./ipc";

interface Props {
  opened: boolean;
  onClose: () => void;
  /** Callback to reveal a rule in the main table. */
  onRevealRule: (index: number) => void;
}

export function RuleTesterModal({ opened, onClose, onRevealRule }: Props) {
  const profile = useProfileStore((s) => s.profile);

  const [application, setApplication] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState<number | "">(443);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runSimulation() {
    if (!profile) return;
    setBusy(true);
    setError(null);
    try {
      const r = await simulateMatch(profile.rules, {
        application: application.trim(),
        host: host.trim(),
        port: typeof port === "number" ? port : 0,
      });
      setResult(r);
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
      title={
        <Group gap={6}>
          <IconTargetArrow size="1.1rem" />
          <Text fw={600}>Rule tester</Text>
        </Group>
      }
      size="xl"
    >
      <Stack gap="md">
        <Text size="xs" c="dimmed">
          Simulate how this profile would route a connection. The first
          enabled rule whose fields all match wins (same order as Proxifier).
        </Text>

        <Group gap="sm" align="flex-end">
          <TextInput
            label="Process (path or bare name)"
            placeholder={"firefox.exe or C:\\path\\to\\app.exe"}
            size="xs"
            value={application}
            onChange={(e) => setApplication(e.currentTarget.value)}
            className="mono"
            style={{ flex: 2 }}
          />
          <TextInput
            label="Host"
            placeholder="api.example.com or 10.0.0.5"
            size="xs"
            value={host}
            onChange={(e) => setHost(e.currentTarget.value)}
            className="mono"
            style={{ flex: 2 }}
          />
          <NumberInput
            label="Port"
            size="xs"
            min={0}
            max={65535}
            value={port}
            onChange={(v) => setPort(typeof v === "number" ? v : "")}
            style={{ width: rem(90) }}
          />
          <Button size="xs" onClick={runSimulation} loading={busy} disabled={!profile}>
            Simulate
          </Button>
        </Group>

        {error && (
          <Text size="xs" c="red">
            {error}
          </Text>
        )}

        {result && (
          <SimulationSummary
            result={result}
            rules={profile?.rules ?? []}
            onRevealRule={(i) => {
              onClose();
              onRevealRule(i);
            }}
          />
        )}
      </Stack>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Summary + per-rule trace
// ---------------------------------------------------------------------------

function SimulationSummary({
  result,
  rules,
  onRevealRule,
}: {
  result: SimulationResult;
  rules: Rule[];
  onRevealRule: (i: number) => void;
}) {
  const winner =
    result.winner != null
      ? { idx: result.winner, rule: rules[result.winner] }
      : null;

  return (
    <Stack gap="sm">
      <Box
        p="sm"
        style={{
          background: winner
            ? "var(--mantine-color-blue-light)"
            : "var(--ppxray-surface-elevated)",
          borderRadius: 4,
          border: "1px solid var(--ppxray-border-strong)",
        }}
      >
        {winner && winner.rule ? (
          <Group gap="sm" justify="space-between">
            <Group gap="xs" wrap="nowrap">
              <Badge color="blue">
                Winner #{winner.idx + 1}
              </Badge>
              <Text size="sm" fw={600}>
                {winner.rule.name}
              </Text>
              <ActionResultBadge action={result.winner_action} />
            </Group>
            <Button
              size="xs"
              variant="light"
              onClick={() => onRevealRule(winner.idx)}
              rightSection={<IconArrowRight size="0.85rem" />}
            >
              Reveal in table
            </Button>
          </Group>
        ) : (
          <Group gap="xs">
            <Badge color="gray">
              No match
            </Badge>
            <Text size="sm" c="dimmed">
              Connection would fall through all rules. Proxifier's default
              behavior applies.
            </Text>
          </Group>
        )}
      </Box>

      <ScrollArea h={rem(320)} type="auto" scrollbarSize={6}>
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th style={{ width: rem(40) }}>#</Table.Th>
              <Table.Th>Rule</Table.Th>
              <Table.Th style={{ width: rem(80) }}>Enabled</Table.Th>
              <Table.Th style={{ width: rem(110) }}>Targets</Table.Th>
              <Table.Th style={{ width: rem(110) }}>Apps</Table.Th>
              <Table.Th style={{ width: rem(110) }}>Ports</Table.Th>
              <Table.Th style={{ width: rem(80) }}>Result</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {result.evaluations.map((e) => (
              <EvalRow
                key={e.rule_index}
                e={e}
                isWinner={result.winner === e.rule_index}
                onReveal={() => onRevealRule(e.rule_index)}
              />
            ))}
          </Table.Tbody>
        </Table>
      </ScrollArea>
    </Stack>
  );
}

function EvalRow({
  e,
  isWinner,
  onReveal,
}: {
  e: RuleEvaluation;
  isWinner: boolean;
  onReveal: () => void;
}) {
  return (
    <Table.Tr style={{ opacity: e.enabled ? 1 : 0.55 }}>
      <Table.Td>
        <Text size="xs" c="dimmed" className="mono">
          {e.rule_index + 1}
        </Text>
      </Table.Td>
      <Table.Td>
        <Tooltip label="Click to reveal" withArrow openDelay={400}>
          <Text
            size="xs"
            fw={isWinner ? 600 : 500}
            c={isWinner ? "blue.3" : undefined}
            style={{ cursor: "pointer" }}
            onClick={onReveal}
          >
            {e.rule_name}
          </Text>
        </Tooltip>
      </Table.Td>
      <Table.Td>
        {e.enabled ? (
          <Badge variant="outline" color="green">
            on
          </Badge>
        ) : (
          <Badge variant="outline" color="gray">
            off
          </Badge>
        )}
      </Table.Td>
      <Table.Td>
        <OutcomeBadge outcome={e.targets_match} />
      </Table.Td>
      <Table.Td>
        <OutcomeBadge outcome={e.applications_match} />
      </Table.Td>
      <Table.Td>
        <OutcomeBadge outcome={e.ports_match} />
      </Table.Td>
      <Table.Td>
        {e.matched ? (
          isWinner ? (
            <Badge color="blue" variant="filled">
              Winner
            </Badge>
          ) : (
            <Badge color="teal" variant="light">
              Match
            </Badge>
          )
        ) : (
          <Badge color="gray" variant="light">
            Skip
          </Badge>
        )}
      </Table.Td>
    </Table.Tr>
  );
}

function OutcomeBadge({ outcome }: { outcome: FieldOutcome }) {
  const kind = outcome as unknown as string;
  if (kind === "Any") {
    return (
      <Group gap={2} wrap="nowrap">
        <IconMinus size="0.85rem" color="var(--mantine-color-dimmed)" />
        <Text size="xs" c="dimmed">
          any
        </Text>
      </Group>
    );
  }
  if (kind === "Matched") {
    return (
      <Group gap={2} wrap="nowrap">
        <IconCheck size="0.85rem" color="var(--mantine-color-teal-4)" />
        <Text size="xs" c="teal.3">
          match
        </Text>
      </Group>
    );
  }
  if (kind === "CandidateMissing") {
    return (
      <Group gap={2} wrap="nowrap">
        <IconMinus size="0.85rem" color="var(--mantine-color-yellow-4)" />
        <Text size="xs" c="yellow.4">
          n/a
        </Text>
      </Group>
    );
  }
  return (
    <Group gap={2} wrap="nowrap">
      <IconX size="0.85rem" color="var(--mantine-color-red-4)" />
      <Text size="xs" c="red.3">
        miss
      </Text>
    </Group>
  );
}

function ActionResultBadge({ action }: { action: WinnerAction | null | undefined }) {
  if (!action) return null;
  switch (action.kind) {
    case "direct":
      return <Badge color="teal">Direct</Badge>;
    case "block":
      return <Badge color="red">Block</Badge>;
    case "proxy":
      return <Badge color="blue">Proxy #{action.proxy_id}</Badge>;
    case "chain":
      return <Badge color="violet">Chain #{action.chain_id}</Badge>;
  }
}
