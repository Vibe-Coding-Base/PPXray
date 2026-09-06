import { Badge, Group, ScrollArea, Stack, Text, UnstyledButton, rem } from "@mantine/core";
import {
  IconAlertCircle,
  IconAlertTriangle,
  IconInfoCircle,
  IconShieldOff,
} from "@tabler/icons-react";

import type {
  ExposureFinding,
  ExposureGraph,
  FindingSeverity,
} from "@ppxray/ipc-schema";

export interface IsolateParams {
  ruleProfileIndex?: number;
  processIndex?: number;
  proxyId?: number;
  chainId?: number;
}

export interface FindingsPanelProps {
  graph: ExposureGraph;
  onFocusRule?: (ruleProfileIndex: number) => void;
  onIsolate?: (params: IsolateParams) => void;
}

export function FindingsPanel({ graph, onFocusRule, onIsolate }: FindingsPanelProps) {
  if (graph.findings.length === 0) {
    return (
      <Stack align="center" gap={4} p="md">
        <IconShieldOff size="2.2rem" color="var(--mantine-color-teal-5)" />
        <Text fw={600} size="sm">No findings</Text>
        <Text size="xs" c="dimmed" ta="center">
          The current profile has no detectable exposure issues.
        </Text>
      </Stack>
    );
  }

  return (
    <Stack gap={6} p="xs" style={{ height: "100%", minHeight: rem(0) }}>
      <Group gap="xs" wrap="nowrap">
        <SeverityCount label="Critical" n={graph.summary.finding_counts.critical} tone="red" />
        <SeverityCount label="High" n={graph.summary.finding_counts.high} tone="orange" />
        <SeverityCount label="Med" n={graph.summary.finding_counts.medium} tone="yellow" />
        <SeverityCount label="Low" n={graph.summary.finding_counts.low} tone="blue" />
      </Group>
      <ScrollArea type="auto" scrollbarSize={8} style={{ flex: 1, minHeight: rem(0) }}>
        <Stack gap={6}>
          {graph.findings.map((f, i) => (
            <FindingRow
              key={i}
              finding={f}
              onFocusRule={onFocusRule}
              onIsolate={onIsolate}
            />
          ))}
        </Stack>
      </ScrollArea>
    </Stack>
  );
}

function SeverityCount({ label, n, tone }: { label: string; n: number; tone: string }) {
  return (
    <Badge size="sm" color={n > 0 ? tone : "gray"} variant={n > 0 ? "filled" : "light"}>
      {label} {n}
    </Badge>
  );
}

interface FindingRowProps {
  finding: ExposureFinding;
  onFocusRule?: (ruleProfileIndex: number) => void;
  onIsolate?: (params: IsolateParams) => void;
}

function FindingRow({ finding, onFocusRule, onIsolate }: FindingRowProps) {
  const Icon = iconFor(finding.severity);
  const color = colorFor(finding.severity);

  const onClick = () => {
    // Priority: rule > proxy > chain > process. The most "actionable"
    // signal wins so the user lands on something they can change.
    if (finding.rule_indices.length > 0) {
      const ruleIdx = finding.rule_indices[0];
      onIsolate?.({ ruleProfileIndex: ruleIdx });
      onFocusRule?.(ruleIdx);
      return;
    }
    if (finding.proxy_ids.length > 0) {
      onIsolate?.({ proxyId: finding.proxy_ids[0] });
      return;
    }
    if (finding.chain_ids.length > 0) {
      onIsolate?.({ chainId: finding.chain_ids[0] });
      return;
    }
    if (finding.process_indices.length > 0) {
      onIsolate?.({ processIndex: finding.process_indices[0] });
    }
  };

  return (
    <UnstyledButton
      onClick={onClick}
      style={{
        padding: rem(8),
        borderRadius: rem(6),
        border: "1px solid var(--ppxray-panel-border, rgba(255,255,255,0.08))",
        background: "var(--ppxray-panel-bg, rgba(255,255,255,0.02))",
        textAlign: "left",
      }}
    >
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <Icon size={16} color={color} style={{ marginTop: 2, flexShrink: 0 }} />
        <Stack gap={2} style={{ flex: 1, minWidth: rem(0) }}>
          <Group gap={6} wrap="nowrap">
            <Text size="sm" fw={600} lineClamp={1}>
              {finding.title}
            </Text>
            <Badge color={color} variant="light">
              {finding.severity}
            </Badge>
          </Group>
          <Text size="xs" c="dimmed" lineClamp={3}>
            {finding.detail}
          </Text>
        </Stack>
      </Group>
    </UnstyledButton>
  );
}

function iconFor(sev: FindingSeverity) {
  switch (sev) {
    case "Critical":
      return IconAlertCircle;
    case "High":
    case "Medium":
      return IconAlertTriangle;
    case "Low":
      return IconInfoCircle;
  }
}

function colorFor(sev: FindingSeverity): string {
  switch (sev) {
    case "Critical":
      return "var(--mantine-color-red-6)";
    case "High":
      return "var(--mantine-color-orange-6)";
    case "Medium":
      return "var(--mantine-color-yellow-6)";
    case "Low":
      return "var(--mantine-color-blue-5)";
  }
}
