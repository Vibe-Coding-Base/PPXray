import {
  ActionIcon,
  Badge,
  Group,
  NumberInput,
  ScrollArea,
  SegmentedControl,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconRobot, IconX } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import type { Rule, RuleAction } from "@ppxray/ipc-schema";

import { ExplainRuleModal } from "@/modules/assistant/ExplainRuleModal";
import { useProfileStore } from "@/stores/profile-store";
import { ChipList, type ChipBadge } from "./ChipList";
import {
  classifyTarget,
  validateApplication,
  validatePort,
  type TargetKind,
} from "./validators";

interface Props {
  rule: Rule;
  index: number;
  onClose: () => void;
}

const TARGET_KIND_META: Record<TargetKind, ChipBadge> = {
  hostname: { kind: "host", color: "gray.4" },
  wildcard: { kind: "glob", color: "blue.3" },
  ipv4: { kind: "ipv4", color: "teal.3" },
  ipv6: { kind: "ipv6", color: "teal.3" },
  "ipv4-cidr": { kind: "cidr", color: "grape.3" },
  "ipv6-cidr": { kind: "cidr", color: "grape.3" },
  "ipv4-range": { kind: "range", color: "cyan.3" },
  env: { kind: "env", color: "yellow.3" },
  invalid: { kind: "?", color: "red.3" },
};

export function RuleDetailPanel({ rule, index, onClose }: Props) {
  const [explaining, setExplaining] = useState(false);
  const updateRule = useProfileStore((s) => s.updateRule);
  const proxies = useProfileStore((s) => s.profile?.proxies ?? []);
  const chains = useProfileStore((s) => s.profile?.chains ?? []);

  const proxyOptions = useMemo(
    () =>
      proxies.map((p) => ({
        value: String(p.id),
        label: `${p.label || `${p.address}:${p.port}`} - ${p.proxy_type}`,
      })),
    [proxies],
  );

  const chainOptions = useMemo(
    () =>
      chains.map((c) => ({
        value: String(c.id),
        label: c.name ? `${c.name} (#${c.id})` : `Chain #${c.id}`,
      })),
    [chains],
  );

  function patch<K extends keyof Rule>(key: K, value: Rule[K]) {
    updateRule(index, { [key]: value } as Partial<Rule>);
  }

  function setAction(a: RuleAction) {
    updateRule(index, { action: a });
  }

  return (
    <Stack
      gap="sm"
      p="sm"
      h="100%"
      style={{
        borderLeft: "1px solid var(--ppxray-border)",
        overflow: "hidden",
      }}
    >
      <Group justify="space-between" wrap="nowrap">
        <Group gap="xs">
          <Badge variant="default">
            #{index + 1}
          </Badge>
          <Text size="sm" fw={600}>
            Rule detail
          </Text>
        </Group>
        <Group gap={2}>
          <Tooltip label="Explain this rule with the assistant" withArrow>
            <ActionIcon
              variant="subtle"
              onClick={() => setExplaining(true)}
              aria-label="Explain this rule"
            >
              <IconRobot size="1rem" />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Close detail (Esc)" withArrow>
            <ActionIcon variant="subtle" onClick={onClose} aria-label="Close">
              <IconX size="1rem" />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      <ExplainRuleModal
        rule={explaining ? rule : null}
        index={index}
        onClose={() => setExplaining(false)}
      />

      <ScrollArea h="100%" type="auto" scrollbarSize={6} offsetScrollbars>
        <Stack gap="sm" pr="xs">
          <TextInput
            label="Name"
            size="xs"
            value={rule.name}
            onChange={(e) => patch("name", e.currentTarget.value)}
          />

          <Group gap="sm">
            <Switch
              size="xs"
              checked={rule.enabled}
              label="Enabled"
              onChange={(e) => patch("enabled", e.currentTarget.checked)}
            />
          </Group>

          <Stack gap={4}>
            <Text size="xs" fw={600} tt="uppercase" c="dimmed">
              Action
            </Text>
            <SegmentedControl
              size="xs"
              fullWidth
              value={rule.action.kind}
              onChange={(kind) => {
                switch (kind) {
                  case "direct":
                    setAction({ kind: "direct" });
                    break;
                  case "block":
                    setAction({ kind: "block" });
                    break;
                  case "proxy":
                    setAction({
                      kind: "proxy",
                      proxy_id:
                        rule.action.kind === "proxy"
                          ? rule.action.proxy_id
                          : (proxies[0]?.id ?? 0),
                    });
                    break;
                  case "chain":
                    setAction({
                      kind: "chain",
                      chain_id:
                        rule.action.kind === "chain"
                          ? rule.action.chain_id
                          : (chains[0]?.id ?? 0),
                    });
                    break;
                }
              }}
              data={[
                { label: "Direct", value: "direct" },
                { label: "Block", value: "block" },
                { label: "Proxy", value: "proxy", disabled: proxies.length === 0 },
                { label: "Chain", value: "chain", disabled: chains.length === 0 },
              ]}
            />
            {rule.action.kind === "proxy" && (
              <Select
                size="xs"
                label="Proxy server"
                data={proxyOptions}
                value={String(rule.action.proxy_id)}
                onChange={(v) => v && setAction({ kind: "proxy", proxy_id: parseInt(v, 10) })}
              />
            )}
            {rule.action.kind === "chain" && (
              <Select
                size="xs"
                label="Chain"
                data={chainOptions}
                value={String(rule.action.chain_id)}
                onChange={(v) => v && setAction({ kind: "chain", chain_id: parseInt(v, 10) })}
              />
            )}
          </Stack>

          <ChipList
            label="Targets"
            placeholder="host; *.example.com; 10.0.0.0/8; 10.*"
            items={rule.targets}
            validate={(v) => classifyTarget(v) !== "invalid"}
            resolveKind={(v) => TARGET_KIND_META[classifyTarget(v)]}
            onChange={(next) => patch("targets", next)}
            hint="Empty = any host"
          />

          <ChipList
            label="Applications"
            placeholder={"chrome.exe; \"C:\\path\\to\\*.exe\""}
            mono
            items={rule.applications}
            validate={validateApplication}
            onChange={(next) => patch("applications", next)}
            hint="Empty = any process"
          />

          <ChipList
            label="Ports"
            placeholder="443; 80; 8000-8100"
            items={rule.ports}
            validate={validatePort}
            onChange={(next) => patch("ports", next)}
            hint="Empty = any port"
          />

          <NumberInput
            label="Position"
            size="xs"
            value={index + 1}
            disabled
            description="Use drag-drop in the table to change position."
          />
        </Stack>
      </ScrollArea>
    </Stack>
  );
}
