// "What does this rule actually match?"
//
// This is the one assistant feature that costs nothing in privacy at any
// setting: a rule is the user's own configuration, not their traffic, so the
// request carries the rule text and nothing else. No log is read and no
// query is run — which is also why the answer is about the *rule*, never
// about what the machine did with it.

import { Alert, Badge, Button, Code, Group, Modal, ScrollArea, Stack, Text,
  rem,
} from "@mantine/core";
import { IconEye, IconRobot } from "@tabler/icons-react";
import { useEffect, useState } from "react";

import type { Rule } from "@ppxray/ipc-schema";
import { ErrorBlock, LoadingBlock } from "@/components/shell/States";
import { Markdown } from "./Markdown";
import { PayloadPreviewModal } from "./PayloadPreviewModal";
import { llmAsk, llmMarkReviewed, llmStatus, type AssistantReply } from "./ipc";

interface Props {
  /** `null` keeps the modal closed. */
  rule: Rule | null;
  index: number;
  onClose: () => void;
}

export function ExplainRuleModal({ rule, index, onClose }: Props) {
  const [reply, setReply] = useState<AssistantReply | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);

  const text = rule ? describe(rule, index) : "";

  // A different rule is a different question; carrying the previous answer
  // over would attribute it to this rule.
  useEffect(() => {
    setReply(null);
    setError(null);
  }, [rule]);

  async function ask(afterApproval: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (afterApproval) await llmMarkReviewed();
      setPreviewOpen(false);
      setReply(await llmAsk("explain-rule", text));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function start() {
    const status = await llmStatus();
    if (!status.settings.enabled) {
      setError(
        "The assistant is off. Turn it on under Settings — it stays disabled until you do.",
      );
      return;
    }
    if (!status.settings.reviewed_payload) {
      setPreviewOpen(true);
      return;
    }
    await ask(false);
  }

  return (
    <>
      <Modal
        opened={rule !== null}
        onClose={onClose}
        size="lg"
        title={
          <Group gap="xs">
            <IconRobot size="1.1rem" />
            <Text fw={600}>Explain rule</Text>
            <Badge variant="default">
              #{index + 1}
            </Badge>
          </Group>
        }
      >
        <Stack gap="sm">
          <Alert variant="light" color="teal" p="xs">
            <Text size="xs">
              This sends the rule text only. Nothing from your log is read or
              transmitted, at any privacy level.
            </Text>
          </Alert>

          <Code block style={{ fontSize: "var(--ppxray-text-dense)", whiteSpace: "pre-wrap" }}>
            {text}
          </Code>

          {error && <ErrorBlock error={error} onRetry={() => void start()} />}
          {busy && !reply && <LoadingBlock label="Asking…" />}

          {reply && (
            <ScrollArea.Autosize mah={rem(360)} type="auto">
              <Alert variant="light" color="blue" p="sm">
                <Markdown>{reply.text}</Markdown>
                <Group gap={6} mt={6}>
                  <Badge variant="light" color="orange">
                    unverified
                  </Badge>
                  <Text size="xs" c="dimmed">
                    A model wrote this. Check it against the matcher in Rules →
                    Test.
                  </Text>
                </Group>
              </Alert>
            </ScrollArea.Autosize>
          )}

          <Group justify="space-between">
            <Button
              size="xs"
              variant="subtle"
              leftSection={<IconEye size="0.85rem" />}
              onClick={() => setPreviewOpen(true)}
            >
              See what would be sent
            </Button>
            <Group gap="xs">
              <Button size="xs" variant="default" onClick={onClose}>
                Close
              </Button>
              <Button size="xs" loading={busy} onClick={() => void start()}>
                {reply ? "Ask again" : "Explain"}
              </Button>
            </Group>
          </Group>
        </Stack>
      </Modal>

      <PayloadPreviewModal
        opened={previewOpen}
        onClose={() => setPreviewOpen(false)}
        task="explain-rule"
        input={text}
        onApprove={() => void ask(true)}
        approving={busy}
      />
    </>
  );
}

/**
 * The rule as text.
 *
 * Written out in Proxifier's own vocabulary — Applications, Targets, Ports,
 * Action — rather than sent as the internal JSON, so the model reasons about
 * the thing the user configured rather than about this app's field names.
 */
function describe(rule: Rule, index: number): string {
  // An empty list means "match any" in Proxifier, which is the opposite of
  // "matches nothing" — worth saying explicitly rather than sending a blank.
  const list = (values: string[]) => (values.length > 0 ? values.join("; ") : "(any)");
  return [
    `Rule #${index + 1}: ${rule.name || "(unnamed)"}`,
    `Enabled: ${rule.enabled ? "yes" : "no"}`,
    `Applications: ${list(rule.applications)}`,
    `Targets: ${list(rule.targets)}`,
    `Ports: ${list(rule.ports)}`,
    `Action: ${actionOf(rule)}`,
  ].join("\n");
}

function actionOf(rule: Rule): string {
  const a = rule.action;
  switch (a.kind) {
    case "direct":
      return "Direct";
    case "block":
      return "Block";
    case "proxy":
      return `Proxy (proxy id ${a.proxy_id})`;
    case "chain":
      return `Chain (chain id ${a.chain_id})`;
  }
}
