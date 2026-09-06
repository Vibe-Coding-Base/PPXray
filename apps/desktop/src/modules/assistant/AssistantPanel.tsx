// The conversation itself: what was asked, what ran, what came back. Rendered
// both as the Assistant module and inside the drawer, so it takes its
// conversation by id and holds no state beyond the composer.
//
// Queries are shown, not hidden: in a security tool the query is the evidence,
// and each one states whether its results were shared with the model.

import {
  Alert,
  Badge,
  Box,
  Button,
  Code,
  Collapse,
  Group,
  ScrollArea,
  Stack,
  Text,
  Textarea,
  Title,
  Tooltip,
  rem,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconBulb,
  IconEye,
  IconEyeOff,
  IconMessage2,
  IconPlayerPlay,
  IconRobot,
  IconSettings,
  IconStethoscope,
} from "@tabler/icons-react";
import { useEffect, useRef, useState } from "react";

import { EmptyBlock, ErrorBlock, ModuleEmptyState } from "@/components/shell/States";
import { useLogStore } from "@/stores/log-store";
import { useAssistantStore, type Exchange } from "@/stores/assistant-store";
import { Markdown } from "./Markdown";
import { PayloadPreviewModal } from "./PayloadPreviewModal";
import { ResultTable } from "./ResultTable";
import { useAssistant } from "./use-assistant";

const SUGGESTIONS = [
  "Which processes reached the most distinct hosts?",
  "Is anything connecting on a fixed interval?",
  "What was blocked, and by which rule?",
  "Which destinations appear only once?",
];

interface Props {
  conversationId: string;
  /** Somewhere to send the user when the assistant is switched off. */
  onOpenSettings: () => void;
  /** The drawer is narrow; the module is not. */
  compact?: boolean;
}

export function AssistantPanel({ conversationId, onOpenSettings, compact }: Props) {
  const conversation = useAssistantStore(
    (s) => s.conversations.find((c) => c.id === conversationId) ?? null,
  );
  const sourcePath = useLogStore((s) => s.sourcePath);
  const { status, question, setQuestion, submit, previewFor, setPreviewFor, approveAndSend } =
    useAssistant(conversationId);

  const settings = status.data?.settings;
  const exchanges = conversation?.exchanges ?? [];
  const busy = conversation?.busy ?? false;

  // Follow the conversation as it grows, the way a chat is expected to.
  const endRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [exchanges.length, busy]);

  if (status.isError) {
    return (
      <Stack p="md" gap="sm">
        <ErrorBlock error={status.error} onRetry={() => void status.refetch()} />
      </Stack>
    );
  }

  if (status.isSuccess && !settings?.enabled) {
    return (
      <ModuleEmptyState
        icon={<IconRobot size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
        title="Assistant is off"
        description={
          <>
            It stays off until you turn it on, and while it is off ppxray makes
            no request to any model provider. Turning it on does not share your
            log either: the default privacy level sends the database schema and
            your question, the assistant writes SQL, ppxray runs it here, and
            the results stay on this machine.
          </>
        }
        actions={
          <Button
            size="sm"
            leftSection={<IconSettings size="1rem" />}
            onClick={onOpenSettings}
          >
            Open Settings
          </Button>
        }
        footnote="Point it at a local model and nothing leaves the machine at all."
      />
    );
  }

  return (
    <Stack h="100%" gap={0}>
      <Group
        px={compact ? "sm" : "md"}
        py="xs"
        justify="space-between"
        wrap="nowrap"
        style={{ borderBottom: "1px solid var(--ppxray-border)" }}
      >
        <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
          {!compact && <Title order={5}>Assistant</Title>}
          {settings && (
            <Badge
              size="sm"
              variant="light"
              color={status.data?.local_endpoint ? "teal" : "yellow"}
            >
              {status.data?.local_endpoint ? "local model" : status.data?.effective_model}
            </Badge>
          )}
          {settings && (
            <Tooltip withArrow multiline w={rem(300)} label={scopeHint(settings.data_scope)}>
              <Badge size="sm" variant="outline" color="gray">
                {scopeLabel(settings.data_scope)}
              </Badge>
            </Tooltip>
          )}
        </Group>
        <Tooltip label="Summarise this log and look for outliers" withArrow>
          <Button
            size="xs"
            variant="default"
            leftSection={<IconStethoscope size="0.85rem" />}
            disabled={busy || !sourcePath}
            onClick={() => submit("review", "")}
          >
            Review log
          </Button>
        </Tooltip>
      </Group>

      <ScrollArea style={{ flex: 1 }} type="auto">
        <Stack p={compact ? "sm" : "md"} gap="lg">
          {exchanges.length === 0 && (
            <EmptyBlock
              title={sourcePath ? "Ask something about this log" : "Open a log first"}
              hint={
                sourcePath
                  ? "The assistant answers by writing SQL that runs here, against the log you have open."
                  : "Load a Proxifier log under Log, then come back."
              }
            />
          )}
          {exchanges.map((e) => (
            <ExchangeView key={e.id} exchange={e} />
          ))}
          <div ref={endRef} />
        </Stack>
      </ScrollArea>

      <Stack p={compact ? "sm" : "md"} gap={6} style={{ borderTop: "1px solid var(--ppxray-border)" }}>
        {exchanges.length === 0 && (
          <Group gap={6}>
            {SUGGESTIONS.map((s) => (
              <Button
                key={s}
                size="compact-sm"
                variant="subtle"
                color="gray"
                onClick={() => setQuestion(s)}
              >
                {s}
              </Button>
            ))}
          </Group>
        )}
        <Group align="flex-end" wrap="nowrap">
          <Textarea
            style={{ flex: 1 }}
            placeholder="Ask about this log…"
            autosize
            minRows={1}
            maxRows={5}
            value={question}
            onChange={(e) => setQuestion(e.currentTarget.value)}
            onKeyDown={(e) => {
              // Shift+Enter for a newline, Enter to send - and never send
              // while an IME is composing, which is how a Vietnamese or CJK
              // input method commits a character.
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                submit("chat", question);
              }
            }}
          />
          <Button
            leftSection={<IconPlayerPlay size="0.85rem" />}
            loading={busy}
            disabled={!question.trim()}
            onClick={() => submit("chat", question)}
          >
            Ask
          </Button>
        </Group>
      </Stack>

      <PayloadPreviewModal
        opened={previewFor !== null}
        onClose={() => setPreviewFor(null)}
        task={previewFor?.task ?? "chat"}
        input={previewFor?.input ?? ""}
        onApprove={() => void approveAndSend()}
        approving={busy}
      />
    </Stack>
  );
}

function ExchangeView({ exchange }: { exchange: Exchange }) {
  const [showThinking, setShowThinking] = useState(false);
  const { question, reply, error } = exchange;

  return (
    <Stack gap="xs">
      <Group gap={6} align="flex-start" wrap="nowrap">
        <IconMessage2 size="1rem" style={{ marginTop: 3, flexShrink: 0 }} />
        <Text size="sm" fw={500} style={{ whiteSpace: "pre-wrap" }}>
          {question}
        </Text>
      </Group>

      {error && (
        <Alert variant="light" color="red" p="xs" icon={<IconAlertTriangle size="1rem" />}>
          <Text size="sm">{error}</Text>
        </Alert>
      )}

      {!reply && !error && (
        <Text size="sm" c="dimmed" pl={22}>
          Working…
        </Text>
      )}

      {reply && (
        <Stack gap="xs" pl={22}>
          {reply.steps.map((step, i) => (
            <Box key={i}>
              <Group gap={6} mb={2}>
                <Badge size="sm" variant="light" color="gray">
                  query {i + 1}
                </Badge>
                <Text size="sm" c="dimmed">
                  {step.purpose}
                </Text>
                <Tooltip
                  withArrow
                  multiline
                  w={rem(280)}
                  label={
                    step.shared_with_model
                      ? "These results were also sent to the model, with hostnames and process paths reduced first."
                      : "These results stayed on this machine. The model was told only how many rows came back and what the columns were."
                  }
                >
                  <Badge
                    size="sm"
                    variant="outline"
                    color={step.shared_with_model ? "yellow" : "teal"}
                    leftSection={
                      step.shared_with_model ? (
                        <IconEye size="0.7rem" />
                      ) : (
                        <IconEyeOff size="0.7rem" />
                      )
                    }
                  >
                    {step.shared_with_model ? "shared" : "local only"}
                  </Badge>
                </Tooltip>
              </Group>
              <Code block style={{ fontSize: "var(--ppxray-text-dense)", whiteSpace: "pre-wrap" }}>
                {step.sql}
              </Code>
              {step.error ? (
                <Text size="sm" c="red" mt={4}>
                  {step.error}
                </Text>
              ) : (
                step.table && <ResultTable table={step.table} />
              )}
            </Box>
          ))}

          {reply.thinking && (
            <Box>
              <Button
                size="compact-sm"
                variant="subtle"
                color="gray"
                leftSection={<IconBulb size="0.8rem" />}
                onClick={() => setShowThinking((v) => !v)}
              >
                {showThinking ? "Hide reasoning" : "Show reasoning"}
              </Button>
              <Collapse in={showThinking}>
                <Text size="sm" c="dimmed" style={{ whiteSpace: "pre-wrap" }} mt={4}>
                  {reply.thinking}
                </Text>
              </Collapse>
            </Box>
          )}

          {reply.text && (
            <Alert variant="light" color="blue" p="sm">
              <Markdown>{reply.text}</Markdown>
              <Group gap={6} mt={6}>
                <Badge size="sm" variant="light" color="orange">
                  unverified
                </Badge>
                <Text size="xs" c="dimmed">
                  A model wrote this. The deterministic findings are in Hunt.
                </Text>
                {reply.output_tokens != null && (
                  <Text size="xs" c="dimmed" className="mono">
                    {reply.input_tokens ?? 0} in / {reply.output_tokens} out
                  </Text>
                )}
              </Group>
            </Alert>
          )}
        </Stack>
      )}
    </Stack>
  );
}

/** Kept beside the panel that shows them so the wording cannot drift. */
export function scopeLabel(scope: string): string {
  if (scope === "schema-only") return "schema only";
  if (scope === "aggregates") return "aggregates";
  return "raw rows";
}

export function scopeHint(scope: string): string {
  if (scope === "schema-only") {
    return "Only the table and column names and your question are sent. Query results are shown here and never reach the model.";
  }
  if (scope === "aggregates") {
    return "Query results are sent, with hostnames reduced to their registrable domain, process paths to a filename, and private addresses to their block.";
  }
  return "Query results are sent unchanged, including exact hostnames and addresses.";
}
