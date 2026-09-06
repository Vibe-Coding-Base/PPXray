// The conversations open this session. They last as long as the app does, by
// design — the panel says so, so nobody plans around history that will not be
// there tomorrow. See `stores/assistant-store.tsx`.

import { ActionIcon, Group, ScrollArea, Stack, Text, Tooltip, UnstyledButton } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";

import { llmResetChat } from "./ipc";
import { useAssistantStore, useAssistantStoreShallow } from "@/stores/assistant-store";

export function ConversationList() {
  const { conversations, activeId } = useAssistantStoreShallow((s) => ({
    conversations: s.conversations,
    activeId: s.activeId,
  }));
  const select = useAssistantStore((s) => s.select);
  const startNew = useAssistantStore((s) => s.startNew);
  const remove = useAssistantStore((s) => s.remove);

  return (
    <Stack gap={0} h="100%" style={{ borderRight: "1px solid var(--ppxray-border)" }}>
      <Group px="sm" py="xs" justify="space-between" wrap="nowrap">
        <Text size="sm" fw={600}>
          Conversations
        </Text>
        <Tooltip label="New conversation" withArrow>
          <ActionIcon variant="subtle" aria-label="New conversation" onClick={() => startNew()}>
            <IconPlus size="1.1rem" />
          </ActionIcon>
        </Tooltip>
      </Group>

      <ScrollArea style={{ flex: 1 }} type="auto">
        <Stack gap={2} px="xs" pb="xs">
          {conversations.map((c) => {
            const active = c.id === activeId;
            return (
              <Group key={c.id} gap={2} wrap="nowrap">
                <UnstyledButton
                  onClick={() => select(c.id)}
                  style={{
                    flex: 1,
                    minWidth: 0,
                    padding: "6px 8px",
                    borderRadius: 4,
                    background: active ? "var(--mantine-color-blue-light)" : "transparent",
                  }}
                >
                  <Text
                    size="sm"
                    c={active ? undefined : "dimmed"}
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={c.title}
                  >
                    {c.title}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {c.exchanges.length === 0
                      ? "empty"
                      : `${c.exchanges.length} question${c.exchanges.length === 1 ? "" : "s"}`}
                    {c.busy ? " - working…" : ""}
                  </Text>
                </UnstyledButton>
                <Tooltip label="Delete" withArrow>
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    aria-label={`Delete conversation ${c.title}`}
                    onClick={() => {
                      // Drop the model-side transcript too, not just the view
                      // of it - otherwise the text stays in memory with no UI
                      // left to reach it.
                      void llmResetChat(c.id);
                      remove(c.id);
                    }}
                  >
                    <IconTrash size="0.9rem" />
                  </ActionIcon>
                </Tooltip>
              </Group>
            );
          })}
        </Stack>
      </ScrollArea>

      <Text size="xs" c="dimmed" px="sm" py="xs" style={{ borderTop: "1px solid var(--ppxray-border)" }}>
        Kept for this session only. Closing ppxray forgets them, so no
        transcript is left on disk.
      </Text>
    </Stack>
  );
}
