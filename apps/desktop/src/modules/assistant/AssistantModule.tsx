// The Assistant tab: the conversation list beside the conversation.
//
// The same panel also renders inside `AssistantDrawer`, which opens over any
// other module. Two surfaces rather than one because they answer different
// needs: the drawer is for asking while you are looking at something, the tab
// is for reading a long answer and moving between conversations.

import { Box } from "@mantine/core";

import { useActiveConversation } from "@/stores/assistant-store";
import { AssistantPanel } from "./AssistantPanel";
import { ConversationList } from "./ConversationList";

export function AssistantModule({ onOpenSettings }: { onOpenSettings: () => void }) {
  const active = useActiveConversation();

  return (
    <Box
      style={{
        height: "calc(100vh - 40px)",
        display: "grid",
        gridTemplateColumns: "minmax(180px, 15rem) 1fr",
        minHeight: 0,
      }}
    >
      <ConversationList />
      <Box style={{ minWidth: 0, minHeight: 0 }}>
        <AssistantPanel
          key={active.id}
          conversationId={active.id}
          onOpenSettings={onOpenSettings}
        />
      </Box>
    </Box>
  );
}
