// The assistant, over whatever you are already looking at.
//
// A separate tab meant leaving the thing you wanted to ask about in order to
// ask about it. This slides in from the right so the question and the
// evidence are on screen together, and it shares its conversations with the
// Assistant tab rather than keeping a second set.

import { ActionIcon, Box, Drawer, Group, Text, Tooltip } from "@mantine/core";
import { IconArrowsMaximize, IconPlus, IconRobot, IconX } from "@tabler/icons-react";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  useActiveConversation,
  useAssistantStore,
} from "@/stores/assistant-store";
import { AssistantPanel } from "./AssistantPanel";

const MIN_WIDTH = 360;
const DEFAULT_WIDTH = 560;
const WIDTH_KEY = "ppxray.assistant-drawer-width";

export function AssistantDrawer({
  onOpenSettings,
  onExpand,
}: {
  onOpenSettings: () => void;
  /** Switch to the full Assistant tab, carrying the conversation with it. */
  onExpand: () => void;
}) {
  const opened = useAssistantStore((s) => s.drawerOpen);
  const setOpen = useAssistantStore((s) => s.setDrawerOpen);
  const startNew = useAssistantStore((s) => s.startNew);
  const active = useActiveConversation();

  // Width is a per-viewer convenience, so it lives in localStorage rather
  // than in settings.json - and a bad stored value must not wedge the panel
  // shut, hence the clamp on read.
  const [width, setWidth] = useState(() => {
    const stored = Number(localStorage.getItem(WIDTH_KEY));
    return Number.isFinite(stored) && stored >= MIN_WIDTH ? stored : DEFAULT_WIDTH;
  });
  const dragging = useRef(false);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragging.current = true;
  }, []);

  useEffect(() => {
    const move = (e: PointerEvent) => {
      if (!dragging.current) return;
      // The drawer is anchored right, so its width is the distance from the
      // pointer to the right edge of the window.
      const next = Math.max(MIN_WIDTH, Math.min(window.innerWidth - 120, window.innerWidth - e.clientX));
      setWidth(next);
    };
    const up = () => {
      if (!dragging.current) return;
      dragging.current = false;
      try {
        localStorage.setItem(WIDTH_KEY, String(width));
      } catch {
        // A blocked storage quota is not worth interrupting a drag over.
      }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
  }, [width]);

  return (
    <Drawer
      opened={opened}
      onClose={() => setOpen(false)}
      position="right"
      size={width}
      padding={0}
      withCloseButton={false}
      // The point is to keep working while it is open, so it does not trap
      // focus or dim what is behind it.
      lockScroll={false}
      trapFocus={false}
      closeOnClickOutside={false}
      overlayProps={{ backgroundOpacity: 0 }}
      styles={{ body: { height: "100%", display: "flex", flexDirection: "column" } }}
    >
      <Group
        px="sm"
        py="xs"
        justify="space-between"
        wrap="nowrap"
        style={{ borderBottom: "1px solid var(--ppxray-border)" }}
      >
        <Group gap={6} wrap="nowrap" style={{ minWidth: 0 }}>
          <IconRobot size="1.1rem" />
          <Text size="sm" fw={600} truncate>
            {active.title}
          </Text>
        </Group>
        <Group gap={4} wrap="nowrap">
          <Tooltip label="New conversation" withArrow>
            <ActionIcon variant="subtle" aria-label="New conversation" onClick={() => startNew()}>
              <IconPlus size="1.25rem" />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Open in the Assistant tab" withArrow>
            <ActionIcon
              variant="subtle"
              aria-label="Open in the Assistant tab"
              onClick={() => {
                setOpen(false);
                onExpand();
              }}
            >
              <IconArrowsMaximize size="1.25rem" />
            </ActionIcon>
          </Tooltip>
          <ActionIcon variant="subtle" aria-label="Close assistant" onClick={() => setOpen(false)}>
            <IconX size="1.25rem" />
          </ActionIcon>
        </Group>
      </Group>

      {/* Drag handle on the inner edge. The drawer is anchored right, so the
          grip belongs on its left. */}
      <Box
        onPointerDown={onPointerDown}
        style={{
          position: "absolute",
          left: 0,
          top: 0,
          bottom: 0,
          width: 6,
          cursor: "col-resize",
          zIndex: 5,
        }}
        className="ppxray-col-resize"
        aria-hidden
      />

      <div style={{ flex: 1, minHeight: 0 }}>
        <AssistantPanel
          key={active.id}
          conversationId={active.id}
          onOpenSettings={onOpenSettings}
          compact
        />
      </div>
    </Drawer>
  );
}
