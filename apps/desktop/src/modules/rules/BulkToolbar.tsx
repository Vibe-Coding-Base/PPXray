import { ActionIcon, Badge, Divider, Group, Text, Tooltip } from "@mantine/core";
import {
  IconArrowDown,
  IconArrowUp,
  IconCopy,
  IconToggleRight,
  IconToggleLeft,
  IconTrash,
  IconX,
} from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { modals } from "@mantine/modals";

import { useProfileStoreShallow } from "@/stores/profile-store";

interface Props {
  selectedIndices: number[];
}

export function BulkToolbar({ selectedIndices }: Props) {
  const store = useProfileStoreShallow((s) => ({
    clearSelection: s.clearSelection,
    setEnabledMany: s.setEnabledMany,
    deleteRules: s.deleteRules,
    duplicateRules: s.duplicateRules,
    moveRulesToTop: s.moveRulesToTop,
    moveRulesToBottom: s.moveRulesToBottom,
  }));

  const count = selectedIndices.length;

  function confirmDelete() {
    modals.openConfirmModal({
      title: `Delete ${count} rule${count === 1 ? "" : "s"}?`,
      children: (
        <Text size="sm">
          This action is undoable, but the rules will be removed from the table immediately.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red", size: "xs" },
      cancelProps: { size: "xs" },
      onConfirm: () => {
        store.deleteRules(selectedIndices);
        store.clearSelection();
        notifications.show({ message: `Deleted ${count} rule(s)`, color: "red" });
      },
    });
  }

  return (
    <Group
      gap="xs"
      px="sm"
      py={4}
      style={{
        background: "var(--ppxray-row-divider)",
        borderTop: "1px solid var(--ppxray-border)",
        borderBottom: "1px solid var(--ppxray-border)",
      }}
    >
      <Badge variant="light" color="blue">
        {count} selected
      </Badge>

      <Tooltip label="Enable (E)" withArrow>
        <ActionIcon
          variant="subtle"
          onClick={() => store.setEnabledMany(selectedIndices, true)}
          aria-label="Enable"
        >
          <IconToggleRight size="1rem" />
        </ActionIcon>
      </Tooltip>
      <Tooltip label="Disable (D)" withArrow>
        <ActionIcon
          variant="subtle"
          onClick={() => store.setEnabledMany(selectedIndices, false)}
          aria-label="Disable"
        >
          <IconToggleLeft size="1rem" />
        </ActionIcon>
      </Tooltip>

      <Divider orientation="vertical" />

      <Tooltip label="Duplicate" withArrow>
        <ActionIcon
          variant="subtle"
          onClick={() => store.duplicateRules(selectedIndices)}
          aria-label="Duplicate"
        >
          <IconCopy size="1rem" />
        </ActionIcon>
      </Tooltip>
      <Tooltip label="Move to top" withArrow>
        <ActionIcon
          variant="subtle"
          onClick={() => store.moveRulesToTop(selectedIndices)}
          aria-label="Move to top"
        >
          <IconArrowUp size="1rem" />
        </ActionIcon>
      </Tooltip>
      <Tooltip label="Move to bottom" withArrow>
        <ActionIcon
          variant="subtle"
          onClick={() => store.moveRulesToBottom(selectedIndices)}
          aria-label="Move to bottom"
        >
          <IconArrowDown size="1rem" />
        </ActionIcon>
      </Tooltip>

      <Divider orientation="vertical" />

      <Tooltip label="Delete (Del)" withArrow>
        <ActionIcon
          variant="subtle"
          color="red"
          onClick={confirmDelete}
          aria-label="Delete"
        >
          <IconTrash size="1rem" />
        </ActionIcon>
      </Tooltip>

      <Tooltip label="Clear selection (Esc)" withArrow>
        <ActionIcon variant="subtle" onClick={store.clearSelection} aria-label="Clear">
          <IconX size="1rem" />
        </ActionIcon>
      </Tooltip>
    </Group>
  );
}
