// App identity and where you are - nothing actionable.
//
// This bar used to carry Open / Save / Save as for the .ppx profile. Sitting
// above every module, those read as global commands, so "Save profile" while
// looking at the Log tab suggested it would save the log. They now live in
// the Rules module beside the path they act on (`modules/rules/ProfileBar`).
//
// The unsaved-changes badge stays, because that is status rather than a
// command: it is worth knowing you have pending profile edits while you are
// three tabs away from them.

import { Badge, Button, Group, Text, Tooltip } from "@mantine/core";
import { IconRobot } from "@tabler/icons-react";

import { useAssistantStore } from "@/stores/assistant-store";
import { useProfileStoreShallow } from "@/stores/profile-store";

type TopBarProps = { active: string };

export function TopBar({ active }: TopBarProps) {
  const { path, dirty } = useProfileStoreShallow((s) => ({
    path: s.path,
    dirty: s.dirty,
  }));
  const toggleAssistant = useAssistantStore((s) => s.toggleDrawer);

  return (
    <Group
      justify="space-between"
      align="center"
      px="md"
      style={{
        height: 40,
        borderBottom: "1px solid var(--ppxray-border)",
      }}
    >
      <Group gap="sm">
        <Text fw={600} size="sm">
          ppxray
        </Text>
        <Badge variant="light" color="gray" tt="uppercase">
          {active}
        </Badge>
      </Group>

      <Group gap="sm" wrap="nowrap">
        {dirty && (
          <Tooltip label={`Unsaved changes in ${path ?? "the open profile"}`} withArrow>
            <Badge color="yellow" variant="light" size="sm">
              unsaved profile changes
            </Badge>
          </Tooltip>
        )}
        {/* Here rather than only in the rail: the point of the drawer is to
            ask about whatever is on screen, so the way in has to be on screen
            too. */}
        {/* A filled button, not a subtle icon: this is the one control in
            the bar and it is meant to be found without being told about. */}
        <Tooltip label="Ask the assistant about what you are looking at (Ctrl+J)" withArrow>
          <Button
            variant="light"
            size="sm"
            leftSection={<IconRobot size="1.25rem" />}
            onClick={toggleAssistant}
          >
            Assistant
          </Button>
        </Tooltip>
      </Group>
    </Group>
  );
}
