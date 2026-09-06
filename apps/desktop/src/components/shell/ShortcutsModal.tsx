import { Code, Group, Modal, ScrollArea, Stack, Table, Text, Title,
  rem,
} from "@mantine/core";

const SECTIONS: { title: string; rows: { keys: string; action: string }[] }[] = [
  {
    title: "Global",
    rows: [
      { keys: "Ctrl+K / Ctrl+P", action: "Command palette" },
      { keys: "?", action: "Show this help" },
    ],
  },
  {
    title: "Rules module",
    rows: [
      { keys: "/", action: "Focus the rule search box" },
      { keys: "Ctrl+Z / Ctrl+Y", action: "Undo / redo last edit" },
      { keys: "Del", action: "Delete selected rule(s)" },
      { keys: "E / D", action: "Enable / disable selected rule(s)" },
      { keys: "Esc", action: "Clear selection or close detail panel" },
      { keys: "Click + Shift", action: "Range-select rules" },
      { keys: "Click + Ctrl/Cmd", action: "Toggle individual selection" },
      { keys: "Drag rule (or grip)", action: "Reorder" },
    ],
  },
  {
    title: "Log module",
    rows: [
      { keys: "/", action: "Focus the event search box" },
      { keys: "Esc", action: "Clear all filters" },
      { keys: "Tab / Enter", action: "Move between row cells and drill in" },
      { keys: "Drag timeline", action: "Filter by time range" },
      { keys: "Click row cell", action: "Drill into that process / host / rule" },
    ],
  },
  {
    title: "Hunt module",
    rows: [
      { keys: "R", action: "Run the detection catalog" },
      { keys: "↑ / ↓", action: "Move through the alert inbox" },
      { keys: "Home / End", action: "Jump to first / last alert" },
      { keys: "Enter", action: "Open alert detail" },
      { keys: "T / F / S", action: "Triage as true / false positive, or suppress" },
      { keys: "Esc", action: "Close the alert detail panel" },
    ],
  },
];

export function ShortcutsModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  return (
    <Modal opened={opened} onClose={onClose} title="Keyboard shortcuts" size="lg">
      <ScrollArea h={rem(460)} type="auto">
        <Stack gap="md">
          {SECTIONS.map((section) => (
            <Stack key={section.title} gap={4}>
              <Title order={6}>{section.title}</Title>
              <Table withColumnBorders={false}>
                <Table.Tbody>
                  {section.rows.map((row) => (
                    <Table.Tr key={row.keys + row.action}>
                      <Table.Td style={{ width: rem(220) }}>
                        <Code>{row.keys}</Code>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm">{row.action}</Text>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Stack>
          ))}
          <Group gap={4}>
            <Text size="xs" c="dimmed">
              Custom shortcuts can be added in a future release.
            </Text>
          </Group>
        </Stack>
      </ScrollArea>
    </Modal>
  );
}
