// The rows a model-written query returned, rendered for the user.
//
// Always unmasked: this is the user's own log on the user's own screen. The
// masking in `llm_bridge::table` governs what goes back over the wire, which
// is a different question.

import { Badge, Group, ScrollArea, Table, Text,
  rem,
} from "@mantine/core";

import type { QueryTable } from "@ppxray/ipc-schema";

/** Beyond this the panel stops being readable; the rest is a scroll away. */
const VISIBLE_ROWS = 12;

export function ResultTable({ table }: { table: QueryTable }) {
  if (table.columns.length === 0) {
    return (
      <Text size="xs" c="dimmed" mt={4}>
        The query returned no columns.
      </Text>
    );
  }

  const shown = table.rows.slice(0, VISIBLE_ROWS);
  const hidden = table.rows.length - shown.length;

  return (
    <>
      <ScrollArea.Autosize mah={rem(280)} type="auto" mt={4}>
        <Table
          stickyHeader
          highlightOnHover
          withTableBorder
          verticalSpacing={2}
          horizontalSpacing={6}
          style={{ fontSize: "var(--ppxray-text-dense)" }}
        >
          <Table.Thead>
            <Table.Tr>
              {table.columns.map((c) => (
                <Table.Th key={c} style={{ whiteSpace: "nowrap" }}>
                  {c}
                </Table.Th>
              ))}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {shown.map((row, i) => (
              // Row order is the query's ORDER BY, which is stable for a
              // given result, so the index is a legitimate key here.
              <Table.Tr key={i}>
                {table.columns.map((c, j) => (
                  <Table.Td
                    key={c}
                    className="mono"
                    style={{
                      whiteSpace: "nowrap",
                      textAlign: typeof row[j] === "number" ? "right" : "left",
                    }}
                  >
                    {render(row[j])}
                  </Table.Td>
                ))}
              </Table.Tr>
            ))}
            {table.rows.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={table.columns.length}>
                  <Text size="xs" c="dimmed">
                    No rows matched.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </ScrollArea.Autosize>
      {(hidden > 0 || table.truncated) && (
        <Group gap={6} mt={2}>
          {hidden > 0 && (
            <Text size="xs" c="dimmed">
              {hidden} more row{hidden === 1 ? "" : "s"} not shown
            </Text>
          )}
          {table.truncated && (
            <Badge variant="light" color="yellow">
              cut off at the row limit
            </Badge>
          )}
        </Group>
      )}
    </>
  );
}

/** A JSON cell as text. `null` reads as SQL NULL, not as the string "null". */
function render(cell: unknown): string {
  if (cell === null || cell === undefined) return "—";
  if (typeof cell === "object") return JSON.stringify(cell);
  return String(cell);
}
