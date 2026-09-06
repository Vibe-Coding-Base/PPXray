// Rule catalog browser: built-in + user-authored rules in one table.
// User rules get edit / delete actions; built-ins are read-only.

import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Code,
  Group,
  ScrollArea,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
  rem,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconEdit,
  IconEye,
  IconFolderOpen,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconTrash,
} from "@tabler/icons-react";
import { useMemo, useState } from "react";

import { EmptyBlock, ErrorBlock, LoadingBlock, rows } from "@/components/shell/States";
import { deleteUserRule, type HuntCatalogEntry } from "./ipc";
import { RuleEditorModal } from "./RuleEditorModal";
import { RuleViewModal } from "./RuleViewModal";
import { cloneFilename, entryToYaml } from "./rule-yaml";
import {
  useHuntCatalog,
  useInvalidateRules,
  useRuleDir,
  useUserRules,
} from "./queries";

export function RulesPanel() {
  const catalogQuery = useHuntCatalog();
  const userRulesQuery = useUserRules();
  const ruleDirQuery = useRuleDir();
  const invalidateRules = useInvalidateRules();

  const catalog = rows(catalogQuery.data);
  const userRules = rows(userRulesQuery.data);
  const ruleDir = ruleDirQuery.data ?? null;

  const [query, setQuery] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<{ filename: string; yaml: string } | null>(
    null,
  );
  const [viewEntry, setViewEntry] = useState<HuntCatalogEntry | null>(null);

  function refresh() {
    invalidateRules();
    void ruleDirQuery.refetch();
  }

  const filteredCatalog = useMemo(() => {
    if (!query.trim()) return catalog;
    const q = query.toLowerCase();
    return catalog.filter(
      (r) =>
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.mitre.some((m) => m.toLowerCase().includes(q)) ||
        r.source.toLowerCase().includes(q),
    );
  }, [catalog, query]);

  const brokenUserFiles = userRules.filter((u) => u.error);

  function onEdit(filename: string) {
    const u = userRules.find((x) => x.filename === filename);
    if (!u) return;
    setEditing({ filename: u.filename, yaml: u.raw_yaml });
    setEditorOpen(true);
  }

  function onNew() {
    setEditing(null);
    setEditorOpen(true);
  }

  // "Clone" seeds the editor with a YAML body derived from a built-in rule
  // while leaving the filename input editable (new-file mode). The seed is
  // consumed once when the editor opens and cleared on close.
  const [cloneSeed, setCloneSeed] = useState<{ filename: string; yaml: string } | null>(
    null,
  );

  function onClone(entry: HuntCatalogEntry) {
    setViewEntry(null);
    setEditing(null);
    setCloneSeed({
      filename: cloneFilename(entry),
      yaml: entryToYaml(entry, { clone: true }),
    });
    setEditorOpen(true);
  }

  function onDelete(filename: string) {
    modals.openConfirmModal({
      title: `Delete ${filename}?`,
      children: (
        <Text size="sm">
          This removes the file from <Code>{ruleDir?.effective}</Code>. This
          cannot be undone.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red", size: "xs" },
      cancelProps: { size: "xs" },
      onConfirm: async () => {
        try {
          await deleteUserRule(filename);
          notifications.show({ message: "Rule deleted", color: "red" });
          invalidateRules();
        } catch (e) {
          notifications.show({
            title: "Delete failed",
            message: String(e),
            color: "red",
          });
        }
      },
    });
  }

  return (
    <Stack gap={0} h="100%" style={{ overflow: "hidden" }}>
      <Group px="sm" py="xs" justify="space-between" wrap="nowrap">
        <Group gap="sm">
          <Title order={5}>Detection rules</Title>
          <Badge variant="default" size="sm">
            {catalog.length} total
          </Badge>
          <Badge variant="light" color="teal" size="sm">
            {catalog.filter((r) => r.source === "builtin").length} built-in
          </Badge>
          <Badge variant="light" color="blue" size="sm">
            {userRules.length} user
          </Badge>
          {brokenUserFiles.length > 0 && (
            <Badge variant="light" color="red" size="sm">
              {brokenUserFiles.length} errored
            </Badge>
          )}
        </Group>
        <Group gap="xs" wrap="nowrap">
          <TextInput
            size="sm"
            leftSection={<IconSearch size="1rem" />}
            placeholder="Filter by id / title / mitre / source…"
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
            style={{ width: rem(280) }}
          />
          <Tooltip label="Refresh" withArrow>
            <ActionIcon variant="subtle" onClick={refresh} aria-label="Refresh">
              <IconRefresh size="1rem" />
            </ActionIcon>
          </Tooltip>
          <Button leftSection={<IconPlus size="1rem" />} onClick={onNew}>
            New rule
          </Button>
        </Group>
      </Group>

      {ruleDir && (
        <Group px="sm" pb="xs" gap={4} wrap="nowrap">
          <IconFolderOpen size="1rem" color="var(--mantine-color-dimmed)" />
          <Text size="sm" c="dimmed" className="mono" title={ruleDir.effective}>
            {ruleDir.effective}
          </Text>
        </Group>
      )}

      {brokenUserFiles.length > 0 && (
        <Box px="sm" pb="xs">
          {brokenUserFiles.map((u) => (
            <Group key={u.filename} gap={4} wrap="nowrap">
              <IconAlertTriangle size="1rem" color="var(--mantine-color-red-5)" />
              <Text size="sm" className="mono">
                {u.filename}
              </Text>
              <Text size="sm" c="red.3">
                {u.error}
              </Text>
              <Button
                size="compact-sm"
                variant="subtle"
                onClick={() => onEdit(u.filename)}
              >
                Edit
              </Button>
            </Group>
          ))}
        </Box>
      )}

      <ScrollArea style={{ flex: 1 }} type="auto">
        <Table stickyHeader highlightOnHover striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th style={{ width: rem(76) }}>Severity</Table.Th>
              <Table.Th>Title</Table.Th>
              <Table.Th style={{ width: rem(240) }}>ID</Table.Th>
              <Table.Th style={{ width: rem(200) }}>MITRE</Table.Th>
              <Table.Th style={{ width: rem(140) }}>Source</Table.Th>
              <Table.Th style={{ width: rem(110) }}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {filteredCatalog.map((r) => (
              <Table.Tr key={`${r.source}:${r.id}`}>
                <Table.Td>
                  <SeverityBadge severity={r.severity} />
                </Table.Td>
                <Table.Td>
                  <Tooltip
                    label={r.description || "(no description)"}
                    multiline
                    w={rem(360)}
                    withArrow
                    openDelay={400}
                  >
                    <Text size="sm" fw={500} lineClamp={1}>
                      {r.title}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Text size="sm" className="mono" c="dimmed" lineClamp={1}>
                    {r.id}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={2} wrap="nowrap">
                    {r.mitre.slice(0, 4).map((m) => (
                      <Badge key={m} size="sm" variant="default">
                        {m}
                      </Badge>
                    ))}
                    {r.mitre.length > 4 && (
                      <Text size="sm" c="dimmed">
                        +{r.mitre.length - 4}
                      </Text>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  {r.source === "builtin" ? (
                    <Badge size="sm" variant="light" color="teal">
                      built-in
                    </Badge>
                  ) : (
                    <Tooltip label={r.source} withArrow>
                      <Badge size="sm" variant="light" color="blue" className="mono">
                        user
                      </Badge>
                    </Tooltip>
                  )}
                </Table.Td>
                <Table.Td>
                  <Group gap={2} wrap="nowrap">
                    <Tooltip label="View details" withArrow>
                      <ActionIcon
                        variant="subtle"
                        size="sm"
                        onClick={() => setViewEntry(r)}
                        aria-label="View"
                      >
                        <IconEye size="1rem" />
                      </ActionIcon>
                    </Tooltip>
                    {r.source !== "builtin" && (
                      <>
                        <Tooltip label="Edit" withArrow>
                          <ActionIcon
                            variant="subtle"
                            size="sm"
                            onClick={() => onEdit(r.source)}
                            aria-label="Edit"
                          >
                            <IconEdit size="1rem" />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Delete" withArrow>
                          <ActionIcon
                            variant="subtle"
                            size="sm"
                            color="red"
                            onClick={() => onDelete(r.source)}
                            aria-label="Delete"
                          >
                            <IconTrash size="1rem" />
                          </ActionIcon>
                        </Tooltip>
                      </>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {catalogQuery.isError ? (
          <ErrorBlock
            error={catalogQuery.error}
            onRetry={() => void catalogQuery.refetch()}
          />
        ) : catalogQuery.isLoading ? (
          <LoadingBlock label="Loading rule catalog…" />
        ) : filteredCatalog.length === 0 ? (
          <EmptyBlock
            title={query.trim() ? "No rules match that search" : "No rules in the catalog"}
            hint={
              query.trim()
                ? "Clear the search box to see the whole catalog."
                : "Use “New rule” to write one, or check the rule directory below."
            }
          />
        ) : null}
      </ScrollArea>

      <RuleEditorModal
        opened={editorOpen}
        onClose={() => {
          setEditorOpen(false);
          setCloneSeed(null);
        }}
        existing={editing}
        seed={cloneSeed}
        onSaved={refresh}
      />

      <RuleViewModal
        opened={viewEntry != null}
        onClose={() => setViewEntry(null)}
        entry={viewEntry}
        onClone={onClone}
      />
    </Stack>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color =
    severity === "Critical"
      ? "red.9"
      : severity === "High"
        ? "red"
        : severity === "Medium"
          ? "orange"
          : "yellow";
  return (
    <Badge color={color} size="sm" variant="filled">
      {severity}
    </Badge>
  );
}
