import { Badge, Group, MultiSelect, TextInput,
  rem,
} from "@mantine/core";
import { IconFilter, IconSearch, IconX } from "@tabler/icons-react";

import { useLogStoreShallow } from "@/stores/log-store";
import { useLogFacets } from "./queries";

export function FilterBar() {
  const { filter, setFilter, clearFilter } = useLogStoreShallow((s) => ({
    filter: s.filter,
    setFilter: s.setFilter,
    clearFilter: s.clearFilter,
  }));

  const { data: facets } = useLogFacets();

  const activeCount = countActive(filter);

  return (
    <Group gap="xs" px="sm" py="xs" wrap="nowrap" align="center">
      <Group gap={4}>
        <IconFilter size="1rem" />
        {activeCount > 0 ? (
          <Badge variant="light" color="blue">
            {activeCount} active
          </Badge>
        ) : (
          <Badge variant="outline" color="gray">
            no filter
          </Badge>
        )}
      </Group>

      <TextInput
        size="xs"
        placeholder="Host / IP contains…"
        leftSection={<IconSearch size="0.85rem" />}
        value={filter.host_contains ?? ""}
        onChange={(e) =>
          setFilter({ host_contains: e.currentTarget.value || null })
        }
        className="mono"
        style={{ width: rem(220) }}
      />

      <MultiSelect
        size="xs"
        placeholder="Process"
        data={facets?.processes ?? []}
        value={filter.processes ?? []}
        onChange={(v) => setFilter({ processes: v.length ? v : null })}
        searchable
        clearable
        style={{ minWidth: rem(180) }}
      />

      <MultiSelect
        size="xs"
        placeholder="Rule"
        data={facets?.rules ?? []}
        value={filter.matched_rules ?? []}
        onChange={(v) => setFilter({ matched_rules: v.length ? v : null })}
        searchable
        clearable
        style={{ minWidth: rem(180) }}
      />

      <MultiSelect
        size="xs"
        placeholder="Action"
        data={facets?.actions ?? ["Direct", "Proxy", "Block", "Other"]}
        value={filter.actions ?? []}
        onChange={(v) => setFilter({ actions: v.length ? v : null })}
        clearable
        style={{ minWidth: rem(140) }}
      />

      <MultiSelect
        size="xs"
        placeholder="Proto"
        data={facets?.protos ?? ["TCP", "UDP", "ICMP"]}
        value={filter.protos ?? []}
        onChange={(v) => setFilter({ protos: v.length ? v : null })}
        clearable
        style={{ width: rem(110) }}
      />

      {activeCount > 0 && (
        <Badge
          variant="subtle"
          color="red"
          leftSection={<IconX size="0.72rem" />}
          onClick={clearFilter}
          style={{ cursor: "pointer" }}
        >
          clear
        </Badge>
      )}
    </Group>
  );
}

function countActive(f: import("@ppxray/ipc-schema").EventFilter): number {
  let n = 0;
  if (f.host_contains) n++;
  if (f.processes && f.processes.length) n++;
  if (f.matched_rules && f.matched_rules.length) n++;
  if (f.actions && f.actions.length) n++;
  if (f.protos && f.protos.length) n++;
  if (f.ts_from || f.ts_to) n++;
  if (f.ipv6 != null) n++;
  return n;
}
