// Free-form search box for the Log module. Compiles to Partial<EventFilter>
// and folds into the global filter via the log store.

import { Badge, Group, Popover, Stack, Text, TextInput, Tooltip } from "@mantine/core";
import { IconSearch, IconAlertTriangle, IconHelp } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";

import { useLogStoreShallow } from "@/stores/log-store";
import { compileLogSearch } from "./log-search-dsl";

export function SearchBox() {
  const { searchQuery, setSearchQuery } = useLogStoreShallow((s) => ({
    searchQuery: s.searchQuery,
    setSearchQuery: s.setSearchQuery,
  }));

  // Local input state: we debounce store updates so typing isn't laggy on
  // every keystroke (the global filter triggers DB queries everywhere).
  const [draft, setDraft] = useState(searchQuery);

  useEffect(() => {
    if (draft === searchQuery) return;
    const handle = window.setTimeout(() => setSearchQuery(draft), 250);
    return () => window.clearTimeout(handle);
  }, [draft, searchQuery, setSearchQuery]);

  // Keep local in sync if the store value changes externally (e.g. cleared
  // by a "clear filter" button).
  useEffect(() => {
    setDraft(searchQuery);
  }, [searchQuery]);

  const compiled = useMemo(() => compileLogSearch(draft), [draft]);
  const tokenCount =
    Object.values(compiled.filter).filter(
      (v) => v != null && (Array.isArray(v) ? v.length > 0 : true),
    ).length;

  return (
    <Group gap={4} wrap="nowrap" style={{ flex: 1 }}>
      <TextInput
        id="log-search-input"
        aria-label="Search events"
        leftSection={<IconSearch size="1rem" />}
        placeholder='process:chrome.exe host:*.example.com action:block ts>2026-04-17 "free text"'
        size="xs"
        value={draft}
        onChange={(e) => setDraft(e.currentTarget.value)}
        className="mono"
        style={{ flex: 1 }}
        rightSection={
          <Group gap={4} wrap="nowrap">
            {tokenCount > 0 && (
              <Badge variant="light" color="blue">
                {tokenCount}
              </Badge>
            )}
            {compiled.unrecognized.length > 0 && (
              <Tooltip
                label={`Unknown tokens: ${compiled.unrecognized.join(", ")}`}
                withArrow
              >
                <IconAlertTriangle size="1rem" color="var(--mantine-color-yellow-5)" />
              </Tooltip>
            )}
            <SearchHelp />
          </Group>
        }
        rightSectionWidth={68}
      />
    </Group>
  );
}

function SearchHelp() {
  return (
    <Popover width={420} position="bottom-end" withArrow>
      <Popover.Target>
        <span style={{ display: "inline-flex", cursor: "help" }}>
          <IconHelp size="1rem" color="var(--mantine-color-dimmed)" />
        </span>
      </Popover.Target>
      <Popover.Dropdown>
        <Stack gap={6}>
          <Text size="sm" fw={600}>
            Search syntax
          </Text>
          <Grid label="process:NAME" hint="alias: proc — multi-token unions" />
          <Grid label="host:VALUE" hint="alias: dst — substring match (case-insensitive)" />
          <Grid label="rule:NAME" hint="quoted span allowed: rule:&quot;Default Block&quot;" />
          <Grid label="action:VAL" hint="direct | proxy | block | other" />
          <Grid label="proto:VAL" hint="tcp | udp | icmp" />
          <Grid label="ipv6:true" hint="ipv6 traffic only" />
          <Grid
            label="ts>VALUE"
            hint="lower bound. accepts YYYY-MM-DD or full ISO"
          />
          <Grid label="ts<VALUE" hint="upper bound (or use after:/before:)" />
          <Grid label="bare word" hint="adds to host substring match" />
          <Text size="xs" c="dimmed">
            Tokens AND across keys, UNION within key. Combine with the dropdown
            filters; search supplements them.
          </Text>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}

function Grid({ label, hint }: { label: string; hint: string }) {
  return (
    <Group justify="space-between" gap="md" wrap="nowrap">
      <Text size="xs" className="mono" c="blue.3">
        {label}
      </Text>
      <Text size="xs" c="dimmed">
        {hint}
      </Text>
    </Group>
  );
}
