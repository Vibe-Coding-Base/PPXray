import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Code,
  Group,
  Stack,
  TextInput,
  Title,
  Tooltip,
  rem,
} from "@mantine/core";
import { useHotkeys } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import {
  IconAlertTriangle,
  IconArrowBackUp,
  IconArrowForwardUp,
  IconAtom,
  IconFolderOpen,
  IconList,
  IconPlus,
  IconSearch,
  IconTargetArrow,
} from "@tabler/icons-react";
import { useCallback, useEffect, useMemo, useState } from "react";


import type { Rule, ShadowPair, ShadowReason } from "@ppxray/ipc-schema";
import { SplitGroup, SplitHandle, SplitPanel } from "@/components/shell/Splitter";
import { ModuleEmptyState } from "@/components/shell/States";

/**
 * Shadow info per shadowed-rule index, pre-joined with the shadower's display
 * name so the row renderer can show a useful tooltip without needing access
 * to the full `rules` list.
 */
export interface EnrichedShadow {
  shadowerIndex: number;
  shadowerName: string;
  reason: ShadowReason;
}
import { useProfileStoreShallow } from "@/stores/profile-store";

import { BulkToolbar } from "./BulkToolbar";
import { ProfileBar } from "./ProfileBar";
import { useOpenProfile } from "./use-open-profile";
import { RuleDetailPanel } from "./RuleDetailPanel";
import { RuleTable } from "./RuleTable";
import { RuleTesterModal } from "./RuleTesterModal";
import { compileSearchDsl } from "./search-dsl";
import {
  consumePendingRulesSearch,
  subscribeRulesSearch,
} from "./cross-tab-search";
import { scanOvershadows } from "./ipc";

export function RuleModule() {
  const { open: openProfile, opening } = useOpenProfile();
  const {
    profile,
    selectedIndices,
    detailIndex,
    openDetail,
    clearSelection,
    deleteRules,
    insertRule,
    setEnabledMany,
    undo,
    redo,
  } = useProfileStoreShallow((s) => ({
    profile: s.profile,
    selectedIndices: s.selectedIndices,
    detailIndex: s.detailIndex,
    openDetail: s.openDetail,
    clearSelection: s.clearSelection,
    deleteRules: s.deleteRules,
    insertRule: s.insertRule,
    setEnabledMany: s.setEnabledMany,
    undo: s.undo,
    redo: s.redo,
  }));

  const [query, setQuery] = useState("");
  const [testerOpen, setTesterOpen] = useState(false);
  const [shadowPairs, setShadowPairs] = useState<ShadowPair[]>([]);

  // Apply a DSL query that arrived from outside (cross-tab pivot, command
  // palette, …). Wrapped here so the mount-time consumer and the live
  // subscription share the same focus-and-select side effect.
  const applyExternalSearch = useCallback((q: string) => {
    setQuery(q);
    queueMicrotask(() => {
      const el = document.getElementById(
        "rule-search-input",
      ) as HTMLInputElement | null;
      el?.focus();
      el?.select();
    });
  }, []);

  // Cross-tab deep-link: the Exposure tab's Rules→Internet table pivots
  // here with a DSL query like `port:443`. The bridge in
  // `cross-tab-search.ts` holds the query across the unmount→mount gap so
  // we don't lose it just because RuleModule wasn't rendered when the
  // pivot was issued.
  useEffect(() => {
    const pending = consumePendingRulesSearch();
    if (pending != null) applyExternalSearch(pending);
    return subscribeRulesSearch(applyExternalSearch);
  }, [applyExternalSearch]);

  // Debounced shadow scan. We throttle to avoid N×N overhead on every
  // keystroke — the real profile has ~130 rules so 400ms is plenty.
  useEffect(() => {
    if (!profile) {
      setShadowPairs([]);
      return;
    }
    const rules = profile.rules;
    const handle = window.setTimeout(async () => {
      try {
        setShadowPairs(await scanOvershadows(rules));
      } catch {
        // Non-fatal; shadow highlighting is a progressive enhancement.
      }
    }, 400);
    return () => window.clearTimeout(handle);
  }, [profile]);

  // Enrich each shadow pair with the shadower's name + reason so the row
  // renderer doesn't need access to the full rule list.
  const overshadows = useMemo(() => {
    const map = new Map<number, EnrichedShadow>();
    if (!profile) return map;
    for (const p of shadowPairs) {
      const shadower = profile.rules[p.shadower];
      map.set(p.shadowed, {
        shadowerIndex: p.shadower,
        shadowerName: shadower?.name ?? "(deleted rule)",
        reason: p.reason,
      });
    }
    return map;
  }, [shadowPairs, profile]);

  const filter = useMemo(() => compileSearchDsl(query), [query]);
  const visibleRows = useMemo(() => {
    if (!profile) return [];
    return profile.rules
      .map((rule, index) => ({ rule, index }))
      .filter(({ rule }) => filter(rule));
  }, [profile, filter]);

  const selectedArr = useMemo(() => [...selectedIndices].sort((a, b) => a - b), [
    selectedIndices,
  ]);

  const activeRule = detailIndex != null ? profile?.rules[detailIndex] : undefined;

  const onRevealRule = useCallback(
    (idx: number) => {
      openDetail(idx);
      // Clear filter if it's hiding the rule we're trying to reveal.
      setQuery((current) => (current.trim() ? "" : current));
    },
    [openDetail],
  );

  const onAddRule = useCallback(() => {
    const blank: Rule = {
      enabled: true,
      name: "New rule",
      action: { kind: "direct" },
      targets: [],
      applications: [],
      ports: [],
    };
    insertRule(detailIndex, blank);
    const newIndex = (detailIndex ?? (profile?.rules.length ?? 1) - 1) + 1;
    openDetail(newIndex);
  }, [insertRule, detailIndex, openDetail, profile]);

  // Keyboard shortcuts for the rules module.
  useHotkeys([
    [
      "mod+z",
      (e) => {
        e.preventDefault();
        const label = undo();
        if (label) notifications.show({ message: `Undo: ${label}`, color: "gray" });
      },
    ],
    [
      "mod+shift+z",
      (e) => {
        e.preventDefault();
        const label = redo();
        if (label) notifications.show({ message: `Redo: ${label}`, color: "gray" });
      },
    ],
    [
      "mod+y",
      (e) => {
        e.preventDefault();
        const label = redo();
        if (label) notifications.show({ message: `Redo: ${label}`, color: "gray" });
      },
    ],
    [
      "Delete",
      () => {
        if (selectedArr.length > 0) {
          deleteRules(selectedArr);
          clearSelection();
        }
      },
    ],
    [
      "Escape",
      () => {
        if (detailIndex != null) openDetail(null);
        else if (selectedArr.length > 0) clearSelection();
      },
    ],
    ["e", () => selectedArr.length > 0 && setEnabledMany(selectedArr, true)],
    ["d", () => selectedArr.length > 0 && setEnabledMany(selectedArr, false)],
    ["/", (e) => {
      e.preventDefault();
      (document.getElementById("rule-search-input") as HTMLInputElement | null)?.focus();
    }],
  ]);

  if (!profile) {
    return (
      // No ProfileBar here: the Log module shows either its path bar or its
      // empty state, never both, and showing a second "Open profile" in the
      // corner alongside the primary one below just splits the user's
      // attention between two controls that do the same thing.
      <Stack gap={0} h="calc(100vh - 40px)">
        {/* Same shape as the Log module's empty state: a heading, a sentence
            of context, and one primary button. Having Rules offer only a
            small subtle control in the corner while Log offered a filled
            call-to-action made the two look like different applications. */}
        <ModuleEmptyState
          icon={<IconList size="2.4rem" stroke={1.2} color="var(--mantine-color-dimmed)" />}
          title="No profile loaded"
          description={
            <>
              Open a Proxifier <Code>.ppx</Code> profile to edit its rules, see
              which ones shadow which, and check what they let out.
            </>
          }
          actions={
            <Button
              size="sm"
              leftSection={<IconFolderOpen size="1rem" />}
              onClick={() => void openProfile()}
              loading={opening}
            >
              Open profile
            </Button>
          }
        />
      </Stack>
    );
  }

  return (
    <Stack gap={0} h="calc(100vh - 40px)">
      <ProfileBar />
      <Group justify="space-between" align="center" px="sm" py="xs">
        <Group gap="sm">
          <Title order={5}>Rules</Title>
          <Badge variant="default">
            {profile.rules.length} total
          </Badge>
          <Badge variant="default">
            {visibleRows.length} visible
          </Badge>
          {overshadows.size > 0 && (
            <Tooltip
              label={`${overshadows.size} rule(s) are overshadowed by an earlier rule and will never fire`}
              withArrow
            >
              <Badge
                size="sm"
                color="yellow.7"
                variant="filled"
                leftSection={<IconAlertTriangle size="0.85rem" />}
              >
                {overshadows.size} shadowed
              </Badge>
            </Tooltip>
          )}
        </Group>

        <Group gap="xs">
          <TextInput
            id="rule-search-input"
            leftSection={<IconSearch size="1rem" />}
            placeholder="action:block host:*.nvidia.com app:chrome.exe …"
            size="xs"
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
            style={{ width: rem(360) }}
            className="mono"
          />
          <Tooltip label="Undo (Ctrl+Z)" withArrow>
            <ActionIcon
              variant="subtle"
              onClick={() => undo()}
              aria-label="Undo"
            >
              <IconArrowBackUp size="1rem" />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Redo (Ctrl+Shift+Z)" withArrow>
            <ActionIcon
              variant="subtle"
              onClick={() => redo()}
              aria-label="Redo"
            >
              <IconArrowForwardUp size="1rem" />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="View 3D exposure surface for this profile" withArrow>
            <Button
              size="xs"
              leftSection={<IconAtom size="1rem" />}
              variant="default"
              onClick={() =>
                window.dispatchEvent(
                  new CustomEvent("proxifier:nav", { detail: "exposure" }),
                )
              }
            >
              Exposure map
            </Button>
          </Tooltip>
          <Button
            size="xs"
            leftSection={<IconTargetArrow size="1rem" />}
            variant="default"
            onClick={() => setTesterOpen(true)}
          >
            Test
          </Button>
          <Button
            size="xs"
            leftSection={<IconPlus size="1rem" />}
            onClick={onAddRule}
          >
            Add rule
          </Button>
        </Group>
      </Group>

      {selectedArr.length > 0 && <BulkToolbar selectedIndices={selectedArr} />}

      <Box style={{ flex: 1, minHeight: rem(0) }}>
        {activeRule && detailIndex != null ? (
          <SplitGroup direction="horizontal" autoSaveId="rules-split">
            <SplitPanel defaultSize={66} minSize={30}>
              <Box style={{ height: "100%", display: "flex", padding: 8 }}>
                <RuleTable rows={visibleRows} overshadows={overshadows} />
              </Box>
            </SplitPanel>
            <SplitHandle orientation="vertical" />
            <SplitPanel defaultSize={34} minSize={20}>
              <RuleDetailPanel
                rule={activeRule}
                index={detailIndex}
                onClose={() => openDetail(null)}
              />
            </SplitPanel>
          </SplitGroup>
        ) : (
          <Box style={{ height: "100%", display: "flex", padding: 8 }}>
            <RuleTable rows={visibleRows} overshadows={overshadows} />
          </Box>
        )}
      </Box>

      <RuleTesterModal
        opened={testerOpen}
        onClose={() => setTesterOpen(false)}
        onRevealRule={onRevealRule}
      />
    </Stack>
  );
}
