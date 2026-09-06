import {
  ActionIcon,
  Box,
  Button,
  Card,
  Code,
  Group,
  SegmentedControl,
  Select,
  Slider,
  Stack,
  Text,
  Title,
  Tooltip,
  useMantineColorScheme,
  rem,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconBrush,
  IconDatabase,
  IconDownload,
  IconFolderOpen,
  IconRefresh,
  IconShieldSearch,
} from "@tabler/icons-react";
import { useState } from "react";

import { checkForUpdates } from "@/hooks/use-updater";
import { useRuleDir } from "@/modules/hunt/queries";
import { useLogStore } from "@/stores/log-store";
import {
  DEFAULT_PREFS,
  MAX_SIZE,
  MIN_SIZE,
  MONO_FONTS,
  UI_FONTS,
  applyPrefs,
  loadPrefs,
  savePrefs,
  type UiPrefs,
} from "@/stores/ui-prefs";
import { AssistantSettings } from "./AssistantSettings";
import { pickRuleDir, setRuleDir } from "./ipc";

export function SettingsModule() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const sourcePath = useLogStore((s) => s.sourcePath);

  const [busy, setBusy] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);

  // Held in component state and mirrored to the document on every change, so
  // dragging the slider is a live preview rather than a guess followed by a
  // reload.
  const [prefs, setPrefs] = useState<UiPrefs>(loadPrefs);

  function commitPrefs(next: UiPrefs) {
    setPrefs(next);
    applyPrefs(next);
    savePrefs(next);
  }

  const patchPrefs = (patch: Partial<UiPrefs>) => commitPrefs({ ...prefs, ...patch });
  const resetPrefs = () => commitPrefs(DEFAULT_PREFS);

  // Shares the cache entry with the Hunt module's rule list, so changing the
  // directory here updates both.
  const ruleDirQuery = useRuleDir();
  const ruleDir = ruleDirQuery.data ?? null;
  const refreshRuleDir = () => ruleDirQuery.refetch();

  async function chooseDir() {
    setBusy(true);
    try {
      const picked = await pickRuleDir(ruleDir?.effective ?? undefined);
      if (!picked) return;
      await setRuleDir(picked);
      await refreshRuleDir();
      notifications.show({ message: "Rule directory updated", color: "teal" });
    } catch (e) {
      notifications.show({
        title: "Failed to set rule dir",
        message: String(e),
        color: "red",
      });
    } finally {
      setBusy(false);
    }
  }

  async function resetDir() {
    setBusy(true);
    try {
      await setRuleDir(null);
      await refreshRuleDir();
      notifications.show({ message: "Reverted to default", color: "teal" });
    } catch (e) {
      notifications.show({ title: "Reset failed", message: String(e), color: "red" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack p="md" gap="md" maw={rem(900)}>
      <Title order={4}>Settings</Title>

      <Card withBorder radius="sm" p="md">
        <Group gap="xs" mb="xs">
          <IconBrush size="1.1rem" />
          <Text fw={600}>Appearance</Text>
        </Group>

        <Stack gap="md">
          <Group justify="space-between" wrap="nowrap">
            <div>
              <Text size="sm" fw={500}>Theme</Text>
              <Text size="sm" c="dimmed">
                Dark is recommended for long log-analysis sessions; light is
                available for screenshots and accessibility.
              </Text>
            </div>
            <SegmentedControl
              value={colorScheme === "auto" ? "dark" : colorScheme}
              onChange={(v) => setColorScheme(v as "light" | "dark")}
              data={[
                { value: "dark", label: "Dark" },
                { value: "light", label: "Light" },
              ]}
              style={{ flexShrink: 0 }}
            />
          </Group>

          <div>
            <Group justify="space-between" mb={2}>
              <Text size="sm" fw={500}>Interface size</Text>
              <Text size="sm" c="dimmed" className="mono">
                {prefs.baseSizePx}px
              </Text>
            </Group>
            <Text size="sm" c="dimmed" mb="xs">
              Scales text, buttons, row heights and spacing together — this is
              the browser base size everything else is measured against, so a
              dense 1080p monitor and a 4K laptop panel can each get a size
              that reads.
            </Text>
            {/* Inset so the end mark labels, which are centred on their
                ticks and so overhang the track, are not clipped by the Card. */}
            <Box px={rem(36)}>
              <Slider
                min={MIN_SIZE}
                max={MAX_SIZE}
                step={1}
                value={prefs.baseSizePx}
                onChange={(v) => patchPrefs({ baseSizePx: v })}
                marks={[
                  { value: MIN_SIZE, label: "Compact" },
                  { value: DEFAULT_PREFS.baseSizePx, label: "Default" },
                  { value: MAX_SIZE, label: "Large" },
                ]}
                mb="lg"
              />
            </Box>
          </div>

          <Group grow align="flex-start">
            <Select
              label="Interface font"
              description="Labels, buttons, prose"
              data={UI_FONTS.map((f) => ({ value: f.value, label: f.label }))}
              value={prefs.fontFamily}
              allowDeselect={false}
              onChange={(v) => v && patchPrefs({ fontFamily: v })}
            />
            <Select
              label="Monospace font"
              description="Hostnames, IPs, process names, SQL"
              data={MONO_FONTS.map((f) => ({ value: f.value, label: f.label }))}
              value={prefs.monoFamily}
              allowDeselect={false}
              onChange={(v) => v && patchPrefs({ monoFamily: v })}
            />
          </Group>

          <Group justify="space-between">
            <Text size="sm" c="dimmed" className="mono">
              svchost.exe → rr5.sn-abcd1234.googlevideo.com:443
            </Text>
            <Button variant="subtle" color="gray" onClick={resetPrefs}>
              Reset to defaults
            </Button>
          </Group>
        </Stack>
      </Card>

      <Card withBorder radius="sm" p="md">
        <Group gap="xs" mb="xs">
          <IconShieldSearch size="1.1rem" />
          <Text fw={600}>Detection rules directory</Text>
        </Group>
        <Text size="sm" c="dimmed" mb="sm">
          Drop your <Code>.yml</Code> / <Code>.yaml</Code> detection rule files
          in this directory. They are loaded alongside the built-in catalog;
          user rules with the same <Code>id</Code> override the built-in.
        </Text>
        <Stack gap={4}>
          <Group justify="space-between" wrap="nowrap">
            <div style={{ minWidth: rem(0), flex: 1 }}>
              <Text size="xs" c="dimmed">
                Effective path
              </Text>
              <Text
                size="sm"
                className="mono"
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
                title={ruleDir?.effective}
              >
                {ruleDir?.effective ?? "…"}
              </Text>
            </div>
            <Group gap={4}>
              <Tooltip label="Refresh" withArrow>
                <ActionIcon
                  variant="subtle"
                  onClick={refreshRuleDir}
                  disabled={busy}
                  aria-label="Refresh"
                >
                  <IconRefresh size="1rem" />
                </ActionIcon>
              </Tooltip>
              <Button
                size="xs"
                variant="default"
                leftSection={<IconFolderOpen size="0.85rem" />}
                onClick={chooseDir}
                loading={busy}
              >
                Choose…
              </Button>
              {ruleDir?.configured && (
                <Button size="xs" variant="subtle" color="gray" onClick={resetDir}>
                  Use default
                </Button>
              )}
            </Group>
          </Group>
          {ruleDir?.configured && (
            <Text size="sm" c="dimmed">
              Custom override in effect. Default: <Code>{ruleDir.default}</Code>
            </Text>
          )}
        </Stack>
      </Card>

      <AssistantSettings />

      <Card withBorder radius="sm" p="md">
        <Group gap="xs" mb="xs">
          <IconDatabase size="1.1rem" />
          <Text fw={600}>Data</Text>
        </Group>
        <Stack gap={4}>
          <Group justify="space-between">
            <Text size="sm" fw={500}>Active log</Text>
            <Text size="sm" c="dimmed" className="mono">
              {sourcePath ?? "(none)"}
            </Text>
          </Group>
          <Text size="sm" c="dimmed">
            Per-log DuckDB analysis files live under your OS app-data directory.
            Delete a file there to drop the cached analysis.
          </Text>
        </Stack>
      </Card>

      <Card withBorder radius="sm" p="md">
        <Group gap="xs" mb="xs">
          <IconDownload size="1.1rem" />
          <Text fw={600}>Updates</Text>
        </Group>
        <Group justify="space-between" wrap="nowrap">
          <Stack gap={0}>
            <Text size="sm" fw={500}>Check for updates</Text>
            <Text size="sm" c="dimmed">
              Asks the GitHub release channel whether a newer version exists,
              and verifies the bundle signature against the key compiled into
              this build before installing. There is no background check — it
              runs only when you press this, and with the assistant off it is
              the only request the app makes.
            </Text>
          </Stack>
          <Button
            variant="default"
            leftSection={<IconDownload size="0.85rem" />}
            style={{ flexShrink: 0 }}
            loading={checkingUpdate}
            onClick={async () => {
              setCheckingUpdate(true);
              try {
                await checkForUpdates();
              } finally {
                setCheckingUpdate(false);
              }
            }}
          >
            Check now
          </Button>
        </Group>
      </Card>

    </Stack>
  );
}
