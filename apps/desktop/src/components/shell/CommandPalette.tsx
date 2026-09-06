// Command palette wired to Mantine's Spotlight.
//
// We register a small set of high-value actions:
//   - module navigation (Rules / Log / Hunt / Settings)
//   - file lifecycle (Open profile / log, Save profile)
//   - hunt actions (Run hunt)
//   - help (Show shortcuts, About)
//   - theme toggle
//
// Triggered with Ctrl/Cmd+K. The palette is global state-aware: it grabs
// callbacks from the relevant stores and IPC modules, so a "Run hunt"
// triggered from the palette acts identically to clicking the button.

import { Spotlight, type SpotlightActionData } from "@mantine/spotlight";
import { notifications } from "@mantine/notifications";
import { useMantineColorScheme } from "@mantine/core";
import {
  IconAtom,
  IconBolt,
  IconDeviceFloppy,
  IconDownload,
  IconFileExport,
  IconFolderOpen,
  IconHelp,
  IconInfoCircle,
  IconList,
  IconMoonStars,
  IconNetwork,
  IconSettings,
  IconShieldCheck,
  IconSun,
  IconUpload,
} from "@tabler/icons-react";
import { useMemo } from "react";

import { pickAndOpenProfile, pickAndSaveProfile, saveProfileToPath } from "@/ipc/profile";
import { useProfileStoreShallow } from "@/stores/profile-store";
import { useLogStoreShallow } from "@/stores/log-store";
import { useHuntStoreShallow } from "@/stores/hunt-store";
import { ingestLog, pickLogFile } from "@/modules/log/ipc";
import { checkForUpdates } from "@/hooks/use-updater";
import { useRunHunt } from "@/modules/hunt/queries";

export type ModuleId =
  | "rules"
  | "exposure"
  | "log"
  | "hunt"
  | "assistant"
  | "settings";

interface Props {
  setActiveModule: (m: ModuleId) => void;
  showShortcuts: () => void;
  showAbout: () => void;
}

export function CommandPalette({ setActiveModule, showShortcuts, showAbout }: Props) {
  const { colorScheme, setColorScheme } = useMantineColorScheme();

  const profile = useProfileStoreShallow((s) => ({
    profile: s.profile,
    path: s.path,
    setLoaded: s.setLoaded,
    markSaved: s.markSaved,
  }));

  const logState = useLogStoreShallow((s) => ({
    sourcePath: s.sourcePath,
    setLoaded: s.setLoaded,
    setProgress: s.setProgress,
  }));

  const hunt = useHuntStoreShallow((s) => ({ setReport: s.setReport }));
  // Shares the mutation (and its cache invalidation) with the Hunt module's
  // own Run button, so the two cannot disagree about what a run did.
  const runHunt = useRunHunt();

  const actions: SpotlightActionData[] = useMemo(
    () => [
      {
        id: "nav-rules",
        label: "Go to Rules",
        description: "Manage .ppx profile rules",
        leftSection: <IconList size="1.1rem" />,
        onClick: () => setActiveModule("rules"),
        keywords: ["module", "navigate"],
      },
      {
        id: "nav-exposure",
        label: "Go to Exposure surface",
        description: "3D view of Internet-exposure paths",
        leftSection: <IconAtom size="1.1rem" />,
        onClick: () => setActiveModule("exposure"),
        keywords: ["module", "surface", "attack"],
      },
      {
        id: "nav-log",
        label: "Go to Log analyzer",
        description: "Filter and inspect Proxifier log events",
        leftSection: <IconNetwork size="1.1rem" />,
        onClick: () => setActiveModule("log"),
        keywords: ["module", "events"],
      },
      {
        id: "nav-hunt",
        label: "Go to Threat hunt",
        description: "Detection rules + alert inbox",
        leftSection: <IconShieldCheck size="1.1rem" />,
        onClick: () => setActiveModule("hunt"),
        keywords: ["alerts", "detection"],
      },
      {
        id: "nav-settings",
        label: "Go to Settings",
        leftSection: <IconSettings size="1.1rem" />,
        onClick: () => setActiveModule("settings"),
      },
      {
        id: "profile-open",
        label: "Open profile…",
        description: "Load a .ppx file",
        leftSection: <IconFolderOpen size="1.1rem" />,
        onClick: async () => {
          try {
            const r = await pickAndOpenProfile();
            if (r) profile.setLoaded(r.profile, r.path);
          } catch (e) {
            notifications.show({ title: "Open failed", message: String(e), color: "red" });
          }
        },
      },
      {
        id: "profile-save",
        label: "Save profile",
        description: profile.path ?? "Save current profile to disk",
        leftSection: <IconDeviceFloppy size="1.1rem" />,
        onClick: async () => {
          if (!profile.profile) return;
          try {
            if (profile.path) {
              await saveProfileToPath(profile.path, profile.profile);
              profile.markSaved(profile.path);
              notifications.show({ message: "Saved", color: "teal" });
            } else {
              const p = await pickAndSaveProfile(profile.profile);
              if (p) profile.markSaved(p);
            }
          } catch (e) {
            notifications.show({ title: "Save failed", message: String(e), color: "red" });
          }
        },
      },
      {
        id: "profile-save-as",
        label: "Save profile as…",
        leftSection: <IconFileExport size="1.1rem" />,
        onClick: async () => {
          if (!profile.profile) return;
          const p = await pickAndSaveProfile(profile.profile, profile.path ?? undefined);
          if (p) profile.markSaved(p);
        },
      },
      {
        id: "log-open",
        label: "Open log file…",
        description: "Stream-parse a Proxifier .txt log",
        leftSection: <IconUpload size="1.1rem" />,
        onClick: async () => {
          try {
            const path = await pickLogFile();
            if (!path) return;
            const result = await ingestLog(path);
            logState.setLoaded(path, result.stats, result.counts);
            setActiveModule("log");
            notifications.show({
              message: `${Number(result.stats.total_events).toLocaleString()} events ingested`,
              color: "teal",
            });
          } catch (e) {
            notifications.show({ title: "Ingest failed", message: String(e), color: "red" });
          }
        },
      },
      {
        id: "hunt-run",
        label: "Run hunt now",
        description: "Execute the built-in detection catalog",
        leftSection: <IconBolt size="1.1rem" />,
        onClick: () => {
          if (!logState.sourcePath) {
            notifications.show({ message: "Open a log first", color: "yellow" });
            return;
          }
          setActiveModule("hunt");
          runHunt.mutate(undefined, {
            onSuccess: (r) => hunt.setReport(r),
            onError: (e) =>
              notifications.show({
                title: "Hunt failed",
                message: String(e),
                color: "red",
              }),
          });
        },
      },
      {
        id: "theme-toggle",
        label: colorScheme === "dark" ? "Switch to light theme" : "Switch to dark theme",
        leftSection: colorScheme === "dark" ? <IconSun size="1.1rem" /> : <IconMoonStars size="1.1rem" />,
        onClick: () => setColorScheme(colorScheme === "dark" ? "light" : "dark"),
      },
      {
        id: "show-shortcuts",
        label: "Keyboard shortcuts",
        leftSection: <IconHelp size="1.1rem" />,
        onClick: showShortcuts,
      },
      {
        id: "check-updates",
        label: "Check for updates",
        description: "Ask the GitHub release channel for a newer version",
        leftSection: <IconDownload size="1.1rem" />,
        onClick: () => void checkForUpdates(),
      },
      {
        id: "about",
        label: "About ppxray",
        leftSection: <IconInfoCircle size="1.1rem" />,
        onClick: showAbout,
      },
    ],
    [colorScheme, setColorScheme, profile, logState, hunt, runHunt, setActiveModule, showShortcuts, showAbout],
  );

  return (
    <Spotlight
      actions={actions}
      shortcut={["mod+k", "mod+p"]}
      nothingFound="No command matches"
      highlightQuery
      searchProps={{
        leftSection: <IconBolt size="1.1rem" />,
        placeholder: "Type a command…",
      }}
    />
  );
}
