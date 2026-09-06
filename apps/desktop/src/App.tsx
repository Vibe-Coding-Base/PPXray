import { getCurrentWindow } from "@tauri-apps/api/window";
import { useEffect, useState } from "react";
import {
  AppShell,
  MantineProvider,
  ScrollArea,
  Stack,
  Tooltip,
  UnstyledButton,
  rem,
} from "@mantine/core";
import { useHotkeys } from "@mantine/hooks";
import { ModalsProvider } from "@mantine/modals";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Notifications } from "@mantine/notifications";
import {
  IconAtom,
  IconChartDots3,
  IconInfoCircle,
  IconList,
  IconLogout,
  IconRobot,
  IconSettings,
  IconShieldCheck,
} from "@tabler/icons-react";

import { ProfileStoreProvider, useProfileStore } from "./stores/profile-store";
import { LogStoreProvider } from "./stores/log-store";
import { HuntStoreProvider } from "./stores/hunt-store";
import { AssistantStoreProvider, useAssistantStore } from "./stores/assistant-store";
import { AssistantDrawer } from "./modules/assistant/AssistantDrawer";
import { AssistantModule } from "./modules/assistant/AssistantModule";
import { HuntModule } from "./modules/hunt/HuntModule";
import { LogModule } from "./modules/log/LogModule";
import { RuleModule } from "./modules/rules/RuleModule";
import { ExposureModule } from "./modules/exposure/ExposureModule";
import { SettingsModule } from "./modules/settings/SettingsModule";
import { AboutModal } from "./components/shell/AboutModal";
import { CommandPalette, type ModuleId } from "./components/shell/CommandPalette";
import { ShortcutsModal } from "./components/shell/ShortcutsModal";
import { TopBar } from "./components/shell/TopBar";
import { useDirtyGuard } from "./hooks/use-dirty-guard";
import { theme } from "./theme";

interface NavItem {
  // A plain string: the rail also holds About, which opens a dialog rather
  // than switching modules and so has no `ModuleId`.
  id: string;
  label: string;
  icon: typeof IconList;
  hint?: string;
}

const NAV_ITEMS: (NavItem & { id: ModuleId })[] = [
  { id: "rules", label: "Rules", icon: IconList, hint: "Manage .ppx profile rules" },
  { id: "log", label: "Log", icon: IconChartDots3, hint: "Analyze Proxifier log files" },
  { id: "hunt", label: "Hunt", icon: IconShieldCheck, hint: "APT / malware detection" },
  { id: "exposure", label: "Exposure", icon: IconAtom, hint: "Internet exposure surface (3D)" },
  {
    id: "assistant",
    label: "Assistant",
    icon: IconRobot,
    hint: "Ask about this log (off by default)",
  },
];

// All data lives in a local DuckDB file reached over Tauri IPC — there is no
// network, no other writer, and nothing that goes stale on its own. So the
// automatic refetch triggers earn nothing here and only cost redundant
// scans; queries are invalidated explicitly when an ingest or hunt changes
// the underlying tables.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
      retry: false,
      staleTime: 30_000,
    },
  },
});

export function App() {
  return (
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="top-right" limit={5} />
      <ModalsProvider>
        <QueryClientProvider client={queryClient}>
          <ProfileStoreProvider>
            <LogStoreProvider>
              <HuntStoreProvider>
                <AssistantStoreProvider>
                  <AppShellInner />
                </AssistantStoreProvider>
              </HuntStoreProvider>
            </LogStoreProvider>
          </ProfileStoreProvider>
        </QueryClientProvider>
      </ModalsProvider>
    </MantineProvider>
  );
}

function AppShellInner() {
  const [active, setActive] = useState<ModuleId>("rules");
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const dirty = useProfileStore((s) => s.dirty);
  useDirtyGuard(dirty);

  // Listen for cross-module nav requests from deeply-nested children (Rules
  // → Exposure, etc.). Simpler than threading a callback through every
  // module prop chain.
  useEffect(() => {
    const handler = (e: Event) => {
      const ce = e as CustomEvent<ModuleId>;
      if (ce.detail) setActive(ce.detail);
    };
    window.addEventListener("proxifier:nav", handler);
    return () => window.removeEventListener("proxifier:nav", handler);
  }, []);

  // Global `?` opens the shortcut help. Limited to the global scope so module
  // hotkeys don't collide.
  const toggleAssistant = useAssistantStore((s) => s.toggleDrawer);

  useHotkeys([
    ["shift+/", () => setShortcutsOpen(true)],
    // The assistant is meant to be asked *while* looking at something, so it
    // gets a shortcut rather than only a trip to another tab.
    ["mod+J", () => toggleAssistant()],
  ]);

  return (
    <AppShell header={{ height: rem(40) }} navbar={{ width: rem(60), breakpoint: 0 }} padding={0}>
      <CommandPalette
        setActiveModule={setActive}
        showShortcuts={() => setShortcutsOpen(true)}
        showAbout={() => setAboutOpen(true)}
      />
      <ShortcutsModal opened={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
      <AboutModal opened={aboutOpen} onClose={() => setAboutOpen(false)} />
      <AssistantDrawer
        onOpenSettings={() => setActive("settings")}
        onExpand={() => setActive("assistant")}
      />

      <AppShell.Header>
        <TopBar active={active} />
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <Stack gap="xs" align="center" style={{ flex: 1 }}>
          {NAV_ITEMS.map((item) => (
            <NavButton
              key={item.id}
              item={item}
              active={active === item.id}
              onClick={() => setActive(item.id)}
            />
          ))}
        </Stack>
        {/* About sits with Settings rather than in the top bar: both are
            about the app itself rather than about the data in front of you,
            and the rail is where people look for that. */}
        <NavButton
          item={{ id: "about", label: "About", icon: IconInfoCircle, hint: "About ppxray" }}
          active={aboutOpen}
          onClick={() => setAboutOpen(true)}
        />
        <NavButton
          item={{ id: "settings", label: "Settings", icon: IconSettings }}
          active={active === "settings"}
          onClick={() => setActive("settings")}
        />
        {/* Goes through the window's close request rather than exiting the
            process, so `useDirtyGuard` still gets to ask about unsaved
            profile edits - a quit button that loses work is worse than none. */}
        <NavButton
          item={{ id: "exit", label: "Exit", icon: IconLogout, hint: "Close ppxray" }}
          active={false}
          onClick={() => void getCurrentWindow().close()}
        />
      </AppShell.Navbar>

      <AppShell.Main style={{ height: "calc(100vh - 40px)" }}>
        {/* Dense modules (rules, log, hunt) manage their own overflow.
            Settings uses a scroll wrapper. */}
        {active === "rules" && <RuleModule />}
        {active === "exposure" && <ExposureModule onPivotToRules={() => setActive("rules")} />}
        {active === "log" && <LogModule />}
        {active === "hunt" && <HuntModule />}
        {active === "assistant" && (
          <AssistantModule onOpenSettings={() => setActive("settings")} />
        )}
        {active === "settings" && (
          <ScrollArea h="100%" type="auto" scrollbarSize={8}>
            <SettingsModule />
          </ScrollArea>
        )}
      </AppShell.Main>
    </AppShell>
  );
}

interface NavButtonProps {
  item: NavItem;
  active: boolean;
  onClick: () => void;
}

function NavButton({ item, active, onClick }: NavButtonProps) {
  const Icon = item.icon;
  return (
    <Tooltip label={item.hint ?? item.label} position="right" withArrow openDelay={250}>
      <UnstyledButton
        onClick={onClick}
        aria-label={item.label}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: rem(40),
          height: rem(40),
          borderRadius: rem(6),
          background: active ? "var(--mantine-color-blue-light)" : "transparent",
          color: active ? "var(--mantine-color-blue-3)" : "var(--mantine-color-dimmed)",
          transition: "background 120ms",
        }}
      >
        <Icon size="1.4rem" stroke={1.6} />
      </UnstyledButton>
    </Tooltip>
  );
}
