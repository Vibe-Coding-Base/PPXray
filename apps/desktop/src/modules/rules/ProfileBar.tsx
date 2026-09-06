// Open / save / close for the loaded profile, inside the module that owns it.
//
// These controls used to live in the global title bar, next to nothing else,
// which read as "app-wide actions" — so from the Log or Hunt tab, "Save
// profile" looked like it might save the thing you were looking at. It does
// not; it only ever touched the .ppx file. The Log module already keeps its
// own path and its own Re-ingest / Open other / Unload row, so this is the
// same shape one module over, and the top bar stops implying otherwise.

import { Badge, Button, Group, Text, Tooltip } from "@mantine/core";
import { useHotkeys } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconDeviceFloppy,
  IconFileExport,
  IconFolderOpen,
  IconX,
} from "@tabler/icons-react";
import { useCallback, useState } from "react";

import { pickAndSaveProfile, saveProfileToPath } from "@/ipc/profile";
import { useProfileStoreShallow } from "@/stores/profile-store";
import { useOpenProfile } from "./use-open-profile";

export function ProfileBar() {
  const { profile, path, dirty, markSaved, clear } = useProfileStoreShallow((s) => ({
    profile: s.profile,
    path: s.path,
    dirty: s.dirty,
    markSaved: s.markSaved,
    clear: s.clear,
  }));
  const { open: onOpen, opening } = useOpenProfile();
  const [busy, setBusy] = useState(false);

  const onSave = useCallback(async () => {
    if (!profile) return;
    setBusy(true);
    try {
      if (path) {
        await saveProfileToPath(path, profile);
        markSaved(path);
        notifications.show({ title: "Saved", message: path, color: "teal" });
      } else {
        const p = await pickAndSaveProfile(profile);
        if (p) {
          markSaved(p);
          notifications.show({ title: "Saved", message: p, color: "teal" });
        }
      }
    } catch (err) {
      notifications.show({ title: "Save failed", message: String(err), color: "red" });
    } finally {
      setBusy(false);
    }
  }, [profile, path, markSaved]);

  const onSaveAs = useCallback(async () => {
    if (!profile) return;
    setBusy(true);
    try {
      const p = await pickAndSaveProfile(profile, path ?? undefined);
      if (p) {
        markSaved(p);
        notifications.show({ title: "Saved as", message: p, color: "teal" });
      }
    } catch (err) {
      notifications.show({ title: "Save As failed", message: String(err), color: "red" });
    } finally {
      setBusy(false);
    }
  }, [profile, path, markSaved]);

  // Closing throws away edits, so a dirty profile gets asked about first —
  // the same courtesy `useDirtyGuard` gives the window close button.
  const onClose = useCallback(() => {
    if (!dirty) {
      clear();
      return;
    }
    modals.openConfirmModal({
      title: "Close without saving?",
      children: (
        <Text size="sm">
          This profile has unsaved edits. Closing it discards them.
        </Text>
      ),
      labels: { confirm: "Discard and close", cancel: "Keep editing" },
      confirmProps: { color: "red" },
      onConfirm: clear,
    });
  }, [dirty, clear]);

  // Scoped to this module now that the controls are. The tooltips advertised
  // these shortcuts while nothing was bound to them.
  useHotkeys([
    ["mod+O", () => void onOpen()],
    ["mod+S", () => void onSave()],
    ["mod+shift+S", () => void onSaveAs()],
  ]);

  return (
    <Group gap="sm" px="sm" py="xs" wrap="nowrap" style={{ overflow: "hidden" }}>
      <Text
        size="xs"
        c="dimmed"
        className="mono"
        style={{
          flex: 1,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={path ?? undefined}
      >
        {path ?? "(no profile loaded)"}
      </Text>

      {dirty && (
        <Badge color="yellow" variant="light">
          unsaved
        </Badge>
      )}

      <Tooltip label="Open a Proxifier .ppx profile (Ctrl+O)" withArrow>
        <Button
          size="xs"
          variant="subtle"
          leftSection={<IconFolderOpen size="0.85rem" />}
          onClick={() => void onOpen()}
          loading={busy || opening}
        >
          {profile ? "Open other" : "Open profile"}
        </Button>
      </Tooltip>

      {profile && (
        <>
          <Tooltip label="Save profile (Ctrl+S)" withArrow>
            <Button
              size="xs"
              variant="subtle"
              leftSection={<IconDeviceFloppy size="0.85rem" />}
              onClick={() => void onSave()}
              loading={busy}
            >
              Save
            </Button>
          </Tooltip>
          <Tooltip label="Save profile as… (Ctrl+Shift+S)" withArrow>
            <Button
              size="xs"
              variant="subtle"
              leftSection={<IconFileExport size="0.85rem" />}
              onClick={() => void onSaveAs()}
              loading={busy}
            >
              Save as…
            </Button>
          </Tooltip>
          <Button
            size="xs"
            variant="subtle"
            color="gray"
            leftSection={<IconX size="0.85rem" />}
            onClick={onClose}
          >
            Close
          </Button>
        </>
      )}
    </Group>
  );
}
