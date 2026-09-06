import { invoke } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";

import type { Profile } from "@ppxray/ipc-schema";

export interface OpenProfileResult {
  profile: Profile;
  path: string;
  modified_at: string;
}

const ppxFilters = () => [
  { name: "Proxifier Profile", extensions: ["ppx"] },
  { name: "All files", extensions: ["*"] },
];

export async function pickAndOpenProfile(): Promise<OpenProfileResult | null> {
  const picked = await openDialog({ multiple: false, filters: ppxFilters() });
  if (!picked || typeof picked !== "string") return null;
  return openProfileFromPath(picked);
}

export function openProfileFromPath(path: string): Promise<OpenProfileResult> {
  return invoke<OpenProfileResult>("profile_open_from_path", { path });
}

export function saveProfileToPath(path: string, profile: Profile): Promise<void> {
  return invoke<void>("profile_save_to_path", { path, profile });
}

export async function pickAndSaveProfile(
  profile: Profile,
  defaultPath?: string,
): Promise<string | null> {
  const picked = await saveDialog({
    filters: ppxFilters(),
    defaultPath: defaultPath ?? undefined,
  });
  if (!picked) return null;
  await saveProfileToPath(picked, profile);
  return picked;
}
