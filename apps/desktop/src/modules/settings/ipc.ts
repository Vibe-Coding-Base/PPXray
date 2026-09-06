import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

export interface RuleDirInfo {
  effective: string;
  configured: string | null;
  default: string;
}

export function getRuleDir(): Promise<RuleDirInfo> {
  return invoke<RuleDirInfo>("settings_rule_dir");
}

export function setRuleDir(path: string | null): Promise<void> {
  return invoke<void>("settings_set_rule_dir", { path });
}

export async function pickRuleDir(defaultPath?: string): Promise<string | null> {
  const picked = await openDialog({
    directory: true,
    multiple: false,
    defaultPath,
  });
  return typeof picked === "string" ? picked : null;
}
