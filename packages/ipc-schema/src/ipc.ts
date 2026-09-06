// Hand-written IPC response shapes. Keep in sync with
// `src-tauri/src/commands/profile.rs`.

import type { Profile } from "./generated/Profile";

export interface OpenProfileResult {
  profile: Profile;
  path: string;
  /** ISO 8601 timestamp of file's mtime at read. */
  modified_at: string;
}

