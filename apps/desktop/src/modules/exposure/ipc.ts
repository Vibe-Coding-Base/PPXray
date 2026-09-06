import { invoke } from "@tauri-apps/api/core";

import type { ExposureGraph, Profile } from "@ppxray/ipc-schema";

export function computeExposure(profile: Profile): Promise<ExposureGraph> {
  return invoke<ExposureGraph>("profile_exposure", { profile });
}
