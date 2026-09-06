import { invoke } from "@tauri-apps/api/core";

import type {
  Candidate,
  Rule,
  ShadowPair,
  SimulationResult,
} from "@ppxray/ipc-schema";

export function simulateMatch(
  rules: Rule[],
  candidate: Candidate,
): Promise<SimulationResult> {
  return invoke<SimulationResult>("rule_simulate_match", { rules, candidate });
}

export function scanOvershadows(rules: Rule[]): Promise<ShadowPair[]> {
  return invoke<ShadowPair[]>("rule_overshadow_scan", { rules });
}
