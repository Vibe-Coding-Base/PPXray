import { invoke } from "@tauri-apps/api/core";

import type { Alert, AlertFilter, HuntRunReport } from "@ppxray/ipc-schema";

export interface QueryDetail {
  kind: "events_where" | "events_grouped" | "dns_where" | "custom";
  where_sql: string | null;
  group_by: "process" | "dst" | "process_and_dst" | null;
  min_count: number | null;
  max_per_run: number | null;
  select_sql: string | null;
}

export interface HuntCatalogEntry {
  id: string;
  title: string;
  description: string;
  severity: string;
  mitre: string[];
  references: string[];
  /** "builtin" for built-in rules, else the user rule filename. */
  source: string;
  query: QueryDetail;
}

export function huntCatalog(): Promise<HuntCatalogEntry[]> {
  return invoke<HuntCatalogEntry[]>("hunt_catalog");
}

export function huntRun(): Promise<HuntRunReport> {
  return invoke<HuntRunReport>("hunt_run");
}

export function huntListAlerts(filter: AlertFilter): Promise<Alert[]> {
  return invoke<Alert[]>("hunt_list_alerts", { filter });
}

export function huntAlertEvidence(alertId: bigint, limit = 50): Promise<bigint[]> {
  return invoke<bigint[]>("hunt_alert_evidence", { alertId, limit });
}

export function huntTriage(alertId: bigint, triage: string): Promise<void> {
  return invoke<void>("hunt_triage", { alertId, triage });
}

// --- User rules -----------------------------------------------------------

export interface UserRuleView {
  filename: string;
  raw_yaml: string;
  id: string | null;
  title: string | null;
  severity: string | null;
  mitre: string[] | null;
  error: string | null;
}

export function listUserRules(): Promise<UserRuleView[]> {
  return invoke<UserRuleView[]>("hunt_user_rules");
}

export function saveUserRule(filename: string, yaml: string): Promise<void> {
  return invoke<void>("hunt_save_user_rule", { filename, yaml });
}

export function deleteUserRule(filename: string): Promise<void> {
  return invoke<void>("hunt_delete_user_rule", { filename });
}
