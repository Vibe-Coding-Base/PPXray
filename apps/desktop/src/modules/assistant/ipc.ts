import { invoke } from "@tauri-apps/api/core";

import type {
  AuditEntry,
  LlmSettings,
  PayloadPreview,
  ProviderKind,
  QueryTable,
} from "@ppxray/ipc-schema";

/** Which prompt a request uses; also the tag written to the audit log. */
export type Task = "chat" | "review" | "explain-rule";

export interface LlmStatus {
  settings: LlmSettings;
  /** A key exists in the OS credential store. The key itself never gets here. */
  has_key: boolean;
  effective_base_url: string;
  effective_model: string;
  local_endpoint: boolean;
  audit_path: string;
}

export interface EndpointPreset {
  label: string;
  base_url: string;
  model: string;
  /** Runs on this machine, so the privacy level stops mattering. */
  local: boolean;
  note: string;
}

export interface ProviderDefaults {
  provider: ProviderKind;
  base_url: string;
  model: string;
  presets: EndpointPreset[];
}

/** One query the assistant ran, as shown to the user. */
export interface AgentStep {
  purpose: string;
  sql: string;
  /** The full, unmasked result — the user's own data on their own screen. */
  table: QueryTable | null;
  error: string | null;
  /**
   * Whether the result was also sent to the model. False at the default
   * privacy level, and rendered, so the reader knows what the answer above
   * was based on.
   */
  shared_with_model: boolean;
}

export interface AssistantReply {
  text: string;
  thinking: string;
  steps: AgentStep[];
  input_tokens: number | null;
  output_tokens: number | null;
  unverified: boolean;
}

export const llmStatus = () => invoke<LlmStatus>("llm_status");

export const llmSetSettings = (settings: LlmSettings) =>
  invoke<LlmStatus>("llm_set_settings", { settings });

export const llmProviderDefaults = () =>
  invoke<ProviderDefaults[]>("llm_provider_defaults");

export const llmSetApiKey = (key: string) => invoke<boolean>("llm_set_api_key", { key });

export const llmClearApiKey = () => invoke<boolean>("llm_clear_api_key");

export const llmMarkReviewed = () => invoke<LlmStatus>("llm_mark_reviewed");

export interface ConnectionCheck {
  ok: boolean;
  summary: string;
  hint: string | null;
  latency_ms: number | null;
  model: string | null;
}

/** One real round trip against the configured endpoint. */
export const llmTestConnection = () => invoke<ConnectionCheck>("llm_test_connection");

export const llmPreview = (task: Task, input: string) =>
  invoke<PayloadPreview>("llm_preview", { task, input });

export const llmAsk = (task: Task, input: string, conversationId?: string) =>
  invoke<AssistantReply>("llm_ask", { task, input, conversationId });

/** Forget one transcript, or every one of them when no id is given. */
export const llmResetChat = (conversationId?: string) =>
  invoke<void>("llm_reset_chat", { conversationId });

export const llmAuditEntries = (limit?: number) =>
  invoke<AuditEntry[]>("llm_audit_entries", { limit });

export const llmClearAudit = () => invoke<void>("llm_clear_audit");
