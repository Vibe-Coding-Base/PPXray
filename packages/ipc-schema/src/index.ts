// Public re-export of all generated Rust → TS model types.
// Generated files live under `./generated/` and must not be edited by hand
// (run `pnpm ts-gen` at repo root to regenerate).

export type { Profile } from "./generated/Profile";
export type { Options } from "./generated/Options";
export type { Resolve } from "./generated/Resolve";
export type { ExclusionList } from "./generated/ExclusionList";
export type { Encryption } from "./generated/Encryption";
export type { ConnectionLoopDetection } from "./generated/ConnectionLoopDetection";
export type { Proxy } from "./generated/Proxy";
export type { ProxyType } from "./generated/ProxyType";
export type { Authentication } from "./generated/Authentication";
export type { Chain } from "./generated/Chain";
export type { ChainMember } from "./generated/ChainMember";
export type { Rule } from "./generated/Rule";
export type { RuleAction } from "./generated/RuleAction";

// Matcher / validator types.
export type { Candidate } from "./generated/Candidate";
export type { SimulationResult } from "./generated/SimulationResult";
export type { RuleEvaluation } from "./generated/RuleEvaluation";
export type { FieldOutcome } from "./generated/FieldOutcome";
export type { WinnerAction } from "./generated/WinnerAction";
export type { EntryKind } from "./generated/EntryKind";
export type { ShadowPair } from "./generated/ShadowPair";
export type { ShadowReason } from "./generated/ShadowReason";
export type { ShadowField } from "./generated/ShadowField";

// Log analyzer types.
export type { Action } from "./generated/Action";
export type { Proto } from "./generated/Proto";
export type { IngestProgress } from "./generated/IngestProgress";
export type { IngestStats } from "./generated/IngestStats";
export type { EventFilter } from "./generated/EventFilter";
export type { EventRow } from "./generated/EventRow";
export type { LogStats } from "./generated/LogStats";
export type { ProcessCount } from "./generated/ProcessCount";
export type { HostCount } from "./generated/HostCount";
export type { RuleCount } from "./generated/RuleCount";
export type { TimeBucket } from "./generated/TimeBucket";
export type { LogDashboard } from "./generated/LogDashboard";
export type { TargetSuggestions } from "./generated/TargetSuggestions";
export type { HostSuggestion } from "./generated/HostSuggestion";
export type { SuggestionKind } from "./generated/SuggestionKind";
export type { FacetValues } from "./generated/FacetValues";

// Exposure surface types.
export type { ExposureGraph } from "./generated/ExposureGraph";
export type { ExposureSummary } from "./generated/ExposureSummary";
export type { ExposureFinding } from "./generated/ExposureFinding";
export type { FindingSeverity } from "./generated/FindingSeverity";
export type { FindingKind } from "./generated/FindingKind";
export type { FindingCounts } from "./generated/FindingCounts";
export type { ProcessBucket } from "./generated/ProcessBucket";
export type { ProcessBucketKind } from "./generated/ProcessBucketKind";
export type { RuleRef } from "./generated/RuleRef";
export type { RuleActionKind } from "./generated/RuleActionKind";
export type { PortGroup } from "./generated/PortGroup";
export type { ExitChannel } from "./generated/ExitChannel";
export type { ExitChannelKind } from "./generated/ExitChannelKind";
export type { ProxyHop } from "./generated/ProxyHop";
export type { ChainDescriptor } from "./generated/ChainDescriptor";
export type { Flow } from "./generated/Flow";

// Hunt / detection-engine types.
export type { Severity } from "./generated/Severity";
export type { Alert } from "./generated/Alert";
export type { AlertTriage } from "./generated/AlertTriage";
export type { AlertEvidence } from "./generated/AlertEvidence";
export type { AlertFilter } from "./generated/AlertFilter";
export type { HuntRunReport } from "./generated/HuntRunReport";
export type { RulePerRuleStat } from "./generated/RulePerRuleStat";

// IPC command result envelope. Mirrors Rust's `Result<T, String>` serde layout
// used by all `#[tauri::command]` handlers in `src-tauri/src/commands/*.rs`.
// The Tauri invoke helper maps Rust `Err(...)` to a thrown error on JS side,
// so handlers returning `Result<T, AppError>` surface as Promise<T> on TS side.
export type { OpenProfileResult } from "./ipc";

// Assistant types. `LlmSettings` is persisted inside settings.json; the API
// key is not part of it — it lives in the OS credential store.
export type { LlmSettings } from "./generated/LlmSettings";
export type { ProviderKind } from "./generated/ProviderKind";
export type { DataScope } from "./generated/DataScope";
export type { PayloadPreview } from "./generated/PayloadPreview";
export type { QueryTable } from "./generated/QueryTable";
export type { Usage } from "./generated/Usage";
export type { AuditEntry } from "./generated/AuditEntry";
export type { AuditOutcome } from "./generated/AuditOutcome";
