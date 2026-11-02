// Types and constants of the decision log (`tollgate.event.v1`, see docs/events-v1.md).
import type { Effect } from "./commandInfo.js";

export const SCHEMA = "tollgate.event.v1";
export const COMPONENT = "tollgate-guardrail";
export const MAX_EVENT_BYTES = 8192;
export const MAX_COMMAND_TEXT = 2048;
export const MAX_REASON = 1024;
export const INVALID = "<invalid>";
export const GENESIS = "0".repeat(64);

/** Event types this package produces. The types of the relay, sender, heartbeat and monitor are reserved. */
export const EVENT_TYPES = [
  "decision", "session_start", "session_end", "subagent_start", "subagent_stop", "chain_start", "chain_continue", "suppressed",
  "log_error", "policy_error", "policy_override_ignored", "logging_disabled", "logging_enabled", "tool_result",
  // Session taint: the session became tainted, a human lifted it, a block in mode `observe` (not enforced).
  "taint_set", "taint_release", "taint_would_block",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const RULE_KINDS = [
  "none", "path_unresolvable", "outside_project", "protected_path", "active_policy", "hardlink_alias", "parse_error", "blocked_command",
  "write_target", "dependency_unverifiable", "dependency", "invalid_input", "size_limit", "policy_error", "internal_error",
  "log_write_error", "enterprise_unsupported_platform", "unchecked_tool", "admin_lock", "lock_error", "taint",
] as const;
export type RuleKind = (typeof RULE_KINDS)[number];

export type Outcome = "allow" | "deny" | "ask" | "observe";

export interface ClaudeFields {
  session_id: string;
  tool_use_id: string | null;
  agent_id: string | null;
  agent_type: string | null;
  hook_event: string;
  permission_mode: string | null;
  project_dir?: string;
  invalid_fields?: string[];
}

export interface ToolFields {
  name: string;
  command?: string;
  command_sha256?: string;
  programs?: string[];
  paths?: string[];
  paths_omitted?: number;
  effects?: Effect[];
  domain?: string;
  truncated: boolean;
}

export interface DecisionFields {
  outcome: Outcome;
  rule_kind: RuleKind;
  rule_id: string | null;
  reason: string | null;
  human_session: boolean;
}

export interface PolicyFields {
  revision: string | null;
  sha256: string | null;
  layers: { level: string; sha256: string; generation?: number }[];
  enterprise_mode: boolean;
}

/** An event before it is chained: no chain_id, seq, prev_hash, hash. */
export interface Draft {
  event_id: string;
  ts: string;
  type: EventType;
  host: { name: string; os: string };
  user: { name: string; id: string };
  claude?: ClaudeFields;
  tool?: ToolFields;
  redactions?: number;
  decision?: DecisionFields;
  policy?: PolicyFields;
  source: { component: string; version: string };
  data?: Record<string, unknown>;
}

export interface TollgateEvent extends Draft {
  schema: typeof SCHEMA;
  chain_id: string;
  seq: number;
  prev_hash: string;
  hash: string;
}

export type CommandDetail = "none" | "hash" | "redacted";
