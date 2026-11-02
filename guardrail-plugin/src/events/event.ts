// Assembly of log events: command text, sanitizing and the 8 KiB size rule.
import { sha256Hex } from "../vendor/hashchain.js";
import { redactCommand } from "./redact.js";
import { sanitizeDeep, truncateText } from "./sanitize.js";
import { GENESIS, MAX_COMMAND_TEXT, MAX_EVENT_BYTES, MAX_REASON, SCHEMA, type CommandDetail, type Draft, type TollgateEvent } from "./types.js";

const RAW_COMMAND_LIMIT = 16 * 1024;
const MAX_PATHS_STORED = 64;
const MAX_PROGRAM_CHARS = 64;
const PATHS_AFTER_TRUNCATION = 8;
const COMMAND_AFTER_TRUNCATION = 512;
const REASON_AFTER_TRUNCATION = 128;

export interface CommandFields {
  command?: string;
  command_sha256?: string;
  redactions: number;
}

/**
 * Command text fields by detail level. `none`: nothing; `hash`: SHA-256 of the raw command; `redacted`: redacted
 * normalized text (nothing if the tokenizer fails). `commandHash` adds the hash to `redacted`.
 */
export function commandFields(command: string, detail: CommandDetail, commandHash: boolean): CommandFields {
  const out: CommandFields = { redactions: 0 };
  if (detail === "hash" || commandHash) out.command_sha256 = sha256Hex(command);
  if (detail === "redacted") {
    // 1. hard limit of the raw text, 2./3. tokenizer and redaction. The bytes are cut, not the characters.
    const limited = Buffer.byteLength(command, "utf8") > RAW_COMMAND_LIMIT ? Buffer.from(command, "utf8").subarray(0, RAW_COMMAND_LIMIT).toString("utf8") : command;
    const redacted = redactCommand(limited);
    if (redacted !== null) {
      out.command = redacted.text;
      out.redactions = redacted.redactions;
    }
  }
  return out;
}

function size(draft: Draft): number {
  const placeholder = { schema: SCHEMA, ...draft, chain_id: "x".repeat(36), seq: Number.MAX_SAFE_INTEGER, prev_hash: GENESIS, hash: GENESIS };
  return Buffer.byteLength(JSON.stringify(placeholder), "utf8");
}

function cut(text: string, max: number): { text: string; cut: boolean } {
  return truncateText(text, max);
}

function markTruncated(draft: Draft): void {
  if (draft.tool !== undefined) draft.tool.truncated = true;
}

/**
 * Sanitizes every string once and enforces the size rules. An event is never dropped; order of the cuts:
 * paths (8 + counter), command (512), reason (128), project_dir, then mandatory fields only.
 */
export function fitDraft(input: Draft): Draft {
  const d = sanitizeDeep(structuredClone(input));
  // Fixed limits that apply independent of the total size.
  if (d.tool?.command !== undefined) {
    const c = cut(d.tool.command, MAX_COMMAND_TEXT);
    d.tool.command = c.text;
    if (c.cut) markTruncated(d);
  }
  if (d.tool?.programs !== undefined) {
    d.tool.programs = d.tool.programs.map((p) => {
      const c = cut(p, MAX_PROGRAM_CHARS);
      if (c.cut) markTruncated(d);
      return c.text;
    });
  }
  if (d.tool?.paths !== undefined && d.tool.paths.length > MAX_PATHS_STORED) {
    d.tool.paths_omitted = (d.tool.paths_omitted ?? 0) + d.tool.paths.length - MAX_PATHS_STORED;
    d.tool.paths = d.tool.paths.slice(0, MAX_PATHS_STORED);
    markTruncated(d);
  }
  if (d.decision?.reason != null) {
    const c = cut(d.decision.reason, MAX_REASON);
    d.decision.reason = c.text;
    if (c.cut) markTruncated(d);
  }
  if (size(d) <= MAX_EVENT_BYTES) return d;
  // 1. paths
  if (d.tool?.paths !== undefined && d.tool.paths.length > PATHS_AFTER_TRUNCATION) {
    d.tool.paths_omitted = (d.tool.paths_omitted ?? 0) + d.tool.paths.length - PATHS_AFTER_TRUNCATION;
    d.tool.paths = d.tool.paths.slice(0, PATHS_AFTER_TRUNCATION);
  }
  markTruncated(d);
  if (size(d) <= MAX_EVENT_BYTES) return d;
  // 2. command text
  if (d.tool?.command !== undefined) d.tool.command = cut(d.tool.command, COMMAND_AFTER_TRUNCATION).text;
  if (size(d) <= MAX_EVENT_BYTES) return d;
  // 3. reason
  if (d.decision?.reason != null) d.decision.reason = cut(d.decision.reason, REASON_AFTER_TRUNCATION).text;
  if (size(d) <= MAX_EVENT_BYTES) return d;
  // 4. project directory
  if (d.claude?.project_dir !== undefined) delete d.claude.project_dir;
  if (size(d) <= MAX_EVENT_BYTES) return d;
  // 5. mandatory fields only
  const minimal: Draft = {
    event_id: d.event_id,
    ts: d.ts,
    type: d.type,
    host: d.host,
    user: d.user,
    source: d.source,
  };
  if (d.claude !== undefined) {
    minimal.claude = {
      session_id: d.claude.session_id,
      tool_use_id: null,
      agent_id: null,
      agent_type: null,
      hook_event: d.claude.hook_event,
      permission_mode: null,
    };
  }
  if (d.tool !== undefined) minimal.tool = { name: d.tool.name, truncated: true };
  if (d.decision !== undefined) {
    minimal.decision = { outcome: d.decision.outcome, rule_kind: d.decision.rule_kind, rule_id: null, reason: null, human_session: d.decision.human_session };
  }
  return minimal;
}

export function serializeEvent(event: TollgateEvent): string {
  return JSON.stringify(event);
}
