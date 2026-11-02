// Validation of the hook's stdin fields before they enter the log.
import { INVALID, type ClaudeFields } from "./types.js";

const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,256}$/;
const HOOK_EVENT = /^[A-Za-z]{1,64}$/;
const PERMISSION_MODE = /^[A-Za-z0-9_-]{1,32}$/;
export const MAX_PATH_BYTES = 4096;
export const MAX_AGENT_FIELD = 128;

export interface Validated {
  claude: ClaudeFields;
  toolName: string;
  invalid: string[];
}

function optionalString(raw: unknown, ok: (s: string) => boolean, name: string, invalid: string[]): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw === "string" && ok(raw)) return raw;
  invalid.push(name);
  return INVALID;
}

/** A path value for the log: at most 4096 bytes, else `<invalid>`. */
export function validPath(value: string): string | null {
  return Buffer.byteLength(value, "utf8") <= MAX_PATH_BYTES ? value : null;
}

export function validateInput(raw: Record<string, unknown>, toolNameRaw: unknown): Validated {
  const invalid: string[] = [];
  let sessionId: string;
  if (typeof raw.session_id === "string" && ID.test(raw.session_id)) sessionId = raw.session_id;
  else {
    sessionId = INVALID;
    invalid.push("session_id");
  }
  let toolName: string;
  if (typeof toolNameRaw === "string" && TOOL_NAME.test(toolNameRaw)) toolName = toolNameRaw;
  else {
    toolName = INVALID;
    invalid.push("tool_name");
  }
  const hookEvent =
    raw.hook_event_name === undefined
      ? "PreToolUse"
      : (optionalString(raw.hook_event_name, (s) => HOOK_EVENT.test(s), "hook_event_name", invalid) ?? "PreToolUse");
  const claude: ClaudeFields = {
    session_id: sessionId,
    tool_use_id: optionalString(raw.tool_use_id, (s) => ID.test(s), "tool_use_id", invalid),
    agent_id: optionalString(raw.agent_id, (s) => s.length <= MAX_AGENT_FIELD, "agent_id", invalid),
    agent_type: optionalString(raw.agent_type, (s) => s.length <= MAX_AGENT_FIELD, "agent_type", invalid),
    hook_event: hookEvent,
    permission_mode: optionalString(raw.permission_mode, (s) => PERMISSION_MODE.test(s), "permission_mode", invalid),
  };
  return { claude, toolName, invalid };
}
