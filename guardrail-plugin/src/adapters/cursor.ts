// Cursor Agent `preToolUse` adapter.
//
// The deterministic decision engine (`runHook`) is reused unchanged; this adapter maps Cursor's runtime tool names
// and input shape to the Claude-shaped event the engine consumes, then translates the decision back.
//
// Cursor delivers a snake_case envelope (`tool_name`, `tool_input`, `cwd`, `hook_event_name`) and its own tool
// names (`Shell`, `Write`, `Read`, `Grep`, `Delete`, `MCP:<tool>`). They are mapped to Claude tool names; a
// `Delete` is checked as a write to its target (so deleting a protected path is denied). Write-class tools whose
// file path cannot be resolved are denied (fail closed).
//
// Deny contract (official docs, cursor.com/docs/agent/hooks): a permission hook returns a single stdout JSON
// object `{"permission":"deny"|"allow"|"ask"}`; exit code `2` also blocks. Cursor is FAIL-OPEN by default, so the
// hook MUST be registered with `failClosed: true` (see docs/multi-agent.md) and scoped with a `matcher` to the
// checked tools only. On allow the adapter emits an explicit `{"permission":"allow"}` so a `failClosed` hook is not
// itself treated as "no output" (which would block). The matcher scoping keeps this allow limited to tools the
// engine actually evaluated, so the guardrail never auto-approves a tool it did not check.
import { runHook, type HookDeps } from "../hook.js";
import { resolveProjectDir } from "./projectDir.js";
import { buildEvent, lookup } from "./translate.js";

export interface AdapterOutput {
  code: number;
  stdout: string;
  stderr: string;
}

// Cursor runtime tool name -> Claude tool name. `Delete` maps to a write check on its target path.
const CURSOR_MAP: Readonly<Record<string, string>> = {
  Shell: "Bash", shell: "Bash", Bash: "Bash",
  Write: "Write", Edit: "Edit", MultiEdit: "MultiEdit", NotebookEdit: "NotebookEdit", Delete: "Write",
  Read: "Read", NotebookRead: "NotebookRead", Grep: "Grep", Glob: "Glob", LS: "LS",
};

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function allow(): AdapterOutput {
  return { code: 0, stdout: JSON.stringify({ permission: "allow" }), stderr: "" };
}

/** Defer to Cursor's own permission flow (the guardrail did not evaluate this call, so it must not auto-approve). */
function ask(): AdapterOutput {
  return { code: 0, stdout: JSON.stringify({ permission: "ask" }), stderr: "" };
}

/** A Cursor deny: the single stdout permission object plus exit 2. */
function deny(reason: string): AdapterOutput {
  return { code: 2, stdout: JSON.stringify({ permission: "deny", agent_message: reason, user_message: reason }), stderr: "" };
}

/** Pure decision: Cursor stdin JSON -> adapter output. Never throws for input problems (fails closed to a deny). */
export function cursorDecision(stdin: string, env: NodeJS.ProcessEnv, cwd: string, deps: HookDeps = {}): AdapterOutput {
  let object: Record<string, unknown>;
  try {
    object = asRecord(JSON.parse(stdin));
  } catch {
    return deny("TollWire: hook input is not valid JSON (fail closed).");
  }
  const toolName = typeof object.tool_name === "string" ? object.tool_name : typeof object.toolName === "string" ? object.toolName : undefined;
  if (toolName === undefined) return deny("TollWire: hook input has no tool name (fail closed).");
  const input = asRecord(object.tool_input ?? object.toolInput);
  const cwdValue = typeof object.cwd === "string" ? object.cwd : cwd;
  const projectDir = resolveProjectDir(cwdValue, env);
  // Use the conversation id (stable across a session) so session taint and admin locks accumulate; the per-call
  // tool_use_id would reset them every call.
  const sessionId = typeof object.conversation_id === "string" ? object.conversation_id : undefined;

  const mapped = buildEvent(lookup(CURSOR_MAP, toolName), toolName, input, cwdValue, sessionId);
  if (mapped.kind === "deny") return deny(mapped.reason);
  const result = runHook(JSON.stringify(mapped.event), env, projectDir, deps);
  if (result.code !== 0) return deny(result.message ?? "TollWire guardrail: blocked.");
  // The engine allowed it: report an explicit allow only for a checked tool it actually evaluated; for an unchecked
  // passthrough, defer to Cursor's own permission flow instead of auto-approving (never approve what we did not check).
  return mapped.enforced ? allow() : ask();
}

/** Executable entry: reads stdin, writes the one permission object, returns the exit code. Fails closed on any throw. */
export async function runCursorMain(
  readInput: () => Promise<string>,
  env: NodeJS.ProcessEnv,
  cwd: string,
  writeOut: (text: string) => void,
  deps: HookDeps = {},
): Promise<number> {
  let out: AdapterOutput;
  try {
    out = cursorDecision(await readInput(), env, cwd, deps);
  } catch {
    out = deny("TollWire: hook failed unexpectedly (fail closed).");
  }
  try {
    if (out.stdout) writeOut(`${out.stdout}\n`);
  } catch {
    // stdout unavailable: exit code 2 still denies.
  }
  return out.code;
}
