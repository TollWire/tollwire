// GitHub Copilot CLI `preToolUse` adapter.
//
// The deterministic decision engine (`runHook`) is reused unchanged; this adapter only translates I/O between
// Copilot's hook contract and the Claude-shaped input the engine already consumes.
//
// Registration requirement: register this hook with a PascalCase `PreToolUse` matcher so Copilot delivers
// Claude-format input (`tool_name` is the Claude name, e.g. "Bash"/"Write", and `tool_input` is an object). With
// the camelCase `preToolUse` form Copilot sends `toolName` + `toolArgs` (a JSON string); the public contract does
// not publish the file-tool argument field names, so the camelCase path reliably covers the shell only and fails
// closed on anything else. If a raw (unmapped) Copilot write-tool name reaches the PascalCase path, the engine
// could not check it, so the adapter fails closed rather than let a write through unchecked.
//
// Copilot deny contract (official reference): exit code `2` = deny; the reason is a single STDOUT JSON object
// `{"permissionDecision":"deny","permissionDecisionReason":"..."}`; exactly one JSON object may be written to
// stdout. A hook timeout is FAIL OPEN (the tool proceeds), so the adapter must stay fast and never hang; any other
// non-zero exit is treated by Copilot as a deny ("hook errored"), which preserves our fail-closed posture. On
// allow, the adapter writes **nothing** and exits 0, so Copilot's own permission flow proceeds unchanged — the
// guardrail denies violations, it never auto-approves a call Copilot would otherwise prompt for.
import { runHook, type HookDeps } from "../hook.js";
import { WRITE_TOOLS } from "../evaluate.js";
import { resolveProjectDir } from "./projectDir.js";

export interface AdapterOutput {
  code: number;
  stdout: string;
  stderr: string;
}

// Tools the engine evaluates (Claude names). A write under any other name is treated by the engine as ALLOW.
const CHECKED: ReadonlySet<string> = new Set(["Bash", ...WRITE_TOOLS]);

// Runtime -> Claude tool-name map for the camelCase fallback. PascalCase registration is required for
// write-blocking; the fallback reliably covers the shell only.
const CAMEL_TOOL_MAP: Readonly<Record<string, string>> = { bash: "Bash", shell: "Bash" };

// Copilot runtime write-tool names (lowercase). If one reaches us as a raw `tool_name` that the engine does not
// check, a write would pass unchecked — fail closed instead.
const RAW_WRITE_TOOLS: ReadonlySet<string> = new Set([
  "edit", "create", "write", "multiedit", "notebookedit", "str_replace", "str_replace_editor", "apply_patch",
]);

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** A Copilot deny: exit 2 (which denies regardless) plus the reason as the single stdout JSON object. */
function deny(reason: string): AdapterOutput {
  return { code: 2, stdout: JSON.stringify({ permissionDecision: "deny", permissionDecisionReason: reason }), stderr: "" };
}

/** Normalizes a Copilot `preToolUse` payload to the Claude-shaped object `runHook` consumes; null = cannot map (fail closed). */
function toClaude(object: Record<string, unknown>): Record<string, unknown> | null {
  // PascalCase registration: already Claude-shaped (tool_name + tool_input).
  if (typeof object.tool_name === "string") {
    const name = object.tool_name;
    // A raw (unmapped) write-tool name the engine would not check: fail closed rather than pass a write through.
    if (!CHECKED.has(name) && RAW_WRITE_TOOLS.has(name.toLowerCase())) return null;
    return { ...object, hook_event_name: "PreToolUse" };
  }
  // camelCase fallback: toolName + toolArgs (a JSON string per the official contract).
  if (typeof object.toolName === "string") {
    const mapped = CAMEL_TOOL_MAP[object.toolName.toLowerCase()];
    if (mapped === undefined) return null; // unknown tool, no reliable argument mapping -> fail closed
    let input: unknown = {};
    if (typeof object.toolArgs === "string") {
      try {
        input = JSON.parse(object.toolArgs);
      } catch {
        return null;
      }
    } else if (object.toolArgs !== undefined) {
      input = object.toolArgs;
    }
    const claude: Record<string, unknown> = { hook_event_name: "PreToolUse", tool_name: mapped, tool_input: asRecord(input) };
    if (typeof object.cwd === "string") claude.cwd = object.cwd;
    if (typeof object.sessionId === "string") claude.session_id = object.sessionId;
    return claude;
  }
  return null;
}

/** Pure decision: Copilot stdin JSON -> adapter output. Never throws for input problems (fails closed to a deny). */
export function copilotDecision(stdin: string, env: NodeJS.ProcessEnv, cwd: string, deps: HookDeps = {}): AdapterOutput {
  let object: Record<string, unknown>;
  try {
    object = asRecord(JSON.parse(stdin));
  } catch {
    return deny("TollWire: hook input is not valid JSON (fail closed).");
  }
  const claude = toClaude(object);
  if (claude === null) {
    return deny("TollWire: the tool call could not be mapped to a checked tool (fail closed). Register the hook with a PascalCase `PreToolUse` matcher.");
  }
  const cwdValue = typeof claude.cwd === "string" ? claude.cwd : cwd;
  const projectDir = resolveProjectDir(cwdValue, env);
  const result = runHook(JSON.stringify(claude), env, projectDir, deps);
  // Allow: no output, exit 0 -> Copilot's own permission flow proceeds (the guardrail never auto-approves).
  if (result.code === 0) return { code: 0, stdout: "", stderr: "" };
  return deny(result.message ?? "TollWire guardrail: blocked.");
}

/** Executable entry: reads stdin, writes the one decision object to stdout on a deny, returns the exit code. Fails closed on any throw. */
export async function runCopilotMain(
  readInput: () => Promise<string>,
  env: NodeJS.ProcessEnv,
  cwd: string,
  writeOut: (text: string) => void,
  deps: HookDeps = {},
): Promise<number> {
  let out: AdapterOutput;
  try {
    out = copilotDecision(await readInput(), env, cwd, deps);
  } catch {
    out = deny("TollWire: hook failed unexpectedly (fail closed).");
  }
  try {
    if (out.stdout) writeOut(`${out.stdout}\n`);
  } catch {
    // stdout unavailable: the exit code still denies (exit 2).
  }
  return out.code;
}
