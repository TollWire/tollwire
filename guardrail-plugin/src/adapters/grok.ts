// xAI Grok Build (Grok CLI) `PreToolUse` adapter.
//
// The deterministic decision engine (`runHook`) is reused unchanged; this adapter maps Grok's runtime tool names
// and input shape to the Claude-shaped event the engine consumes, then translates the decision back.
//
// Grok delivers a camelCase envelope (`toolName`, `toolInput`, `cwd`, `sessionId`) and its own runtime tool names
// (`run_terminal_command`, `search_replace`, `read_file`, `grep`, ...). They are mapped to Claude tool names via
// the documented alias table. Write-class tools whose file path cannot be resolved are denied (fail closed).
//
// Deny contract (official repo docs, 10-hooks.md): a `deny` decision in stdout is honored regardless of exit code,
// and exit code `2` is an explicit deny; this adapter emits both. IMPORTANT: Grok is FAIL-OPEN on crashes,
// timeouts and malformed output — ONLY an explicit `deny` blocks — so the adapter emits an explicit deny on any
// catchable error, and must stay fast. On allow it exits 0 with no output (Grok continues).
import { runHook, type HookDeps } from "../hook.js";
import { resolveProjectDir } from "./projectDir.js";
import { buildEvent, lookup } from "./translate.js";

export interface AdapterOutput {
  code: number;
  stdout: string;
  stderr: string;
}

// Grok runtime tool name -> Claude tool name (from Grok's documented alias table). Claude names are also accepted,
// because Grok can load a shared `~/.claude/settings.json` and deliver Claude-named matchers.
const GROK_MAP: Readonly<Record<string, string>> = {
  run_terminal_command: "Bash", bash: "Bash", Bash: "Bash",
  search_replace: "Write", str_replace: "Write", write: "Write", Write: "Write", Edit: "Edit", MultiEdit: "MultiEdit", NotebookEdit: "NotebookEdit",
  read_file: "Read", Read: "Read", NotebookRead: "NotebookRead",
  grep: "Grep", Grep: "Grep",
  list_dir: "LS", LS: "LS", glob: "Glob", Glob: "Glob",
};

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function allow(): AdapterOutput {
  return { code: 0, stdout: "", stderr: "" };
}

/** A Grok deny: an explicit `decision: "deny"` on stdout (honored regardless of exit) plus exit 2 and a stderr reason. */
function deny(reason: string): AdapterOutput {
  return { code: 2, stdout: JSON.stringify({ decision: "deny", reason }), stderr: reason };
}

/** Pure decision: Grok stdin JSON -> adapter output. Never throws for input problems (fails closed to a deny). */
export function grokDecision(stdin: string, env: NodeJS.ProcessEnv, cwd: string, rawDeps: HookDeps = {}): AdapterOutput {
  // The agent name comes from this adapter, never from the caller or from the input.
  const deps: HookDeps = { ...rawDeps, agent: "grok" };
  let object: Record<string, unknown>;
  try {
    object = asRecord(JSON.parse(stdin));
  } catch {
    return deny("TollWire: hook input is not valid JSON (fail closed).");
  }
  const toolName = typeof object.toolName === "string" ? object.toolName : typeof object.tool_name === "string" ? object.tool_name : undefined;
  if (toolName === undefined) return deny("TollWire: hook input has no tool name (fail closed).");
  const input = asRecord(object.toolInput ?? object.tool_input);
  const cwdValue = typeof object.cwd === "string" ? object.cwd : cwd;
  const projectDir = resolveProjectDir(cwdValue, env);
  const sessionId = typeof object.sessionId === "string" ? object.sessionId : typeof object.session_id === "string" ? object.session_id : undefined;

  // Grok's hook IS its permission system, so an allowed call simply exits 0 with no output (Grok continues).
  const mapped = buildEvent(lookup(GROK_MAP, toolName), toolName, input, cwdValue, sessionId);
  if (mapped.kind === "deny") return deny(mapped.reason);
  const result = runHook(JSON.stringify(mapped.event), env, projectDir, deps);
  return result.code === 0 ? allow() : deny(result.message ?? "TollWire guardrail: blocked.");
}

/** Executable entry: reads stdin, writes the decision, returns the exit code. Fails closed on any throw (emits an explicit deny). */
export async function runGrokMain(
  readInput: () => Promise<string>,
  env: NodeJS.ProcessEnv,
  cwd: string,
  writeOut: (text: string) => void,
  writeErr: (text: string) => void,
  deps: HookDeps = {},
): Promise<number> {
  let out: AdapterOutput;
  try {
    out = grokDecision(await readInput(), env, cwd, deps);
  } catch {
    out = deny("TollWire: hook failed unexpectedly (fail closed).");
  }
  try {
    if (out.stdout) writeOut(`${out.stdout}\n`);
  } catch {
    // stdout unavailable: Grok is fail-open on a missing decision; the exit code 2 is the remaining deny signal.
  }
  try {
    if (out.stderr) writeErr(`${out.stderr}\n`);
  } catch {
    // stderr unavailable.
  }
  return out.code;
}
