// OpenAI Codex CLI `PreToolUse` adapter.
//
// The deterministic decision engine (`runHook`) is reused unchanged; this adapter only translates I/O between
// Codex's hook contract and the Claude-shaped input the engine already consumes.
//
// Codex delivers Claude-compatible `PreToolUse` input (`tool_name`, `tool_input`, `cwd`, `hook_event_name`,
// `session_id`, ...). Three things are handled here beyond a pass-through:
//
//  1. apply_patch. Codex reports `tool_name: "apply_patch"` for file edits (even though the matcher aliases
//     "Edit"/"Write" also match it). "apply_patch" is NOT one of the engine's checked write tools, so passing it
//     through unchanged would fail OPEN. The patch envelope is parsed for its target file paths and each is
//     evaluated as a `Write`. The parser is **fail-closed**: a patch with an unrecognized `*** ` directive, an
//     empty path, or no parseable target is denied (an attacker must not get a write past the check by hiding it
//     in a header the adapter does not recognize but Codex does).
//  2. apply_patch through the shell. If the same patch is applied via a `Bash`/exec command (e.g. a heredoc into
//     `apply_patch`), the engine's command analysis would not see it as a write either, so the command is scanned
//     for an apply_patch invocation and its targets are checked the same way before the normal Bash evaluation.
//  3. Deny format. Codex accepts the preferred STDOUT JSON
//     `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`
//     and/or exit code `2` with the reason on stderr; this adapter emits both. Exit `0` with no output lets Codex
//     continue (no explicit allow is emitted, so Codex's own permission flow is never overridden).
//
// Tools the engine does not check (mcp__*, update_plan, spawn_agent, reads, ...) pass through with the same
// treatment as Claude Code. Codex's own docs call tool hooks "a useful guardrail, not a complete enforcement
// boundary" — the same position as TollWire's SECURITY.md.
import { runHook, type HookDeps } from "../hook.js";
import { resolveProjectDir } from "./projectDir.js";
import { claudeToolName } from "./translate.js";

export interface AdapterOutput {
  code: number;
  stdout: string;
  stderr: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function allow(): AdapterOutput {
  return { code: 0, stdout: "", stderr: "" };
}

/** A Codex deny: the preferred stdout JSON plus exit 2 with the reason on stderr (both channels say deny). */
function deny(reason: string): AdapterOutput {
  const stdout = JSON.stringify({
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
  });
  return { code: 2, stdout, stderr: reason };
}

export interface PatchScan {
  paths: string[];
  /** True when the patch contains a `*** ` directive line the parser does not recognize (fail closed). */
  malformed: boolean;
}

// Canonical apply_patch headers (column 0, exact case — the format Codex itself honours). Content and context
// lines are prefixed with `+`, `-` or a space, so a column-0 `*** ` is always a directive.
const FILE_HEADER = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/;
const MOVE_HEADER = /^\*\*\* Move to: (.+)$/;
const STRUCTURAL = /^\*\*\* (?:Begin Patch|End Patch|End of File)$/;
// apply_patch invoked as a program in a shell command (apply_patch / apply-patch / applypatch).
const APPLY_PATCH_TOKEN = /(?:^|[\s;&|("'`])apply[_-]?patch(?:[\s;&|)"'`]|$)/i;

/** Target file paths of an apply_patch envelope, and whether it carried an unrecognized directive (fail closed). */
export function applyPatchTargets(command: string): PatchScan {
  const paths: string[] = [];
  let malformed = false;
  for (const line of command.split(/\r?\n/)) {
    const file = FILE_HEADER.exec(line);
    if (file !== null) {
      const path = file[1];
      if (path !== undefined && path.trim() !== "") paths.push(path.trim());
      else malformed = true;
      continue;
    }
    const move = MOVE_HEADER.exec(line);
    if (move !== null) {
      const path = move[1];
      if (path !== undefined && path.trim() !== "") paths.push(path.trim());
      else malformed = true;
      continue;
    }
    // A column-0 `*** ` directive we do not recognize: an unknown write header could slip past unchecked, so fail closed.
    if (line.startsWith("*** ") && STRUCTURAL.exec(line) === null) malformed = true;
  }
  return { paths, malformed };
}

/**
 * Evaluates every write target of an apply_patch command against the engine.
 * Returns a deny output, or null when every target is allowed. `strict` (the apply_patch tool itself) denies when
 * no target is parseable; the shell path is lenient there, since the token may appear incidentally.
 */
function denyForPatch(
  command: string,
  strict: boolean,
  env: NodeJS.ProcessEnv,
  projectDir: string,
  cwdValue: string,
  sessionId: string | undefined,
  deps: HookDeps,
): AdapterOutput | null {
  const scan = applyPatchTargets(command);
  if (scan.malformed) return deny("TollWire: the apply_patch envelope has an unrecognized directive (fail closed).");
  if (scan.paths.length === 0) return strict ? deny("TollWire: apply_patch target paths could not be parsed (fail closed).") : null;
  for (const path of scan.paths) {
    const event: Record<string, unknown> = {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path, content: "" },
      cwd: cwdValue,
    };
    if (sessionId !== undefined) event.session_id = sessionId;
    const result = runHook(JSON.stringify(event), env, projectDir, deps);
    if (result.code !== 0) return deny(result.message ?? "TollWire guardrail: blocked.");
  }
  return null;
}

/** Pure decision: Codex stdin JSON -> adapter output. Never throws for input problems (fails closed to a deny). */
export function codexDecision(stdin: string, env: NodeJS.ProcessEnv, cwd: string, rawDeps: HookDeps = {}): AdapterOutput {
  // The agent name comes from this adapter, never from the caller or from the input.
  const deps: HookDeps = { ...rawDeps, agent: "codex" };
  let object: Record<string, unknown>;
  try {
    object = asRecord(JSON.parse(stdin));
  } catch {
    return deny("TollWire: hook input is not valid JSON (fail closed).");
  }
  const toolName = typeof object.tool_name === "string" ? object.tool_name : undefined;
  const cwdValue = typeof object.cwd === "string" ? object.cwd : cwd;
  const projectDir = resolveProjectDir(cwdValue, env);
  const sessionId = typeof object.session_id === "string" ? object.session_id : undefined;
  const input = asRecord(object.tool_input);
  const command = typeof input.command === "string" ? input.command : undefined;

  if (toolName === "apply_patch") {
    if (command === undefined) return deny("TollWire: apply_patch without a command (fail closed).");
    return denyForPatch(command, true, env, projectDir, cwdValue, sessionId, deps) ?? allow();
  }

  // Bash / exec: also catch apply_patch invoked through the shell, which the engine would not see as a write.
  if (command !== undefined && APPLY_PATCH_TOKEN.test(command)) {
    const denied = denyForPatch(command, false, env, projectDir, cwdValue, sessionId, deps);
    if (denied !== null) return denied;
  }

  // Everything else: pass through (parity with Claude Code), with the tool name normalized case-insensitively to its
  // Claude name (`WRITE` -> `Write`), so the engine checks it; an unknown write-class name fails closed (shared
  // write-class detection, see translate.ts).
  let claude: Record<string, unknown> = { ...object, hook_event_name: "PreToolUse" };
  if (toolName !== undefined) {
    const checked = claudeToolName(toolName, "all");
    if (checked.kind === "deny") return deny(checked.reason);
    claude = { ...claude, tool_name: checked.name };
  }
  const result = runHook(JSON.stringify(claude), env, projectDir, deps);
  return result.code === 0 ? allow() : deny(result.message ?? "TollWire guardrail: blocked.");
}

/** Executable entry: reads stdin, writes the decision (stdout JSON on deny) and the reason to stderr, returns the exit code. */
export async function runCodexMain(
  readInput: () => Promise<string>,
  env: NodeJS.ProcessEnv,
  cwd: string,
  writeOut: (text: string) => void,
  writeErr: (text: string) => void,
  deps: HookDeps = {},
): Promise<number> {
  let out: AdapterOutput;
  try {
    out = codexDecision(await readInput(), env, cwd, deps);
  } catch {
    out = deny("TollWire: hook failed unexpectedly (fail closed).");
  }
  try {
    if (out.stdout) writeOut(`${out.stdout}\n`);
  } catch {
    // stdout unavailable: the exit code still denies (exit 2).
  }
  try {
    if (out.stderr) writeErr(`${out.stderr}\n`);
  } catch {
    // stderr unavailable: the exit code still denies.
  }
  return out.code;
}
