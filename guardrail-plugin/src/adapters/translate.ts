// Shared translation for agents whose tool calls are NOT already in Claude form (Grok Build, Cursor).
// Unlike Codex/Copilot (which deliver Claude tool names via a PascalCase `PreToolUse` matcher), these agents use
// their own runtime tool names and input shapes, so each adapter maps its runtime tool name to a Claude tool name
// and then builds the Claude-shaped event the engine (`runHook`) consumes.
//
// Fail-closed posture:
//  - a write-class tool whose file path cannot be resolved, or that names more than one path, is DENIED;
//  - a write to a dependency manifest/lockfile is DENIED (the real content is not available to this adapter, so the
//    dependency allowlist cannot be checked — same decision the engine makes for an unverifiable Bash write, #162);
//  - the shell without a command, or with conflicting command fields, is DENIED;
//  - an UNKNOWN runtime tool whose name looks write-class is DENIED; any other unknown tool is passed through to the
//    engine under its original name (so the enterprise unchecked-tool allowlist, session taint and the decision log
//    all still apply — parity with Claude, which also runs unknown tools through the hook).
import { basename } from "node:path";
import { WRITE_TOOLS, isDependencyFile } from "../evaluate.js";
import { READ_TOOLS } from "../credentials.js";

/** Result of mapping one runtime tool call to the engine. `enforced` = the engine made a definitive allow/deny
 *  decision on a checked tool (so an allow may be reported as allow); false = unchecked/observed (defer instead). */
export type Mapped =
  | { kind: "event"; event: Record<string, unknown>; enforced: boolean }
  | { kind: "deny"; reason: string };

// File-path field names seen across agents; the exact key is not always documented, so the common ones are tried.
const PATH_KEYS = [
  "file_path", "filePath", "path", "file", "target_file", "targetFile",
  "notebook_path", "notebookPath", "directory", "dir", "target_directory",
] as const;
// Shell command field names.
const COMMAND_KEYS = ["command", "cmd", "script"] as const;
// Unmapped runtime tool names that look like they modify files: denied rather than passed through unchecked.
const WRITE_ISH = /write|edit|replace|patch|delete|remove|create|append|move|rename|notebook|mkdir|touch/i;

/** Distinct non-empty string values across the given keys, in key order. */
function distinctStrings(input: Record<string, unknown>, keys: readonly string[]): string[] {
  const out: string[] = [];
  for (const key of keys) {
    const value = input[key];
    if (typeof value === "string" && value !== "" && !out.includes(value)) out.push(value);
  }
  return out;
}

/** First resolvable file path in a tool input, across the known field-name variants. */
export function firstPath(input: Record<string, unknown>): string | undefined {
  return distinctStrings(input, PATH_KEYS)[0];
}

/**
 * Maps a runtime tool call to a Claude-shaped event or a deny verdict.
 * @param claudeName the Claude tool name the runtime tool maps to, or undefined for an unmapped runtime tool.
 * @param originalName the runtime tool name (used for the unchecked passthrough and the write-class guard).
 */
export function buildEvent(
  claudeName: string | undefined,
  originalName: string,
  input: Record<string, unknown>,
  cwd: string,
  sessionId: string | undefined,
): Mapped {
  const base: Record<string, unknown> = { hook_event_name: "PreToolUse", cwd };
  if (sessionId !== undefined) base.session_id = sessionId;

  if (claudeName === undefined) {
    // An unmapped write-class tool must not pass unchecked.
    if (WRITE_ISH.test(originalName)) {
      return { kind: "deny", reason: `TollWire: unrecognized write-class tool '${originalName}' (fail closed).` };
    }
    // Any other unknown tool: run it through the engine under its own name (unchecked/observe/enterprise/taint parity).
    return { kind: "event", event: { ...base, tool_name: originalName, tool_input: input }, enforced: false };
  }

  if (claudeName === "Bash") {
    const commands = distinctStrings(input, COMMAND_KEYS);
    if (commands.length === 0) return { kind: "deny", reason: "TollWire: shell call without a command (fail closed)." };
    if (commands.length > 1) return { kind: "deny", reason: "TollWire: shell call with conflicting command fields (fail closed)." };
    return { kind: "event", event: { ...base, tool_name: "Bash", tool_input: { command: commands[0] } }, enforced: true };
  }

  if (WRITE_TOOLS.has(claudeName)) {
    const paths = distinctStrings(input, PATH_KEYS);
    if (paths.length === 0) return { kind: "deny", reason: "TollWire: a write whose file path could not be determined (fail closed)." };
    if (paths.length > 1) return { kind: "deny", reason: "TollWire: a write naming more than one path (fail closed)." };
    const path = paths[0] as string;
    // A dependency manifest/lockfile cannot be verified from a path-only event (the real content is unavailable here).
    if (isDependencyFile(basename(path))) {
      return { kind: "deny", reason: `TollWire: ${basename(path)} is a dependency manifest; its contents cannot be verified here (fail closed).` };
    }
    return { kind: "event", event: { ...base, tool_name: "Write", tool_input: { file_path: path, content: "" } }, enforced: true };
  }

  if (READ_TOOLS.has(claudeName)) {
    const paths = distinctStrings(input, PATH_KEYS);
    // With a resolvable path, check it directly; otherwise pass the raw input through so the engine's credential-read
    // lock still runs on any field it recognizes (rather than blindly allowing).
    const toolInput = paths.length >= 1 ? { file_path: paths[0] } : input;
    return { kind: "event", event: { ...base, tool_name: claudeName, tool_input: toolInput }, enforced: true };
  }

  // A mapped name that is neither Bash, a write nor a read tool: pass through unchecked (parity).
  return { kind: "event", event: { ...base, tool_name: originalName, tool_input: input }, enforced: false };
}

/** Safe own-property lookup in a plain-object map (avoids `__proto__`/`constructor` resolving to inherited members). */
export function lookup(map: Readonly<Record<string, string>>, name: string): string | undefined {
  return Object.hasOwn(map, name) ? map[name] : undefined;
}
