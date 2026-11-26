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
//  - an UNKNOWN runtime tool whose name looks write-class (`isWriteClassToolName`, shared by all adapters) is DENIED; any other unknown tool is passed through to the
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
// Write-class detection of tool names: the single source used by every adapter (no adapter keeps its own list).
// A tool name is split into words at snake_case, kebab-case, camelCase and any other non-letter boundary and lowercased;
// it is write-class when one word is a keyword below. Keywords of four or more letters also match at the start or end of a
// word, so compounds without separators ("applypatch", "multiedit", "writefile") are caught; the short ones (rm, mv, cp,
// set, put) only match a whole word, so read names such as "settings" or "setup" are not hit. This is a name heuristic:
// a write tool with a completely neutral name is not recognized (see docs/multi-agent.md, "Unknown tools").
const WRITE_KEYWORDS: readonly string[] = [
  "write", "edit", "create", "patch", "replace", "insert", "delete", "remove", "rename", "move", "mv", "copy", "cp",
  "append", "save", "put", "store", "overwrite", "truncate", "upload", "dump", "export", "sync", "output", "apply",
  "modify", "update", "set", "mkdir", "rm", "touch", "chmod", "chown", "link", "unlink", "notebook",
];
const WRITE_WORDS: ReadonlySet<string> = new Set(WRITE_KEYWORDS);
const AFFIX_KEYWORDS: readonly string[] = WRITE_KEYWORDS.filter((k) => k.length >= 4);

/** Lowercased words of a tool name (split at snake/kebab/camel/other non-letter boundaries). */
export function toolNameWords(name: string): string[] {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z]+/)
    .filter((w) => w !== "");
}

/** True when a tool name looks like it modifies files (fail-closed heuristic for tools the adapter cannot map). */
export function isWriteClassToolName(name: string): boolean {
  for (const word of toolNameWords(name)) {
    if (WRITE_WORDS.has(word)) return true;
    if (AFFIX_KEYWORDS.some((k) => word.startsWith(k) || word.endsWith(k))) return true;
  }
  return false;
}

/** Deny reason for an unrecognized write-class tool. */
export function unrecognizedWrite(name: string): string {
  return `TollWire: unrecognized write-class tool '${name}' (fail closed).`;
}

/** Tool names the engine evaluates (Claude names). */
const CHECKED_NAMES: readonly string[] = ["Bash", ...WRITE_TOOLS];
// Claude-native tools without file access whose names contain a write keyword; they keep passing through to the engine
// (which applies the unchecked-tool policy), as with Claude Code itself. `update_plan` is the Codex plan tool.
const NON_FILE_TOOLS: ReadonlySet<string> = new Set(["TodoWrite", "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "update_plan"]);

export type NameCheck = { kind: "name"; name: string } | { kind: "deny"; reason: string };

/**
 * Tool-name check for agents that deliver Claude-shaped input (Codex, Copilot with a PascalCase matcher).
 * - an exact Claude name is kept;
 * - a case variant of a Claude name is normalized to it (`WRITE` -> `Write`, `bash` -> `Bash`), so the engine checks it
 *   instead of treating it as an unknown tool; `normalize` = "shell" limits this to the shell, "all" covers every checked
 *   and read tool;
 * - any other write-class name is denied (fail closed), except Claude-native non-file tools and MCP tools (`mcp__*`),
 *   which go to the engine's unchecked-tool policy as with Claude Code;
 * - every other name is kept.
 */
export function claudeToolName(name: string, normalize: "shell" | "all"): NameCheck {
  if (CHECKED_NAMES.includes(name) || READ_TOOLS.has(name)) return { kind: "name", name };
  const known = normalize === "all" ? [...CHECKED_NAMES, ...READ_TOOLS] : ["Bash"];
  const folded = name.toLowerCase();
  const canonical = known.find((k) => k.toLowerCase() === folded);
  if (canonical !== undefined) return { kind: "name", name: canonical };
  if (NON_FILE_TOOLS.has(name) || name.startsWith("mcp__")) return { kind: "name", name };
  if (isWriteClassToolName(name)) return { kind: "deny", reason: unrecognizedWrite(name) };
  return { kind: "name", name };
}

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
    if (isWriteClassToolName(originalName)) return { kind: "deny", reason: unrecognizedWrite(originalName) };
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
