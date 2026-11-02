import { readFileSync, statSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import { checkNpm, checkPypi } from "./deps.js";
import { applyMasks, maskingSafe, messageMasks } from "./gitMessages.js";
import type { RuleKind } from "./events/types.js";
import { installProblems } from "./installs.js";
import { matches } from "./matchers.js";
import { canonicalPath, foldPath, resolveProjectPath } from "./paths.js";
import type { Policy } from "./policy.js";
import { parseShell, ShellSyntaxError } from "./shell.js";
import { acceptedTmpdir, ALWAYS_PROTECTED_PATHS, checkBashWrites, MAX_COMMAND_BYTES, normalizeAbsolute, type TempHost, utf8Length } from "./writes.js";

export { canonicalPath } from "./paths.js";

export const WRITE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);

export interface ToolEvent {
  tool_name: string;
  tool_input: Record<string, unknown>;
}

export interface Context {
  projectDir: string;
  /** True only in an interactive session of the human owner (TOLLGATE_HUMAN_SESSION=1). */
  humanSession: boolean;
  /** Working directory of the Bash tool (hook input `cwd`); relative write targets are checked against it too. */
  cwd?: string | undefined;
  /** Home directory for `~` and protected home files in Bash write targets (default: none). */
  home?: string | undefined;
  /**
   * Temporary directory (TMPDIR); writes below /tmp and /var/tmp are allowed outside the project, below
   * TMPDIR only if it lies below a fixed temporary root (see acceptedTmpdir in writes.ts).
   */
  tmpdir?: string | undefined;
  /** Absolute path of the active policy file; always protected for agents. */
  policyFile?: string | undefined;
  /**
   * Further absolute paths that are always protected for agents (user configuration, log directories, enterprise
   * policy, managed settings). An entry ending in `/` is a directory and protects everything below it.
   */
  extraProtected?: readonly string[] | undefined;
}

/** Public decision: allowed, or blocked with a reason. */
export type Decision = { allowed: true } | { allowed: false; reason: string };

/** Decision with the structured cause that goes into the decision log (`rule_kind`, `rule_id`). */
export type Detailed = { allowed: true } | { allowed: false; reason: string; kind: RuleKind; ruleId: string | null };

const ALLOW: Detailed = { allowed: true };

function block(reason: string, kind: RuleKind, ruleId: string | null = null): Detailed {
  return { allowed: false, reason, kind, ruleId };
}

/** Strips the structured cause, so that public results keep their shape. */
export function plain(decision: Detailed): Decision {
  return decision.allowed ? decision : { allowed: false, reason: decision.reason };
}

/** Entry of `extra` that covers one of the paths (exactly, or below a directory entry), or undefined. */
function extraHit(paths: readonly string[], extra: readonly string[]): string | undefined {
  for (const entry of extra) {
    const base = entry.endsWith("/") ? entry.slice(0, -1) : entry;
    const bases = [base, safeCanonical(base) ?? base].map(foldPath);
    if (paths.map(foldPath).some((p) => bases.some((b) => p === b || (entry.endsWith("/") && p.startsWith(`${b}/`))))) return entry;
  }
  return undefined;
}

/** Configured protected paths plus git configuration/hooks and `.tollgate/` (always protected for agents). */
export function protectedPatterns(policy: Policy): string[] {
  return [...policy.protectedPaths, ...ALWAYS_PROTECTED_PATHS];
}

function safeCanonical(path: string): string | null {
  try {
    return canonicalPath(path);
  } catch {
    return null;
  }
}

/**
 * Temporary directories (lexical and with symlinks resolved): /tmp, /var/tmp and TMPDIR if it lies,
 * lexically and physically, below a fixed temporary root. Any other TMPDIR is ignored, because it comes
 * from the agent's environment and could otherwise name /etc or the home directory.
 */
export function temporaryDirs(tmpdir: string | undefined, host?: TempHost): string[] {
  const accepted = acceptedTmpdir(tmpdir, host);
  const dirs = ["/tmp", "/var/tmp", ...(tmpdir !== undefined && accepted !== null ? [normalizeAbsolute(tmpdir), accepted] : [])];
  const all = dirs.flatMap((d) => [d, safeCanonical(d) ?? d]);
  return all.filter((d, i) => d !== "/" && all.indexOf(d) === i);
}

function isTemporary(path: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => path.startsWith(`${d}/`));
}

/** A regular file with more than one hard link may be a second name for a protected file. */
function multiplyLinked(path: string): boolean {
  try {
    const st = statSync(path);
    return st.isFile() && st.nlink > 1;
  } catch {
    return false;
  }
}

function protectedMatch(rel: string, policy: Policy): string | undefined {
  const key = foldPath(rel);
  return protectedPatterns(policy).find((p) => {
    const pattern = foldPath(p);
    return p.endsWith("/") ? key.startsWith(pattern.endsWith("/") ? pattern : `${pattern}/`) : key === pattern;
  });
}

/**
 * Project boundary applies to everyone (temporary directories excepted); the human session only lifts
 * the protected-path rules. Both the requested path and its symlink target are checked; files with more
 * than one hard link inside the project are refused for agents (possible alias of a protected file).
 */
export function checkPath(filePath: string, policy: Policy, ctx: Context): Decision {
  return plain(pathDecision(filePath, policy, ctx));
}

function pathDecision(filePath: string, policy: Policy, ctx: Context): Detailed {
  const absolute = isAbsolute(filePath) ? resolve(filePath) : resolve(ctx.projectDir, filePath);
  let resolved;
  let canonical;
  try {
    resolved = resolveProjectPath(filePath, ctx.projectDir);
    canonical = canonicalPath(absolute);
  } catch {
    return block(`${filePath} cannot be resolved safely (symlink loop or filesystem error).`, "path_unresolvable");
  }
  if (resolved.requested === null || resolved.canonical === null) {
    const tmp = temporaryDirs(ctx.tmpdir);
    const roots = [resolve(ctx.projectDir), safeCanonical(resolve(ctx.projectDir)) ?? resolve(ctx.projectDir)];
    const rootOrAncestor = [absolute, canonical].some((p) => roots.some((r) => r === p || r.startsWith(`${p}/`)));
    if (rootOrAncestor || !(resolved.requested === null && resolved.canonical === null && isTemporary(absolute, tmp) && isTemporary(canonical, tmp))) {
      return block(`${filePath} is outside the project directory.`, "outside_project");
    }
  }
  if (ctx.humanSession) return ALLOW;
  for (const rel of [resolved.requested, resolved.canonical]) {
    if (rel === null) continue;
    const hit = protectedMatch(rel, policy);
    if (hit) return block(`${rel} is a protected path (${hit}); changes need human review.`, "protected_path", hit);
  }
  if (ctx.policyFile !== undefined) {
    const policyFile = resolve(ctx.policyFile);
    if (foldPath(absolute) === foldPath(policyFile) || foldPath(canonical) === foldPath(safeCanonical(policyFile) ?? policyFile)) {
      return block(`${filePath} is the active guardrail policy; changes need human review.`, "active_policy");
    }
  }
  const protectedByHost = extraHit([absolute, canonical], ctx.extraProtected ?? []);
  if (protectedByHost !== undefined) {
    return block(`${filePath} is a protected path (${protectedByHost}); changes need human review.`, "protected_path", protectedByHost);
  }
  if (resolved.canonical !== null && multiplyLinked(canonical)) {
    return block(`${filePath} has more than one hard link (possible alias of a protected file); requires a human.`, "hardlink_alias");
  }
  return ALLOW;
}

/** Joins shell line continuations (backslash-newline) so one logical command is matched as one line. */
export function normalizeCommand(command: string): string {
  return command.replace(/\\\r?\n/g, " ");
}

/**
 * Removes shell quoting that does not change the executed word:
 * `$'x'` → `'x'`, quote characters, and backslash escapes (`\-` → `-`).
 * `git push '--force'` and `git push --fo""rce` thus become `git push --force`.
 */
export function unquoteCommand(command: string): string {
  return command
    .replace(/\$'/g, "'")
    .replace(/\\([\s\S])/g, "$1")
    .replace(/['"]/g, "");
}

/**
 * Texts the rules are matched against. Throws ShellSyntaxError if the command cannot be
 * tokenized unambiguously.
 * 1. The raw command (line continuations joined): keeps multi-command rules (pipes, process
 *    substitution, download and run) working on the original text.
 * 2. Its unquoted form (former stopgap, kept as defense in depth).
 * 3. Every simple command, re-joined from its unquoted words with single spaces; includes the
 *    commands inside subshells and command/process substitutions. Line terminators inside words
 *    become spaces so that `.` in rules cannot be stopped by a quoted newline (same in Python).
 * Commit/tag message arguments that git certainly treats as text are replaced by `_` in all
 * variants, so `git commit -m 'docs: explain --force'` no longer matches the force-push rule.
 */
const LINE_TERMINATORS = /[\n\r\u2028\u2029]/g;
// Characters on which JS and Python regex dialects disagree for `.` and `\s` (CR, Unicode line/space
// separators, BOM, \x1c-\x1f, NEL) become plain spaces, and trailing newlines are dropped (Python's `$`
// also matches before a final newline). Mirrored in guard.py so both consumers match identically.
const DIALECT_SPACES = /[\r\x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/g;

function matchText(text: string): string {
  return text.replace(DIALECT_SPACES, " ").replace(/\n+$/, "");
}

export function commandVariants(command: string): string[] {
  const parsed = parseShell(command);
  const masks = maskingSafe(parsed, command) ? parsed.commands.flatMap((c) => messageMasks(c, command)) : [];
  const raw = normalizeCommand(applyMasks(command, masks));
  const replaced = new Map(masks.map((m) => [m.word, m.replacement]));
  const simple = parsed.commands.map((c) =>
    c.words
      .map((w) => replaced.get(w) ?? w.value)
      .join(" ")
      .replace(LINE_TERMINATORS, " "),
  );
  // 4. Commands with a static word containing whitespace (`-c "user.name=A B"`), whitespace inside such words replaced by "_"
  //    so that option rules see one word per argument. Masked message words keep their replacement.
  const spaced = parsed.commands
    .filter((c) => c.words.some((w) => !replaced.has(w) && !w.expands && /[ \t\n\r\v\f]/.test(w.value)))
    .map((c) =>
      c.words
        .map((w) => replaced.get(w) ?? (w.expands ? w.value : w.value.replace(/[ \t\n\r\v\f]/g, "_")))
        .join(" ")
        .replace(LINE_TERMINATORS, " "),
    );
  return [raw, unquoteCommand(raw), ...simple, ...spaced].map(matchText);
}

export function checkCommand(command: string, policy: Policy): Decision {
  return plain(commandDecision(command, policy));
}

function commandDecision(command: string, policy: Policy): Detailed {
  let variants: string[];
  try {
    variants = commandVariants(command);
  } catch (err) {
    const detail = err instanceof ShellSyntaxError ? err.message : "tokenizer error";
    return block(`Command cannot be parsed unambiguously (${detail}); fail closed. Simplify or fix the quoting.`, "parse_error");
  }
  let words: string[][] | undefined;
  for (const [index, rule] of policy.blockedCommands.entries()) {
    let hit: boolean;
    if (rule.match !== undefined) {
      words ??= parseShell(command).commands.map((c) => c.words.map((w) => w.value));
      hit = matches(rule.match, variants, words);
    } else if (rule.pattern !== undefined) {
      const re = new RegExp(rule.pattern);
      hit = variants.some((v) => re.test(v));
    } else {
      hit = false;
    }
    if (hit) return block(rule.reason, "blocked_command", rule.id ?? `blockedCommands[${index}]`);
  }
  return ALLOW;
}

/**
 * Protected-path check for files a Bash command writes (redirections, sed -i, cp/mv, tee, inline code,
 * bash -c ...). Callers skip it in a human session.
 */
export function checkBashCommandWrites(command: string, policy: Policy, ctx: Context): Decision {
  return checkBashWrites(command, protectedPatterns(policy), { root: ctx.projectDir, cwd: ctx.cwd, home: ctx.home, tmpdir: ctx.tmpdir }, extraProtectedFor(ctx));
}

function extraProtectedFor(ctx: Context): string[] {
  return [...(ctx.policyFile === undefined ? [] : [resolve(ctx.policyFile)]), ...(ctx.extraProtected ?? [])];
}

type ManifestKind = "npm" | "pypi" | null;

export function manifestKind(name: string): ManifestKind {
  if (name === "package.json") return "npm";
  if (/^requirements.*\.txt$/.test(name)) return "pypi";
  return null;
}

/** Manifest kind of the requested file or of its symlink target. */
function manifestKindOf(filePath: string, ctx: Context): ManifestKind {
  const requested = manifestKind(basename(filePath));
  if (requested) return requested;
  try {
    const target = resolveProjectPath(filePath, ctx.projectDir).canonical;
    return target ? manifestKind(basename(target)) : null;
  } catch {
    return null;
  }
}

export function checkManifestContent(kind: Exclude<ManifestKind, null>, content: string, policy: Policy): Decision {
  return plain(manifestDecision(kind, content, policy));
}

function manifestDecision(kind: Exclude<ManifestKind, null>, content: string, policy: Policy): Detailed {
  let violations;
  try {
    violations =
      kind === "npm"
        ? checkNpm(content, policy.allowedDependencies.npm)
        : checkPypi(content, policy.allowedDependencies.pypi);
  } catch {
    return block(`${kind} manifest could not be parsed; refusing to write unverifiable dependencies.`, "dependency_unverifiable");
  }
  if (violations.length === 0) return ALLOW;
  const list = violations.map((v) => `${v.ecosystem}:${v.name}`).join(", ");
  return block(`Dependencies not on the allowlist: ${list}.`, "dependency", "allowedDependencies");
}

/** Kept for callers that only know the file name. */
export function checkWrittenDependencies(filePath: string, content: string, policy: Policy): Decision {
  const kind = manifestKind(basename(filePath));
  return kind ? checkManifestContent(kind, content, policy) : ALLOW;
}

interface EditOp {
  old_string?: unknown;
  new_string?: unknown;
  replace_all?: unknown;
}

/** Applies Edit/MultiEdit operations to the current file content; null if they cannot be applied. */
export function applyEdits(content: string, edits: EditOp[]): string | null {
  let result = content;
  for (const edit of edits) {
    if (!edit || typeof edit !== "object") return null;
    if (typeof edit.old_string !== "string" || typeof edit.new_string !== "string") return null;
    if (!result.includes(edit.old_string)) return null;
    result = edit.replace_all === true
      ? result.split(edit.old_string).join(edit.new_string)
      : result.replace(edit.old_string, () => edit.new_string as string);
  }
  return result;
}

/** Content a write tool would produce, or null if not determinable. */
export function resultingContent(tool: string, input: Record<string, unknown>, filePath: string, ctx: Context): string | null {
  if (tool === "Write") return typeof input.content === "string" ? input.content : null;
  const edits = tool === "MultiEdit" ? (input.edits as EditOp[] | undefined) : tool === "Edit" ? [input as EditOp] : undefined;
  if (!Array.isArray(edits)) return null;
  let current: string;
  try {
    current = readFileSync(isAbsolute(filePath) ? filePath : resolve(ctx.projectDir, filePath), "utf8");
  } catch {
    return null;
  }
  return applyEdits(current, edits);
}

export function evaluate(event: ToolEvent, policy: Policy, ctx: Context): Decision {
  return plain(evaluateDetailed(event, policy, ctx));
}

/** Same decision as `evaluate`, with the structured cause for the decision log. */
export function evaluateDetailed(event: ToolEvent, policy: Policy, ctx: Context): Detailed {
  const { tool_name: tool, tool_input: input } = event;

  if (WRITE_TOOLS.has(tool)) {
    const filePath = input.file_path ?? input.notebook_path;
    if (typeof filePath !== "string" || filePath === "") return block(`${tool} without a file path.`, "invalid_input");
    const pathResult = pathDecision(filePath, policy, ctx);
    if (!pathResult.allowed) return pathResult;
    const kind = manifestKindOf(filePath, ctx);
    if (kind === null) return ALLOW;
    const content = resultingContent(tool, input, filePath, ctx);
    if (content === null) {
      return block(`Cannot verify dependencies for ${basename(filePath)}; use Write with the full content.`, "dependency_unverifiable");
    }
    return manifestDecision(kind, content, policy);
  }

  if (tool === "Bash") {
    if (typeof input.command !== "string") return block("Bash call without a command string.", "invalid_input");
    // Bounds the run time of tokenizer, rules and write analysis (fail closed).
    if (utf8Length(input.command) > MAX_COMMAND_BYTES) return block(`Command is longer than ${MAX_COMMAND_BYTES} bytes; split it or use a script file.`, "size_limit");
    const decision = commandDecision(input.command, policy);
    if (!decision.allowed) return decision;
    const installs = installProblems(input.command, policy.allowedDependencies);
    if (installs.length > 0) {
      return block(`Dependencies not on the allowlist: ${installs.join(", ")}.`, "dependency", "allowedDependencies");
    }
    if (ctx.humanSession) return decision;
    const writes = checkBashCommandWrites(input.command, policy, ctx);
    return writes.allowed ? ALLOW : block(writes.reason, "write_target");
  }

  return ALLOW;
}
