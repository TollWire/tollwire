// Read lock for credential stores in the home directory (audit F-01, #160). The command rule in the policy matches text only
// (`~/.ssh`, `$HOME/.ssh`, `/home/<name>/.ssh` ...). This module resolves paths against every known home directory instead:
// lexically and with symlinks resolved, also through a hard link, for the read tools (Read, NotebookRead, LS, Grep, Glob) and for
// every word of a Bash command. The policy rule stays as an additional layer. Fail closed: a spelling that names a store but
// cannot be resolved (unknown home directory, variables, `~user`, symlink loop) is blocked.
import { lstatSync, readdirSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { maskingSafe, messageMasks } from "./gitMessages.js";
import { canonicalPath, expandHomePrefix, foldGlob, foldPath } from "./paths.js";
import { parseShell, type ShellWord } from "./shell.js";
import { globMayMatch } from "./writes.js";

/** Credential stores relative to a home directory; an entry ending in `/` is a directory and covers everything below it. */
export const CREDENTIAL_STORES: readonly string[] = [
  ".ssh/", ".aws/", ".gnupg/", ".kube/", ".azure/", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".docker/config.json",
  ".config/gh/", ".config/gcloud/", "Library/Keychains/",
];

/** Tools that read files and are checked against the credential stores (they are not otherwise evaluated by the hook). */
export const READ_TOOLS: ReadonlySet<string> = new Set(["Read", "NotebookRead", "LS", "Grep", "Glob"]);

export interface CredentialContext {
  projectDir: string;
  /** Working directory of the tool call, if known (absolute). */
  cwd?: string | undefined;
  /** Home directory for `~` and `$HOME`. */
  home?: string | undefined;
  /** Further home directories whose stores are guarded (see knownHomes in guardContext.ts). */
  homes?: readonly string[] | undefined;
}

export interface CredentialBlock {
  allowed: false;
  reason: string;
  kind: "credential_read" | "invalid_input";
  ruleId: string | null;
}

function credentialBlock(reason: string, ruleId: string | null): CredentialBlock {
  return { allowed: false, reason, kind: "credential_read", ruleId };
}

function safeCanonical(path: string): string | null {
  try {
    return canonicalPath(path);
  } catch {
    return null;
  }
}

/** Known home directories, absolute, without a root directory, each as written and with symlinks resolved. */
export function credentialHomes(ctx: Pick<CredentialContext, "home" | "homes">): string[] {
  const all = [ctx.home, ...(ctx.homes ?? [])].filter((h): h is string => typeof h === "string" && h !== "" && isAbsolute(h)).map((h) => resolve(h));
  const usable = all.filter((h) => h !== "/" && !/^[A-Za-z]:\\?$/.test(h));
  return [...new Set(usable.flatMap((h) => [h, safeCanonical(h) ?? h]))];
}

/** Store entry that contains the path (equal to it or below a directory entry), or undefined. */
function storeOf(path: string, homes: readonly string[]): string | undefined {
  const target = foldPath(path);
  for (const home of homes) {
    const root = foldPath(home);
    if (!target.startsWith(`${root}/`)) continue;
    const rel = target.slice(root.length + 1);
    const hit = CREDENTIAL_STORES.find((entry) => {
      const key = foldPath(entry.endsWith("/") ? entry.slice(0, -1) : entry);
      return rel === key || rel.startsWith(`${key}/`);
    });
    if (hit !== undefined) return hit;
  }
  return undefined;
}

/**
 * Conventional home directories (`/home/<name>`, `/Users/<name>`, `/root`, `/var/root`) of other accounts: their stores are locked
 * as well, the same places the command rule of the policy names by text.
 */
function conventionalHome(path: string): string | undefined {
  const m = /^(\/(?:home|users)\/[^/]+|\/root|\/var\/root)\//.exec(foldPath(path));
  return m === null ? undefined : m[1];
}

/** True if the path is a home directory or one of its ancestors (a recursive read from there reaches the stores). */
function homeOrAbove(path: string, homes: readonly string[]): boolean {
  const target = foldPath(path);
  return target === "/" || homes.some((h) => {
    const root = foldPath(h);
    return root === target || root.startsWith(`${target}/`);
  });
}

/** Store names in a path text whose base is unknown (variables, `~user`, unknown home or working directory). */
const STORE_TEXT = /(?:^|\/)(?:\.(?:ssh|aws|gnupg|kube|azure)(?:\/|$)|\.(?:netrc|npmrc|pypirc|git-credentials)$|\.docker\/config\.json$|\.config\/(?:gh|gcloud)(?:\/|$))/;

export function namesCredentialStore(text: string): boolean {
  return STORE_TEXT.test(foldPath(text.replace(/\\/g, "/")));
}

const MAX_ALIAS_SCAN = 20000;
const MAX_ALIAS_DEPTH = 8;

/**
 * Inodes of the files in the stores, built once per decision and only when a file with more than one hard link is looked at.
 * The walk is bounded; a store with more entries makes every multiply linked file a hit (fail closed).
 */
class AliasIndex {
  private files: Map<string, string> | null = null;
  private overflow = false;

  constructor(private readonly homes: readonly string[]) {}

  private build(): Map<string, string> {
    const files = new Map<string, string>();
    let seen = 0;
    const walk = (p: string, depth: number, entry: string): void => {
      seen += 1;
      if (seen > MAX_ALIAS_SCAN) {
        this.overflow = true;
        return;
      }
      let ls;
      try {
        ls = lstatSync(p);
      } catch {
        return;
      }
      if (ls.isFile()) {
        files.set(`${ls.dev}:${ls.ino}`, entry);
        return;
      }
      if (!ls.isDirectory() || depth > MAX_ALIAS_DEPTH) return;
      let names: string[];
      try {
        names = readdirSync(p);
      } catch {
        return;
      }
      for (const n of names) {
        if (this.overflow) return;
        walk(join(p, n), depth + 1, entry);
      }
    };
    for (const home of this.homes) {
      for (const entry of CREDENTIAL_STORES) walk(join(home, entry.endsWith("/") ? entry.slice(0, -1) : entry), 0, entry);
    }
    return files;
  }

  /** Store entry of which the file is a hard link (same device and inode), or undefined. */
  aliasOf(path: string): string | undefined {
    let st;
    try {
      st = statSync(path);
    } catch {
      return undefined;
    }
    if (!st.isFile() || st.nlink <= 1) return undefined;
    this.files ??= this.build();
    if (this.overflow) return CREDENTIAL_STORES[0];
    return this.files.get(`${st.dev}:${st.ino}`);
  }
}

type Mode = "file" | "tree";

/**
 * Decision for one absolute path: a store (as written or with symlinks resolved), a hard link to a store file, or (mode `tree`)
 * a home directory or an ancestor of one. `strict`: a path that cannot be resolved is blocked; otherwise only if it names a store.
 */
function absoluteDecision(path: string, homes: readonly string[], aliases: AliasIndex, mode: Mode, strict: boolean, shown: string): CredentialBlock | null {
  const lexical = resolve(path);
  const canonical = safeCanonical(lexical);
  if (canonical === null) {
    if (strict || namesCredentialStore(lexical) || storeOf(lexical, homes) !== undefined) {
      return credentialBlock(`${shown} cannot be resolved safely (symlink loop or filesystem error); fail closed for the credential store read lock.`, null);
    }
    return null;
  }
  if (homes.length === 0 && (namesCredentialStore(lexical) || namesCredentialStore(canonical))) {
    return credentialBlock(`${shown} names a credential store and no home directory is known; fail closed.`, null);
  }
  for (const p of [lexical, canonical]) {
    const other = conventionalHome(p);
    const entry = storeOf(p, other === undefined ? homes : [...homes, other]);
    if (entry !== undefined) return credentialBlock(`${shown} is in the credential store ~/${entry}; reading it is not allowed (audit F-01).`, entry);
  }
  if (mode === "tree" && (homeOrAbove(lexical, homes) || homeOrAbove(canonical, homes))) {
    return credentialBlock(`${shown} is a home directory or above it; a recursive read reaches the credential stores (audit F-01).`, null);
  }
  const alias = aliases.aliasOf(canonical);
  if (alias !== undefined) return credentialBlock(`${shown} is a hard link to a file in the credential store ~/${alias} (audit F-01).`, alias);
  return null;
}

/** Bases for relative paths: working directory and project directory. */
function basesOf(ctx: CredentialContext): string[] {
  return [...new Set([ctx.cwd, ctx.projectDir].filter((b): b is string => typeof b === "string" && isAbsolute(b)).map((b) => resolve(b)))];
}

/** Decision for one path argument of a tool (`~`, `$HOME`, relative against the bases). Unknown home with `~`: fail closed. */
export function credentialPathDecision(path: string, ctx: CredentialContext, mode: Mode = "file"): CredentialBlock | null {
  const homes = credentialHomes(ctx);
  const expanded = expandHomePrefix(path, ctx.home);
  if (expanded === null) return credentialBlock(`${path} names the home directory, which is unknown; fail closed.`, null);
  const targets = isAbsolute(expanded) ? [expanded] : basesOf(ctx).map((b) => resolve(b, expanded));
  if (targets.length === 0) return credentialBlock(`${path} is relative and the working directory is unknown; fail closed.`, null);
  const aliases = new AliasIndex(homes);
  for (const target of targets) {
    const d = absoluteDecision(target, homes, aliases, mode, true, path);
    if (d !== null) return d;
  }
  return null;
}

/** The glob with its directory prefix (the segments before the first wildcard) resolved through symlinks, if that differs. */
function globVariants(glob: string): string[] {
  const at = glob.search(/[*?[{]/);
  const cut = at < 0 ? glob.length : glob.lastIndexOf("/", at);
  if (cut <= 0) return [glob];
  const prefix = safeCanonical(glob.slice(0, cut));
  return prefix === null || prefix === glob.slice(0, cut) ? [glob] : [glob, `${prefix}${glob.slice(cut)}`];
}

/**
 * Decision for an absolute glob: blocked if it may match a store, a path below a directory store, or an ancestor of a store.
 * Without `dotglob`, `*` and `**` do not match a leading dot (shell default), so a store must be named by a segment that starts
 * with a dot (`.ssh`, `.s*`, `.*`); a brace expression counts as "anything below" (conservative).
 */
function globDecision(glob: string, homes: readonly string[], dotglob: boolean, shown: string): CredentialBlock | null {
  for (const variant of globVariants(glob)) {
    const g = foldGlob(dotglob ? variant : variant.replace(/(^|\/)\*\*(?=\/|$)/g, "$1*"));
    for (const home of homes) {
      for (const entry of CREDENTIAL_STORES) {
        const dir = entry.endsWith("/");
        if (globMayMatch(g, foldPath(`${home}/${dir ? entry.slice(0, -1) : entry}`), dir, dotglob)) {
          return credentialBlock(`${shown} may match files in the credential store ~/${entry} (audit F-01).`, entry);
        }
      }
    }
  }
  return null;
}

/** The field as a non-empty string, undefined if absent (nothing to read, the tool itself rejects the call), null if invalid. */
function stringField(input: Record<string, unknown>, key: string): string | null | undefined {
  const value = input[key];
  if (value === undefined) return undefined;
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * Decision for a read tool call (Read, NotebookRead, LS, Grep, Glob), or null if allowed. Invalid path fields fail closed.
 * Grep searches recursively, so a home directory or an ancestor of one is blocked as well (also its default, the working
 * directory). Glob lists names: blocked if its directory is in a store or its pattern may match files in one.
 */
export function readToolDecision(tool: string, input: Record<string, unknown>, ctx: CredentialContext): CredentialBlock | null {
  const invalid = (what: string): CredentialBlock => ({ allowed: false, reason: `${tool} with an invalid ${what}; fail closed.`, kind: "invalid_input", ruleId: null });
  if (tool === "Read" || tool === "NotebookRead") {
    const path = stringField(input, tool === "Read" ? "file_path" : "notebook_path");
    if (path === undefined) return null;
    if (path === null) return invalid("file path");
    return credentialPathDecision(path, ctx);
  }
  if (tool === "LS") {
    const path = stringField(input, "path");
    if (path === undefined) return null;
    if (path === null) return invalid("path");
    return credentialPathDecision(path, ctx);
  }
  if (tool === "Grep") {
    const path = stringField(input, "path");
    if (path === null) return invalid("path");
    if (path === undefined) {
      for (const base of basesOf(ctx).slice(0, 1)) {
        const homes = credentialHomes(ctx);
        const d = absoluteDecision(base, homes, new AliasIndex(homes), "tree", true, base);
        if (d !== null) return d;
      }
      return null;
    }
    return credentialPathDecision(path, ctx, "tree");
  }
  if (tool === "Glob") {
    const pattern = stringField(input, "pattern");
    const path = stringField(input, "path");
    if (pattern === null) return invalid("pattern");
    if (path === null) return invalid("path");
    if (pattern === undefined) return path === undefined ? null : credentialPathDecision(path, ctx);
    if (path !== undefined) {
      const d = credentialPathDecision(path, ctx);
      if (d !== null) return d;
    }
    const expanded = expandHomePrefix(pattern, ctx.home);
    const dir = path === undefined ? basesOf(ctx)[0] : expandHomePrefix(path, ctx.home);
    if (expanded === null || dir === null) return credentialBlock(`${pattern} names the home directory, which is unknown; fail closed.`, null);
    if (!isAbsolute(expanded) && dir === undefined) return credentialBlock(`${pattern} is relative and the working directory is unknown; fail closed.`, null);
    const glob = isAbsolute(expanded) ? expanded : `${resolve(basesOf(ctx)[0] ?? "/", dir as string)}/${expanded}`;
    return globDecision(glob, credentialHomes(ctx), false, pattern);
  }
  return null;
}

// ---- Bash

/** Programs that read directories recursively (always, or with the flags in RECURSIVE_FLAGS). */
const RECURSIVE_ALWAYS = new Set(["tar", "bsdtar", "zip", "7z", "7za", "7zz", "rsync", "scp", "rg", "ag", "ack", "find", "fd", "rclone", "restic", "borg", "duplicity", "gtar"]);
const RECURSIVE_WITH_FLAG = new Set(["cp", "grep", "egrep", "fgrep", "zgrep"]);
const RECURSIVE_FLAGS = /^(?:-[A-Za-z]*[rRa][A-Za-z]*|--(?:recursive|archive|dereference-recursive))$/;
const WRAPPERS = new Set(["env", "sudo", "doas", "command", "builtin", "exec", "nice", "nohup", "time", "xargs", "timeout", "stdbuf", "ionice", "chroot"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** Options that change the directory of a program (`tar -C`, `git -C`, `make -C`, `--directory`). */
const DIR_OPTIONS = new Set(["-C", "--directory", "--cwd"]);
/** Separators inside a word: inline scripts (`bash -c '...'`, `python3 -c "open('...')"`), option values (`--file=...`), lists. */
const TOKEN_SPLIT = /[\s;|&()<>=,'"`:\\]+/;
const MAX_TOKENS = 8192;
const MAX_BASES = 32;

function programName(words: readonly ShellWord[]): string | undefined {
  let i = 0;
  while (i < words.length) {
    const w = words[i] as ShellWord;
    if (w.redirect) {
      i += 2;
      continue;
    }
    const name = w.value.split("/").pop() ?? w.value;
    if (ASSIGNMENT.test(w.value) || WRAPPERS.has(name) || (i > 0 && w.value.startsWith("-") && WRAPPERS.has((words[i - 1] as ShellWord).value.split("/").pop() ?? ""))) {
      i += 1;
      continue;
    }
    return name;
  }
  return undefined;
}

function recursiveCommand(words: readonly ShellWord[]): boolean {
  const name = programName(words);
  if (name === undefined) return false;
  if (RECURSIVE_ALWAYS.has(name)) return true;
  return RECURSIVE_WITH_FLAG.has(name) && words.some((w) => RECURSIVE_FLAGS.test(w.value));
}

function tokensOf(value: string): string[] {
  const parts = [value, ...value.split(TOKEN_SPLIT)];
  // Attached short option values: `-i/path`, `-f~/x`.
  const attached = parts.filter((p) => /^-[A-Za-z][/~.$]/.test(p)).map((p) => p.slice(2));
  return [...new Set([...parts, ...attached])].filter((p) => p !== "" && p !== "-" && p !== "--");
}

interface BashState {
  homes: string[];
  home: string | undefined;
  bases: string[];
  /** A `cd` to a directory that is not known statically: relative words are checked by their text as well. */
  unknownBase: boolean;
  dotglob: boolean;
  aliases: AliasIndex;
}

/** Static directory of a word (`~`, `$HOME` expanded), or null if not known statically. */
function staticDir(value: string, state: BashState, quoted: boolean): string | null {
  const expanded = quoted && value.startsWith("~") ? value : expandHomePrefix(value, state.home);
  if (expanded === null || /[$`*?[{]/.test(expanded)) return null;
  return expanded;
}

function joinBases(bases: readonly string[], dir: string): string[] {
  return isAbsolute(dir) ? [resolve(dir)] : bases.map((b) => resolve(b, dir));
}

/** Union of the directories the commands may run in (start bases plus every `cd`/`pushd` target); see directoryChanges in writes.ts. */
function directoryChanges(commands: readonly ShellWord[][], state: BashState): void {
  for (const words of commands) {
    const args = words.filter((w, k) => !w.redirect && !(k > 0 && (words[k - 1] as ShellWord).redirect));
    const name = programName(args);
    if (name !== "cd" && name !== "pushd") continue;
    const at = args.findIndex((w) => w.value === name);
    const target = args.slice(at + 1).find((w) => !(w.value.startsWith("-") && w.value !== "-"));
    let dir: string | null;
    if (target === undefined) dir = state.home ?? null;
    else if (target.value === "-") dir = null;
    else dir = staticDir(target.value, state, target.quoted);
    if (dir === null) {
      state.unknownBase = true;
      continue;
    }
    const next = [...new Set([...state.bases, ...joinBases(state.bases, dir)])];
    if (next.length > MAX_BASES) state.unknownBase = true;
    else state.bases = next;
  }
}

function tokenDecision(token: string, bases: readonly string[], state: BashState, mode: Mode, shown: string): CredentialBlock | null {
  if (/^~[^/]/.test(token)) {
    // `~user/...`: another user's home directory, not resolved here.
    return namesCredentialStore(token) ? credentialBlock(`${shown} names a credential store below a home directory that is not resolved (~user); fail closed.`, null) : null;
  }
  const expanded = expandHomePrefix(token, state.home);
  if (expanded === null) {
    return namesCredentialStore(token) ? credentialBlock(`${shown} names a credential store and the home directory is unknown; fail closed.`, null) : null;
  }
  if (/[$`]/.test(expanded)) {
    return namesCredentialStore(expanded) ? credentialBlock(`${shown} builds a credential store path from a variable or substitution; fail closed.`, null) : null;
  }
  if (!isAbsolute(expanded) && state.unknownBase && namesCredentialStore(expanded)) {
    return credentialBlock(`${shown} is a relative credential store path after a change to an unknown directory; fail closed.`, null);
  }
  const targets = isAbsolute(expanded) ? [expanded] : bases.map((b) => resolve(b, expanded));
  const glob = /[*?[{]/.test(expanded);
  for (const target of targets) {
    if (glob) {
      const d = globDecision(target, state.homes, state.dotglob, shown);
      if (d !== null) return d;
      continue;
    }
    const d = absoluteDecision(target, state.homes, state.aliases, mode, false, shown);
    if (d !== null) return d;
  }
  return null;
}

/**
 * The same exemption as the command rules of the policy: one `gh pr|issue <sub>` command with a title/body/message option, without
 * a file option and without operators, substitutions or redirections.
 */
const GH_MESSAGE_ONLY = /^\s*gh\s+(?:pr|issue)\s+\w+\b(?![^\n]*\s-(?:F|f|-(?:file|body-file|template))\b)(?=[^\n;&|`$<>]*\s-(?:m|b|t|-(?:message|body|title))\b)[^\n;&|`$<>]*$/;
const GH_MESSAGE_OPTIONS = new Set(["-m", "-b", "-t", "--message", "--body", "--title"]);

/** Value words of the title/body/message options of such a `gh` command (they are text, not paths). */
function ghMessageWords(command: string, commands: readonly ShellWord[][]): ShellWord[] {
  if (commands.length !== 1 || !GH_MESSAGE_ONLY.test(command)) return [];
  const words = commands[0] as ShellWord[];
  const out: ShellWord[] = [];
  for (let i = 0; i < words.length; i += 1) {
    const v = (words[i] as ShellWord).value;
    if (GH_MESSAGE_OPTIONS.has(v) && words[i + 1] !== undefined) out.push(words[i + 1] as ShellWord);
    else if (/^--(?:message|body|title)=/.test(v)) out.push(words[i] as ShellWord);
  }
  return out;
}

/**
 * Credential store read lock for a Bash command: every word of every simple command (also inside substitutions, inline scripts
 * and option values) is resolved like a path against the working directory, the project directory and the `cd` targets of the
 * command. Recursive readers (`tar`, `rsync`, `grep -r`, `find` ...) are also blocked on a home directory or above it.
 * Throws ShellSyntaxError if the command cannot be parsed (callers block it before).
 */
export function bashCredentialDecision(command: string, ctx: CredentialContext): CredentialBlock | null {
  const parsed = parseShell(command);
  const commands = parsed.commands.map((c) => c.words);
  // Commit and PR message arguments that git/gh certainly treat as text are not paths (same masking as the command rules).
  const messages = new Set<ShellWord>(maskingSafe(parsed, command) ? parsed.commands.flatMap((c) => messageMasks(c, command)).map((m) => m.word) : []);
  for (const w of ghMessageWords(command, commands)) messages.add(w);
  const homes = credentialHomes(ctx);
  const state: BashState = { homes, home: ctx.home, bases: basesOf(ctx), unknownBase: basesOf(ctx).length === 0, dotglob: /\bdotglob\b|\bGLOBIGNORE\b/.test(command), aliases: new AliasIndex(homes) };
  directoryChanges(commands, state);
  let budget = MAX_TOKENS;
  for (const words of commands) {
    const mode: Mode = recursiveCommand(words) ? "tree" : "file";
    let bases = state.bases;
    for (let k = 0; k + 1 < words.length; k += 1) {
      if (!DIR_OPTIONS.has((words[k] as ShellWord).value)) continue;
      const dir = staticDir((words[k + 1] as ShellWord).value, state, (words[k + 1] as ShellWord).quoted);
      if (dir === null) state.unknownBase = true;
      else bases = [...new Set([...bases, ...joinBases(state.bases, dir)])];
    }
    for (const word of words) {
      if (word.redirect || word.heredoc !== undefined || messages.has(word)) continue;
      for (const token of tokensOf(word.value)) {
        // Each word is resolved against every base: the budget bounds the file system lookups, not only the words.
        budget -= Math.max(1, bases.length);
        if (budget < 0) return credentialBlock("The command has too many words for the credential store check; split it.", null);
        const d = tokenDecision(token, bases, state, mode, token);
        if (d !== null) return d;
      }
    }
  }
  return null;
}
