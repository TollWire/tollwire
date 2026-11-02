// Facts about a Bash call for the decision log: program names, effects, affected paths and whether the call is a
// read-only call that may be summarized under the flood limit.
import { isAbsolute, posix, resolve } from "node:path";
import { parseShell, type ShellWord } from "../shell.js";
import { analyzeWrites, codeLanguage, writeIndicator } from "../writes.js";

export type Effect = "write" | "network" | "package" | "exec" | "unknown";
export const EFFECT_ORDER: readonly Effect[] = ["write", "network", "package", "exec", "unknown"];

export interface CommandInfo {
  programs: string[];
  effects: Effect[];
  paths: string[];
  /** Every simple command is on the read-only allowlist, nothing is opaque, and no path is sensitive or outside. */
  suppressible: boolean;
  /** False if the tokenizer failed (programs and paths are empty, effects are `unknown`). */
  parsed: boolean;
}

export interface CommandContext {
  projectDir: string;
  cwd?: string | undefined;
  home?: string | undefined;
  /** Environment of the hook process (only `RIPGREP_CONFIG_PATH` is looked at). */
  env?: NodeJS.ProcessEnv | undefined;
}

export const MAX_PROGRAMS = 16;
export const MAX_PROGRAM_LENGTH = 64;
export const MAX_PATHS = 64;
export const DYNAMIC_PROGRAM = "<dynamic>";

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
const FD_PREFIX = /^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})$/;
const WRITE_REDIRECTS = new Set([">", ">>", ">|", "<>", "&>", "&>>"]);
const SAFE_DEVICES = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/full"]);
const KEYWORDS = new Set(["{", "}", "!", "if", "then", "else", "elif", "do", "while", "until", "fi", "done", "esac", "case", "for", "select", "function"]);

interface WrapperSpec {
  /** Short options that take a value. */
  short: string;
  long: readonly string[];
  /** Positional words consumed before the wrapped program (timeout: the duration). */
  positional?: number;
  /** Skips `NAME=value` words (env). */
  assignments?: boolean;
}

// Wrappers as in writes.ts (WRAPPERS) plus env, time and timeout.
const WRAPPERS: Readonly<Record<string, WrapperSpec>> = {
  sudo: { short: "ugCDhprtUTR", long: ["--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout", "--chroot"] },
  doas: { short: "uC", long: [] },
  env: { short: "uCS", long: ["--unset", "--chdir", "--split-string"], assignments: true },
  nohup: { short: "", long: [] },
  nice: { short: "n", long: ["--adjustment"] },
  timeout: { short: "sk", long: ["--signal", "--kill-after"], positional: 1 },
  stdbuf: { short: "ioe", long: ["--input", "--output", "--error"] },
  command: { short: "", long: [] },
  exec: { short: "a", long: [] },
  time: { short: "of", long: ["--output", "--format"] },
  setsid: { short: "", long: [] },
  ionice: { short: "cn", long: ["--class", "--classdata"] },
  unbuffer: { short: "", long: [] },
  chronic: { short: "", long: [] },
  builtin: { short: "", long: [] },
};

export interface Part {
  word: ShellWord;
  value: string;
}

/** Last path component of a command word (`/opt/x/bin/tool` becomes `tool`). */
export function baseName(value: string): string {
  const parts = value.split(/[\\/]/);
  const last = parts[parts.length - 1] as string;
  return last === "" ? value : last;
}

function isAssignment(part: Part, src: string): boolean {
  const first = src.charAt(part.word.start);
  if (first === "'" || first === '"' || first === "\\" || first === "$") return false; // a quoted name is a command name
  return ASSIGNMENT.test(part.value);
}

/** Words of a simple command without redirections (operator, target and file-descriptor prefix). */
export function plainParts(words: readonly ShellWord[]): { parts: Part[]; redirects: { op: string; target: string | undefined }[] } {
  const parts: Part[] = [];
  const redirects: { op: string; target: string | undefined }[] = [];
  for (let i = 0; i < words.length; i += 1) {
    const w = words[i] as ShellWord;
    if (w.redirect) {
      redirects.push({ op: w.value, target: words[i + 1]?.value });
      i += 1;
      continue;
    }
    const next = words[i + 1];
    if (next?.redirect === true && next.start === w.end && FD_PREFIX.test(w.value)) continue;
    parts.push({ word: w, value: w.value });
  }
  return { parts, redirects };
}

/** Index after the options (and positional words) of a wrapper whose name is at `index`. */
function skipWrapper(parts: readonly Part[], index: number, spec: WrapperSpec, src: string): number {
  let j = index + 1;
  let positional = spec.positional ?? 0;
  while (j < parts.length) {
    const w = (parts[j] as Part).value;
    if (w === "--") return j + 1;
    if (w.startsWith("--") && w.length > 2) {
      j += !w.includes("=") && spec.long.includes(w) ? 2 : 1;
    } else if (w.startsWith("-") && w.length > 1) {
      let consumed = 1;
      for (let k = 1; k < w.length; k += 1) {
        if (spec.short.includes(w.charAt(k))) {
          if (k === w.length - 1) consumed = 2; // value is the next word
          break;
        }
      }
      j += consumed;
    } else if (spec.assignments === true && isAssignment(parts[j] as Part, src)) {
      j += 1;
    } else if (positional > 0) {
      positional -= 1;
      j += 1;
    } else {
      return j;
    }
  }
  return j;
}

interface Resolved {
  name: string;
  dynamic: boolean;
  /** Words after the program word. */
  args: Part[];
  assignments: Part[];
  /** The program was started through a wrapper such as `sudo` or `env`. */
  wrapped: boolean;
  /** The program word as written (before the path is reduced to the file name). */
  raw: string;
}

export function resolveProgram(parts: readonly Part[], src: string): Resolved | null {
  const assignments: Part[] = [];
  let i = 0;
  let wrapped = false;
  for (let depth = 0; depth < 6; depth += 1) {
    while (i < parts.length) {
      const p = parts[i] as Part;
      if (KEYWORDS.has(p.value) && !p.word.quoted) i += 1;
      else if (isAssignment(p, src)) {
        assignments.push(p);
        i += 1;
      } else break;
    }
    const p = parts[i];
    if (p === undefined) return null;
    if (p.word.expands || p.word.executes) return { name: DYNAMIC_PROGRAM, dynamic: true, args: parts.slice(i + 1), assignments, wrapped, raw: p.value };
    const name = baseName(p.value);
    const spec = WRAPPERS[name];
    if (spec === undefined) return { name, dynamic: false, args: parts.slice(i + 1), assignments, wrapped, raw: p.value };
    const next = skipWrapper(parts, i, spec, src);
    if (next >= parts.length) return { name, dynamic: false, args: parts.slice(i + 1), assignments, wrapped, raw: p.value };
    wrapped = true;
    i = next;
  }
  return null;
}

const NETWORK = new Set([
  "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "http", "https", "xh", "gh", "aws", "gcloud",
  "az", "kubectl", "docker", "podman", "terraform", "ping", "dig", "nslookup", "host", "mosh",
]);
const PACKAGE = new Set([
  "npm", "npx", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "uvx", "poetry", "cargo", "gem", "bundle", "composer", "apt", "apt-get",
  "dnf", "yum", "apk", "pacman", "brew", "conda", "mamba", "nuget",
]);
const EXEC = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "python", "python3", "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua",
  "eval", "source", ".", "xargs", "make", "cmake", "ninja", "java", "go", "dotnet", "swift",
]);
const WRITERS = new Set([
  "rm", "mv", "cp", "tee", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "ln", "dd", "install", "truncate", "shred", "patch",
  "tar", "unzip", "zip", "gzip", "gunzip", "bzip2", "xz", "mktemp", "rsync", "sed", "awk", "ed", "vi", "vim", "nano", "emacs",
]);
const NO_EFFECT = new Set([
  "echo", "printf", "true", "false", "cd", "pwd", "test", "[", "[[", "sleep", "date", "whoami", "uname", "hostname", "id", "basename",
  "dirname", "realpath", "readlink", "sort", "uniq", "cut", "tr", "diff", "cmp", "which", "type", "wc", "ls", "stat", "head", "tail",
  "cat", "grep", "rg", "find", "file", "du", "df", "ps", "tree", "less", "more", "jq", "export", "set", "unset", "read", "wait", "nproc",
  "env", "printenv", "tput", "seq", "yes", "column", "expr", "tac", "rev", "fold", "nl", "od", "xxd", "md5sum", "sha256sum", "sha1sum",
]);
const GIT_NETWORK = new Set(["push", "pull", "fetch", "clone", "ls-remote", "remote", "submodule"]);
const GIT_WRITE = new Set([
  "add", "commit", "checkout", "switch", "restore", "reset", "merge", "rebase", "cherry-pick", "revert", "apply", "am", "stash", "rm",
  "mv", "init", "tag", "branch", "clean", "config", "worktree", "gc", "prune", "update-index", "write-tree", "commit-tree", "notes",
]);
const GIT_READ = new Set([
  "status", "log", "diff", "show", "rev-parse", "describe", "blame", "ls-files", "ls-tree", "cat-file", "shortlog", "grep", "rev-list",
  "show-ref", "for-each-ref", "name-rev", "merge-base", "version", "help", "reflog", "whatchanged",
]);

function gitSubcommand(args: readonly Part[]): string | null {
  // Skips global options with an argument (`-C dir`, `-c k=v`, `--git-dir=...`); anything else unknown is no subcommand.
  for (let i = 0; i < args.length; i += 1) {
    const v = (args[i] as Part).value;
    if (v === "-C" || v === "-c") {
      i += 1;
      continue;
    }
    if (v.startsWith("-")) continue;
    return v;
  }
  return null;
}

function classifyProgram(name: string, args: readonly Part[]): Effect[] {
  if (name === DYNAMIC_PROGRAM) return ["exec", "unknown"];
  const out: Effect[] = [];
  if (name === "git") {
    const sub = gitSubcommand(args);
    if (sub === null) return ["unknown"];
    if (GIT_NETWORK.has(sub)) out.push("network");
    if (GIT_WRITE.has(sub) && sub !== "worktree") out.push("write");
    if (sub === "worktree" || sub === "submodule") out.push("write");
    if (out.length === 0 && !GIT_READ.has(sub)) out.push("unknown");
    return out;
  }
  if (name === "sed") return args.some((a) => /^-[A-Za-z]*i/.test(a.value) || a.value.startsWith("--in-place")) ? ["write"] : [];
  if (name === "awk" || name === "gawk" || name === "mawk") return ["unknown"];
  if (NETWORK.has(name)) out.push("network");
  if (PACKAGE.has(name)) out.push("package");
  if (EXEC.has(name)) out.push("exec");
  if (WRITERS.has(name) && !["sed", "awk"].includes(name)) out.push("write");
  if (out.length === 0 && !NO_EFFECT.has(name)) out.push("unknown");
  return out;
}

// --- read-only allowlist (flood limit) ---------------------------------------------------------------------------

const TAIL_FORBIDDEN_LONG = ["--follow", "--retry", "--pid"];
const RG_FORBIDDEN_LONG = ["--pre", "--pre-glob", "--hostname-bin", "--search-zip"];
const FIND_FORBIDDEN = ["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls"];
const READ_ONLY = new Set(["ls", "pwd", "wc", "stat", "head", "cat", "tail", "grep", "rg", "find"]);

/** GNU abbreviation rule: `--fol` is `--follow`; ambiguity or abbreviation of a forbidden option counts as forbidden. */
function abbreviatesForbidden(option: string, forbidden: readonly string[]): boolean {
  const name = option.split("=")[0] as string;
  return name.startsWith("--") && name.length > 2 && forbidden.some((f) => f.startsWith(name));
}

function shortCluster(option: string, chars: string): boolean {
  return /^-[^-]/.test(option) && [...option.slice(1)].some((c) => chars.includes(c));
}

function readOnlyOptionsOk(name: string, args: readonly Part[], env: NodeJS.ProcessEnv | undefined, assignments: readonly Part[]): boolean {
  const values: string[] = [];
  for (const a of args) {
    if (a.value === "--") break;
    values.push(a.value);
  }
  if (name === "tail") {
    return !values.some((v) => abbreviatesForbidden(v, TAIL_FORBIDDEN_LONG) || (v.startsWith("--") ? false : shortCluster(v, "fF")));
  }
  if (name === "rg") {
    const configured = env?.RIPGREP_CONFIG_PATH !== undefined || assignments.some((a) => a.value.startsWith("RIPGREP_CONFIG_PATH="));
    if (configured) return false;
    return !values.some((v) => abbreviatesForbidden(v, RG_FORBIDDEN_LONG) || (v.startsWith("--") ? false : shortCluster(v, "z")));
  }
  if (name === "find") {
    return !args.some((a) => FIND_FORBIDDEN.includes(a.value) || a.value.startsWith("-fprint"));
  }
  return true;
}

const SENSITIVE_SEGMENTS = new Set([
  ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".env", ".secrets",
  "secrets", "credentials", "shadow", "gshadow", "sudoers", "environ", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys",
  ".bash_history", ".claude", ".password-store", ".local",
]);

/** True for paths that must never be summarized: credentials, keys, shell history, other processes' environment. */
export function sensitivePath(absolute: string): boolean {
  const p = posix.normalize(absolute.replace(/\\/g, "/")).toLowerCase();
  if (p.startsWith("/proc/") || p.startsWith("/sys/") || p.startsWith("/dev/") || p === "/proc") return true;
  if (p.startsWith("/etc/") && /\/(shadow|gshadow|sudoers|ssh|ssl|tollgate)(\/|$)/.test(p)) return true;
  return p.split("/").some((seg) => SENSITIVE_SEGMENTS.has(seg) || seg.startsWith(".env.") || /\.(pem|key|p12|pfx|kdbx)$/.test(seg));
}

function insideProject(absolute: string, projectDir: string): boolean {
  const root = resolve(projectDir);
  return absolute === root || absolute.startsWith(root.endsWith("/") ? root : `${root}/`);
}

/** Path of an argument word as an absolute path; the part before the first glob character is used. */
function argumentPath(value: string, ctx: CommandContext): string {
  let v = value;
  if (v === "~" || v.startsWith("~/")) v = `${ctx.home ?? "/nonexistent-home"}${v.slice(1)}`;
  const glob = v.search(/[*?[{]/);
  if (glob >= 0) v = v.slice(0, glob) || ".";
  return isAbsolute(v) ? posix.normalize(v) : resolve(ctx.cwd ?? ctx.projectDir, v);
}

/** True if a path may be left out of the log under the flood limit: inside the project and not sensitive. */
export function pathSummarizable(absolute: string, projectDir: string): boolean {
  return insideProject(absolute, projectDir) && !sensitivePath(absolute);
}

export function projectRelative(absolute: string, projectDir: string): string {
  const root = resolve(projectDir);
  if (absolute === root) return ".";
  return absolute.startsWith(`${root}/`) ? absolute.slice(root.length + 1) : absolute;
}

interface SearchSpec {
  /** Short options that take a value (the value is the rest of the word or the next word). */
  short: string;
  /** Long options that take a value. */
  long: readonly string[];
  /** Short and long options whose value is the search pattern. */
  patternShort: string;
  patternLong: readonly string[];
  /** Short and long options whose value is a file with patterns. */
  fileShort: string;
  fileLong: readonly string[];
  /** The first positional word is the pattern unless a pattern option is present. */
  implicitPattern: boolean;
}

const GREP_LONG = [
  "--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context", "--directories", "--devices", "--include",
  "--exclude", "--exclude-from", "--exclude-dir", "--label", "--binary-files",
] as const;
const GREP_SPEC: SearchSpec = {
  short: "efmABCdD", long: GREP_LONG, patternShort: "e", patternLong: ["--regexp"], fileShort: "f", fileLong: ["--file"], implicitPattern: true,
};
const SEARCH_PROGRAMS: Readonly<Record<string, SearchSpec>> = {
  grep: GREP_SPEC,
  egrep: GREP_SPEC,
  fgrep: GREP_SPEC,
  rg: {
    short: "efgmABCtTjMEdr",
    long: [
      "--regexp", "--file", "--glob", "--iglob", "--max-count", "--after-context", "--before-context", "--context", "--type", "--type-not",
      "--type-add", "--type-clear", "--threads", "--max-columns", "--encoding", "--replace", "--max-depth", "--max-filesize", "--sort",
      "--sortr", "--path-separator", "--pre", "--pre-glob", "--engine", "--colors", "--context-separator", "--field-context-separator",
      "--field-match-separator", "--ignore-file", "--dfa-size-limit", "--regex-size-limit", "--hostname-bin",
    ],
    patternShort: "e", patternLong: ["--regexp"], fileShort: "f", fileLong: ["--file"], implicitPattern: true,
  },
  ag: {
    short: "ABCGgmpWD",
    long: ["--after", "--before", "--context", "--file-search-regex", "--max-count", "--path-to-ignore", "--pager", "--workers", "--depth", "--ignore"],
    patternShort: "", patternLong: [], fileShort: "", fileLong: [], implicitPattern: true,
  },
};

export type ArgumentKind = "path" | "pattern" | "pattern-file";
interface ReadArgument {
  value: string;
  kind: ArgumentKind;
}

/**
 * Non-option words of a read-only call. For search programs the pattern (first positional word or the value of `-e` and
 * `--regexp`) is marked as such and a pattern file (`-f`, `--file`) as `pattern-file`: neither is a path to log, because a
 * pattern may be a secret.
 */
function readArguments(name: string, args: readonly Part[]): ReadArgument[] {
  const spec = SEARCH_PROGRAMS[name];
  const out: ReadArgument[] = [];
  let explicitPattern = false;
  let firstPositional = -1;
  let optionsEnded = false;
  for (let i = 0; i < args.length; i += 1) {
    const v = (args[i] as Part).value;
    if (!optionsEnded && v === "--") {
      optionsEnded = true;
      continue;
    }
    if (optionsEnded || !(v.startsWith("-") && v.length > 1)) {
      if (firstPositional < 0) firstPositional = out.length;
      out.push({ value: v, kind: "path" });
      continue;
    }
    if (spec === undefined) continue;
    let role: ArgumentKind;
    let inline: string | null;
    if (v.startsWith("--")) {
      const eq = v.indexOf("=");
      const option = eq < 0 ? v : v.slice(0, eq);
      // GNU abbreviation rule: `--reg` is `--regexp`.
      const matches = spec.long.includes(option) ? [option] : spec.long.filter((l) => l.startsWith(option));
      if (matches.length === 0) continue;
      role = matches.some((m) => spec.patternLong.includes(m)) ? "pattern" : matches.some((m) => spec.fileLong.includes(m)) ? "pattern-file" : "path";
      inline = eq < 0 ? null : v.slice(eq + 1);
    } else {
      let k = 1;
      while (k < v.length && !spec.short.includes(v.charAt(k))) k += 1;
      if (k >= v.length) continue;
      const c = v.charAt(k);
      role = spec.patternShort.includes(c) ? "pattern" : spec.fileShort.includes(c) ? "pattern-file" : "path";
      inline = k < v.length - 1 ? v.slice(k + 1) : null;
    }
    if (role !== "path") explicitPattern = true;
    if (inline !== null) {
      // The value is part of the word (`-ePATTERN`, `--regexp=PATTERN`); only a pattern file is still checked.
      if (role === "pattern-file") out.push({ value: inline, kind: role });
      continue;
    }
    const next = args[i + 1];
    if (next === undefined) continue;
    i += 1;
    out.push({ value: next.value, kind: role });
  }
  if (spec?.implicitPattern === true && !explicitPattern && firstPositional >= 0) (out[firstPositional] as ReadArgument).kind = "pattern";
  return out;
}

function pushUnique(list: string[], value: string): void {
  if (!list.includes(value)) list.push(value);
}

/** Analyses a Bash command string. Never throws. */
export function analyzeCommand(command: string, ctx: CommandContext): CommandInfo {
  let commands;
  try {
    commands = parseShell(command).commands;
  } catch {
    return { programs: [], effects: ["unknown"], paths: [], suppressible: false, parsed: false };
  }
  const programs: string[] = [];
  const effects = new Set<Effect>();
  const paths: string[] = [];
  let suppressible = commands.length > 0;
  for (const cmd of commands) {
    const { parts, redirects } = plainParts(cmd.words);
    for (const r of redirects) {
      if (WRITE_REDIRECTS.has(r.op) && !(r.target !== undefined && SAFE_DEVICES.has(r.target))) effects.add("write");
      suppressible = false; // any redirection (also from a here-document or file) is not a plain read
    }
    if (cmd.words.some((w) => w.executes || w.expands)) suppressible = false;
    const resolved = resolveProgram(parts, command);
    if (resolved === null) {
      // Only assignments or keywords: no program runs. An assignment can still change the environment of later commands.
      if (parts.some((p) => isAssignment(p, command))) suppressible = false;
      if (!parts.every((p) => KEYWORDS.has(p.value) || isAssignment(p, command))) {
        effects.add("unknown");
        suppressible = false;
      }
      continue;
    }
    if (programs.length < MAX_PROGRAMS) programs.push(resolved.name.slice(0, MAX_PROGRAM_LENGTH));
    for (const e of classifyProgram(resolved.name, resolved.args)) effects.add(e);
    // Read-only allowlist: bare names only (`./ls` is unknown), no wrapper-free dynamic name.
    const bare = !resolved.dynamic && !resolved.wrapped && READ_ONLY.has(resolved.name) && !/[\\/]/.test(resolved.raw);
    if (!bare || !readOnlyOptionsOk(resolved.name, resolved.args, ctx.env, resolved.assignments) || resolved.assignments.length > 0) {
      suppressible = false;
    } else {
      for (const a of readArguments(resolved.name, resolved.args)) {
        if (a.kind === "pattern") continue; // a search pattern is not a path and may contain a secret
        const abs = argumentPath(a.value, ctx);
        if (a.kind === "path") pushUnique(paths, projectRelative(abs, ctx.projectDir));
        if (!pathSummarizable(abs, ctx.projectDir)) suppressible = false;
      }
    }
  }
  try {
    const home = ctx.home;
    const findings = analyzeWrites(command, { root: ctx.projectDir, cwd: ctx.cwd, home }).findings;
    for (const f of findings) {
      if (f.kind === "path" && SAFE_DEVICES.has(f.value)) continue;
      if (f.kind === "path") pushUnique(paths, projectRelative(f.value, ctx.projectDir));
      if (f.kind === "path" || f.kind === "glob" || f.kind === "dynamic") effects.add("write");
      if (f.kind === "code" && writeIndicator(f.value, codeLanguage(f.via))) effects.add("write");
      if (f.kind === "opaque" || f.kind === "patch" || f.kind === "git") effects.add("unknown");
      suppressible = false;
    }
  } catch {
    effects.add("unknown");
    suppressible = false;
  }
  return {
    programs,
    effects: EFFECT_ORDER.filter((e) => effects.has(e)),
    paths: paths.slice(0, MAX_PATHS),
    suppressible,
    parsed: true,
  };
}
