// Session taint: a session that has read untrusted content is "tainted"; in a tainted session the hook blocks
// network egress, git push, access to secrets and credential files, and protected writes even in a human session.
// Only a human lifts the taint, outside the agent's channel (stand-alone: `tollgate-taint release` in a real terminal;
// enterprise: a root-owned release file written by `sudo tollgate-taint admin-release`).
//
// State `tollgate.taint.v1`: one file per session, HMAC-SHA256 with a per-user key. A missing, unreadable or manipulated
// state counts as tainted (fail closed). Limits (residual risks, see the README): the key lies in the user's own directory, so code
// that runs as the same user outside the hook can read it; the hook is defense in depth, not a security boundary.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, writeSync } from "node:fs";
import { isAbsolute, join, posix, resolve } from "node:path";
import { baseName, DYNAMIC_PROGRAM, plainParts, resolveProgram, sensitivePath } from "./events/commandInfo.js";
import { readTrustedFile } from "./enterprise.js";
import { parseShell } from "./shell.js";
import { canonicalJson, sha256Hex } from "./vendor/hashchain.js";
import { taintToolMatches, type TaintPolicy } from "./taintPolicy.js";
import { SESSION_PATTERN } from "./vendor/locks.js";

export const TAINT_SCHEMA = "tollgate.taint.v1";
export const TAINT_RELEASE_SCHEMA = "tollgate.taint-release.v1";
/** Root-owned directory of the enterprise release files (below `/var/lib/tollgate/`, a protected system path). */
export const TAINT_RELEASE_DIR = "/var/lib/tollgate/taint/releases";
export const MAX_STATE_BYTES = 16 * 1024;
export const MAX_SOURCES = 10;
const KEY_FILE = "key";
const HEX64 = /^[0-9a-f]{64}$/;
const EPOCH = /^[0-9a-f]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const NOCTTY = constants.O_NOCTTY ?? 0;

// --- classification -------------------------------------------------------------------------------------------------

export type SourceKind = "tool" | "bash_network" | "bash_wrapper" | "read_outside_project";
export interface TaintSource {
  kind: SourceKind;
  /** Tool name or program name; never a path, URL or argument. */
  name: string;
}

export type RestrictCategory = "network" | "git_push" | "secrets" | "release_cli" | "nested_agent";
export interface Restriction {
  category: RestrictCategory;
  /** For the log; no command text, no paths. */
  reason: string;
}

export interface ClassifyContext {
  projectDir: string;
  cwd?: string | undefined;
  home?: string | undefined;
  /** Directories whose content counts as secret in a tainted session (taint state and key, user configuration). */
  secretDirs: readonly string[];
}

const READ_TOOLS = new Set(["Read", "Glob", "Grep", "LS", "NotebookRead"]);
const WRITE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);
/** Programs that print the environment (it can hold secrets) when called without a command. */
const ENV_PRINTERS = new Set(["printenv"]);
/** The release command and the hook entry points: in a tainted session the agent must not run them (a hook run by hand could
 * start a "new" session and so a clean state). `ptyRelease.py` is the smoke-test driver that types the release code in a
 * pseudo-terminal; it would do the same for an agent. */
const RELEASE_PROGRAMS = new Set(["tollgate-taint", "taintCli.js", "taintCli.ts", "hookCli.js", "hookCliPosix.js", "hookCliWin.js", "hook.js", "ptyRelease.py"]);
/** Coding-agent CLIs: a nested agent starts a new session without the taint of this one. */
const AGENT_CLIS = new Set(["claude", "codex", "gemini", "aider", "cursor-agent", "copilot", "opencode", "goose", "amp", "qwen", "crush"]);
/** Programs that run another command given as arguments; what they run is not analyzed here. */
const COMMAND_WRAPPERS = new Set([
  "xargs", "watch", "flock", "su", "runuser", "parallel", "sg", "chroot", "nsenter", "unshare", "script", "expect", "tmux", "screen",
  "at", "batch", "systemd-run", "pkexec", "dbus-run-session", "eval", "exec", "taskset", "chrt", "strace", "ltrace", "proxychains",
  "proxychains4", "torsocks", "torify", "bwrap", "firejail", "setpriv", "numactl", "cgexec", "faketime", "catchsegv", "valgrind",
]);
/** Shells and interpreters whose inline code (`-c`) is analyzed like a command line. */
const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox"]);
/** Devices that are neither content nor secrets. */
const SAFE_DEVICES = new Set(["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/fd/0", "/dev/fd/1", "/dev/fd/2"]);

function stringField(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === "string" && v !== "" ? v : undefined;
}

function absoluteOf(value: string, ctx: ClassifyContext): string {
  let v = value;
  if (v === "~" || v.startsWith("~/")) v = `${ctx.home ?? "/nonexistent-home"}${v.slice(1)}`;
  if (v.startsWith("$HOME/") || v === "$HOME" || v.startsWith("${HOME}")) v = `${ctx.home ?? "/nonexistent-home"}${v.slice(v.startsWith("${HOME}") ? 7 : 5)}`;
  return isAbsolute(v) ? posix.normalize(v) : resolve(ctx.cwd ?? ctx.projectDir, v);
}

function inside(absolute: string, dir: string): boolean {
  const root = resolve(dir);
  return absolute === root || absolute.startsWith(root.endsWith("/") ? root : `${root}/`);
}

function secretPath(absolute: string, ctx: ClassifyContext): boolean {
  if (SAFE_DEVICES.has(absolute)) return false;
  return sensitivePath(absolute) || ctx.secretDirs.some((d) => inside(absolute, d.replace(/\/+$/, "")));
}

function toolPaths(input: Record<string, unknown>): string[] {
  return ["file_path", "path", "notebook_path"].map((k) => stringField(input, k)).filter((v): v is string => v !== undefined);
}

/** Git options that take their value as the next word (`git -C dir`, `git --git-dir dir`). */
const GIT_VALUE_OPTIONS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--exec-path", "--attr-source", "--list-cmds"]);

interface BashCommand {
  program: string | null;
  dynamic: boolean;
  args: string[];
  raw: string[];
  gitSub: string | null;
  /** `git -c ...`, `--config-env ...` or `--exec-path`: configuration on the command line can run commands (pager, fsmonitor, ...). */
  gitConfig: boolean;
}

/** Words of a Bash command per simple command: the program and its argument words (without redirections). Throws if unparsable. */
function bashCommands(command: string): BashCommand[] {
  const out: BashCommand[] = [];
  for (const cmd of parseShell(command).commands) {
    const { parts, redirects } = plainParts(cmd.words);
    const resolved = resolveProgram(parts, command);
    const raw = [...parts.map((p) => p.value), ...redirects.map((r) => r.target ?? "")];
    if (resolved === null) {
      out.push({ program: null, dynamic: false, args: [], raw, gitSub: null, gitConfig: false });
      continue;
    }
    const args = resolved.args.map((a) => a.value);
    let gitSub: string | null = null;
    let gitConfig = false;
    if (resolved.name === "git") {
      for (let i = 0; i < args.length; i += 1) {
        const v = args[i] as string;
        // Every configuration value and the program directory can make git run a command (core.pager, core.fsmonitor,
        // core.sshCommand, credential.helper, diff.external, alias.*, ...). The list of such keys is long and changes, so in
        // a tainted session every one is restricted.
        if (v === "-c" || v === "--config-env" || v === "--exec-path" || /^-c./.test(v) || v.startsWith("--config-env=") || v.startsWith("--exec-path=")) gitConfig = true;
        if (GIT_VALUE_OPTIONS.has(v)) {
          i += 1;
          continue;
        }
        if (v.startsWith("-")) continue;
        gitSub = v;
        break;
      }
    }
    out.push({ program: resolved.name, dynamic: resolved.dynamic || resolved.name === DYNAMIC_PROGRAM, args, raw, gitSub, gitConfig });
  }
  return out;
}

const NETWORK_PROGRAMS = new Set([
  "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "http", "https", "xh", "gh", "aws", "gcloud",
  "az", "kubectl", "docker", "podman", "terraform", "ping", "dig", "nslookup", "host", "mosh", "socat", "openssl", "rclone", "aria2c",
  "lftp", "axel", "httpie", "ftpget", "ftpput", "tftp", "smbclient", "s3cmd", "gsutil", "azcopy", "mc", "sshpass", "glab", "hub",
]);
/** Applets of busybox that use the network. */
const BUSYBOX_NETWORK = new Set(["wget", "nc", "ftpget", "ftpput", "tftp", "telnet", "ssl_client", "httpd", "nslookup", "ping", "sendmail"]);
const GIT_NETWORK = new Set(["push", "pull", "fetch", "clone", "ls-remote", "remote", "submodule", "send-email", "request-pull", "send-pack", "fetch-pack", "upload-pack", "receive-pack", "archive", "svn", "p4", "imap-send", "http-push", "http-fetch", "credential", "bundle"]);
const GIT_KNOWN = new Set([
  ...GIT_NETWORK,
  "status", "log", "diff", "show", "rev-parse", "describe", "blame", "ls-files", "ls-tree", "cat-file", "shortlog", "grep", "rev-list",
  "show-ref", "for-each-ref", "name-rev", "merge-base", "version", "help", "reflog", "whatchanged", "add", "commit", "checkout",
  "switch", "restore", "reset", "merge", "rebase", "cherry-pick", "revert", "apply", "am", "stash", "rm", "mv", "init", "tag",
  "branch", "clean", "config", "worktree", "gc", "prune", "update-index", "write-tree", "commit-tree", "notes", "format-patch",
  "range-diff", "bisect", "mergetool", "difftool", "sparse-checkout", "maintenance", "fsck", "count-objects", "check-ignore",
  "check-attr", "var", "hash-object", "mktree", "stripspace", "interpret-trailers", "symbolic-ref", "update-ref",
]);

/** The environment is printed: `printenv`, `env` without a command (also `env -0`), `export`/`declare -x`/`set` without names. */
/** Builtins that print variables: `set` only without arguments (`set -e` sets options), the others without names. */
function printsVariables(name: string, args: readonly string[]): boolean {
  if (name === "set") return args.length === 0;
  if (name === "compgen") return args.some((a) => a === "-v" || a === "-e");
  if (["export", "declare", "typeset", "readonly"].includes(name)) return args.every((a) => a.startsWith("-") || a.startsWith("+"));
  return false;
}

/** `env` without a command prints the environment: options with a value (`-u NAME`, `-C DIR`) and assignments are skipped. */
function envPrints(args: readonly string[]): boolean {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] as string;
    if (a === "-u" || a === "--unset" || a === "-C" || a === "--chdir") {
      i += 1;
      continue;
    }
    if (a === "-S" || a === "--split-string" || a.startsWith("--split-string=") || /^-[^-]*S/.test(a)) return false; // runs a command
    if (a === "--") return i === args.length - 1;
    if (a.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) continue;
    return false; // a command follows
  }
  return true;
}

function printsEnvironment(c: BashCommand): boolean {
  if (c.program === null) {
    // resolveProgram returns null for assignment-only lines; a bare `export` or `set` is a word of its own here
    const [first, ...rest] = c.raw;
    return first !== undefined && printsVariables(first, rest);
  }
  if (ENV_PRINTERS.has(c.program)) return true;
  if (c.program === "env") return envPrints(c.args);
  return printsVariables(c.program, c.args);
}

/** Package runners: `npx claude`, `bunx @openai/codex`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `pipx run`. Returns the package. */
function runnerPackage(c: BashCommand): string | null {
  if (c.program === null) return null;
  let args: readonly string[] = [];
  if (c.program === "npx" || c.program === "bunx" || c.program === "uvx") args = c.args;
  else if ((c.program === "pnpm" || c.program === "yarn") && c.args[0] === "dlx") args = c.args.slice(1);
  else if (c.program === "npm" && (c.args[0] === "exec" || c.args[0] === "x")) args = c.args.slice(1);
  else if (c.program === "pipx" && c.args[0] === "run") args = c.args.slice(1);
  else if (c.program === "bun" && c.args[0] === "x") args = c.args.slice(1);
  else return null;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] as string;
    if (a === "--package" || a === "-p") return args[i + 1] ?? null;
    if (a.startsWith("--package=")) return a.slice(10);
    if (a.startsWith("-")) continue;
    return a;
  }
  return null;
}

const AGENT_PACKAGE = /^(?:claude(?:-code)?|codex|gemini(?:-cli)?|aider(?:-chat)?|cursor-agent|copilot|github-copilot-cli|opencode(?:-ai)?|goose|amp|qwen(?:-code)?|crush)$/;

/** True if a package spec (`@scope/name@1.2`, `name`) names a coding-agent CLI. */
function agentPackage(spec: string): boolean {
  const name = spec.replace(/^@[^/]+\//, "").replace(/@[^@]*$/, "").toLowerCase();
  return AGENT_PACKAGE.test(name) || AGENT_CLIS.has(name);
}

function bashRestriction(command: string, ctx: ClassifyContext, depth: number): Restriction | null {
  let commands: BashCommand[];
  try {
    commands = bashCommands(command);
  } catch {
    // Not parsable: the policy evaluation blocks it anyway; here it counts as possible egress (fail closed).
    return { category: "network", reason: "the command cannot be parsed, so network access cannot be ruled out" };
  }
  for (const c of commands) {
    if (c.raw.some((w) => RELEASE_PROGRAMS.has(baseName(w)))) return { category: "release_cli", reason: "the release command is for a human in a terminal, not for the agent" };
  }
  for (const c of commands) {
    if (printsEnvironment(c)) return { category: "secrets", reason: "the environment can hold secrets" };
    if (c.program === null) continue;
    if (c.dynamic) return { category: "network", reason: "a program name that is only known at run time can hide network access" };
    if (AGENT_CLIS.has(c.program)) return { category: "nested_agent", reason: `${c.program} would start a new agent session without this session's taint` };
    const pkg = runnerPackage(c);
    if (pkg !== null && agentPackage(pkg)) return { category: "nested_agent", reason: `${c.program} would start a coding agent without this session's taint` };
    if (c.program === "git") {
      if (c.gitConfig) return { category: "network", reason: "git configuration on the command line (-c, --config-env, --exec-path) can run commands, also push" };
      if (c.gitSub === "push") return { category: "git_push", reason: "git push sends data out of the session" };
      if (c.gitSub !== null && GIT_NETWORK.has(c.gitSub)) return { category: "network", reason: `git ${c.gitSub} uses the network` };
      if (c.gitSub !== null && !GIT_KNOWN.has(c.gitSub)) return { category: "network", reason: "an unknown git subcommand (alias or external command) can use the network" };
    }
    if (NETWORK_PROGRAMS.has(c.program)) return { category: "network", reason: `${c.program} uses the network` };
    if (c.program === "busybox" && BUSYBOX_NETWORK.has(c.args[0] ?? "")) return { category: "network", reason: "busybox network applet" };
    if (COMMAND_WRAPPERS.has(c.program)) return { category: "network", reason: `${c.program} runs a command that is not analyzed here` };
    if (c.program === "find" && c.args.some((a) => ["-exec", "-execdir", "-ok", "-okdir"].includes(a))) return { category: "network", reason: "find -exec runs a command that is not analyzed here" };
    if (SHELLS.has(c.program)) {
      const i = c.args.findIndex((a) => /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
      if (i >= 0) {
        const inner = c.args[i + 1];
        if (inner === undefined || depth >= 4) return { category: "network", reason: "nested shell code cannot be analyzed" };
        const r = bashRestriction(inner, ctx, depth + 1);
        if (r !== null) return r;
      }
    }
  }
  for (const c of commands) {
    for (const w of c.raw) {
      // `--opt=value` and `NAME=value`: the value; a bare option is not a path.
      const assigned = /^(?:--?[A-Za-z][A-Za-z0-9-]*|[A-Za-z_][A-Za-z0-9_]*)=/.exec(w);
      const value = assigned === null ? w : w.slice(assigned[0].length);
      if (value === "" || (assigned === null && value.startsWith("-")) || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)) continue;
      if (secretPath(absoluteOf(value, ctx), ctx)) return { category: "secrets", reason: "an argument names a secret, credential or guardrail state file" };
    }
  }
  return null;
}

/**
 * What a call would do that a tainted session must not: network egress (also `git push`), access to secrets or credential
 * files, a nested agent session, or running the release command. Null if nothing of that. Throws only on internal errors (the
 * caller fails closed).
 */
export function restrictionOf(tool: string, input: Record<string, unknown>, policy: TaintPolicy, ctx: ClassifyContext): Restriction | null {
  if (policy.restrictTools.some((p) => taintToolMatches(tool, p))) return { category: "network", reason: `the tool ${tool} can send data out of the session` };
  if (READ_TOOLS.has(tool) || WRITE_TOOLS.has(tool)) {
    for (const p of toolPaths(input)) {
      if (secretPath(absoluteOf(p, ctx), ctx)) return { category: "secrets", reason: "the path is a secret, credential or guardrail state file" };
    }
    return null;
  }
  if (tool !== "Bash") return null;
  const command = stringField(input, "command");
  if (command === undefined) return null;
  return bashRestriction(command, ctx, 0);
}

/** Why the result of this call is untrusted content, or null. */
export function sourceOf(tool: string, input: Record<string, unknown>, policy: TaintPolicy, ctx: ClassifyContext): TaintSource | null {
  if (policy.sourceTools.some((p) => taintToolMatches(tool, p))) return { kind: "tool", name: tool.slice(0, 128) };
  if (policy.readOutsideProject && READ_TOOLS.has(tool)) {
    for (const p of toolPaths(input)) {
      if (!inside(absoluteOf(p, ctx), ctx.projectDir)) return { kind: "read_outside_project", name: tool };
    }
  }
  if (tool !== "Bash") return null;
  const command = stringField(input, "command");
  if (command === undefined) return null;
  return bashSource(command, policy, ctx, 0);
}

/**
 * Source of a Bash command, with the same descent as `bashRestriction`: shell code after `-c` is analyzed; a wrapper whose
 * command is not analyzed (`xargs`, `find -exec`, `su -c`, `watch`, ...), a dynamic program name or an unknown git command line
 * counts as a source of unknown content (kind `bash_wrapper`).
 */
function bashSource(command: string, policy: TaintPolicy, ctx: ClassifyContext, depth: number): TaintSource | null {
  let commands: BashCommand[];
  try {
    commands = bashCommands(command);
  } catch {
    return null; // not parsable: the policy blocks it
  }
  if (policy.bashNetwork) {
    for (const c of commands) {
      if (c.program === null) continue;
      const busybox = c.program === "busybox" && BUSYBOX_NETWORK.has(c.args[0] ?? "");
      if (busybox || NETWORK_PROGRAMS.has(c.program) || (c.program === "git" && c.gitSub !== null && GIT_NETWORK.has(c.gitSub) && c.gitSub !== "push")) {
        return { kind: "bash_network", name: c.program.slice(0, 64) };
      }
      if (SHELLS.has(c.program)) {
        const i = c.args.findIndex((a) => /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
        if (i >= 0) {
          const inner = c.args[i + 1];
          if (inner === undefined || depth >= 4) return { kind: "bash_wrapper", name: c.program.slice(0, 64) };
          const r = bashSource(inner, policy, ctx, depth + 1);
          if (r !== null) return r;
        }
      }
      const wrapper = COMMAND_WRAPPERS.has(c.program) || (c.program === "find" && c.args.some((a) => ["-exec", "-execdir", "-ok", "-okdir"].includes(a)));
      if (wrapper || c.dynamic || (c.program === "git" && (c.gitConfig || (c.gitSub !== null && !GIT_KNOWN.has(c.gitSub))))) {
        return { kind: "bash_wrapper", name: c.program.slice(0, 64) };
      }
    }
  }
  if (policy.readOutsideProject) {
    for (const c of commands) {
      for (const w of c.args) {
        if (w.startsWith("-") || /^[A-Za-z]+:\/\//.test(w)) continue;
        if (!(w.startsWith("/") || w.startsWith("~") || w.startsWith("$HOME") || w.startsWith("${HOME}") || w.startsWith(".."))) continue;
        const abs = absoluteOf(w.replace(/[*?[{].*$/, "") || ".", ctx);
        if (!inside(abs, ctx.projectDir) && !SAFE_DEVICES.has(abs)) return { kind: "read_outside_project", name: (c.program ?? "bash").slice(0, 64) };
      }
    }
  }
  return null;
}


// --- state ----------------------------------------------------------------------------------------------------------

/** A source as stored: the kinds of `TaintSource`, or the state itself was missing or invalid (fail closed). */
export interface TaintSourceRecord {
  kind: SourceKind | "state_missing" | "state_invalid" | "inherited";
  name: string;
  at: string;
}

export interface TaintState {
  schema: typeof TAINT_SCHEMA;
  session_id: string;
  /** Random per state file; a release names it, so an old release never fits a new state. */
  epoch: string;
  status: "clean" | "tainted";
  /** Counts the transitions to `tainted`; a release names the value it releases. */
  taint_seq: number;
  created: string;
  updated: string;
  sources: TaintSourceRecord[];
  released: { at: string; via: "user" | "admin"; release_id: string } | null;
  mac: string;
}

export type StateProblem = "state_missing" | "state_invalid" | "key_missing" | "session_invalid";

export type TaintCheck =
  | { ok: true; state: TaintState; tainted: boolean }
  | { ok: false; problem: StateProblem; /** SHA-256 of the unusable file, if one was read (for the log). */ sha256: string | null };

export interface TaintRelease {
  schema: typeof TAINT_RELEASE_SCHEMA;
  id: string;
  session_id: string;
  uid: number;
  epoch: string;
  taint_seq: number;
  created: string;
  by_uid: number;
}

export class TaintError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TaintError";
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function exactKeys(v: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(v);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(v, k));
}

function validTimestamp(v: unknown): v is string {
  return typeof v === "string" && TIMESTAMP.test(v) && Number.isFinite(Date.parse(v));
}

const STATE_KEYS = ["schema", "session_id", "epoch", "status", "taint_seq", "created", "updated", "sources", "released", "mac"] as const;

/** Strict parser: exactly the fields of the schema; null if anything is off (the caller treats that as tainted). */
export function parseTaintState(text: string): TaintState | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw) || !exactKeys(raw, STATE_KEYS)) return null;
  if (raw.schema !== TAINT_SCHEMA || typeof raw.session_id !== "string" || !SESSION_PATTERN.test(raw.session_id)) return null;
  if (typeof raw.epoch !== "string" || !EPOCH.test(raw.epoch) || (raw.status !== "clean" && raw.status !== "tainted")) return null;
  if (typeof raw.taint_seq !== "number" || !Number.isSafeInteger(raw.taint_seq) || raw.taint_seq < 0) return null;
  if (!validTimestamp(raw.created) || !validTimestamp(raw.updated) || typeof raw.mac !== "string" || !HEX64.test(raw.mac)) return null;
  if (!Array.isArray(raw.sources) || raw.sources.length > MAX_SOURCES) return null;
  for (const s of raw.sources) {
    if (!isRecord(s) || !exactKeys(s, ["kind", "name", "at"])) return null;
    if (s.kind !== "tool" && s.kind !== "bash_network" && s.kind !== "bash_wrapper" && s.kind !== "read_outside_project" && s.kind !== "state_missing" && s.kind !== "state_invalid" && s.kind !== "inherited") return null;
    if (typeof s.name !== "string" || s.name.length > 128 || !validTimestamp(s.at)) return null;
  }
  if (raw.released !== null) {
    const r = raw.released;
    if (!isRecord(r) || !exactKeys(r, ["at", "via", "release_id"]) || !validTimestamp(r.at) || (r.via !== "user" && r.via !== "admin")) return null;
    if (typeof r.release_id !== "string" || !UUID.test(r.release_id)) return null;
  }
  if (raw.status === "tainted" && raw.taint_seq === 0) return null;
  return raw as unknown as TaintState;
}

const RELEASE_KEYS = ["schema", "id", "session_id", "uid", "epoch", "taint_seq", "created", "by_uid"] as const;

export function parseTaintRelease(text: string): TaintRelease | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw) || !exactKeys(raw, RELEASE_KEYS) || raw.schema !== TAINT_RELEASE_SCHEMA) return null;
  if (typeof raw.id !== "string" || !UUID.test(raw.id) || typeof raw.session_id !== "string" || !SESSION_PATTERN.test(raw.session_id)) return null;
  if (typeof raw.epoch !== "string" || !EPOCH.test(raw.epoch) || typeof raw.taint_seq !== "number" || !Number.isSafeInteger(raw.taint_seq) || raw.taint_seq < 1) return null;
  for (const k of ["uid", "by_uid"] as const) {
    const v = raw[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 4294967294) return null;
  }
  if (!validTimestamp(raw.created)) return null;
  return raw as unknown as TaintRelease;
}

export function serializeTaintRelease(r: TaintRelease): string {
  return `${canonicalJson(r)}\n`;
}

/** File name of a session: the session id is hashed (it may contain characters that are not good in file names). */
export function sessionFileName(sessionId: string): string {
  return `s-${sha256Hex(sessionId).slice(0, 40)}.json`;
}

export function releaseFileName(uid: number, sessionId: string): string {
  return `r-${uid}-${sha256Hex(sessionId).slice(0, 40)}.json`;
}

export interface StoreOptions {
  dir: string;
  uid: number | undefined;
  clock: () => Date;
  uuid: () => string;
  /** Random bytes (tests inject). */
  random?: (n: number) => Buffer;
}

function readBounded(path: string, max: number): Buffer | null {
  let fd: number;
  try {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || !info.isFile()) throw new TaintError("not a regular file");
    fd = openSync(path, constants.O_RDONLY | NOFOLLOW | NOCTTY);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw error instanceof TaintError ? error : new TaintError("file cannot be opened");
  }
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > max) throw new TaintError("file is not a small regular file");
    const bytes = Buffer.alloc(info.size);
    let off = 0;
    while (off < bytes.length) {
      const n = readSync(fd, bytes, off, bytes.length - off, off);
      if (n === 0) break;
      off += n;
    }
    return bytes.subarray(0, off);
  } finally {
    closeSync(fd);
  }
}

function writeAtomic(path: string, dir: string, data: string, random: (n: number) => Buffer): void {
  const tmp = join(dir, `.tmp-${random(8).toString("hex")}`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, 0o600);
    if (process.platform !== "win32") fchmodSync(fd, 0o600);
    const buf = Buffer.from(data, "utf8");
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
  } catch {
    if (fd !== undefined) closeSync(fd);
    rmSync(tmp, { force: true });
    throw new TaintError("state file cannot be written");
  }
}

/** Per-session taint state with HMAC. Every method throws `TaintError` on I/O problems; the hook fails closed. */
export class TaintStore {
  readonly dir: string;
  private readonly random: (n: number) => Buffer;

  constructor(private readonly opts: StoreOptions) {
    this.dir = opts.dir;
    this.random = opts.random ?? randomBytes;
  }

  private checkDir(create: boolean): boolean {
    let info;
    try {
      info = lstatSync(this.dir);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw new TaintError("state directory cannot be inspected");
      if (!create) return false;
      try {
        mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        if (process.platform !== "win32") chmodSync(this.dir, 0o700);
      } catch {
        throw new TaintError("state directory cannot be created");
      }
      info = lstatSync(this.dir);
    }
    if (info.isSymbolicLink() || !info.isDirectory()) throw new TaintError("state directory is a link or not a directory");
    if (this.opts.uid !== undefined && process.platform !== "win32" && info.uid !== this.opts.uid) throw new TaintError("state directory belongs to another user");
    if (process.platform !== "win32" && (info.mode & 0o077) !== 0) throw new TaintError("state directory is accessible by group or others");
    return true;
  }

  /** The key, or null if it does not exist. With `create`, a missing key is created (only at session start). */
  private key(create: boolean): Buffer | null {
    if (!this.checkDir(create)) return null;
    const path = join(this.dir, KEY_FILE);
    const bytes = readBounded(path, 256);
    if (bytes !== null) {
      const text = bytes.toString("utf8").trim();
      if (!HEX64.test(text)) throw new TaintError("key file is invalid");
      return Buffer.from(text, "hex");
    }
    if (!create) return null;
    const key = this.random(32);
    let fd: number | undefined;
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, 0o600);
      if (process.platform !== "win32") fchmodSync(fd, 0o600);
      writeSync(fd, `${key.toString("hex")}\n`);
      fsyncSync(fd);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return this.key(false);
      throw new TaintError("key file cannot be created");
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
    return key;
  }

  private mac(key: Buffer, state: Omit<TaintState, "mac">): string {
    return createHmac("sha256", key).update(canonicalJson(state)).digest("hex");
  }

  private sealed(key: Buffer, state: Omit<TaintState, "mac">): TaintState {
    return { ...state, mac: this.mac(key, state) };
  }

  /**
   * Exclusive lock of the state directory for one change (`O_CREAT|O_EXCL` on `.lock`, content: a random owner token): taint,
   * release and session start do not overwrite each other. A lock older than 10 s is taken over by renaming it away and checking
   * that the renamed file still holds the stale token (a fresh lock of another process that came in between is put back). The
   * lock is only removed by its owner (token compared). Throws on timeout.
   */
  private locked<T>(fn: () => T): T {
    const lock = join(this.dir, ".lock");
    const token = this.random(16).toString("hex");
    const deadline = Date.now() + 2000;
    for (;;) {
      let fd: number | undefined;
      try {
        fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, 0o600);
        writeSync(fd, token);
        closeSync(fd);
        break;
      } catch (error) {
        if (fd !== undefined) closeSync(fd);
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new TaintError("state lock cannot be created");
        this.takeOverStale(lock);
        if (Date.now() > deadline) throw new TaintError("state lock timeout");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      return fn();
    } finally {
      try {
        const held = readBounded(lock, 256);
        if (held !== null && held.toString("utf8") === token) rmSync(lock, { force: true });
      } catch {
        // not ours or unreadable: leave it; it becomes stale after 10 s
      }
    }
  }

  private takeOverStale(lock: string): void {
    try {
      const info = lstatSync(lock);
      if (Date.now() - info.mtimeMs <= 10_000) return;
      const stale = readBounded(lock, 256)?.toString("utf8") ?? "";
      const aside = join(this.dir, `.lock-stale-${this.random(8).toString("hex")}`);
      renameSync(lock, aside);
      const moved = readBounded(aside, 256)?.toString("utf8") ?? "";
      if (moved !== stale) {
        // Another process took the lock in between: give it back (fails only if a third one holds it already).
        try {
          linkSync(aside, lock);
        } catch {
          // the lock is taken again; that owner stays
        }
      }
      rmSync(aside, { force: true });
    } catch {
      // gone in between or unreadable: try again
    }
  }

  private path(sessionId: string): string {
    return join(this.dir, sessionFileName(sessionId));
  }

  private write(state: TaintState): void {
    writeAtomic(this.path(state.session_id), this.dir, `${canonicalJson(state)}\n`, this.random);
  }

  /** Reads and verifies the state of a session. Missing or bad state, key or session id: `ok: false` (= tainted). */
  check(sessionId: string): TaintCheck {
    if (!SESSION_PATTERN.test(sessionId)) return { ok: false, problem: "session_invalid", sha256: null };
    const key = this.key(false);
    if (key === null) return { ok: false, problem: "key_missing", sha256: null };
    let bytes: Buffer | null;
    try {
      bytes = readBounded(this.path(sessionId), MAX_STATE_BYTES);
    } catch {
      return { ok: false, problem: "state_invalid", sha256: null };
    }
    if (bytes === null) return { ok: false, problem: "state_missing", sha256: null };
    const state = parseTaintState(bytes.toString("utf8"));
    const sha = sha256Hex(bytes);
    if (state === null || state.session_id !== sessionId) return { ok: false, problem: "state_invalid", sha256: sha };
    const { mac, ...rest } = state;
    const expected = Buffer.from(this.mac(key, rest), "hex");
    if (!timingSafeEqual(expected, Buffer.from(mac, "hex"))) return { ok: false, problem: "state_invalid", sha256: sha };
    return { ok: true, state, tainted: state.status === "tainted" };
  }

  /**
   * Session start: creates the key if needed. An existing state (also a bad one) is kept as it is. A missing state becomes clean
   * only for a new session (`fresh`: source `startup` or `clear`); for a resumed or compacted session the history is unknown, so
   * a missing state becomes tainted (`taint` with kind `state_missing`, outcome `tainted_missing`).
   */
  init(sessionId: string, fresh: boolean): { outcome: "created" | "existing" | "tainted_missing" | "session_invalid"; check: TaintCheck } {
    if (!SESSION_PATTERN.test(sessionId)) return { outcome: "session_invalid", check: { ok: false, problem: "session_invalid", sha256: null } };
    this.checkDir(true);
    return this.locked(() => this.initUnlocked(sessionId, fresh));
  }

  private initUnlocked(sessionId: string, fresh: boolean): { outcome: "created" | "existing" | "tainted_missing" | "session_invalid"; check: TaintCheck } {
    const key = this.key(true) as Buffer;
    if (readBounded(this.path(sessionId), MAX_STATE_BYTES) !== null) return { outcome: "existing", check: this.check(sessionId) };
    if (!fresh) {
      const t = this.taintUnlocked(sessionId, { kind: "state_missing", name: "resume", at: this.opts.clock().toISOString() });
      return { outcome: "tainted_missing", check: { ok: true, state: t.state, tainted: true } };
    }
    const now = this.opts.clock().toISOString();
    const state = this.sealed(key, { schema: TAINT_SCHEMA, session_id: sessionId, epoch: this.random(16).toString("hex"), status: "clean", taint_seq: 0, created: now, updated: now, sources: [], released: null });
    this.write(state);
    return { outcome: "created", check: { ok: true, state, tainted: false } };
  }

  /**
   * Marks the session tainted. A clean state becomes tainted (`taint_seq + 1`); a tainted one only records the source. A missing
   * or bad state is replaced by a new tainted state with a fresh epoch (tightening only; the old content's hash goes into the log).
   * Returns the state and whether this call changed clean into tainted.
   */
  taint(sessionId: string, source: TaintSourceRecord): { state: TaintState; transition: boolean; previous: "clean" | "tainted" | StateProblem } {
    if (!SESSION_PATTERN.test(sessionId)) throw new TaintError("invalid session id");
    this.checkDir(true);
    return this.locked(() => this.taintUnlocked(sessionId, source));
  }

  private taintUnlocked(sessionId: string, source: TaintSourceRecord): { state: TaintState; transition: boolean; previous: "clean" | "tainted" | StateProblem } {
    const check = this.check(sessionId);
    const key = this.key(check.ok ? false : true);
    if (key === null) throw new TaintError("key missing");
    const now = this.opts.clock().toISOString();
    const record: TaintSourceRecord = { kind: source.kind, name: source.name.slice(0, 128), at: source.at };
    if (check.ok) {
      const s = check.state;
      const sources = [...s.sources, record].slice(-MAX_SOURCES);
      const next = this.sealed(key, { ...withoutMac(s), status: "tainted", taint_seq: s.status === "clean" ? s.taint_seq + 1 : s.taint_seq, updated: now, sources });
      this.write(next);
      return { state: next, transition: s.status === "clean", previous: s.status };
    }
    const next = this.sealed(key, { schema: TAINT_SCHEMA, session_id: sessionId, epoch: this.random(16).toString("hex"), status: "tainted", taint_seq: 1, created: now, updated: now, sources: [record], released: null });
    this.write(next);
    return { state: next, transition: true, previous: check.problem };
  }

  /** Lifts the taint of exactly (`epoch`, `taint_seq`). Throws if the state changed in between (a new taint needs a new release). */
  release(sessionId: string, epoch: string, taintSeq: number, via: "user" | "admin", releaseId: string): TaintState {
    // Check and write under the lock: a taint that arrives in between is never overwritten by the release.
    if (!this.checkDir(false)) throw new TaintError("the state is unusable (key_missing)");
    return this.locked(() => this.releaseUnlocked(sessionId, epoch, taintSeq, via, releaseId));
  }

  private releaseUnlocked(sessionId: string, epoch: string, taintSeq: number, via: "user" | "admin", releaseId: string): TaintState {
    const check = this.check(sessionId);
    if (!check.ok) throw new TaintError(`the state is unusable (${check.problem})`);
    const s = check.state;
    if (s.status !== "tainted") throw new TaintError("the session is not tainted");
    if (s.epoch !== epoch || s.taint_seq !== taintSeq) throw new TaintError("the state changed since the release was prepared; check the status again");
    const key = this.key(false);
    if (key === null) throw new TaintError("key missing");
    const now = this.opts.clock().toISOString();
    const next = this.sealed(key, { ...withoutMac(s), status: "clean", updated: now, released: { at: now, via, release_id: releaseId } });
    this.write(next);
    return next;
  }
}

function withoutMac(s: TaintState): Omit<TaintState, "mac"> {
  const rest: Partial<TaintState> = { ...s };
  delete rest.mac;
  return rest as Omit<TaintState, "mac">;
}

/** Directory of the taint state: `<home>/.local/state/tollgate/taint` in enterprise mode (fixed), else `<private log dir>/taint`. */
export function taintStateDir(privateDir: string): string {
  return join(privateDir, "taint");
}

/** Reads the enterprise release of a session (root-owned file). Null if there is none or it is not trustworthy. */
export function readAdminRelease(uid: number, sessionId: string, opts: { dir?: string; ownerUid?: number; stopAt?: string | undefined } = {}): TaintRelease | null {
  const path = join(opts.dir ?? TAINT_RELEASE_DIR, releaseFileName(uid, sessionId));
  const trusted = readTrustedFile(path, { ownerUid: opts.ownerUid ?? 0, stopAt: opts.stopAt, what: "taint release" });
  if (!trusted.ok) return null;
  const release = parseTaintRelease(trusted.text);
  if (release === null || release.uid !== uid || release.session_id !== sessionId) return null;
  return release;
}
