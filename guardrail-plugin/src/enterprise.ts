// Enterprise mode: detection, the admin-owned policy (version 2), the merge with
// lower layers (only tightening), checks of the project directory and the always-protected system paths.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, posix, resolve } from "node:path";
import { z } from "zod";
import { validGlob, type Match } from "./matchers.js";
import { ENTERPRISE_DEFAULTS, type LogSettings } from "./events/settings.js";
import { enterpriseLayout, userProtectedDirs, type Layout, type LocationEnv } from "./events/layout.js";
import type { PolicyFinding } from "./events/logger.js";
import { BUNDLED_POLICY_PATH, parsePolicy, PROJECT_POLICY_FILE, type Policy, type Rule } from "./policy.js";
import { mergeTaint, TAINT_OFF, TaintSectionSchema, taintFromSection, type TaintPolicy } from "./taintPolicy.js";
import { TOOL_PATTERN } from "./vendor/locks.js";

/**
 * Build switch of the macOS enterprise mode (activated only after the acceptance test has passed). A constant in the build, never an
 * environment variable: while it is `false`, the signal on macOS ends in `enterprise_unsupported_platform` (fail closed).
 * A human sets it to `true` once the acceptance on real hardware (`docs/abnahme-macos.md` of the enterprise package) passed.
 * Rollback: set it back to `false` and release the plugin.
 */
export const MACOS_ENTERPRISE_ACCEPTED = false;

/** The administrators' group on macOS (gid 80, `admin`). */
export const MACOS_ADMIN_GID = 80;
/** The only parent directories whose group write access for gid 80 is tolerated and reported. */
export const MACOS_ADMIN_PARENTS: readonly string[] = ["/Library", "/Library/Application Support"];
/** The root-owned Node of the enterprise package (the hook must not run on a user-writable Node). */
export const MACOS_NODE_PREFIX = "/Library/Application Support/TollGate/node/";

export const MAX_POLICY_BYTES = 64 * 1024;
export const MAX_RULES = 200;
export const MAX_PATTERN = 500;

export interface EnterprisePaths {
  adminDir: string;
  policyFile: string;
}

/** Fixed locations of the admin-owned policy. macOS is reserved (inactive); Windows uses a constant root. */
export function enterprisePaths(platform: NodeJS.Platform): EnterprisePaths {
  if (platform === "darwin") {
    return { adminDir: "/Library/Application Support/TollGate", policyFile: "/Library/Application Support/TollGate/policy.json" };
  }
  if (platform === "win32") return { adminDir: "C:\\ProgramData\\TollGate", policyFile: "C:\\ProgramData\\TollGate\\policy.json" };
  return { adminDir: "/etc/tollgate", policyFile: "/etc/tollgate/policy.json" };
}

export interface EnterpriseSignal {
  active: boolean;
  /** `admin_dir`: the admin-owned directory exists; `env`: `TOLLGATE_ENTERPRISE=1`. */
  reasons: ("admin_dir" | "env")[];
}

function pathExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/** Two signals activate the mode. Without either, the previous (fail-open) behaviour stays. */
export function detectEnterprise(env: NodeJS.ProcessEnv, platform: NodeJS.Platform, exists: (path: string) => boolean = pathExists): EnterpriseSignal {
  const reasons: EnterpriseSignal["reasons"] = [];
  if (exists(enterprisePaths(platform).adminDir)) reasons.push("admin_dir");
  if (env.TOLLGATE_ENTERPRISE === "1") reasons.push("env");
  return { active: reasons.length > 0, reasons };
}

// --- trusted file ---------------------------------------------------------------------------------------------------

export interface TrustOptions {
  /** Required owner of the file and of every directory above it (root). */
  ownerUid: number;
  /** Directory at which the walk upwards ends (exclusive); default: the file system root, which is checked too. */
  stopAt?: string | undefined;
  /**
   * macOS only: parent directories (exact paths) whose group write access is tolerated if the group is `gid`
   * and others cannot write. A tolerated parent is reported in `notes`. Everything else stays strict.
   */
  groupWritableParents?: { paths: readonly string[]; gid: number } | undefined;
  /** macOS only: asked for the directory and the file; any answer other than "none" is refused (fail closed). */
  aclProbe?: AclProbe | undefined;
  /** Name of the file in the refusal reasons (default "policy file"). */
  what?: string | undefined;
}

export type TrustedRead = { ok: true; text: string; sha256: string; notes: string[] } | { ok: false; reason: string };

/** Result of the ACL probe: no ACL, an ACL, or the probe itself failed (treated as unsafe). */
export type AclResult = "none" | "acl" | "error";
export type AclProbe = (path: string) => AclResult;

/**
 * Reads the output of `/bin/ls -lde <path>` (macOS): an ACL shows as a `+` after the mode string and as numbered
 * entry lines below the first line. Anything that is not one entry line for the path is `error`. Format [V: VM2, Mac].
 */
export function parseLsAcl(stdout: string): AclResult {
  const lines = stdout.split("\n").filter((l) => l.trim() !== "");
  const first = lines[0];
  if (first === undefined || !/^[-dlbcpsw?][-rwxsStT@+.]{8,12}[ \t]/.test(first)) return "error";
  const mode = first.split(/[ \t]/)[0] as string;
  if (mode.includes("+") || lines.slice(1).some((l) => /^\s*[0-9]+:\s/.test(l))) return "acl";
  return lines.length === 1 ? "none" : "error";
}

/** Probe with the system `ls`: absolute program, empty environment, no shell, short time limit. A missing `ls` is `error`. */
export const systemAclProbe: AclProbe = (path) => {
  try {
    const out = execFileSync("/bin/ls", ["-lde", path], { env: {}, encoding: "utf8", timeout: 5000, maxBuffer: 64 * 1024, stdio: ["ignore", "pipe", "ignore"], shell: false });
    return parseLsAcl(out);
  } catch {
    return "error";
  }
};

function unsafeMode(mode: number): boolean {
  return (mode & 0o022) !== 0;
}

function readAll(fd: number, size: number): Buffer {
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < buffer.length) {
    const n = readSync(fd, buffer, offset, buffer.length - offset, offset);
    if (n === 0) break;
    offset += n;
  }
  return buffer.subarray(0, offset);
}

/**
 * Reads a policy file of a lower level (or the default). Same hardening as `readTrustedFile` for the file itself, without the
 * owner checks: no symbolic link as the last path component, no blocking on a FIFO or device, only a regular file, at most
 * 64 KiB. Throws if the file is not acceptable (the callers fail closed).
 */
function fileSha(path: string): { text: string; sha256: string } {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error("not a regular file");
    if (info.size > MAX_POLICY_BYTES) throw new Error("file is larger than 64 KiB");
    const bytes = readAll(fd, info.size);
    return { text: bytes.toString("utf8"), sha256: createHash("sha256").update(bytes).digest("hex") };
  } finally {
    closeSync(fd);
  }
}

/**
 * Reads an admin-owned file. Refused: a symlink anywhere on the path, an owner other than `ownerUid` for the file or any
 * parent directory, group or world write access on any of them, a hard-linked or non-regular file, a file over 64 KiB.
 */
export function readTrustedFile(path: string, options: TrustOptions): TrustedRead {
  const notes: string[] = [];
  const what = options.what ?? "policy file";
  try {
    let dir = dirname(path);
    for (;;) {
      if (options.stopAt !== undefined && dir === resolve(options.stopAt)) break;
      const info = lstatSync(dir);
      if (info.isSymbolicLink() || !info.isDirectory()) return { ok: false, reason: "a parent directory is a link or not a directory" };
      if (info.uid !== options.ownerUid) return { ok: false, reason: "a parent directory is not owned by the administrator" };
      if (unsafeMode(info.mode)) {
        const tolerated = options.groupWritableParents;
        const onlyGroup = (info.mode & 0o002) === 0 && info.gid === tolerated?.gid && tolerated.paths.includes(dir);
        if (!onlyGroup) return { ok: false, reason: "a parent directory is writable by group or others" };
        notes.push("parent_admin_writable");
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    const pre = lstatSync(path);
    if (pre.isSymbolicLink()) return { ok: false, reason: `the ${what} is a symbolic link` };
    if (options.aclProbe !== undefined) {
      for (const target of [dirname(path), path]) if (options.aclProbe(target) !== "none") return { ok: false, reason: "an access control list is set or cannot be ruled out" };
    }
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const info = fstatSync(fd);
      if (!info.isFile() || info.nlink !== 1) return { ok: false, reason: `the ${what} is not a regular file with a single link` };
      if (info.uid !== options.ownerUid) return { ok: false, reason: `the ${what} is not owned by the administrator` };
      if (unsafeMode(info.mode)) return { ok: false, reason: `the ${what} is writable by group or others` };
      if (info.size > MAX_POLICY_BYTES) return { ok: false, reason: `the ${what} is larger than 64 KiB` };
      const bytes = readAll(fd, info.size);
      return { ok: true, text: bytes.toString("utf8"), sha256: createHash("sha256").update(bytes).digest("hex"), notes };
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return { ok: false, reason: code === "ENOENT" ? `the ${what} does not exist` : `the ${what} cannot be read safely` };
  }
}

// --- schemas --------------------------------------------------------------------------------------------------------

const LoggingSchema = z
  .object({
    enabled: z.boolean().optional(),
    layout: z.enum(["per_user", "shared"]).optional(),
    tools: z.enum(["all", "checked"]).optional(),
    commandDetail: z.enum(["none", "hash", "redacted"]).optional(),
    commandHash: z.boolean().optional(),
    projectDir: z.boolean().optional(),
    onWriteError: z.enum(["block", "warn"]).optional(),
    rateLimit: z.number().int().min(0).max(100_000).optional(),
  })
  .optional();

// TOOL_PATTERN (a tool name or `mcp__<server>__*`, no other wildcard) comes from the locks module: the same rule names tools in locks.

const ToolsSchema = z
  .object({
    unchecked: z.enum(["observe", "deny"]).default("deny"),
    allow: z.array(z.string().regex(TOOL_PATTERN)).max(MAX_RULES).default([]),
  })
  .strict();

const DependenciesSchema = z.object({ npm: z.array(z.string().max(214)).max(5000), pypi: z.array(z.string().max(214)).max(5000) });

const EnterprisePolicySchema = z.object({
  version: z.literal(2),
  revision: z.string().min(1).max(128),
  protectedPaths: z.array(z.string().min(1).max(MAX_PATTERN)).max(MAX_RULES).default([]),
  blockedCommands: z
    .array(z.object({ id: z.string().min(1).max(64), pattern: z.string().min(1).max(MAX_PATTERN), reason: z.string().min(1).max(500) }))
    .max(MAX_RULES)
    .default([]),
  allowedDependencies: DependenciesSchema,
  logging: LoggingSchema,
  humanSession: z.object({ allowed: z.boolean() }).optional(),
  project: z.object({ mode: z.enum(["tighten", "ignore"]) }).optional(),
  tools: ToolsSchema.optional(),
  forwarding: z.unknown().optional(),
  /** Admin locks: the lock file counts only if the enterprise policy switches this on. */
  control: z.object({ enabled: z.boolean() }).optional(),
  /** Session taint. Absent: the bundled default decides. */
  taint: TaintSectionSchema.optional(),
});

const MatchSchema = z.union([
  z.object({ literal: z.string().min(1).max(MAX_PATTERN) }).strict(),
  z.object({ tokens: z.array(z.string().min(1).max(200)).min(1).max(16) }).strict(),
  z.object({ glob: z.string().min(1).max(MAX_PATTERN) }).strict(),
]);

const LowerLayerSchema = z.object({
  version: z.union([z.literal(1), z.literal(2)]),
  protectedPaths: z.array(z.string().min(1).max(MAX_PATTERN)).max(MAX_RULES).default([]),
  blockedCommands: z
    .array(
      z.object({
        id: z.string().min(1).max(64).optional(),
        pattern: z.string().min(1).max(MAX_PATTERN).optional(),
        match: MatchSchema.optional(),
        reason: z.string().min(1).max(500),
      }),
    )
    .max(MAX_RULES)
    .default([]),
  allowedDependencies: DependenciesSchema.optional(),
  logging: z.unknown().optional(),
  humanSession: z.unknown().optional(),
  project: z.unknown().optional(),
  tools: z.unknown().optional(),
  forwarding: z.unknown().optional(),
  control: z.unknown().optional(),
  /** Session taint: lower layers can only tighten (`mergeTaint`). */
  taint: TaintSectionSchema.optional(),
});

/** Tools that are not checked by the hook (everything except Bash and the write tools). */
export interface UncheckedToolPolicy {
  /** `observe`: record only (default, as before). `deny`: block every unchecked tool that is not on `allow`. */
  mode: "observe" | "deny";
  allow: string[];
}

/**
 * Tools that are on the allowlist in enterprise mode whatever the policy says (unless the policy sets `unchecked: "observe"`): read-only
 * search and listing tools, the task list and subagents. Names are taken from the Claude Code tool list; `LS` and `Task` are not in the
 * current tools reference (older names) and are kept for older versions. WebFetch, WebSearch and every MCP tool need an entry.
 */
export const BASE_UNCHECKED_ALLOW: readonly string[] = [
  "Read",
  "Glob",
  "Grep",
  "LS",
  "TodoWrite",
  "Task",
  "Agent",
  // Coordination tools without file, process or network access. SubagentHandback is how a subagent returns its result;
  // without it every Agent/Task call fails in enterprise mode (seen in the WSL acceptance test, 2026-10-18).
  "SubagentHandback",
  "AskUserQuestion",
  "EnterPlanMode",
  "ExitPlanMode",
  "TaskCreate",
  "TaskGet",
  "TaskList",
  "TaskUpdate",
  "ToolSearch",
];

export interface EnterprisePolicy {
  revision: string;
  protectedPaths: string[];
  blockedCommands: { id: string; pattern: string; reason: string }[];
  allowedDependencies: { npm: string[]; pypi: string[] };
  logging: LogSettings;
  humanSessionAllowed: boolean;
  projectMode: "tighten" | "ignore";
  uncheckedTools: UncheckedToolPolicy;
  /** Admin locks. Without the section the lock file is ignored. */
  control: { enabled: boolean };
  /** Session taint; null if the enterprise policy has no section (then the bundled default applies). */
  taint: TaintPolicy | null;
}

/** True if the tool may run under `policy`: always in `observe` mode, else only if named exactly or covered by `mcp__<server>__*`. */
export function uncheckedToolAllowed(name: string, policy: UncheckedToolPolicy): boolean {
  if (policy.mode !== "deny") return true;
  return policy.allow.some((entry) => {
    if (!entry.endsWith("__*")) return name === entry;
    const prefix = entry.slice(0, -1);
    if (!name.startsWith(prefix)) return false;
    const rest = name.slice(prefix.length);
    // The tool part must not contain "__": `mcp__a__x__t` is server `a__x`, tool `t` (or server `a`, tool `x__t`), which is not decidable.
    return rest.length > 0 && !rest.includes("__");
  });
}

/** Parses the enterprise policy (version 2). Throws on invalid structure, regular expressions or duplicate ids. */
export function parseEnterprisePolicy(text: string): EnterprisePolicy {
  const raw = EnterprisePolicySchema.parse(JSON.parse(text));
  const ids = new Set<string>();
  for (const rule of raw.blockedCommands) {
    new RegExp(rule.pattern); // fail early on invalid patterns
    if (ids.has(rule.id)) throw new Error("duplicate rule id");
    ids.add(rule.id);
  }
  const l = raw.logging ?? {};
  const logging: LogSettings = {
    enabled: l.enabled ?? ENTERPRISE_DEFAULTS.enabled,
    layout: l.layout ?? ENTERPRISE_DEFAULTS.layout,
    tools: l.tools ?? ENTERPRISE_DEFAULTS.tools,
    commandDetail: l.commandDetail ?? ENTERPRISE_DEFAULTS.commandDetail,
    commandHash: l.commandHash ?? ENTERPRISE_DEFAULTS.commandHash,
    projectDir: l.projectDir ?? ENTERPRISE_DEFAULTS.projectDir,
    onWriteError: l.onWriteError ?? ENTERPRISE_DEFAULTS.onWriteError,
    rateLimit: l.rateLimit ?? ENTERPRISE_DEFAULTS.rateLimit,
  };
  return {
    revision: raw.revision,
    protectedPaths: raw.protectedPaths,
    blockedCommands: raw.blockedCommands,
    allowedDependencies: raw.allowedDependencies,
    logging,
    humanSessionAllowed: raw.humanSession?.allowed === true,
    projectMode: raw.project?.mode ?? "tighten",
    // Default in enterprise mode: deny with the base allowlist, also if the section is missing. `observe` is an explicit opt-out.
    uncheckedTools: { mode: raw.tools?.unchecked ?? "deny", allow: [...new Set([...BASE_UNCHECKED_ALLOW, ...(raw.tools?.allow ?? [])])] },
    control: { enabled: raw.control?.enabled === true },
    taint: raw.taint === undefined ? null : taintFromSection(raw.taint),
  };
}

export interface LowerLayer {
  level: "project" | "explicit";
  protectedPaths: string[];
  blockedCommands: Rule[];
  allowedDependencies?: { npm: string[]; pypi: string[] };
  taint?: TaintPolicy;
}

/**
 * Parses a lower layer (project policy, `TOLLGATE_POLICY`) in enterprise mode. Only the safe subset counts: regular
 * expression rules are ignored (finding `policy_error`), sections that only the enterprise policy may set are ignored
 * (finding `policy_override_ignored`). Throws if the file is not a policy at all.
 */
export function parseLowerLayer(text: string, level: LowerLayer["level"]): { layer: LowerLayer; findings: PolicyFinding[] } {
  const raw = LowerLayerSchema.parse(JSON.parse(text));
  const findings: PolicyFinding[] = [];
  const rules: Rule[] = [];
  for (const [i, rule] of raw.blockedCommands.entries()) {
    const label = rule.id ?? `blockedCommands[${i}]`;
    if (rule.match === undefined) {
      findings.push({ type: "policy_error", level, id: label, detail: "regular expression rules are not allowed on this level; use literal, tokens or glob" });
      continue;
    }
    if ("glob" in rule.match && !validGlob(rule.match.glob)) {
      findings.push({ type: "policy_error", level, id: label, detail: "glob with more than two '*' is ignored" });
      continue;
    }
    rules.push({ id: rule.id, match: rule.match as Match, reason: rule.reason });
  }
  for (const key of ["logging", "humanSession", "project", "tools", "forwarding", "control"] as const) {
    if (raw[key] !== undefined) findings.push({ type: "policy_override_ignored", level, detail: `section '${key}' is only valid in the enterprise policy` });
  }
  const layer: LowerLayer = { level, protectedPaths: raw.protectedPaths, blockedCommands: rules };
  if (raw.allowedDependencies !== undefined) layer.allowedDependencies = raw.allowedDependencies;
  if (raw.taint !== undefined) {
    if (raw.taint.release !== undefined) findings.push({ type: "policy_override_ignored", level, detail: "taint.release is only valid in the enterprise policy" });
    layer.taint = { ...taintFromSection(raw.taint), release: "admin" };
  }
  return { layer, findings };
}

// --- merge ----------------------------------------------------------------------------------------------------------

function union(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])];
}

/**
 * Merges the layers, tightening only. Order: enterprise, bundled default (trusted, regular expressions allowed), then
 * the lower layers. Protected paths and command rules are united (the first rule with an id wins, later rules with
 * the same id are ignored and reported), allowed dependencies are the intersection of the enterprise policy and every
 * lower layer that sets them. Never loosens: the result blocks at least what each input blocks.
 */
export function mergePolicies(
  enterprise: Pick<EnterprisePolicy, "protectedPaths" | "allowedDependencies"> & {
    blockedCommands: { id?: string | undefined; pattern: string; reason: string }[];
    /** Taint of the top layer; null or absent: the taint of `base` applies. Lower layers can only tighten it. */
    taint?: TaintPolicy | null | undefined;
  },
  base: Policy,
  lowers: readonly LowerLayer[],
  topLevel = "enterprise",
): { policy: Policy; findings: PolicyFinding[] } {
  const findings: PolicyFinding[] = [];
  const seen = new Set<string>();
  const rules: Rule[] = [];
  const add = (rule: Rule, level: string): void => {
    if (rule.id !== undefined) {
      if (seen.has(rule.id)) {
        findings.push({ type: "policy_override_ignored", level, id: rule.id, detail: "a rule with this id already exists on a higher level" });
        return;
      }
      seen.add(rule.id);
    }
    rules.push(rule);
  };
  for (const r of enterprise.blockedCommands) add({ id: r.id, pattern: r.pattern, reason: r.reason }, topLevel);
  for (const [i, r] of base.blockedCommands.entries()) add({ id: r.id ?? `default-${i}`, pattern: r.pattern, reason: r.reason }, "default");
  let protectedPaths = union(enterprise.protectedPaths, base.protectedPaths);
  let npm = [...enterprise.allowedDependencies.npm];
  let pypi = [...enterprise.allowedDependencies.pypi];
  let taint: TaintPolicy | undefined = enterprise.taint ?? base.taint;
  for (const lower of lowers) {
    if (lower.taint !== undefined) taint = mergeTaint(taint ?? TAINT_OFF, lower.taint);
    protectedPaths = union(protectedPaths, lower.protectedPaths);
    for (const r of lower.blockedCommands) add(r, lower.level);
    if (lower.allowedDependencies !== undefined) {
      const extraNpm = lower.allowedDependencies.npm.filter((n) => !npm.includes(n));
      const extraPypi = lower.allowedDependencies.pypi.filter((n) => !pypi.includes(n));
      if (extraNpm.length + extraPypi.length > 0) {
        findings.push({ type: "policy_override_ignored", level: lower.level, detail: "dependencies that the enterprise policy does not allow are ignored" });
      }
      npm = npm.filter((n) => lower.allowedDependencies?.npm.includes(n));
      pypi = pypi.filter((n) => lower.allowedDependencies?.pypi.includes(n));
    }
  }
  const policy: Policy = { version: 1, protectedPaths, blockedCommands: rules, allowedDependencies: { npm, pypi } };
  if (taint !== undefined) policy.taint = taint;
  return { policy, findings };
}

// --- resolution -----------------------------------------------------------------------------------------------------

export interface PolicyLayerInfo {
  level: "default" | "enterprise" | "project" | "explicit";
  sha256: string;
}

/** Where the admin locks live. */
export const LOCKS_FILE = "/var/lib/tollgate/control/locks.json";

export interface Resolved {
  policy: Policy;
  /** Active policy file of the previous behaviour (protected for agents). */
  policyFile?: string | undefined;
  /** More policy files that are protected for agents. */
  protectedFiles: string[];
  layers: PolicyLayerInfo[];
  revision: string | null;
  findings: PolicyFinding[];
  enterprise: { policy: EnterprisePolicy; settings: LogSettings } | null;
}

export type Resolution = ({ ok: true } & Resolved) | { ok: false; kind: "policy_error" | "enterprise_unsupported_platform"; message: string };

export interface ResolveOptions {
  env: NodeJS.ProcessEnv;
  projectDir: string;
  platform: NodeJS.Platform;
  /** Owner required for the enterprise policy and its parent directories (root = 0). */
  ownerUid?: number;
  stopAt?: string | undefined;
  /** Existence probe for the enterprise signal only (default: the file system). */
  exists?: (path: string) => boolean;
  /** Where the enterprise policy lives (default: `enterprisePaths(platform)`). */
  paths?: EnterprisePaths;
  /** The bundled default policy (default: the file shipped with the plugin; injectable for tests). */
  bundledPolicy?: string;
  /** macOS only. Default: the build switch `MACOS_ENTERPRISE_ACCEPTED`. Tests set it; production never does. */
  macosAccepted?: boolean;
  /** macOS only: ACL probe (default: `/bin/ls -lde`). */
  aclProbe?: AclProbe;
  /** macOS only: tolerated group-writable parents (default: `/Library`, `/Library/Application Support` for gid 80). */
  groupWritableParents?: { paths: readonly string[]; gid: number };
  /** macOS only: path of the running Node binary (default `process.execPath`) and the prefix it must live in. */
  execPath?: string;
  nodePrefix?: string;
}

/** Why the Node binary is not acceptable on macOS, or null. The hook must run on the root-owned Node. */
export function nodeBinaryProblem(execPath: string, prefix: string, ownerUid: number, aclProbe: AclProbe = systemAclProbe): string | null {
  try {
    const real = realpathSync(execPath);
    if (!real.startsWith(prefix)) return "the hook does not run on the root-owned Node of the enterprise package";
    const info = lstatSync(real);
    if (!info.isFile() || info.uid !== ownerUid || unsafeMode(info.mode)) return "the Node binary is not owned by the administrator or is writable by group or others";
    if (aclProbe(real) !== "none") return "an access control list is set on the Node binary or cannot be ruled out";
    // Every directory from the binary up to the package's node directory: real directory, owner, mode, no ACL.
    const top = prefix.replace(/\/+$/, "");
    for (let dir = dirname(real); ; dir = dirname(dir)) {
      const d = lstatSync(dir);
      if (d.isSymbolicLink() || !d.isDirectory() || d.uid !== ownerUid || unsafeMode(d.mode)) return "a directory of the Node binary is not owned by the administrator or is writable by group or others";
      if (aclProbe(dir) !== "none") return "an access control list is set on a directory of the Node binary or cannot be ruled out";
      if (dir === top || dirname(dir) === dir) break;
    }
    return null;
  } catch {
    return "the Node binary cannot be checked";
  }
}

/** The directory that makes the signal on macOS: a real directory owned by the administrator, not writable by others. */
function adminDirProblem(adminDir: string, ownerUid: number, aclProbe: AclProbe): string | null {
  let info;
  try {
    info = lstatSync(adminDir);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT" ? null : "the administrator directory cannot be read safely";
  }
  if (info.isSymbolicLink() || !info.isDirectory()) return "the administrator directory is a link or not a directory";
  if (info.uid !== ownerUid) return "the administrator directory is not owned by the administrator";
  if (unsafeMode(info.mode)) return "the administrator directory is writable by group or others";
  if (aclProbe(adminDir) !== "none") return "an access control list is set on the administrator directory or cannot be ruled out";
  return null;
}


const UNSUPPORTED_MACOS = "Unternehmensmodus auf macOS nicht unterstützt / Enterprise mode is not supported on macOS.";

/**
 * Resolves the effective policy. Without an enterprise signal: project policy > bundled default; `TOLLGATE_POLICY` is
 * only a further layer that can tighten (same merge as the lower layers in enterprise mode, `policy_override_ignored`
 * for what it tries to loosen). With a signal: fail closed if the enterprise policy is missing or unsafe, and merge the layers.
 */
export function resolvePolicy(options: ResolveOptions): Resolution {
  const signal = detectEnterprise(options.env, options.platform, options.exists);
  if (!signal.active) return resolveStandalone(options);
  const darwin = options.platform === "darwin";
  if (darwin && !(options.macosAccepted ?? MACOS_ENTERPRISE_ACCEPTED)) return { ok: false, kind: "enterprise_unsupported_platform", message: UNSUPPORTED_MACOS };
  if (options.platform === "win32") {
    return { ok: false, kind: "policy_error", message: "enterprise policy: the access rights on Windows cannot be verified by this version (fail closed)." };
  }
  const paths = options.paths ?? enterprisePaths(options.platform);
  const ownerUid = options.ownerUid ?? 0;
  const aclProbe = options.aclProbe ?? systemAclProbe;
  if (darwin) {
    const problem = adminDirProblem(paths.adminDir, ownerUid, aclProbe) ?? nodeBinaryProblem(options.execPath ?? process.execPath, options.nodePrefix ?? MACOS_NODE_PREFIX, ownerUid, aclProbe);
    if (problem !== null) return { ok: false, kind: "policy_error", message: `enterprise policy is unusable: ${problem} (fail closed).` };
  }
  const trusted = readTrustedFile(paths.policyFile, {
    ownerUid,
    stopAt: options.stopAt,
    ...(darwin ? { aclProbe, groupWritableParents: options.groupWritableParents ?? { paths: MACOS_ADMIN_PARENTS, gid: MACOS_ADMIN_GID } } : {}),
  });
  if (!trusted.ok) return { ok: false, kind: "policy_error", message: `enterprise policy is unusable: ${trusted.reason} (fail closed).` };
  let enterprise: EnterprisePolicy;
  try {
    enterprise = parseEnterprisePolicy(trusted.text);
  } catch {
    return { ok: false, kind: "policy_error", message: "enterprise policy is invalid (fail closed)." };
  }
  // Variant S (shared directory) does not exist on macOS: fail closed instead of a silent other layout.
  if (darwin && enterprise.logging.layout === "shared") return { ok: false, kind: "policy_error", message: "enterprise policy: log layout \"shared\" is not available on macOS (fail closed)." };
  let base: Policy;
  let baseSha: string;
  try {
    const bundled = fileSha(options.bundledPolicy ?? BUNDLED_POLICY_PATH);
    base = parsePolicy(JSON.parse(bundled.text));
    baseSha = bundled.sha256;
  } catch {
    return { ok: false, kind: "policy_error", message: "default policy could not be loaded (fail closed)." };
  }
  const layers: PolicyLayerInfo[] = [
    { level: "enterprise", sha256: trusted.sha256 },
    { level: "default", sha256: baseSha },
  ];
  const lowers: LowerLayer[] = [];
  const findings: PolicyFinding[] = trusted.notes.map((id) => ({ type: "policy_error" as const, level: "enterprise", id, detail: "a parent directory of the policy is writable by the group admin (tolerated on macOS)" }));
  const protectedFiles = [paths.policyFile];
  if (enterprise.projectMode !== "ignore") {
    // Both lower layers apply (project policy, then TOLLGATE_POLICY); neither can loosen anything.
    const exists = pathExists;
    const candidates: { level: LowerLayer["level"]; path: string; optional: boolean }[] = [{ level: "project", path: resolve(options.projectDir, PROJECT_POLICY_FILE), optional: true }];
    if (options.env.TOLLGATE_POLICY) candidates.push({ level: "explicit", path: options.env.TOLLGATE_POLICY, optional: false });
    for (const c of candidates) {
      if (c.optional && !exists(c.path)) continue;
      try {
        const file = fileSha(c.path);
        const parsed = parseLowerLayer(file.text, c.level);
        lowers.push(parsed.layer);
        findings.push(...parsed.findings);
        layers.push({ level: c.level, sha256: file.sha256 });
        protectedFiles.push(resolve(c.path));
      } catch {
        return { ok: false, kind: "policy_error", message: `${c.level} policy could not be loaded (fail closed).` };
      }
    }
  }
  const merged = mergePolicies(enterprise, base, lowers);
  return {
    ok: true,
    policy: merged.policy,
    policyFile: paths.policyFile,
    protectedFiles,
    layers,
    revision: enterprise.revision,
    findings: [...findings, ...merged.findings],
    enterprise: { policy: enterprise, settings: enterprise.logging },
  };
}

function resolveStandalone(options: ResolveOptions): Resolution {
  let path: string;
  let policy: Policy;
  let baseSha: string;
  const bundledPath = options.bundledPolicy ?? BUNDLED_POLICY_PATH;
  try {
    path = resolveProjectOrDefault(options.projectDir, bundledPath);
    const file = fileSha(path);
    policy = parsePolicy(JSON.parse(file.text));
    baseSha = file.sha256;
  } catch {
    return { ok: false, kind: "policy_error", message: "policy could not be loaded (fail closed)." };
  }
  const level = path === bundledPath ? "default" : "project";
  const layers: PolicyLayerInfo[] = [{ level, sha256: baseSha }];
  if (level === "project") {
    // Session taint: the bundled default is the floor; a project policy can tighten it, never switch it off.
    try {
      const bundled = parsePolicy(JSON.parse(fileSha(bundledPath).text));
      if (bundled.taint !== undefined || policy.taint !== undefined) policy.taint = mergeTaint(policy.taint ?? TAINT_OFF, bundled.taint ?? TAINT_OFF);
    } catch {
      return { ok: false, kind: "policy_error", message: "default policy could not be loaded (fail closed)." };
    }
  }
  const explicit = options.env.TOLLGATE_POLICY;
  if (!explicit) return { ok: true, policy, policyFile: path, protectedFiles: [], layers, revision: null, findings: [], enterprise: null };
  // TOLLGATE_POLICY never replaces the effective base: it is a further layer that can only tighten.
  try {
    const file = fileSha(explicit);
    const parsed = parseLowerLayer(file.text, "explicit");
    const empty: Policy = { version: 1, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
    const merged = mergePolicies(
      { protectedPaths: policy.protectedPaths, blockedCommands: policy.blockedCommands.map((r, i) => ({ id: r.id ?? `${level}-${i}`, pattern: r.pattern as string, reason: r.reason })), allowedDependencies: policy.allowedDependencies, taint: policy.taint },
      empty,
      [parsed.layer],
      level,
    );
    layers.push({ level: "explicit", sha256: file.sha256 });
    return { ok: true, policy: merged.policy, policyFile: path, protectedFiles: [resolve(explicit)], layers, revision: null, findings: [...parsed.findings, ...merged.findings], enterprise: null };
  } catch {
    return { ok: false, kind: "policy_error", message: "policy could not be loaded (fail closed)." };
  }
}

function resolveProjectOrDefault(projectDir: string, bundledPath: string): string {
  const projectPolicy = resolve(projectDir, PROJECT_POLICY_FILE);
  return pathExists(projectPolicy) ? projectPolicy : bundledPath;
}

// --- project directory and protected system paths -------------------------------------------------------------------

/** Paths that agents never write, in addition to the policy: log, policy, managed settings, plugin installation. */
export function systemProtectedPaths(platform: NodeJS.Platform): string[] {
  const posixPaths = ["/etc/tollgate/", "/var/log/tollgate/", "/var/lib/tollgate/", "/opt/tollgate/", "/etc/claude-code/"];
  if (platform === "darwin") return [...posixPaths, "/Library/Application Support/ClaudeCode/", "/Library/Application Support/TollGate/", "/Library/Logs/TollGate/"];
  return posixPaths;
}

/**
 * Everything that is always protected: system paths, the user's configuration and log directories derived from the
 * environment, the fixed directory of enterprise layout S (`<home>/.local/state/tollgate/`) and the directories that the
 * active log layout really uses (they do not depend on `XDG_STATE_HOME` in enterprise mode).
 */
export function alwaysProtectedPaths(platform: NodeJS.Platform, env: LocationEnv, home: string, uid: number | undefined, active?: Layout): string[] {
  const fixed = enterpriseLayout("shared", uid ?? 0, home, platform);
  const used = active === undefined ? [] : [active.eventsDir, active.lockDir];
  // macOS: the log root itself is a protected system path (see systemProtectedPaths); Linux: the fixed paths of the layouts.
  const dirs = [fixed.lockDir, ...used].map((d) => `${d}/`);
  return [...new Set([...systemProtectedPaths(platform), ...userProtectedDirs(env, platform, home, uid), ...dirs])];
}

/**
 * Validates `CLAUDE_PROJECT_DIR` in enterprise mode (AS2-N11). Returns the reason if it is not acceptable, else null.
 */
export function projectDirProblem(projectDir: string, cwd: string | undefined, home: string, platform: NodeJS.Platform): string | null {
  if (!isAbsolute(projectDir)) return "CLAUDE_PROJECT_DIR is not an absolute path";
  const dir = posix.normalize(projectDir).replace(/\/+$/, "") || "/";
  const homeParent = posix.dirname(home);
  const homeDirs = new Set(["/", "/home", "/Users", homeParent, home].map((p) => posix.normalize(p).replace(/\/+$/, "") || "/"));
  if (homeDirs.has(dir)) return "CLAUDE_PROJECT_DIR is the file system root, the home directory or the parent of home directories";
  for (const protectedDir of systemProtectedPaths(platform)) {
    const base = protectedDir.slice(0, -1);
    if (dir === base || dir.startsWith(`${base}/`)) return "CLAUDE_PROJECT_DIR lies in a protected system path";
    if (base.startsWith(`${dir}/`)) return "CLAUDE_PROJECT_DIR contains a protected system path";
  }
  if (cwd !== undefined && cwd !== dir && !posix.normalize(cwd).startsWith(`${dir}/`)) return "the working directory is not inside CLAUDE_PROJECT_DIR";
  return null;
}
