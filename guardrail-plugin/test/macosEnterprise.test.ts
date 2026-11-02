import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  alwaysProtectedPaths,
  MACOS_ENTERPRISE_ACCEPTED,
  nodeBinaryProblem,
  parseLsAcl,
  readTrustedFile,
  resolvePolicy,
  systemAclProbe,
  type AclProbe,
} from "../src/enterprise.js";
import { enterpriseLayout, enterpriseLogRoot } from "../src/events/layout.js";
import { runHook, UNCHECKED_DENY_EXIT_CODE, type HookDeps } from "../src/hook.js";
import { checkBashWrites, HOME_PROTECTED_PATHS } from "../src/writes.js";
import { evaluate } from "../src/evaluate.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { defaultPolicy } from "./helpers.js";

// macOS is simulated on the host (any OS, any UID of the test process): the platform is a parameter, the "administrator" is the
// uid of the test process, and the ACL probe is injected. What only a Mac can show is listed in docs/abnahme-macos.md (VM1...VM15).
const uid = process.getuid?.() ?? 0;
const ENTERPRISE = { version: 2, revision: "mac-1", protectedPaths: ["secrets/"], blockedCommands: [], allowedDependencies: { npm: ["zod"], pypi: [] } };
const none: AclProbe = () => "none";

interface Fx {
  root: string;
  admin: string;
  policyFile: string;
  node: string;
  options: Parameters<typeof resolvePolicy>[0];
}

function fixture(policy: unknown = ENTERPRISE): Fx {
  return fixtureAt(tempDir("tg-mac-"), policy);
}

function fixtureAt(root: string, policy: unknown): Fx {
  mkdirSync(root, { recursive: true });
  const lib = join(root, "Library");
  const support = join(lib, "Application Support");
  const admin = join(support, "TollGate");
  const nodeDir = join(admin, "node", "bin");
  mkdirSync(nodeDir, { recursive: true });
  for (const d of [lib, support, admin]) chmodSync(d, 0o755);
  const node = join(nodeDir, "node");
  writeFileSync(node, "#!/bin/sh\n"); // only metadata is checked, the content is irrelevant
  chmodSync(node, 0o755);
  const policyFile = join(admin, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o644 });
  chmodSync(policyFile, 0o644);
  const project = join(root, "project");
  mkdirSync(project);
  return {
    root,
    admin,
    policyFile,
    node,
    options: {
      env: { TOLLGATE_ENTERPRISE: "1" },
      projectDir: project,
      platform: "darwin",
      ownerUid: uid,
      stopAt: root,
      paths: { adminDir: admin, policyFile },
      macosAccepted: true,
      aclProbe: none,
      execPath: node,
      nodePrefix: join(admin, "node") + "/",
    },
  };
}

describe("macOS build switch", () => {
  it("is off in this build: the signal still ends in enterprise_unsupported_platform, with or without a good installation", () => {
    expect(MACOS_ENTERPRISE_ACCEPTED).toBe(false);
    const f = fixture();
    const { macosAccepted: _unused, ...rest } = f.options;
    void _unused;
    expect(resolvePolicy(rest)).toMatchObject({ ok: false, kind: "enterprise_unsupported_platform" });
    expect(resolvePolicy({ ...rest, macosAccepted: false })).toMatchObject({ ok: false, kind: "enterprise_unsupported_platform" });
  });
  it("is not switched by the environment", () => {
    const f = fixture();
    const { macosAccepted: _unused, ...rest } = f.options;
    void _unused;
    expect(resolvePolicy({ ...rest, env: { TOLLGATE_ENTERPRISE: "1", TOLLGATE_MACOS_ENTERPRISE: "1", TOLLGATE_MACOS_ACCEPTED: "1" } })).toMatchObject({ kind: "enterprise_unsupported_platform" });
  });
  it("without a signal macOS behaves as the stand-alone plugin", () => {
    const f = fixture();
    expect(resolvePolicy({ ...f.options, env: {}, exists: () => false, macosAccepted: false }).ok).toBe(true);
  });
});

describe("macOS enterprise mode, switch on (M2, M3)", () => {
  it("accepts a root-owned (admin-owned) installation and merges the policy", () => {
    const f = fixture();
    const r = resolvePolicy(f.options);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.revision).toBe("mac-1");
      expect(r.policyFile).toBe(f.policyFile);
      expect(r.findings).toEqual([]);
    }
  });
  it("signal without a policy file fails closed (policy_error, not a silent pass)", () => {
    const f = fixture();
    expect(resolvePolicy({ ...f.options, paths: { adminDir: f.admin, policyFile: join(f.admin, "gone.json") } })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("does not exist") });
  });
  it("the admin directory must be owned by the administrator, not group- or world-writable, a real directory", () => {
    const owner = fixture();
    expect(resolvePolicy({ ...owner.options, ownerUid: uid + 1 })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("administrator directory is not owned") });
    for (const mode of [0o775, 0o757, 0o777]) {
      const f = fixture();
      chmodSync(f.admin, mode);
      expect(resolvePolicy(f.options), mode.toString(8)).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("administrator directory is writable") });
    }
    const f = fixture();
    const link = join(f.root, "linkdir");
    symlinkSync(f.admin, link);
    expect(resolvePolicy({ ...f.options, paths: { adminDir: link, policyFile: join(link, "policy.json") } })).toMatchObject({ ok: false, kind: "policy_error" });
  });
  it("an ACL on the directory or on the file fails closed; a failing probe (no ls) fails closed too", () => {
    const f = fixture();
    expect(resolvePolicy({ ...f.options, aclProbe: (p) => (p === f.admin ? "acl" : "none") })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("access control list") });
    expect(resolvePolicy({ ...f.options, aclProbe: (p) => (p === f.policyFile ? "acl" : "none") })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("access control list") });
    expect(resolvePolicy({ ...f.options, aclProbe: () => "error" }).ok).toBe(false);
  });
  it("the default probe fails closed when /bin/ls is not usable for the path", () => {
    expect(systemAclProbe(join(tempDir("tg-mac-"), "nonexistent"))).toBe("error");
  });
  it("tolerates the group admin on exactly the named parents and reports it (Q3); other parents stay strict", () => {
    const f = fixture();
    const support = join(f.root, "Library", "Application Support");
    const gid = process.getgid?.() ?? 0;
    chmodSync(support, 0o775);
    const strict = resolvePolicy(f.options);
    expect(strict).toMatchObject({ ok: false, message: expect.stringContaining("parent directory is writable") });
    const tolerant = { paths: [support], gid };
    const ok = resolvePolicy({ ...f.options, groupWritableParents: tolerant });
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.findings).toEqual([expect.objectContaining({ type: "policy_error", id: "parent_admin_writable" })]);
    // wrong group, world-writable, or a parent that is not named: refused
    expect(resolvePolicy({ ...f.options, groupWritableParents: { paths: [support], gid: gid + 1 } }).ok).toBe(false);
    expect(resolvePolicy({ ...f.options, groupWritableParents: { paths: [join(f.root, "Library")], gid } }).ok).toBe(false);
    chmodSync(support, 0o777);
    expect(resolvePolicy({ ...f.options, groupWritableParents: tolerant }).ok).toBe(false);
    // the policy directory itself and the file are never tolerated
    chmodSync(support, 0o755);
    chmodSync(f.admin, 0o775);
    expect(resolvePolicy({ ...f.options, groupWritableParents: { paths: [f.admin], gid } }).ok).toBe(false);
  });
  it("the policy file: group/world write, link, hard link are refused as on Linux", () => {
    const f = fixture();
    chmodSync(f.policyFile, 0o664);
    expect(resolvePolicy(f.options)).toMatchObject({ ok: false, message: expect.stringContaining("writable by group or others") });
    const g = fixture();
    expect(readTrustedFile(g.policyFile, { ownerUid: uid, stopAt: g.root, aclProbe: none })).toMatchObject({ ok: true, notes: [] });
  });
  it("layout S does not exist on macOS: fail closed", () => {
    const f = fixture({ ...ENTERPRISE, logging: { layout: "shared" } });
    expect(resolvePolicy(f.options)).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("shared") });
  });
  it("the hook must run on the root-owned Node of the package (TM-M3)", () => {
    const f = fixture();
    expect(resolvePolicy({ ...f.options, execPath: process.execPath })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("root-owned Node") });
    chmodSync(f.node, 0o775);
    expect(nodeBinaryProblem(f.node, f.options.nodePrefix as string, uid, none)).toContain("writable");
    expect(nodeBinaryProblem(f.node, f.options.nodePrefix as string, uid + 1, none)).toContain("owned");
    chmodSync(f.node, 0o755);
    expect(nodeBinaryProblem(f.node, f.options.nodePrefix as string, uid, none)).toBeNull();
    // a link inside the prefix that points out of it does not count
    const link = join(f.admin, "node", "bin", "evil");
    symlinkSync(process.execPath, link);
    expect(nodeBinaryProblem(link, f.options.nodePrefix as string, uid, none)).toContain("root-owned Node");
    expect(nodeBinaryProblem(join(f.admin, "nonexistent"), "/", uid, none)).toContain("cannot be checked");
  });
  it("checks ACL, owner and mode of the Node binary and of every directory up to the package's node directory", () => {
    const f = fixture();
    const prefix = f.options.nodePrefix as string;
    const nodeDir = prefix.replace(/\/$/, "");
    const binDir = join(nodeDir, "bin");
    expect(nodeBinaryProblem(f.node, prefix, uid, () => "none")).toBeNull();
    for (const target of [f.node, binDir, nodeDir]) {
      expect(nodeBinaryProblem(f.node, prefix, uid, (p) => (p === target ? "acl" : "none")), target).toContain("access control list");
      expect(nodeBinaryProblem(f.node, prefix, uid, (p) => (p === target ? "error" : "none")), target).toContain("access control list");
    }
    for (const dir of [binDir, nodeDir]) {
      chmodSync(dir, 0o775);
      expect(nodeBinaryProblem(f.node, prefix, uid, none), dir).toContain("directory of the Node binary");
      chmodSync(dir, 0o755);
    }
    expect(nodeBinaryProblem(f.node, prefix, uid + 1, () => "none")).toContain("owned");
    // end to end: an ACL on the bin directory makes the policy unusable
    expect(resolvePolicy({ ...f.options, aclProbe: (p) => (p === binDir ? "acl" : "none") })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("Node binary") });
  });
});

describe("parseLsAcl (output of /bin/ls -lde; format to be verified on a Mac, VM2)", () => {
  it("recognizes no ACL, the + marker and ACL entry lines", () => {
    expect(parseLsAcl("drwxr-xr-x  5 root  wheel  160 Oct 16 10:00 /Library/Application Support/TollGate\n")).toBe("none");
    expect(parseLsAcl("drwxr-xr-x@ 5 root  wheel  160 Oct 16 10:00 /x\n")).toBe("none");
    expect(parseLsAcl("drwxr-xr-x+ 5 root  wheel  160 Oct 16 10:00 /x\n 0: user:dev allow write\n")).toBe("acl");
    expect(parseLsAcl("drwxr-xr-x 5 root wheel 160 Oct 16 10:00 /x\n 0: group:everyone deny delete\n")).toBe("acl");
  });
  it("anything else is an error (fail closed)", () => {
    for (const text of ["", "\n", "ls: /x: No such file or directory\n", "garbage line\n", "-rw-r--r-- 1 root wheel 5 Oct 16 10:00 /x\nunexpected extra\n"]) expect(parseLsAcl(text), text).toBe("error");
  });
});

describe("macOS locations and protected paths (M6)", () => {
  it("the enterprise log root is under /Library, never under /var or /etc", () => {
    expect(enterpriseLogRoot("darwin")).toBe("/Library/Logs/TollGate");
    expect(enterpriseLogRoot("linux")).toBe("/var/log/tollgate");
    const layout = enterpriseLayout("per_user", 501, "/Users/dev", "darwin");
    expect(layout).toMatchObject({ kind: "enterprise-per-user", eventsDir: "/Library/Logs/TollGate/events/501", lockDir: "/Library/Logs/TollGate/events/501", fileMode: 0o640, createEventsDir: false });
    expect(enterpriseLayout("per_user", 1000, "/home/dev").eventsDir).toBe("/var/log/tollgate/events/1000");
    expect(alwaysProtectedPaths("darwin", {}, "/Users/dev", 501)).toContain("/Library/Logs/TollGate/");
  });
  it("lists the macOS persistence paths for the home directory", () => {
    expect(HOME_PROTECTED_PATHS).toContain("Library/LaunchAgents/");
    expect(HOME_PROTECTED_PATHS).toContain("Library/Application Support/Claude/");
    // Q7: not the whole .config directory
    expect(HOME_PROTECTED_PATHS).not.toContain(".config/");
  });
  const home = tempDir("tg-mac-home-");
  const project = tempDir("tg-mac-proj-");
  const policy = defaultPolicy();
  const ctx = { projectDir: project, humanSession: false, home };
  it("blocks Bash writes to LaunchAgents and Claude Desktop settings (any case, as on APFS)", () => {
    // File tools outside the project directory are refused by the project boundary (outside_project) already; the home list is the
    // Bash write check (the same protection via Write and via Bash).
    for (const cmd of [
      `echo x > "${home}/Library/LaunchAgents/x.plist"`,
      `echo x > "${home}/library/launchagents/x.plist"`,
      "cp a.plist ~/Library/LaunchAgents/",
      `tee "$HOME/Library/Application Support/Claude/c.json"`,
      `echo x > "${home}/LIBRARY/APPLICATION SUPPORT/claude/c.json"`,
    ]) {
      expect(checkBashWrites(cmd, policy.protectedPaths, { root: project, home }).allowed, cmd).toBe(false);
    }
  });
  it("still allows ordinary work in the project", () => {
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(project, "src", "a.ts"), content: "" } }, policy, ctx).allowed).toBe(true);
    expect(checkBashWrites(`echo x > "${project}/src/a.ts"`, policy.protectedPaths, { root: project, home }).allowed).toBe(true);
  });
});

describe("hook on a simulated macOS (build switch off): fail closed for checked tools", () => {
  it("denies Bash with enterprise_unsupported_platform, independent of the user", () => {
    const f = fixture();
    const rt = { platform: "darwin" as const, uid: 501, username: "dev", home: "/Users/dev", hostname: "mac", version: "0", pluginRoot: f.root, clock: () => new Date(0), uuid: () => "00000000-0000-4000-8000-000000000000" };
    const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" }, hook_event_name: "PreToolUse", session_id: "s" }), { TOLLGATE_ENTERPRISE: "1" }, f.root, { runtime: rt, event: "PreToolUse", resolve: { exists: () => true } });
    expect(r.code).toBe(2);
    expect(r.message).toContain("macOS");
  });
});

describe("hook on a simulated macOS with the switch on (end to end)", () => {
  function setup(extraPolicy: Record<string, unknown> = {}) {
    const root = tempDir("tg-mac-e2e-");
    const project = join(root, "project");
    mkdirSync(project);
    const f = fixtureAt(join(root, "mac"), { ...ENTERPRISE, protectedPaths: ["secrets/"], ...extraPolicy });
    const rt = { ...runtimeFor(root, new Fixture()), platform: "darwin" as const, home: join(root, "home") };
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const env: NodeJS.ProcessEnv = { ...envFor(root), CLAUDE_PROJECT_DIR: project, TOLLGATE_ENTERPRISE: "1" };
    const deps: HookDeps = {
      runtime: rt,
      resolve: { ownerUid: uid, stopAt: f.root, paths: f.options.paths as { adminDir: string; policyFile: string }, macosAccepted: true, aclProbe: none, execPath: f.node, nodePrefix: f.options.nodePrefix as string },
      enterpriseLayout: (variant, r) => ({ ...enterpriseLayout(variant, uid, r.home, r.platform), eventsDir: dir, lockDir: dir }),
    };
    const call = (tool: string, input: Record<string, unknown>) =>
      runHook(JSON.stringify({ session_id: "s-1", tool_use_id: "toolu_1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), env, project, { ...deps, event: "PreToolUse" });
    return { call, project, dir, deps, env };
  }

  it("applies the enterprise policy and logs: allows ordinary work, blocks protected paths", () => {
    const s = setup();
    expect(s.call("Write", { file_path: join(s.project, "src", "a.ts"), content: "x" }).code).toBe(0);
    expect(s.call("Write", { file_path: join(s.project, "secrets", "k"), content: "x" }).code).toBe(2);
    expect(s.call("Write", { file_path: join(s.project, ".CLAUDE", "settings.json"), content: "{}" }).code).toBe(2);
    const events = readEvents(s.dir).flatMap((x) => x.events).filter((e) => e.type === "decision");
    expect(events.length).toBe(3);
    expect(events[0]?.host.os).toBe("macos");
  });
  it("an unusable installation blocks checked and unchecked tools (policy_error, fail closed)", () => {
    const s = setup();
    s.deps.resolve = { ...s.deps.resolve, aclProbe: () => "acl" };
    const env = { ...s.env };
    const run = (tool: string, input: Record<string, unknown>) =>
      runHook(JSON.stringify({ session_id: "s-1", tool_use_id: "t", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), env, s.project, { ...s.deps, event: "PreToolUse" });
    expect(run("Bash", { command: "ls" }).code).toBe(2);
    expect(run("WebFetch", { url: "https://example.com" }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });
  it("sessions on a normal Mac without the signal are not affected by the switch", () => {
    const s = setup();
    const env = { ...s.env };
    delete env.TOLLGATE_ENTERPRISE;
    const r = runHook(JSON.stringify({ session_id: "s", tool_use_id: "t", hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: join(s.project, "a.ts"), content: "" } }), env, s.project, { ...s.deps, resolve: { ...s.deps.resolve, exists: () => false }, event: "PreToolUse" });
    expect(r.code).toBe(0);
  });
});
