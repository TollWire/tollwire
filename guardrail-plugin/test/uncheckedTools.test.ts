import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { BASE_UNCHECKED_ALLOW, parseEnterprisePolicy, parseLowerLayer, uncheckedToolAllowed } from "../src/enterprise.js";
import { enterpriseLayout } from "../src/events/layout.js";
import { BLOCK_EXIT_CODE, runHook, UNCHECKED_DENY_EXIT_CODE, type HookDeps } from "../src/hook.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

// Enterprise policy section `tools`: tools that the hook does not check (MCP servers, WebFetch, subagents, ...) are only
// recorded by default. With `unchecked: "deny"` the enterprise policy turns that into an allowlist (fail closed, enterprise
// mode only). The section is tightening-only: lower layers cannot set it, and policies without it behave as before.
const uid = process.getuid?.() ?? 0;

const BASE = {
  version: 2,
  revision: "acme-tools",
  protectedPaths: [],
  blockedCommands: [],
  allowedDependencies: { npm: [], pypi: [] },
};
const DENY = { ...BASE, tools: { unchecked: "deny", allow: ["Read", "Glob", "Grep", "mcp__tollgate-guardrail__*", "mcp__docs__search"] } };

function enterprise(policy: unknown, enterpriseMode = true, override: Partial<HookDeps> = {}) {
  const root = tempDir("tg-tools-");
  const project = join(root, "project");
  mkdirSync(project);
  const rt = runtimeFor(root, new Fixture());
  const env: NodeJS.ProcessEnv = { ...envFor(root), CLAUDE_PROJECT_DIR: project, ...(enterpriseMode ? { TOLLGATE_ENTERPRISE: "1" } : {}) };
  // Pinned default policy without session taint (tool calls without a session start).
  const deps: HookDeps = { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };
  const dir = join(root, "events", String(uid));
  mkdirSync(dir, { recursive: true, mode: 0o750 });
  if (enterpriseMode) {
    const admin = join(root, "etc", "tollgate");
    mkdirSync(admin, { recursive: true });
    chmodSync(join(root, "etc"), 0o755);
    chmodSync(admin, 0o755);
    const policyFile = join(admin, "policy.json");
    writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o644 });
    chmodSync(policyFile, 0o644);
    deps.resolve = { ownerUid: uid, stopAt: root, paths: { adminDir: admin, policyFile }, bundledPolicy: BUNDLED_WITHOUT_TAINT };
    deps.enterpriseLayout = () => ({ ...enterpriseLayout("per_user", uid, rt.home), eventsDir: dir, lockDir: dir });
  }
  Object.assign(deps, override);
  const call = (tool: string, input: Record<string, unknown> = {}) =>
    runHook(JSON.stringify({ session_id: "s-1", tool_use_id: "toolu_1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), env, project, { ...deps, event: "PreToolUse" });
  const decisions = () => {
    try {
      return readEvents(dir).flatMap((f) => f.events).filter((e) => e.type === "decision");
    } catch {
      return [];
    }
  };
  return { call, decisions, project, root };
}

describe("tools section of the enterprise policy", () => {
  it("denies by default with the base allowlist, with or without the section (owner decision)", () => {
    const expected = { mode: "deny", allow: [...BASE_UNCHECKED_ALLOW] };
    expect(parseEnterprisePolicy(JSON.stringify(BASE)).uncheckedTools).toEqual(expected);
    expect(parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: {} })).uncheckedTools).toEqual(expected);
    expect(parseEnterprisePolicy(JSON.stringify(DENY)).uncheckedTools.mode).toBe("deny");
    expect(BASE_UNCHECKED_ALLOW).toEqual(["Read", "Glob", "Grep", "LS", "TodoWrite", "Task", "Agent", "SubagentHandback", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "ToolSearch"]);
    // Regression (WSL acceptance test 2026-10-18): subagents return their result through SubagentHandback.
    expect(BASE_UNCHECKED_ALLOW).toContain("SubagentHandback");
    // Tools with network or MCP access stay off the base list.
    for (const t of ["WebFetch", "WebSearch", "mcp__any__tool"]) expect(BASE_UNCHECKED_ALLOW).not.toContain(t);
  });
  it("adds the policy's entries to the base list and lets only an explicit observe switch the default off", () => {
    const extra = parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { allow: ["WebSearch"] } })).uncheckedTools;
    expect(extra.allow).toEqual([...BASE_UNCHECKED_ALLOW, "WebSearch"]);
    expect(uncheckedToolAllowed("WebSearch", extra)).toBe(true);
    expect(uncheckedToolAllowed("WebFetch", extra)).toBe(false);
    expect(uncheckedToolAllowed("mcp__x__y", extra)).toBe(false);
    const observe = parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { unchecked: "observe" } })).uncheckedTools;
    expect(observe.mode).toBe("observe");
    expect(uncheckedToolAllowed("WebFetch", observe)).toBe(true);
  });
  it.each([
    ["wildcard only", ["*"]],
    ["wildcard in the middle", ["mcp__*__tool"]],
    ["server prefix without separator", ["mcp__srv*"]],
    ["wildcard on a built-in tool", ["Web*"]],
    ["empty name", [""]],
    ["whitespace", ["Web Fetch"]],
    ["regular expression", ["(Read|Glob)"]],
    ["path-like", ["../Read"]],
    ["server name with a double underscore", ["mcp__a__b__*"]],
    ["server name ending in an underscore", ["mcp__a___*"]],
  ])("rejects an allowlist entry: %s", (_name, allow) => {
    expect(() => parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { unchecked: "deny", allow } }))).toThrow();
  });
  it("rejects unknown keys and modes", () => {
    expect(() => parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { unchecked: "allow" } }))).toThrow();
    expect(() => parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { extra: 1 } }))).toThrow();
  });
  it("matches exact names and the mcp server wildcard only", () => {
    const policy = parseEnterprisePolicy(JSON.stringify(DENY)).uncheckedTools;
    expect(uncheckedToolAllowed("Read", policy)).toBe(true);
    expect(uncheckedToolAllowed("mcp__tollgate-guardrail__check_command", policy)).toBe(true);
    expect(uncheckedToolAllowed("mcp__docs__search", policy)).toBe(true);
    for (const name of ["WebFetch", "WebSearch", "read", "Reader", "mcp__docs__write_file", "mcp__tollgate-guardrail__", "mcp__tollgate-guardrailx__a", "mcp__other__x", "EnterWorktree", ""]) {
      expect(uncheckedToolAllowed(name, policy), name).toBe(false);
    }
    expect(uncheckedToolAllowed("WebFetch", { mode: "observe", allow: [] })).toBe(true);
  });
  it("does not let a server wildcard cover a server whose name starts with the same part", () => {
    const policy = parseEnterprisePolicy(JSON.stringify({ ...BASE, tools: { unchecked: "deny", allow: ["mcp__a__*", "mcp__x__exact__tool"] } })).uncheckedTools;
    expect(uncheckedToolAllowed("mcp__a__read", policy)).toBe(true);
    for (const name of ["mcp__a__x__t", "mcp__a__x__", "mcp__a____t", "mcp__a__"]) expect(uncheckedToolAllowed(name, policy), name).toBe(false);
    expect(uncheckedToolAllowed("mcp__x__exact__tool", policy)).toBe(true);
  });
  it("is ignored with a finding when a lower layer sets it", () => {
    const { findings } = parseLowerLayer(JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [], tools: { unchecked: "observe", allow: ["*"] } }), "project");
    expect(findings).toEqual([{ type: "policy_override_ignored", level: "project", detail: "section 'tools' is only valid in the enterprise policy" }]);
  });
});

describe("unchecked tools in the hook", () => {
  it("fails closed with exit 42 if the decision cannot be logged because of an exception (review finding)", () => {
    // An exception from the logging path would leave runHook with exit 2, which the manifest entry for unchecked tools reads as
    // "do not block". The deny must carry the exit code of the allowlist rule.
    const e = enterprise(DENY, true, {
      enterpriseLayout: () => {
        throw new Error("layout failure with /secret/path");
      },
    });
    for (const tool of ["WebFetch", "mcp__fs__write_file"]) {
      const r = e.call(tool, {});
      expect(r.code, tool).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(r.message).toContain("not on the enterprise tool allowlist");
      expect(r.message).not.toContain("/secret/path");
    }
    // An allowed unchecked tool stays open (unchanged): only the record is lost.
    expect(e.call("Read", { file_path: join(e.project, "a.ts") }).code).toBe(0);
  });
  it("fails closed with exit 42 for an unchecked tool if the policy is unusable and the log throws", () => {
    const e = enterprise(DENY, true, {
      enterpriseLayout: () => {
        throw new Error("layout failure");
      },
    });
    writeFileSync(join(e.root, "etc", "tollgate", "policy.json"), "{ not json", { mode: 0o644 });
    const r = e.call("WebFetch", {});
    expect(r.code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });
  it("blocks an unlisted MCP tool, WebFetch and other tools with unchecked_tool and logs it", () => {
    const e = enterprise(DENY);
    for (const [tool, input] of [["mcp__fs__write_file", { path: "/tmp/x" }], ["WebFetch", { url: "https://example.org/" }], ["EnterWorktree", {}], ["mcp__docs__write_file", {}]] as const) {
      const r = e.call(tool, input);
      expect(r.code, tool).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(r.message).toContain("not on the enterprise tool allowlist");
      // structured block message (#52): rule id, kind, target, hint; no allowlist content
      expect(r.message).toContain("rule_id: tools.unchecked\nrule_kind: unchecked_tool\ntarget (untrusted, verbatim): " + JSON.stringify(tool) + "\n");
      expect(r.message).toContain("fix: tool not approved in enterprise mode - approval is a policy change (R2); ask your administrator.");
      expect(r.message).not.toContain("mcp__docs__search");
      expect(r.message).not.toContain("Glob");
    }
    const first = e.decisions()[0];
    expect(first?.decision).toMatchObject({ outcome: "deny", rule_kind: "unchecked_tool", rule_id: "tools.unchecked" });
    expect(first?.tool?.name).toBe("mcp__fs__write_file");
  });
  it("lets listed tools through and still records them", () => {
    const e = enterprise(DENY);
    expect(e.call("Read", { file_path: join(e.project, "a.ts") })).toEqual({ code: 0 });
    expect(e.call("mcp__tollgate-guardrail__check_command", {})).toEqual({ code: 0 });
    expect(e.call("mcp__docs__search", {})).toEqual({ code: 0 });
    expect(e.decisions().map((d) => d.decision?.outcome)).toEqual(["observe", "observe", "observe"]);
  });
  it("blocks a tool whose name is not a valid name without echoing it", () => {
    const e = enterprise(DENY);
    const r = e.call("mcp__x\nINJECT", {});
    expect(r.code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(r.message).not.toContain("INJECT");
  });
  it("uses an exit code of its own, never the code of the checked tools", () => {
    expect(UNCHECKED_DENY_EXIT_CODE).not.toBe(BLOCK_EXIT_CODE);
    expect(UNCHECKED_DENY_EXIT_CODE).not.toBe(0);
  });
  it("does not change the checked tools", () => {
    const e = enterprise(DENY);
    expect(e.call("Bash", { command: "ls" })).toEqual({ code: 0 });
    expect(e.call("Write", { file_path: join(e.project, "a.ts"), content: "x" })).toEqual({ code: 0 });
  });
  it("denies WebFetch, WebSearch and MCP tools without the section, and lets the base tools through", () => {
    const e = enterprise(BASE);
    for (const tool of ["mcp__fs__write_file", "WebFetch", "WebSearch"]) expect(e.call(tool, {}).code, tool).toBe(UNCHECKED_DENY_EXIT_CODE);
    for (const tool of BASE_UNCHECKED_ALLOW) expect(e.call(tool, {}), tool).toEqual({ code: 0 });
  });
  it("observes everything when the policy opts out with unchecked = observe", () => {
    const e = enterprise({ ...BASE, tools: { unchecked: "observe" } });
    expect(e.call("mcp__fs__write_file", {})).toEqual({ code: 0 });
    expect(e.call("WebFetch", { url: "https://example.org/" })).toEqual({ code: 0 });
  });
  it("leaves the stand-alone mode unchanged: no enterprise policy, no block", () => {
    const e = enterprise(DENY, false);
    expect(e.call("mcp__fs__write_file", {})).toEqual({ code: 0 });
    expect(e.call("WebFetch", { url: "https://example.org/" })).toEqual({ code: 0 });
  });
});

describe("unchecked tools when the policy cannot be resolved", () => {
  function broken(enterpriseSignal: boolean) {
    const e = enterprise(DENY, enterpriseSignal);
    // A repository file that makes the lower layer unusable: the whole resolution fails in enterprise mode.
    mkdirSync(join(e.project, ".tollgate"), { recursive: true });
    writeFileSync(join(e.project, ".tollgate", "policy.json"), "{broken");
    return e;
  }
  it("blocks unchecked tools in enterprise mode, so a broken project policy cannot switch the allowlist off", () => {
    const e = broken(true);
    for (const tool of ["mcp__fs__write_file", "WebFetch", "Read"]) {
      const r = e.call(tool, {});
      expect(r.code, tool).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(r.message).toContain("policy");
    }
    expect(e.call("Bash", { command: "ls" }).code).toBe(BLOCK_EXIT_CODE);
  });
  it("blocks them when the enterprise policy itself is unusable", () => {
    const e = enterprise("{not json");
    expect(e.call("mcp__fs__write_file", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });
  it("keeps stand-alone mode open", () => {
    const e = broken(false);
    expect(e.call("mcp__fs__write_file", {})).toEqual({ code: 0 });
  });
});
