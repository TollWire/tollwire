import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { enterpriseLayout } from "../src/events/layout.js";
import { BLOCK_EXIT_CODE, runHook, runMain, UNCHECKED_DENY_EXIT_CODE, type HookDeps } from "../src/hook.js";
import { envFor, Fixture, runtimeFor, tempDir } from "./events/helpers.js";

// Review B1/B2 (#52): whatever fails while a block message is built or the allowlist is looked at, a block stays a block with the
// exit code of its tool class (42 for unchecked tools). Exit 2 would be read as "do not block" by the manifest entry.
const state = vi.hoisted(() => ({ failFormat: false, failAllowed: false }));

vi.mock("../src/blockMessage.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/blockMessage.js")>();
  return {
    ...real,
    formatBlock: (...args: Parameters<typeof real.formatBlock>) => {
      if (state.failFormat) throw new Error("format failure /secret/path");
      return real.formatBlock(...args);
    },
    shortPath: (...args: Parameters<typeof real.shortPath>) => {
      if (state.failFormat) throw new Error("short failure");
      return real.shortPath(...args);
    },
  };
});
vi.mock("../src/enterprise.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/enterprise.js")>();
  return {
    ...real,
    uncheckedToolAllowed: (...args: Parameters<typeof real.uncheckedToolAllowed>) => {
      if (state.failAllowed) throw new Error("allowlist failure");
      return real.uncheckedToolAllowed(...args);
    },
  };
});

const uid = process.getuid?.() ?? 0;
const POLICY = { version: 2, revision: "t", protectedPaths: ["secret/"], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] }, tools: { unchecked: "deny", allow: ["Read"] } };

function setup() {
  const root = tempDir("tg-blkf-");
  const project = join(root, "project");
  mkdirSync(project);
  const rt = runtimeFor(root, new Fixture());
  const env: NodeJS.ProcessEnv = { ...envFor(root), CLAUDE_PROJECT_DIR: project, TOLLGATE_ENTERPRISE: "1" };
  const admin = join(root, "etc", "tollgate");
  mkdirSync(admin, { recursive: true });
  chmodSync(join(root, "etc"), 0o755);
  chmodSync(admin, 0o755);
  const policyFile = join(admin, "policy.json");
  writeFileSync(policyFile, JSON.stringify(POLICY), { mode: 0o644 });
  chmodSync(policyFile, 0o644);
  const dir = join(root, "events", String(uid));
  mkdirSync(dir, { recursive: true, mode: 0o750 });
  const deps: HookDeps = { runtime: rt, resolve: { ownerUid: uid, stopAt: root, paths: { adminDir: admin, policyFile } }, enterpriseLayout: () => ({ ...enterpriseLayout("per_user", uid, rt.home), eventsDir: dir, lockDir: dir }) };
  const call = (tool: string, input: Record<string, unknown> = {}) =>
    runHook(JSON.stringify({ session_id: "s-1", tool_use_id: "t-1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), env, project, { ...deps, event: "PreToolUse" });
  return { call, env, project, root, policyFile, deps };
}

describe("fail closed if building the message fails", () => {
  it("B1: unchecked tool, formatBlock and shortPath throw -> exit 42 with a constant message", () => {
    const e = setup();
    state.failFormat = true;
    try {
      const r = e.call("WebFetch", {});
      expect(r.code).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(r.message).toContain("rule_kind: unchecked_tool");
      expect(r.message).not.toContain("/secret/path");
    } finally {
      state.failFormat = false;
    }
  });
  it("B1: unchecked tool, policy unusable and formatBlock throws -> exit 42", () => {
    const e = setup();
    writeFileSync(e.policyFile, "{ not json", { mode: 0o644 });
    state.failFormat = true;
    try {
      expect(e.call("WebFetch", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    } finally {
      state.failFormat = false;
    }
  });
  it("B1: the allowlist lookup throws -> deny with exit 42", () => {
    const e = setup();
    state.failAllowed = true;
    try {
      expect(e.call("WebFetch", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(e.call("Read", { file_path: join(e.project, "a") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    } finally {
      state.failAllowed = false;
    }
  });
  it("B2: checked tools stay at exit 2 (runMain) when formatBlock throws in the block, evaluation and input paths", async () => {
    const e = setup();
    const main = async (stdin: string): Promise<{ code: number; err: string }> => {
      const errors: string[] = [];
      const code = await runMain(async () => stdin, e.env, e.project, (t) => errors.push(t), e.deps);
      return { code, err: errors.join("") };
    };
    state.failFormat = true;
    try {
      const blocked = await main(JSON.stringify({ session_id: "s", tool_name: "Write", tool_input: { file_path: "secret/a", content: "x" } }));
      expect(blocked.code).toBe(BLOCK_EXIT_CODE);
      expect(blocked.err).toContain("fail closed");
      expect(blocked.err).not.toContain("/secret/path");
      expect((await main("not json")).code).toBe(BLOCK_EXIT_CODE);
      expect(runHook("not json", e.env, e.project).code).toBe(BLOCK_EXIT_CODE);
      const errors: string[] = [];
      const code = await runMain(async () => { throw new Error("EIO"); }, {}, "/", (t) => errors.push(t));
      expect(code).toBe(BLOCK_EXIT_CODE);
      expect(errors.join("")).toContain("fail closed");
    } finally {
      state.failFormat = false;
    }
  });
});
