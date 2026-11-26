import { appendFileSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { codexDecision } from "../src/adapters/codex.js";
import { copilotDecision } from "../src/adapters/copilot.js";
import { cursorDecision } from "../src/adapters/cursor.js";
import { grokDecision } from "../src/adapters/grok.js";
import { AGENT_NAMES, type TollgateEvent } from "../src/events/types.js";
import { verifyFiles } from "../src/events/verify.js";
import { runHook, type HookDeps } from "../src/hook.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

interface Setup {
  project: string;
  env: NodeJS.ProcessEnv;
  deps: HookDeps;
  events: () => TollgateEvent[];
  dir: string;
}

function setup(): Setup {
  const root = tempDir("tg-agent-");
  const project = join(root, "project");
  mkdirSync(project);
  const rt = runtimeFor(root, new Fixture());
  const dir = join(root, "state", "tollgate", "events");
  return {
    project,
    env: { ...envFor(root), CLAUDE_PROJECT_DIR: project },
    deps: { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } },
    events: () => {
      try {
        return readEvents(dir).flatMap((f) => f.events);
      } catch {
        return [];
      }
    },
    dir,
  };
}

const bashPayload = (cmd: string): Record<string, unknown> => ({ hook_event_name: "PreToolUse", session_id: "s-1", tool_name: "Bash", tool_input: { command: cmd } });
const decisions = (events: TollgateEvent[]): TollgateEvent[] => events.filter((e) => e.type === "decision");

describe("agent identity in events", () => {
  it("claude-code: runHook with the agent set from the entry", () => {
    const s = setup();
    expect(runHook(JSON.stringify(bashPayload("git push --force")), s.env, s.project, { ...s.deps, agent: "claude-code" }).code).toBe(2);
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "claude-code" });
  });

  it("engine without an adapter name writes no agent member (old shape)", () => {
    const s = setup();
    runHook(JSON.stringify(bashPayload("ls")), s.env, s.project, s.deps);
    const [d] = decisions(s.events());
    expect(d).toBeDefined();
    expect("agent" in (d as object)).toBe(false);
  });

  it("codex adapter sets codex", () => {
    const s = setup();
    expect(codexDecision(JSON.stringify(bashPayload("git push --force")), s.env, s.project, s.deps).code).toBe(2);
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "codex" });
  });

  it("copilot adapter sets copilot", () => {
    const s = setup();
    expect(copilotDecision(JSON.stringify(bashPayload("ls")), s.env, s.project, s.deps).code).toBe(0);
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "copilot" });
  });

  it("grok adapter sets grok", () => {
    const s = setup();
    const stdin = JSON.stringify({ hook_event_name: "PreToolUse", sessionId: "s-1", cwd: s.project, toolName: "run_terminal_command", toolInput: { command: "git push --force" } });
    expect(grokDecision(stdin, s.env, s.project, s.deps).code).toBe(2);
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "grok" });
  });

  it("cursor adapter sets cursor", () => {
    const s = setup();
    const stdin = JSON.stringify({ hook_event_name: "preToolUse", conversation_id: "c1", tool_use_id: "t1", cwd: s.project, tool_name: "Shell", tool_input: { command: "git push --force" } });
    expect(cursorDecision(stdin, s.env, s.project, s.deps).code).toBe(2);
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "cursor" });
  });

  it("an adapter cannot be told another name by its caller, the input or the environment", () => {
    const s = setup();
    const forged = { ...bashPayload("ls"), agent: { name: "cursor" }, agent_name: "cursor" };
    codexDecision(JSON.stringify(forged), { ...s.env, TOLLGATE_AGENT: "cursor" }, s.project, { ...s.deps, agent: "cursor" });
    expect(decisions(s.events())[0]?.agent).toEqual({ name: "codex" });
  });

  it("session and tool_result events carry the agent", () => {
    const s = setup();
    const d = { ...s.deps, agent: "claude-code" as const };
    runHook(JSON.stringify({ hook_event_name: "SessionStart", session_id: "s-1", source: "startup" }), s.env, s.project, { ...d, event: "SessionStart" });
    runHook(JSON.stringify({ ...bashPayload("ls"), hook_event_name: "PostToolUse", tool_response: "ok" }), s.env, s.project, { ...d, event: "PostToolUse" });
    const events = s.events().filter((e) => e.type === "session_start" || e.type === "tool_result");
    expect(events.map((e) => e.type).sort()).toEqual(["session_start", "tool_result"]);
    for (const e of events) expect(e.agent).toEqual({ name: "claude-code" });
  });

  it("dryRun writes nothing", () => {
    const s = setup();
    expect(runHook(JSON.stringify(bashPayload("git push --force")), s.env, s.project, { ...s.deps, dryRun: true, agent: "claude-code" }).code).toBe(2);
    expect(s.events()).toEqual([]);
  });

  it("the agent is part of the hashed content; old events without it stay valid", () => {
    const s = setup();
    runHook(JSON.stringify(bashPayload("ls")), s.env, s.project, s.deps); // old shape
    codexDecision(JSON.stringify(bashPayload("ls")), s.env, s.project, s.deps); // new shape
    const name = readdirSync(s.dir).filter((n) => n.endsWith(".jsonl"))[0] as string;
    expect(verifyFiles([join(s.dir, name)]).chainOk).toBe(true);
    expect(decisions(s.events()).map((e) => e.agent?.name)).toEqual([undefined, "codex"]);
    // Tampering with the agent breaks the hash.
    const tampered = join(tempDir("tg-agent-t-"), name);
    writeFileSync(tampered, "");
    for (const e of s.events()) appendFileSync(tampered, `${JSON.stringify(e.agent?.name === "codex" ? { ...e, agent: { name: "claude-code" } } : e)}\n`);
    expect(verifyFiles([tampered]).chainFindings.some((f) => f.kind === "hash_mismatch")).toBe(true);
  });

  it("the agent names are the documented set", () => {
    expect([...AGENT_NAMES]).toEqual(["claude-code", "codex", "copilot", "grok", "cursor", "unknown"]);
  });
});
