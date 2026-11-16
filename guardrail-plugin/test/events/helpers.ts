import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EVENT_FILE, standaloneLayout, type Layout } from "../../src/events/layout.js";
import { LogStore, type Meta, type StoreDeps } from "../../src/events/store.js";
import type { Draft, TollgateEvent } from "../../src/events/types.js";
import type { Runtime } from "../../src/events/runtime.js";
import type { ClaudeFields, DecisionFields, PolicyFields } from "../../src/events/types.js";

export const META: Meta = {
  host: { name: "host-1", os: "linux" },
  user: { name: "alice", id: String(process.getuid?.() ?? 0) },
  source: { component: "tollgate-guardrail", version: "0.1.0" },
};

export function tempDir(prefix = "tg-events-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** Clock and UUID source that tests can control. */
export class Fixture {
  time = Date.parse("2026-10-11T08:15:02.113Z");
  counter = 0;
  readonly deps: StoreDeps = {
    clock: () => new Date(this.time),
    uuid: () => {
      this.counter += 1;
      return `00000000-0000-4000-8000-${String(this.counter).padStart(12, "0")}`;
    },
  };
  advance(ms: number): void {
    this.time += ms;
  }
}

export function standaloneStore(root: string, fixture = new Fixture(), overrides: Partial<StoreDeps> = {}): { store: LogStore; layout: Layout; fixture: Fixture } {
  const layout = standaloneLayout({ XDG_STATE_HOME: join(root, "state") }, "linux", join(root, "home"), process.getuid?.());
  const store = new LogStore(layout, META, { ...fixture.deps, ...overrides });
  return { store, layout, fixture };
}

export function decisionDraft(store: LogStore, extra: Partial<Draft> = {}): Draft {
  return store.draft("decision", {
    claude: { session_id: "s-1", tool_use_id: "t-1", agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: "default" },
    tool: { name: "Bash", programs: ["ls"], paths: [], effects: [], truncated: false },
    redactions: 0,
    decision: { outcome: "allow", rule_kind: "none", rule_id: null, reason: null, human_session: false },
    ...extra,
  });
}

function key(name: string): string {
  const m = EVENT_FILE.exec(name) as RegExpExecArray;
  return `${m[2]}-${String(Number(m[3] ?? 0)).padStart(4, "0")}`;
}

export function readEvents(dir: string): { file: string; events: TollgateEvent[] }[] {
  return readdirSync(dir)
    .filter((n) => EVENT_FILE.test(n))
    .sort((a, b) => key(a).localeCompare(key(b)))
    .map((file) => ({
      file,
      events: readFileSync(join(dir, file), "utf8")
        .split("\n")
        .filter((l) => l !== "")
        .map((l) => JSON.parse(l) as TollgateEvent),
    }));
}

export function ensureDir(path: string): string {
  mkdirSync(path, { recursive: true });
  return path;
}


export const PACKAGE_ROOT = join(new URL("../..", import.meta.url).pathname);

export function runtimeFor(root: string, fixture = new Fixture(), patch: Partial<Runtime> = {}): Runtime {
  return {
    platform: "linux",
    uid: process.getuid?.(),
    username: "alice",
    home: join(root, "home"),
    hostname: "host-1",
    version: "0.1.0",
    pluginRoot: PACKAGE_ROOT,
    clock: fixture.deps.clock,
    uuid: fixture.deps.uuid,
    ...patch,
  };
}

export function envFor(root: string): NodeJS.ProcessEnv {
  return { XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config") };
}

export const POLICY: PolicyFields = { revision: null, sha256: "1".repeat(64), layers: [{ level: "default", sha256: "1".repeat(64) }], enterprise_mode: false };

export function claude(sessionId = "s-1", extra: Partial<ClaudeFields> = {}): ClaudeFields {
  return { session_id: sessionId, tool_use_id: "t-1", agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: "default", ...extra };
}

export const ALLOW: DecisionFields = { outcome: "allow", rule_kind: "none", rule_id: null, reason: null, human_session: false };
export const DENY: DecisionFields = { outcome: "deny", rule_kind: "blocked_command", rule_id: "blockedCommands[0]", reason: "Force push is not allowed.", human_session: false };

export function writeConfig(root: string, content: string): string {
  const dir = join(root, "config", "tollgate");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "config.json");
  writeFileSync(path, content);
  return path;
}
