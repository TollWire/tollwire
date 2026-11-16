import { describe, expect, it } from "vitest";
import { commandFields, fitDraft, serializeEvent } from "../../src/events/event.js";
import { sha256Hex } from "../../src/vendor/hashchain.js";
import type { Draft, TollgateEvent } from "../../src/events/types.js";

const base = (): Draft => ({
  event_id: "00000000-0000-4000-8000-000000000001",
  ts: "2026-10-11T08:15:02.113Z",
  type: "decision",
  host: { name: "h", os: "linux" },
  user: { name: "u", id: "1000" },
  claude: { session_id: "s", tool_use_id: "t", agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: "default", project_dir: "/repo" },
  tool: { name: "Bash", paths: [], truncated: false },
  redactions: 0,
  decision: { outcome: "deny", rule_kind: "blocked_command", rule_id: "r", reason: "because", human_session: false },
  policy: { revision: null, sha256: "1".repeat(64), layers: [], enterprise_mode: false },
  source: { component: "tollgate-guardrail", version: "0.1.0" },
});

const full = (d: Draft): TollgateEvent => ({ schema: "tollgate.event.v1", ...d, chain_id: "x".repeat(36), seq: Number.MAX_SAFE_INTEGER, prev_hash: "0".repeat(64), hash: "0".repeat(64) });
const bytes = (d: Draft): number => Buffer.byteLength(serializeEvent(full(d)), "utf8");

describe("commandFields", () => {
  it("logs no text and no hash by default (none)", () => {
    expect(commandFields("ls -la", "none", false)).toEqual({ redactions: 0 });
  });
  it("logs the SHA-256 of the raw command", () => {
    expect(commandFields("ls -la", "hash", false)).toEqual({ command_sha256: sha256Hex("ls -la"), redactions: 0 });
    expect(commandFields("ls -la", "none", true)).toEqual({ command_sha256: sha256Hex("ls -la"), redactions: 0 });
  });
  it("logs redacted text", () => {
    expect(commandFields("curl -u a:b x", "redacted", false)).toEqual({ command: "curl -u [REDACTED:credential] x", redactions: 1 });
    const both = commandFields("echo hi", "redacted", true);
    expect(both.command).toBe("echo hi");
    expect(both.command_sha256).toBe(sha256Hex("echo hi"));
  });
  it("logs nothing if the tokenizer fails", () => {
    expect(commandFields("echo 'open", "redacted", false)).toEqual({ redactions: 0 });
    expect(commandFields("echo 'open", "redacted", true)).toEqual({ command_sha256: sha256Hex("echo 'open"), redactions: 0 });
  });
  it("limits the raw text to 16 KiB before tokenizing", () => {
    const long = `echo ${"a".repeat(20_000)} ; echo second`;
    const out = commandFields(long, "redacted", false);
    expect(out.command).not.toContain("second");
    expect(out.command?.length).toBeLessThanOrEqual(16 * 1024);
  });
});

describe("fitDraft", () => {
  it("sanitizes all strings exactly once", () => {
    const d = base();
    d.tool = { name: "Bash", command: "a\\b\u001b", truncated: false };
    d.decision = { ...(d.decision as NonNullable<Draft["decision"]>), reason: "x‮y" };
    const out = fitDraft(d);
    expect(out.tool?.command).toBe("a\\\\b\\u{001B}");
    expect(out.decision?.reason).toBe("x\\u{202E}y");
  });
  it("does not modify its input", () => {
    const d = base();
    d.tool = { name: "Bash", command: "x\u001b", truncated: false };
    fitDraft(d);
    expect(d.tool?.command).toBe("x\u001b");
  });
  it("leaves a small event untouched and not truncated", () => {
    const out = fitDraft(base());
    expect(out).toEqual(base());
    expect(out.tool?.truncated).toBe(false);
  });
  it("cuts the command text to 2048 characters and marks it", () => {
    const d = base();
    d.tool = { name: "Bash", command: "c".repeat(3000), truncated: false };
    const out = fitDraft(d);
    expect(out.tool?.command).toHaveLength(2048);
    expect(out.tool?.truncated).toBe(true);
  });
  it("cuts programs to 64 characters", () => {
    const d = base();
    d.tool = { name: "Bash", programs: ["p".repeat(100)], truncated: false };
    const out = fitDraft(d);
    expect(out.tool?.programs?.[0]).toHaveLength(64);
    expect(out.tool?.truncated).toBe(true);
  });
  it("keeps at most 64 paths and counts the rest", () => {
    const d = base();
    d.tool = { name: "Bash", paths: Array.from({ length: 70 }, (_, i) => `p${i}`), truncated: false };
    const out = fitDraft(d);
    expect(out.tool?.paths).toHaveLength(64);
    expect(out.tool?.paths_omitted).toBe(6);
    expect(out.tool?.truncated).toBe(true);
  });
  it("applies the cuts in the documented order until the event fits", () => {
    const long = (): Draft => {
      const d = base();
      d.tool = { name: "Bash", command: "c".repeat(2000), paths: Array.from({ length: 40 }, (_, i) => `${"p".repeat(120)}${i}`), truncated: false };
      d.decision = { ...(d.decision as NonNullable<Draft["decision"]>), reason: "r".repeat(1000) };
      return d;
    };
    expect(bytes(long())).toBeGreaterThan(8192);
    const out = fitDraft(long());
    expect(bytes(out)).toBeLessThanOrEqual(8192);
    expect(out.tool?.truncated).toBe(true);
    // Step 1 (paths) was enough: command and reason are kept.
    expect(out.tool?.paths).toHaveLength(8);
    expect(out.tool?.paths_omitted).toBe(32);
    expect(out.tool?.command).toHaveLength(2000);
    expect(out.decision?.reason).toHaveLength(1000);
  });
  // Builds an event that is `over` bytes above the limit after the fixed limits were applied.
  const oversize = (over: number, projectDir = "/repo"): Draft => {
    const d = base();
    d.tool = { name: "Bash", command: "c".repeat(2048), paths: ["x"], truncated: false };
    d.decision = { ...(d.decision as NonNullable<Draft["decision"]>), reason: "r".repeat(1024) };
    d.claude = { ...(d.claude as NonNullable<Draft["claude"]>), project_dir: projectDir };
    d.data = { filler: "" };
    d.data.filler = "f".repeat(Math.max(0, 8192 + over - bytes(d)));
    return d;
  };
  it("cuts the command (512) when the paths alone do not suffice", () => {
    const out = fitDraft(oversize(1000));
    expect(bytes(out)).toBeLessThanOrEqual(8192);
    expect(out.tool?.command).toHaveLength(512);
    expect(out.decision?.reason).toHaveLength(1024);
    expect(out.tool?.truncated).toBe(true);
  });
  it("cuts the reason (128) next", () => {
    const out = fitDraft(oversize(1536 + 300));
    expect(bytes(out)).toBeLessThanOrEqual(8192);
    expect(out.tool?.command).toHaveLength(512);
    expect(out.decision?.reason).toHaveLength(128);
    expect(out.claude?.project_dir).toBe("/repo");
  });
  it("drops the project directory next", () => {
    const out = fitDraft(oversize(1536 + 896 + 100, "d".repeat(500)));
    expect(bytes(out)).toBeLessThanOrEqual(8192);
    expect(out.claude?.project_dir).toBeUndefined();
    expect(out.decision?.reason).toHaveLength(128);
    expect(out.tool?.command).toHaveLength(512);
  });
  it("reduces to the mandatory fields as the last step and never drops the event", () => {
    const d = base();
    d.data = { filler: "f".repeat(9000) };
    const out = fitDraft(d);
    expect(bytes(out)).toBeLessThanOrEqual(8192);
    expect(out.data).toBeUndefined();
    expect(out.policy).toBeUndefined();
    expect(out.claude).toEqual({ session_id: "s", tool_use_id: null, agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: null });
    expect(out.tool).toEqual({ name: "Bash", truncated: true });
    expect(out.decision).toEqual({ outcome: "deny", rule_kind: "blocked_command", rule_id: null, reason: null, human_session: false });
    expect(out.event_id).toBe(base().event_id);
  });
  it("reduces an event without claude, tool or decision", () => {
    const d: Draft = { ...base(), type: "log_error", data: { filler: "f".repeat(9000) } };
    delete d.claude;
    delete d.tool;
    delete d.decision;
    const out = fitDraft(d);
    expect(out.claude).toBeUndefined();
    expect(out.tool).toBeUndefined();
    expect(out.data).toBeUndefined();
  });
  it("cuts the reason to 1024 characters even for small events", () => {
    const d = base();
    d.decision = { ...(d.decision as NonNullable<Draft["decision"]>), reason: "r".repeat(2000) };
    expect(fitDraft(d).decision?.reason).toHaveLength(1024);
  });
});
