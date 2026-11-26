import { describe, expect, it } from "vitest";
import {
  RULE_KIND_CONTROL_MAP,
  parseGuardrailDecisions,
  summarizeDenyControls,
  type GuardrailDecision,
} from "../src/ruleKindControls.js";

const decision = (rule_kind: string, outcome = "deny", extra: Partial<GuardrailDecision> = {}): GuardrailDecision => ({
  ts: "2026-11-18T00:00:00.000Z",
  tool: { name: "Bash" },
  decision: { outcome, rule_kind, rule_id: `${rule_kind}[0]` },
  ...extra,
});

describe("rule_kind control mapping", () => {
  it("maps credential/path blocks to CC6.1 and supply-chain to CC6.8", () => {
    expect(RULE_KIND_CONTROL_MAP.protected_path!.map((c) => c.id)).toContain("CC6.1");
    expect(RULE_KIND_CONTROL_MAP.dependency!.map((c) => c.id)).toContain("CC6.8");
    expect(RULE_KIND_CONTROL_MAP.taint!.map((c) => c.id)).toContain("CC7.2");
  });

  it("leaves operational rule_kinds unmapped (not evidence of a control)", () => {
    for (const k of ["parse_error", "invalid_input", "size_limit", "internal_error", "none"]) {
      expect(RULE_KIND_CONTROL_MAP[k]).toBeUndefined();
    }
  });
});

describe("parseGuardrailDecisions", () => {
  it("parses top-level and relay-wrapped decision events, skipping junk", () => {
    const top = JSON.stringify({ type: "decision", ts: "2026-11-18T00:00:00.000Z", tool: { name: "Write" }, decision: { outcome: "deny", rule_kind: "protected_path", rule_id: null } });
    const wrapped = JSON.stringify({ type: "relay_record", data: { event: { type: "decision", ts: "2026-11-18T00:01:00.000Z", tool: { name: "Bash", effects: ["network"] }, decision: { outcome: "deny", rule_kind: "blocked_command", rule_id: "x" } } } });
    const content = [top, "not json", JSON.stringify({ type: "session_start" }), wrapped, ""].join("\n");
    const decisions = parseGuardrailDecisions(content);
    expect(decisions).toHaveLength(2);
    expect(decisions[0]!).toMatchObject({ tool: { name: "Write" }, decision: { rule_kind: "protected_path" } });
    expect(decisions[1]!.tool?.effects).toEqual(["network"]);
  });

  it("ignores the additive agent member and skips enforcement_status events", () => {
    const withAgent = JSON.stringify({ type: "decision", ts: "2026-11-26T00:00:00.000Z", agent: { name: "codex" }, tool: { name: "Bash" }, decision: { outcome: "deny", rule_kind: "blocked_command", rule_id: "x" } });
    const status = JSON.stringify({ type: "enforcement_status", ts: "2026-11-26T00:00:01.000Z", agent: { name: "grok" }, data: { status: "DEGRADED" } });
    const decisions = parseGuardrailDecisions([withAgent, status].join("\n"));
    expect(decisions).toHaveLength(1);
    expect(decisions[0]!.decision.rule_kind).toBe("blocked_command");
  });

  it("drops decision events with non-string required fields", () => {
    const bad = JSON.stringify({ type: "decision", ts: 123, decision: { outcome: "deny", rule_kind: "protected_path" } });
    expect(parseGuardrailDecisions(bad)).toHaveLength(0);
  });
});

describe("summarizeDenyControls", () => {
  it("counts denies per control and ignores allow/ask decisions", () => {
    const rows = summarizeDenyControls([decision("protected_path"), decision("protected_path"), decision("protected_path", "allow")]);
    const cc61 = rows.find((r) => r.id === "CC6.1");
    expect(cc61?.blocked_count).toBe(2);
  });

  it("caps samples at 5 but keeps the full count", () => {
    const rows = summarizeDenyControls(Array.from({ length: 8 }, () => decision("dependency")));
    const cc68 = rows.find((r) => r.id === "CC6.8");
    expect(cc68?.blocked_count).toBe(8);
    expect(cc68?.samples).toHaveLength(5);
  });

  it("attributes a blocked network command to boundary protection CC6.6", () => {
    const rows = summarizeDenyControls([decision("blocked_command", "deny", { tool: { name: "Bash", effects: ["network"] } })]);
    expect(rows.map((r) => r.id)).toContain("CC6.6");
    // a blocked_command without network effect does not claim CC6.6
    const noNet = summarizeDenyControls([decision("blocked_command")]);
    expect(noNet.map((r) => r.id)).not.toContain("CC6.6");
  });

  it("produces nothing for an unmapped rule_kind", () => {
    expect(summarizeDenyControls([decision("parse_error")])).toEqual([]);
  });

  it("filters by date bounds", () => {
    const early = decision("protected_path", "deny", { ts: "2020-01-01T00:00:00.000Z" });
    const rows = summarizeDenyControls([early, decision("protected_path")], { start: Date.parse("2026-01-01"), end: Date.parse("2027-01-01") });
    expect(rows.find((r) => r.id === "CC6.1")?.blocked_count).toBe(1);
  });
});
