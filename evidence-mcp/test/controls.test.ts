import { describe, expect, it } from "vitest";
import { CONTROL_MAP, EVENT_TYPES, controlsFor, type ControlRef } from "../src/controls.js";

const SOC2 = "SOC 2 (AICPA TSC 2017)";
const soc2Ids = (type: (typeof EVENT_TYPES)[number]): string[] =>
  controlsFor(type).filter((c: ControlRef) => c.framework === SOC2).map((c) => c.id);

// `anchor` keeps its ISO/NIS2 mapping only: external record protection has no clean SOC 2
// criterion, and monitoring (CC7.2) is already covered by `agent_action`.
const SOC2_MAPPED = EVENT_TYPES.filter((t) => t !== "anchor");

describe("SOC 2 control mapping", () => {
  it("maps every mapped event type to at least one SOC 2 criterion", () => {
    for (const type of SOC2_MAPPED) expect(soc2Ids(type).length).toBeGreaterThan(0);
  });

  it("does not add a SOC 2 criterion to anchor (ISO/NIS2 only)", () => {
    expect(soc2Ids("anchor")).toEqual([]);
  });

  it("maps change-management event types to CC8.1", () => {
    for (const type of ["change", "review", "approval", "deployment"] as const) {
      expect(soc2Ids(type)).toContain("CC8.1");
    }
  });

  it("maps scan to vulnerability detection (CC7.1) and change management (CC8.1)", () => {
    expect(soc2Ids("scan")).toEqual(expect.arrayContaining(["CC7.1", "CC8.1"]));
  });

  it("maps incident to evaluation (CC7.3) and response (CC7.4)", () => {
    expect(soc2Ids("incident")).toEqual(expect.arrayContaining(["CC7.3", "CC7.4"]));
  });

  it("maps access_change to logical access (CC6.1, CC6.3)", () => {
    expect(soc2Ids("access_change")).toEqual(expect.arrayContaining(["CC6.1", "CC6.3"]));
  });

  it("maps agent_action monitoring to CC7.2", () => {
    expect(soc2Ids("agent_action")).toContain("CC7.2");
  });

  it("does not claim SOC 2 CC6.6/CC6.8 (guardrail-side, not yet evidenced in the log)", () => {
    const allSoc2 = EVENT_TYPES.flatMap((t) => soc2Ids(t));
    expect(allSoc2).not.toContain("CC6.6");
    expect(allSoc2).not.toContain("CC6.8");
  });

  it("keeps ISO 27001 and NIS2 references intact alongside SOC 2", () => {
    const frameworks = new Set(CONTROL_MAP.change.map((c) => c.framework));
    expect(frameworks.has("ISO/IEC 27001:2022 Annex A")).toBe(true);
    expect(frameworks.has("NIS2 Art. 21(2)")).toBe(true);
    expect(frameworks.has(SOC2)).toBe(true);
  });
});
