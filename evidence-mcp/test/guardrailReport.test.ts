import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";

function decisionLine(rule_kind: string, outcome = "deny"): string {
  return JSON.stringify({ type: "decision", ts: "2026-11-18T00:00:00.000Z", tool: { name: "Bash" }, decision: { outcome, rule_kind, rule_id: null } });
}

async function connect(logPath: string, guardrailLog?: string): Promise<Client> {
  const c = new Client({ name: "test-guardrail", version: "0.0.0" });
  if (guardrailLog) process.env.TOLLGATE_GUARDRAIL_LOG = guardrailLog;
  else delete process.env.TOLLGATE_GUARDRAIL_LOG;
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await createServer(logPath).connect(st);
  await c.connect(ct);
  return c;
}

afterEach(() => {
  delete process.env.TOLLGATE_GUARDRAIL_LOG;
});
const reportText = (res: unknown) => (res as { content: { text: string }[] }).content[0]?.text ?? "";

describe("export_report with a Guardrail decision log", () => {
  it("adds a deny-coverage section when TOLLGATE_GUARDRAIL_LOG events are present", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ev-guardrail-"));
    const guardrailLog = join(dir, "guardrail.jsonl");
    writeFileSync(guardrailLog, [decisionLine("protected_path"), decisionLine("dependency"), decisionLine("protected_path", "allow")].join("\n") + "\n");
    const c = await connect(join(dir, "evidence.jsonl"), guardrailLog);
    const report = reportText(await c.callTool({ name: "export_report", arguments: {} }));
    expect(report).toContain("Guardrail-Blockaden je Control");
    expect(report).toContain("| SOC 2 (AICPA TSC 2017) | CC6.1 |");
    expect(report).toContain("| SOC 2 (AICPA TSC 2017) | CC6.8 |");
    await c.close();
  });

  it("omits the section when no Guardrail log is configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ev-guardrail-none-"));
    const c = await connect(join(dir, "evidence.jsonl"));
    const report = reportText(await c.callTool({ name: "export_report", arguments: {} }));
    expect(report).not.toContain("Guardrail-Blockaden je Control");
    await c.close();
  });

  it("omits the section (does not fail) when the configured log is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ev-guardrail-missing-"));
    const c = await connect(join(dir, "evidence.jsonl"), join(dir, "does-not-exist.jsonl"));
    const report = reportText(await c.callTool({ name: "export_report", arguments: {} }));
    expect(report).toContain("# Evidenzbericht");
    expect(report).not.toContain("Guardrail-Blockaden je Control");
    await c.close();
  });
});
