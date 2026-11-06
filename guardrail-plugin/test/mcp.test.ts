import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../src/mcp/server.js";
import { checkDependenciesTool } from "../src/mcp/tools.js";
import { defaultPolicy, PROJECT } from "./helpers.js";

const policy = defaultPolicy({ allowedDependencies: { npm: ["zod"], pypi: [] } });
const client = new Client({ name: "test", version: "0.0.0" });

function payload(res: unknown): Record<string, unknown> {
  const content = (res as { content: { text: string }[] }).content;
  return JSON.parse(content[0]?.text ?? "{}") as Record<string, unknown>;
}

beforeAll(async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await createServer(policy, PROJECT).connect(serverTransport);
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
});

describe("MCP server", () => {
  it("lists the four guardrail tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["check_command", "check_dependencies", "check_path", "describe_policy"]);
  });

  it("tools/list is identical to the SDK 1.32.0 server (fixture recorded before the switch)", async () => {
    const fixture = JSON.parse(readFileSync(new URL("fixtures/tools-list.sdk-1.32.0.json", import.meta.url), "utf8")) as unknown;
    const res = await createServer(policy, PROJECT).handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(res?.result).toEqual(fixture);
  });

  it("check_command blocks force push", async () => {
    const res = await client.callTool({ name: "check_command", arguments: { command: "git push --force" } });
    expect(payload(res)).toMatchObject({ allowed: false });
  });

  it("check_path treats callers as agents", async () => {
    const res = await client.callTool({ name: "check_path", arguments: { path: "/repo/AGENTS.md" } });
    expect(payload(res)).toMatchObject({ allowed: false });
  });

  it("check_dependencies reports violations", async () => {
    const res = await client.callTool({
      name: "check_dependencies",
      arguments: { ecosystem: "npm", manifest: '{"dependencies":{"zod":"4","evil":"1"}}' },
    });
    expect(payload(res)).toEqual({ allowed: false, violations: [{ ecosystem: "npm", name: "evil" }] });
  });

  it("describe_policy exposes reasons but not regex internals", async () => {
    const res = payload(await client.callTool({ name: "describe_policy", arguments: {} }));
    expect(res.protectedPaths).toContain("AGENTS.md");
    expect(JSON.stringify(res)).not.toContain("pattern");
  });

  it("rejects invalid arguments", async () => {
    const res = await client.callTool({ name: "check_dependencies", arguments: { ecosystem: "cargo", manifest: "" } });
    expect(res.isError).toBe(true);
  });
});

describe("tools", () => {
  it("fails closed on unparsable manifests", () => {
    const res = checkDependenciesTool(policy, "npm", "{broken");
    expect(JSON.parse(res.content[0]?.text ?? "{}")).toMatchObject({ allowed: false });
  });
});
