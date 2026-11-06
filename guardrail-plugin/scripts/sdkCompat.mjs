// Compatibility test: the official MCP SDK client (devDependency) talks to the built server over stdio.
// Checks initialize (version negotiation), ping, tools/list (identical to the SDK 1.32.0 fixture) and tools/call for every tool.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { LATEST_PROTOCOL_VERSION, ListResourcesResultSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const project = mkdtempSync(join(tmpdir(), "gr-sdk-compat-"));
const fixture = JSON.parse(readFileSync(new URL("../test/fixtures/tools-list.sdk-1.32.0.json", import.meta.url), "utf8"));
const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const failures = [];
const expect = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  sdk compat: ${name}${ok ? "" : ` ${detail}`}`);
  if (!ok) failures.push(name);
};
const payload = (res) => JSON.parse(res.content?.[0]?.text ?? "null");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/mcp/server.js"],
  cwd: root,
  env: { PATH: process.env.PATH ?? "", CLAUDE_PROJECT_DIR: project },
  stderr: "pipe",
});
// The SDK client reports the negotiated version through this optional transport hook.
let negotiated;
transport.setProtocolVersion = (v) => {
  negotiated = v;
};
const client = new Client({ name: "sdk-compat", version: "0.0.0" });
try {
  await client.connect(transport);
  const info = client.getServerVersion();
  expect("initialize (serverInfo)", info?.name === "tollgate-guardrail" && info?.version === version, JSON.stringify(info));
  expect("initialize (capabilities)", client.getServerCapabilities()?.tools !== undefined);
  expect("protocol version negotiated", negotiated === LATEST_PROTOCOL_VERSION, String(negotiated));
  expect("ping", JSON.stringify(await client.ping()) === "{}");

  const listed = await client.request({ method: "tools/list", params: {} }, ListToolsResultSchema);
  expect("tools/list equals SDK 1.32.0 fixture", isDeepStrictEqual(listed, fixture), JSON.stringify(listed));

  const safe = payload(await client.callTool({ name: "check_command", arguments: { command: "git status" } }));
  expect("check_command allows git status", safe?.allowed === true, JSON.stringify(safe));
  const force = payload(await client.callTool({ name: "check_command", arguments: { command: "git push --force" } }));
  expect("check_command blocks force push", force?.allowed === false, JSON.stringify(force));
  const path = payload(await client.callTool({ name: "check_path", arguments: { path: join(project, "AGENTS.md") } }));
  expect("check_path blocks a protected path", path?.allowed === false, JSON.stringify(path));
  const deps = payload(await client.callTool({ name: "check_dependencies", arguments: { ecosystem: "npm", manifest: '{"dependencies":{"evil-pkg":"1"}}' } }));
  expect("check_dependencies reports a violation", deps?.allowed === false && deps.violations?.[0]?.name === "evil-pkg", JSON.stringify(deps));
  const policy = payload(await client.callTool({ name: "describe_policy", arguments: {} }));
  expect("describe_policy lists protected paths", Array.isArray(policy?.protectedPaths) && policy.protectedPaths.length > 0);

  const invalid = await client.callTool({ name: "check_dependencies", arguments: { ecosystem: "cargo", manifest: "" } });
  expect("invalid arguments -> isError", invalid.isError === true && String(invalid.content?.[0]?.text).includes("Input validation error"));
  const unknown = await client.callTool({ name: "no_such_tool", arguments: {} });
  expect("unknown tool -> isError", unknown.isError === true && String(unknown.content?.[0]?.text).includes("not found"));
  let methodError;
  try {
    await client.request({ method: "resources/list", params: {} }, ListResourcesResultSchema);
  } catch (error) {
    methodError = error;
  }
  expect("unknown method -> -32601", methodError?.code === -32601, String(methodError));
} catch (error) {
  expect("session", false, String(error));
} finally {
  await client.close();
}
if (failures.length) {
  console.error(`SDK compatibility test failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("SDK compatibility test passed.");
