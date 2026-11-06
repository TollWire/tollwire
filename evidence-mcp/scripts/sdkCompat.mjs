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
const log = join(mkdtempSync(join(tmpdir(), "ev-sdk-compat-")), "log.jsonl");
const fixture = JSON.parse(readFileSync(new URL("../test/fixtures/tools-list.sdk-1.32.0.json", import.meta.url), "utf8"));
const failures = [];
const expect = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  sdk compat: ${name}${ok ? "" : ` ${detail}`}`);
  if (!ok) failures.push(name);
};
const payload = (res) => JSON.parse(res.content?.[0]?.text ?? "null");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/server.js"],
  cwd: root,
  env: { PATH: process.env.PATH ?? "", TOLLGATE_EVIDENCE_LOG: log },
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
  expect("initialize (serverInfo)", info?.name === "tollgate-evidence" && info?.version === "0.1.2", JSON.stringify(info));
  expect("initialize (capabilities)", client.getServerCapabilities()?.tools !== undefined);
  expect("protocol version negotiated", negotiated === LATEST_PROTOCOL_VERSION, String(negotiated));
  expect("ping", JSON.stringify(await client.ping()) === "{}");

  const listed = await client.request({ method: "tools/list", params: {} }, ListToolsResultSchema);
  expect("tools/list equals SDK 1.32.0 fixture", isDeepStrictEqual(listed, fixture), JSON.stringify(listed));

  const recorded = payload(await client.callTool({ name: "record_event", arguments: { type: "change", summary: "sdk compat", actor: "ci" } }));
  expect("record_event", recorded?.recorded === true && recorded.seq === 1, JSON.stringify(recorded));
  const listedEvents = payload(await client.callTool({ name: "list_events", arguments: { type: "change" } }));
  expect("list_events", Array.isArray(listedEvents) && listedEvents.length === 1 && listedEvents[0].summary === "sdk compat", JSON.stringify(listedEvents));
  const anchor = payload(await client.callTool({ name: "create_anchor", arguments: {} }));
  expect("create_anchor", anchor?.created === true && anchor.anchor?.seq === 1, JSON.stringify(anchor));
  const verified = payload(await client.callTool({ name: "verify_log", arguments: { anchors: [anchor.anchor] } }));
  expect("verify_log", verified?.valid === true && verified.externalAnchorsChecked === 1, JSON.stringify(verified));
  const controls = payload(await client.callTool({ name: "map_controls", arguments: { type: "change" } }));
  expect("map_controls", controls !== null && typeof controls === "object", JSON.stringify(controls));
  const report = await client.callTool({ name: "export_report", arguments: { from: "2000-01-01" } });
  expect("export_report", report.isError === false && String(report.content?.[0]?.text).startsWith("#"), JSON.stringify(report).slice(0, 300));

  const invalid = await client.callTool({ name: "map_controls", arguments: { type: "nope" } });
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
