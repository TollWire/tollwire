// Release 0.1.3: messages a user sees carry the public name TollWire, never TollGate.
// Technical identifiers (server name `tollgate-guardrail`, paths, TOLLGATE_* variables, schema ids) stay unchanged.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatBlock } from "../src/blockMessage.js";
import { createServer } from "../src/mcp/server.js";
import { WATCHDOG_MESSAGE } from "../src/watchdog.js";
import { defaultPolicy, PROJECT } from "./helpers.js";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : path.endsWith(".ts") ? [path] : [];
  });
}

describe("visible names (TollWire)", () => {
  it("the block message starts with the TollWire name", () => {
    const text = formatBlock({ kind: "blocked_command", ruleId: "git.force-push", detail: "force push", target: "git push -f" });
    expect(text.split("\n")[0]).toBe("TollWire guardrail: blocked.");
    expect(text).not.toContain("TollGate");
  });

  it("the watchdog message names TollWire", () => {
    expect(WATCHDOG_MESSAGE.startsWith("TollWire guardrail: ")).toBe(true);
    expect(WATCHDOG_MESSAGE).not.toContain("TollGate");
  });

  it("tool descriptions name TollWire, the server name stays tollgate-guardrail", async () => {
    const server = createServer(defaultPolicy(), PROJECT);
    const res = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    const tools = (res?.result as { tools: { name: string; description: string }[] }).tools;
    expect(tools.find((t) => t.name === "check_command")?.description).toContain("TollWire policy");
    for (const tool of tools) expect(tool.description).not.toContain("TollGate");
    const init = await server.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    });
    expect((init?.result as { serverInfo: { name: string } }).serverInfo.name).toBe("tollgate-guardrail");
  });

  it("no source file has a TollGate message text (only paths such as Logs/TollGate remain)", () => {
    // A message text has the old name followed by a space, a colon or a full stop; paths have / or \ or a quote after it.
    const hits = sources(SRC).flatMap((file) =>
      readFileSync(file, "utf8")
        .split("\n")
        .flatMap((line, i) => (/TollGate[ :.]/.test(line) ? [`${file}:${i + 1}`] : []))
    );
    expect(hits).toEqual([]);
  });
});
