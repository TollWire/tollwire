import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// INV-12/13: the hook and the MCP server open no connection. Static import test, same idea as tollgate-enterprise/test/noNetwork.test.ts.
const SRC = new URL("../src/", import.meta.url).pathname;
const NETWORK = /^(?:node:)?(net|http|https|http2|tls|dgram|dns|dns\/promises|cluster|inspector)$/;
// The MCP server talks over stdio only; every other SDK entry (HTTP, SSE, client, auth) is a network path.
const SDK_ALLOWED = new Set([
  "@modelcontextprotocol/sdk/server/mcp.js",
  "@modelcontextprotocol/sdk/server/stdio.js",
]);
// Explicit allowlist (relative to src/) for modules that may import a network module. Empty on purpose: add an entry only with an ADR.
const NETWORK_ALLOWLIST = new Set<string>([]);

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (path.endsWith(".ts")) out.push(path);
  }
  return out;
}

function specifiers(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/(?:from|import|require)\s*\(?\s*["']([^"']+)["']/g)) out.push(m[1] as string);
  return out;
}

function code(path: string): string {
  return readFileSync(path, "utf8").replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}

describe("guardrail-plugin opens no network connection (INV-12/13)", () => {
  const all = files(SRC);

  it("finds the sources", () => {
    expect(all.length).toBeGreaterThan(10);
  });

  it("imports no network module outside the allowlist", () => {
    for (const file of all) {
      const rel = relative(SRC, file);
      if (NETWORK_ALLOWLIST.has(rel)) continue;
      for (const spec of specifiers(readFileSync(file, "utf8"))) expect(spec, `${rel} imports ${spec}`).not.toMatch(NETWORK);
    }
  });

  it("uses no fetch, WebSocket, XMLHttpRequest or EventSource", () => {
    for (const file of all) {
      expect(code(file), relative(SRC, file)).not.toMatch(/\bfetch\s*\(|new\s+WebSocket|XMLHttpRequest|new\s+EventSource/);
    }
  });

  it("imports only the stdio parts of the MCP SDK", () => {
    for (const file of all) {
      for (const spec of specifiers(readFileSync(file, "utf8"))) {
        if (spec.startsWith("@modelcontextprotocol/")) expect(SDK_ALLOWED.has(spec), `${relative(SRC, file)} imports ${spec}`).toBe(true);
      }
    }
  });

  it("the detection patterns catch the usual forms", () => {
    for (const s of ["node:net", "tls", "node:https", "dns/promises", "node:dgram"]) expect(s).toMatch(NETWORK);
    expect("node:path").not.toMatch(NETWORK);
    expect(specifiers('import tls from "node:tls"; const n = require("net"); await import("node:http");')).toEqual(["node:tls", "net", "node:http"]);
  });
});
