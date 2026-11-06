import { readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// INV-12/13: the hook and the MCP server open no connection. Static import test, same idea as tollgate-enterprise/test/noNetwork.test.ts.
const SRC = new URL("../src/", import.meta.url).pathname;
const NETWORK = /^(?:node:)?(net|http|https|http2|tls|dgram|dns|dns\/promises|cluster|inspector)$/;
// The MCP server is the own stdio implementation (src/vendor/mcpStdio.ts); the SDK is a devDependency for the
// compatibility test only. Runtime imports: node: built-ins, relative modules and zod, nothing else.
const RUNTIME_PACKAGES = new Set(["zod"]);
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

describe("evidence-mcp opens no network connection (INV-12/13)", () => {
  const all = files(SRC);

  it("finds the sources", () => {
    expect(all.length).toBeGreaterThan(4);
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

  it("imports no part of the MCP SDK and no package other than zod", () => {
    for (const file of all) {
      for (const spec of specifiers(readFileSync(file, "utf8"))) {
        const where = `${relative(SRC, file)} imports ${spec}`;
        expect(spec, where).not.toMatch(/^@modelcontextprotocol\//);
        // Only module specifiers (the scan also sees strings such as regex sources in codeScan.ts).
        const pkg = /^((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)(?:\/.*)?$/.exec(spec)?.[1];
        if (pkg === undefined || builtinModules.includes(pkg)) continue;
        expect(RUNTIME_PACKAGES.has(pkg), where).toBe(true);
      }
    }
  });

  it("the detection patterns catch the usual forms", () => {
    for (const s of ["node:net", "tls", "node:https", "dns/promises", "node:dgram"]) expect(s).toMatch(NETWORK);
    expect("node:path").not.toMatch(NETWORK);
    expect(specifiers('import tls from "node:tls"; const n = require("net"); await import("node:http");')).toEqual(["node:tls", "net", "node:http"]);
  });
});
