// Protocol tests of the shared MCP stdio server. Kept byte-identical in every package that uses the module.
import { existsSync, readFileSync } from "node:fs";
import { PassThrough, Writable } from "node:stream";
import * as sdkTypes from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ErrorCode,
  LATEST_PROTOCOL_VERSION,
  MAX_JSON_DEPTH,
  MAX_LINE_BYTES,
  McpStdioServer,
  parseJsonLine,
  serveStdio,
  SUPPORTED_PROTOCOL_VERSIONS,
  type JsonRpcResponse,
  type ToolResult,
} from "../src/vendor/mcpStdio.js";

const text = (t: string): ToolResult => ({ content: [{ type: "text", text: t }] });

function server(): McpStdioServer {
  const s = new McpStdioServer({ name: "test-server", version: "1.2.3" });
  s.registerTool("echo", { description: "Echo.", inputSchema: { value: z.string().max(10), n: z.number().int().default(1) } }, ({ value, n }) =>
    text(`${value}:${n}`),
  );
  s.registerTool("nested", { description: "Nested.", inputSchema: { a: z.object({ b: z.array(z.string()) }) } }, () => text("ok"));
  s.registerTool("plain", { description: "No arguments." }, () => text("plain"));
  s.registerTool("throws", { description: "Throws." }, () => {
    throw new Error("secret /home/user/path");
  });
  s.registerTool("async", { description: "Async." }, async () => text("later"));
  return s;
}

async function line(s: McpStdioServer, raw: string): Promise<JsonRpcResponse | undefined> {
  return s.handleLine(raw);
}

async function call(s: McpStdioServer, message: unknown): Promise<JsonRpcResponse | undefined> {
  return s.handleLine(JSON.stringify(message));
}

function req(method: string, params?: unknown, id: unknown = 1): Record<string, unknown> {
  return { jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) };
}

const init = (protocolVersion: unknown) =>
  req("initialize", { protocolVersion, capabilities: {}, clientInfo: { name: "c", version: "0" } });

describe("protocol versions", () => {
  it("match @modelcontextprotocol/sdk (devDependency)", () => {
    expect(LATEST_PROTOCOL_VERSION).toBe(sdkTypes.LATEST_PROTOCOL_VERSION);
    expect([...SUPPORTED_PROTOCOL_VERSIONS]).toEqual([...sdkTypes.SUPPORTED_PROTOCOL_VERSIONS]);
  });

  it("echoes every supported version and falls back to the latest otherwise (as the SDK)", async () => {
    const s = server();
    for (const v of SUPPORTED_PROTOCOL_VERSIONS) {
      expect((await call(s, init(v)))?.result).toEqual({
        protocolVersion: v,
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "test-server", version: "1.2.3" },
      });
    }
    for (const v of ["1999-01-01", "2099-12-31", ""]) {
      expect((await call(s, init(v)))?.result?.protocolVersion).toBe(LATEST_PROTOCOL_VERSION);
    }
  });

  it("rejects malformed initialize params with -32602", async () => {
    const s = server();
    for (const params of [undefined, {}, { protocolVersion: 1, capabilities: {}, clientInfo: { name: "c", version: "0" } },
      { protocolVersion: "2025-06-18", capabilities: {} }, { protocolVersion: "2025-06-18", clientInfo: { name: "c", version: "0" } }]) {
      expect(await call(s, req("initialize", params, 7))).toEqual({
        jsonrpc: "2.0", id: 7, error: { code: ErrorCode.InvalidParams, message: "Invalid params" },
      });
    }
  });
});

describe("JSON-RPC framing errors", () => {
  it("parse error -32700 with id null", async () => {
    for (const raw of ["not json", "{", '{"jsonrpc":"2.0",', "\u0000"]) {
      expect(await line(server(), raw)).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    }
  });

  it("invalid request -32600 (id kept only when it is valid)", async () => {
    const s = server();
    const invalid = (id: string | number | null) => ({ jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } });
    expect(await line(s, "[]")).toEqual(invalid(null)); // batches are not supported (MCP 2025-06-18 and later)
    expect(await line(s, "[" + JSON.stringify(req("ping")) + "]")).toEqual(invalid(null));
    expect(await line(s, "null")).toEqual(invalid(null));
    expect(await line(s, "42")).toEqual(invalid(null));
    expect(await line(s, '"x"')).toEqual(invalid(null));
    expect(await call(s, { id: 3, method: "ping" })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "1.0", id: 3, method: "ping" })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "2.0", id: 3, method: 5 })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "2.0", id: 3, method: "ping", params: [] })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "2.0", id: 3, method: "ping", params: "x" })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "2.0", id: 3 })).toEqual(invalid(3));
    expect(await call(s, { jsonrpc: "2.0", id: 1.5, method: "ping" })).toEqual(invalid(null));
    expect(await call(s, { jsonrpc: "2.0", id: null, method: "ping" })).toEqual(invalid(null));
    expect(await call(s, { jsonrpc: "2.0", id: { a: 1 }, method: "ping" })).toEqual(invalid(null));
    expect(await call(s, { jsonrpc: "2.0", id: true, method: "ping" })).toEqual(invalid(null));
    expect(await call(s, { jsonrpc: "2.0", id: 2 ** 60, method: "ping" })).toEqual(invalid(null));
  });

  it("unknown methods -32601, also for names of Object.prototype members", async () => {
    const s = server();
    for (const method of ["nope", "resources/list", "prompts/list", "logging/setLevel", "constructor", "__proto__", "toString",
      "hasOwnProperty", "notifications/initialized"]) {
      expect(await call(s, req(method, undefined, "s1"))).toEqual({
        jsonrpc: "2.0", id: "s1", error: { code: -32601, message: "Method not found" },
      });
    }
  });

  it("notifications and client responses get no reply", async () => {
    const s = server();
    for (const msg of [
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } },
      { jsonrpc: "2.0", method: "unknown/notification" },
      { jsonrpc: "2.0", method: "tools/call", params: { name: "throws" } },
      { jsonrpc: "2.0", id: 12, result: {} },
      { jsonrpc: "2.0", id: "x", error: { code: 1, message: "m" } },
    ]) {
      expect(await call(s, msg)).toBeUndefined();
    }
  });

  it("ping answers an empty result", async () => {
    expect(await call(server(), req("ping", undefined, 0))).toEqual({ jsonrpc: "2.0", id: 0, result: {} });
    expect(await call(server(), req("ping", { _meta: {} }, "p"))).toEqual({ jsonrpc: "2.0", id: "p", result: {} });
  });
});

describe("prototype pollution", () => {
  it("rejects __proto__ at any depth as invalid request and leaves Object.prototype alone", async () => {
    const s = server();
    const raws = [
      '{"jsonrpc":"2.0","id":1,"method":"ping","__proto__":{"polluted":1}}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"__proto__":{"polluted":1},"value":"a"}}}',
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"x":[{"__proto__":{"polluted":1}}]},"clientInfo":{"name":"c","version":"0"}}}',
    ];
    for (const raw of raws) {
      expect(await line(s, raw)).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => parseJsonLine('{"a":{"__proto__":1}}')).toThrow();
    expect(parseJsonLine('{"constructor":{"prototype":{"x":1}}}')).toEqual({ constructor: { prototype: { x: 1 } } });
  });

  it("tool lookup does not reach Object.prototype members", async () => {
    const s = server();
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      const res = await call(s, req("tools/call", { name, arguments: {} }));
      expect(res?.result).toEqual({ content: [{ type: "text", text: `MCP error -32602: Tool ${name} not found` }], isError: true });
    }
  });
});

describe("tools/list", () => {
  it("lists tools in registration order with draft-07 JSON Schema (input side) and taskSupport forbidden", async () => {
    const res = await call(server(), req("tools/list", { cursor: "ignored" }));
    const tools = res?.result?.tools as Record<string, unknown>[];
    expect(tools.map((t) => t.name)).toEqual(["echo", "nested", "plain", "throws", "async"]);
    expect(tools[0]).toEqual({
      name: "echo",
      description: "Echo.",
      inputSchema: {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        properties: { value: { type: "string", maxLength: 10 }, n: { default: 1, type: "integer", minimum: -9007199254740991, maximum: 9007199254740991 } },
        required: ["value"],
      },
      execution: { taskSupport: "forbidden" },
    });
    expect(tools[2]?.inputSchema).toEqual({ type: "object", properties: {} });
  });

  it("refuses a second tool with the same name", () => {
    const s = server();
    expect(() => s.registerTool("plain", { description: "again" }, () => text("x"))).toThrow(/already registered/);
  });
});

describe("tools/call", () => {
  it("validates with zod, applies defaults and strips unknown keys", async () => {
    const s = server();
    expect((await call(s, req("tools/call", { name: "echo", arguments: { value: "hi", extra: 1 } })))?.result).toEqual(text("hi:1"));
    expect((await call(s, req("tools/call", { name: "echo", arguments: { value: "hi", n: 3 } })))?.result).toEqual(text("hi:3"));
    expect((await call(s, req("tools/call", { name: "plain", arguments: { ignored: true } })))?.result).toEqual(text("plain"));
    expect((await call(s, req("tools/call", { name: "plain" })))?.result).toEqual(text("plain"));
    expect((await call(s, req("tools/call", { name: "async" })))?.result).toEqual(text("later"));
  });

  it("reports invalid arguments as isError result with the SDK's text", async () => {
    const s = server();
    const err = (t: string) => ({ content: [{ type: "text", text: t }], isError: true });
    expect((await call(s, req("tools/call", { name: "echo", arguments: {} })))?.result).toEqual(
      err("MCP error -32602: Input validation error: Invalid arguments for tool echo: Invalid input: expected string, received undefined at value"),
    );
    expect((await call(s, req("tools/call", { name: "echo" })))?.result).toEqual(
      err("MCP error -32602: Input validation error: Invalid arguments for tool echo: Invalid input: expected string, received undefined at value"),
    );
    const many = await call(s, req("tools/call", { name: "echo", arguments: { value: "x".repeat(11), n: 1.5 } }));
    expect((many?.result as ToolResult).content[0]?.text).toBe(
      "MCP error -32602: Input validation error: Invalid arguments for tool echo: Too big: expected string to have <=10 characters at value\n" +
        "Invalid input: expected int, received number at n",
    );
    const nested = await call(s, req("tools/call", { name: "nested", arguments: { a: { b: ["ok", 5] } } }));
    expect((nested?.result as ToolResult).content[0]?.text).toBe(
      "MCP error -32602: Input validation error: Invalid arguments for tool nested: Invalid input: expected string, received number at a.b[1]",
    );
  });

  it("unknown tool is an isError result (as the SDK)", async () => {
    expect((await call(server(), req("tools/call", { name: "missing", arguments: {} })))?.result).toEqual({
      content: [{ type: "text", text: "MCP error -32602: Tool missing not found" }],
      isError: true,
    });
  });

  it("malformed tools/call params are a JSON-RPC error -32602", async () => {
    const s = server();
    for (const params of [undefined, {}, { name: 5 }, { name: "echo", arguments: [] }, { name: "echo", arguments: "x" }, { name: "echo", arguments: null }]) {
      expect(await call(s, req("tools/call", params, 9))).toEqual({
        jsonrpc: "2.0", id: 9, error: { code: -32602, message: "Invalid params" },
      });
    }
  });

  it("an exception in a tool does not leak its message", async () => {
    const res = await call(server(), req("tools/call", { name: "throws" }));
    expect(res?.result).toEqual({ content: [{ type: "text", text: "MCP error -32603: Internal error in tool throws" }], isError: true });
    expect(JSON.stringify(res)).not.toContain("secret");
  });
});

class Sink extends Writable {
  chunks: string[] = [];
  override _write(chunk: Buffer, _enc: BufferEncoding, cb: (error?: Error | null) => void): void {
    this.chunks.push(chunk.toString("utf8"));
    cb();
  }
  get messages(): JsonRpcResponse[] {
    return this.chunks.join("").split("\n").filter(Boolean).map((l) => JSON.parse(l) as JsonRpcResponse);
  }
}

function stdio(maxLineBytes?: number) {
  const input = new PassThrough();
  const output = new Sink();
  const diagnostics = new Sink();
  const done = serveStdio(server(), { input, output, diagnostics, ...(maxLineBytes ? { maxLineBytes } : {}) });
  return { input, output, diagnostics, done };
}

describe("serveStdio", () => {
  it("answers newline-delimited messages in order, across chunk borders, with CRLF, skipping blank lines", async () => {
    const { input, output, diagnostics, done } = stdio();
    const all = [init("2025-06-18"), { jsonrpc: "2.0", method: "notifications/initialized" }, req("ping", undefined, 2),
      req("tools/call", { name: "async" }, 3), req("tools/call", { name: "echo", arguments: { value: "v" } }, 4)]
      .map((m) => JSON.stringify(m)).join("\r\n") + "\n\n\r\n";
    input.write(all.slice(0, 17));
    input.write(Buffer.from(all.slice(17, 120)));
    input.end(all.slice(120));
    expect(await done).toBe("end");
    expect(output.messages.map((m) => m.id)).toEqual([1, 2, 3, 4]);
    expect(output.messages[3]?.result).toEqual(text("v:1"));
    expect(output.chunks.every((c) => c.endsWith("\n") && c.indexOf("\n") === c.length - 1)).toBe(true);
    expect(diagnostics.chunks).toEqual([]);
  });

  it("ignores an unterminated last line (as the SDK)", async () => {
    const { input, output, done } = stdio();
    input.end(JSON.stringify(req("ping", undefined, 1)) + "\n" + JSON.stringify(req("ping", undefined, 2)));
    expect(await done).toBe("end");
    expect(output.messages.map((m) => m.id)).toEqual([1]);
  });

  it("accepts a line of exactly the limit", async () => {
    const { input, output, done } = stdio(64);
    const msg = JSON.stringify(req("ping", undefined, "x"));
    const padded = msg.slice(0, -1) + ",\"pad\":\"" + "a".repeat(64 - msg.length - 9) + "\"}";
    expect(Buffer.byteLength(padded)).toBe(64);
    input.end(padded + "\n");
    expect(await done).toBe("end");
    expect(output.messages).toEqual([{ jsonrpc: "2.0", id: "x", result: {} }]);
  });

  it("fails closed on a line over the limit (complete line): earlier lines answered, error, session ends", async () => {
    const { input, output, diagnostics, done } = stdio(64);
    input.write(JSON.stringify(req("ping", undefined, 1)) + "\n" + "x".repeat(65) + "\n" + JSON.stringify(req("ping", undefined, 2)) + "\n");
    expect(await done).toBe("overflow");
    expect(output.messages).toEqual([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request: line exceeds 64 bytes" } },
    ]);
    expect(diagnostics.chunks.join("")).toContain("exceeds 64 bytes");
    expect(input.destroyed).toBe(true);
  });

  it("fails closed on an unterminated line growing over the limit (multi-byte UTF-8 counted in bytes)", async () => {
    const { input, output, done } = stdio(64);
    input.write("ä".repeat(20));
    input.write("ä".repeat(13)); // 66 bytes, 33 characters
    expect(await done).toBe("overflow");
    expect(output.messages).toEqual([{ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request: line exceeds 64 bytes" } }]);
  });

  it("default limit is 1 MiB", async () => {
    expect(MAX_LINE_BYTES).toBe(1024 * 1024);
    const { input, output, done } = stdio();
    input.write(" ".repeat(MAX_LINE_BYTES));
    input.write(" ");
    expect(await done).toBe("overflow");
    expect(output.messages[0]?.error?.code).toBe(-32600);
  });

  it("stops when the output fails", async () => {
    const input = new PassThrough();
    const output = new Writable({ write: (_c, _e, cb) => cb(new Error("EPIPE")) });
    const done = serveStdio(server(), { input, output, diagnostics: new Sink() });
    input.write(JSON.stringify(req("ping")) + "\n");
    input.write(JSON.stringify(req("ping")) + "\n");
    expect(await done).toBe("closed");
  });

  it("ends on an input error", async () => {
    const { input, done } = stdio();
    input.destroy(new Error("broken"));
    expect(await done).toBe("end");
  });

  it("an input error after the session ended is not an uncaught exception", async () => {
    const { input, done } = stdio();
    input.end();
    expect(await done).toBe("end");
    expect(input.listenerCount("error")).toBeGreaterThan(0);
    expect(() => input.emit("error", new Error("late"))).not.toThrow();
  });
});

describe("back-pressure", () => {
  /** Output that accepts one byte before asking for drain and completes each write later (slow reader). */
  class SlowSink extends Writable {
    lines: string[] = [];
    maxBuffered = 0;
    constructor() {
      super({ highWaterMark: 1 });
    }
    override _write(chunk: Buffer, _enc: BufferEncoding, cb: (error?: Error | null) => void): void {
      this.maxBuffered = Math.max(this.maxBuffered, this.writableLength);
      this.lines.push(chunk.toString("utf8"));
      setTimeout(cb, 0);
    }
  }

  it("a flood with a slow reader keeps the queue and the output buffer bounded and loses no response", async () => {
    const total = 3000;
    const pendingLimit = 16;
    const input = new PassThrough({ highWaterMark: 256 });
    const output = new SlowSink();
    let read = 0;
    let maxBacklog = 0;
    // A second data listener sees exactly what the server consumes; pause() stops both.
    input.on("data", (chunk: Buffer) => {
      for (const byte of chunk) if (byte === 0x0a) read++;
      maxBacklog = Math.max(maxBacklog, read - output.lines.length);
    });
    const done = serveStdio(server(), { input, output, diagnostics: new Sink(), maxPendingLines: pendingLimit });
    // The writer honours the input's back-pressure, as a pipe from the client does.
    for (let i = 0; i < total; i++) {
      if (!input.write(JSON.stringify(req("ping", undefined, i)) + "\n")) await new Promise((r) => input.once("drain", r));
    }
    input.end();
    expect(await done).toBe("end");
    await new Promise<void>((resolve) => output.end(resolve));
    const ids = output.lines.join("").split("\n").filter(Boolean).map((l) => (JSON.parse(l) as JsonRpcResponse).id);
    expect(ids).toEqual(Array.from({ length: total }, (_, i) => i));
    // Lines handed to the server but not yet answered: at most the queue limit plus the line being processed.
    expect(maxBacklog).toBeLessThanOrEqual(pendingLimit + 2);
    // write() return value honoured: never more than one response waiting in the output buffer.
    expect(output.maxBuffered).toBeLessThan(200);
  });

  it("one big chunk ending the input is processed in portions without losing lines", async () => {
    const input = new PassThrough();
    const output = new SlowSink();
    const done = serveStdio(server(), { input, output, diagnostics: new Sink(), maxPendingLines: 4 });
    input.end(Array.from({ length: 500 }, (_, i) => JSON.stringify(req("ping", undefined, i))).join("\n") + "\n");
    expect(await done).toBe("end");
    await new Promise<void>((resolve) => output.end(resolve));
    const ids = output.lines.join("").split("\n").filter(Boolean).map((l) => (JSON.parse(l) as JsonRpcResponse).id);
    expect(ids).toEqual(Array.from({ length: 500 }, (_, i) => i));
  });

  it("pauses the input while the queue is full and resumes afterwards", async () => {
    const input = new PassThrough({ highWaterMark: 64 });
    const output = new SlowSink();
    const done = serveStdio(server(), { input, output, diagnostics: new Sink(), maxPendingLines: 2 });
    const line = JSON.stringify(req("ping", undefined, 1)) + "\n";
    let sawPaused = false;
    for (let i = 0; i < 50; i++) {
      if (!input.write(line)) await new Promise((r) => input.once("drain", r));
      if (input.isPaused()) sawPaused = true;
    }
    input.end();
    expect(await done).toBe("end");
    expect(sawPaused).toBe(true);
    expect(output.lines.join("").split("\n").filter(Boolean)).toHaveLength(50);
  });
});

describe("deep nesting", () => {
  it("survives 200k unclosed and closed brackets within 1 MiB and answers the next request", async () => {
    const s = server();
    for (const raw of ["[".repeat(200_000), "[".repeat(200_000) + "]".repeat(200_000), '{"a":'.repeat(100_000) + "1" + "}".repeat(100_000)]) {
      expect(Buffer.byteLength(raw)).toBeLessThanOrEqual(MAX_LINE_BYTES);
      const res = await s.handleLine(raw);
      expect(res?.id).toBeNull();
      expect([-32700, -32600]).toContain(res?.error?.code);
    }
    expect(await s.handleLine(JSON.stringify(req("ping", undefined, 5)))).toEqual({ jsonrpc: "2.0", id: 5, result: {} });
  });

  it("rejects nesting deeper than MAX_JSON_DEPTH before parsing, accepts it up to the limit, ignores brackets in strings", async () => {
    const s = server();
    const nested = (depth: number) => JSON.stringify(req("tools/call", { name: "plain", arguments: { x: JSON.parse("[".repeat(depth) + "]".repeat(depth)) } }));
    // Message, params and arguments add three levels.
    expect((await s.handleLine(nested(MAX_JSON_DEPTH - 3)))?.result).toEqual(text("plain"));
    expect(await s.handleLine(nested(MAX_JSON_DEPTH - 2))).toEqual({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
    const inString = JSON.stringify(req("tools/call", { name: "echo", arguments: { value: "[[[[" + "\\\"" } }));
    expect((await s.handleLine(inString.replace('"[[[[', '"' + "[".repeat(5000))))?.result).toMatchObject({ isError: true });
  });

  it("a deep line in a stdio session does not end the session", async () => {
    const { input, output, done } = stdio();
    input.end("[".repeat(200_000) + "\n" + JSON.stringify(req("ping", undefined, 2)) + "\n");
    expect(await done).toBe("end");
    expect(output.messages.map((m) => m.id)).toEqual([null, 2]);
  });
});

describe("shared module", () => {
  for (const [copy, source] of [
    ["../src/vendor/mcpStdio.ts", "../../modules/mcp-stdio/mcpStdio.ts"],
    ["./mcpStdio.test.ts", "../../modules/mcp-stdio/mcpStdio.test.ts"],
  ] as const) {
    const src = new URL(source, import.meta.url);
    // Not present in the public export; there only this comparison is skipped.
    it.skipIf(!existsSync(src))(`${copy} is byte-identical to the shared module`, () => {
      expect(readFileSync(new URL(copy, import.meta.url)).equals(readFileSync(src))).toBe(true);
    });
  }
});
