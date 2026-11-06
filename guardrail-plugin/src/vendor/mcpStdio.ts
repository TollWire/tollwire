// Minimal MCP server over stdio: JSON-RPC 2.0, one message per line.
// This file is kept byte-identical in every package that uses it; a test in each package checks the copy.
// Imports: zod only. No network, no file access; stderr is used for diagnostics only.
import type { Readable, Writable } from "node:stream";
import { z } from "zod";

/** Protocol versions as in @modelcontextprotocol/sdk 1.32.0 (dist/esm/types.js). */
export const LATEST_PROTOCOL_VERSION = "2025-11-25";
export const SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = [
  LATEST_PROTOCOL_VERSION,
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
  "2024-10-07",
];

/** Longest accepted input line in bytes (without the newline). A longer line ends the session (fail closed). */
export const MAX_LINE_BYTES = 1024 * 1024;

/** Deepest accepted nesting of arrays/objects in one message; checked before JSON.parse (no recursion limits hit). */
export const MAX_JSON_DEPTH = 64;

/** Received lines waiting for processing; above this the input is paused until the queue is drained. */
export const MAX_PENDING_LINES = 64;

export const ErrorCode = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
} as const;

export type RequestId = string | number;

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: RequestId | null;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

type ToolHandler = (args: Record<string, unknown>) => ToolResult | Promise<ToolResult>;

interface RegisteredTool {
  description: string;
  schema: z.ZodObject | undefined;
  inputSchema: Record<string, unknown>;
  handler: ToolHandler;
}

/**
 * Message transport with the shape of the SDK's Transport interface (start/send/close, onmessage), so the official SDK
 * client can talk to this server in-process (tests). `send` takes `never` so that any transport with a narrower message
 * type fits; the server only ever passes a JsonRpcResponse.
 */
export interface MessageTransport {
  start(): Promise<void>;
  send(message: never): Promise<void>;
  close(): Promise<void>;
  onmessage?(message: unknown): void;
}

/** Tool without arguments, as the SDK lists it. */
const EMPTY_OBJECT_JSON_SCHEMA = { type: "object", properties: {} };

const InitializeParams = z.object({
  protocolVersion: z.string(),
  capabilities: z.record(z.string(), z.unknown()),
  clientInfo: z.object({ name: z.string(), version: z.string() }),
});
const CallToolParams = z.object({ name: z.string(), arguments: z.record(z.string(), z.unknown()).optional() });

class ForbiddenKey extends Error {}

/** Nesting depth of arrays/objects outside of strings (linear scan, stops once the limit is exceeded). */
export function jsonDepthExceeds(line: string, limit: number = MAX_JSON_DEPTH): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++; // backslash: skip the escaped character
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x5b || c === 0x7b) {
      if (++depth > limit) return true;
    } else if (c === 0x5d || c === 0x7d) depth--;
  }
  return false;
}

/** JSON.parse that rejects the key `__proto__` at any depth (no prototype pollution downstream). */
export function parseJsonLine(line: string): unknown {
  return JSON.parse(line, (key, value: unknown) => {
    if (key === "__proto__") throw new ForbiddenKey();
    return value;
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function isRequestId(value: unknown): value is RequestId {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

function errorResponse(id: RequestId | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/** Path formatting as in the SDK (getDotPath): a.b[0].c */
function dotPath(path: readonly PropertyKey[]): string {
  return path.reduce<string>((acc, seg, index) => {
    if (index === 0) return String(seg);
    return typeof seg === "number" ? `${acc}[${seg}]` : `${acc}.${String(seg)}`;
  }, "");
}

/** Tool error result with the SDK's text format ("MCP error <code>: <message>"). */
function toolError(code: number, message: string): ToolResult {
  return { content: [{ type: "text", text: `MCP error ${code}: ${message}` }], isError: true };
}

export class McpStdioServer {
  readonly #info: { name: string; version: string };
  readonly #tools = new Map<string, RegisteredTool>();
  #queue: Promise<void> = Promise.resolve();

  constructor(info: { name: string; version: string }) {
    this.#info = { name: info.name, version: info.version };
  }

  registerTool<S extends z.ZodRawShape>(
    name: string,
    config: { description: string; inputSchema: S },
    handler: (args: z.output<z.ZodObject<S>>) => ToolResult | Promise<ToolResult>,
  ): void;
  registerTool(name: string, config: { description: string }, handler: () => ToolResult | Promise<ToolResult>): void;
  registerTool(
    name: string,
    config: { description: string; inputSchema?: z.ZodRawShape },
    handler: (args: never) => ToolResult | Promise<ToolResult>,
  ): void {
    if (this.#tools.has(name)) throw new Error(`Tool ${name} is already registered`);
    const schema = config.inputSchema ? z.object(config.inputSchema) : undefined;
    this.#tools.set(name, {
      description: config.description,
      schema,
      inputSchema: schema
        ? (z.toJSONSchema(schema, { target: "draft-7", io: "input" }) as Record<string, unknown>)
        : { ...EMPTY_OBJECT_JSON_SCHEMA },
      handler: handler as ToolHandler,
    });
  }

  /** Handles one parsed message; returns the response, or undefined for notifications and client responses. */
  async handleMessage(message: unknown): Promise<JsonRpcResponse | undefined> {
    if (!isRecord(message)) return errorResponse(null, ErrorCode.InvalidRequest, "Invalid Request");
    const id = hasOwn(message, "id") ? message.id : undefined;
    const replyId = isRequestId(id) ? id : null;
    if (message.jsonrpc !== "2.0") return errorResponse(replyId, ErrorCode.InvalidRequest, "Invalid Request");
    if (!hasOwn(message, "method")) {
      // A response from the client: this server never sends requests, so there is nothing to match. Ignore it.
      if (isRequestId(id) && (hasOwn(message, "result") || hasOwn(message, "error"))) return undefined;
      return errorResponse(replyId, ErrorCode.InvalidRequest, "Invalid Request");
    }
    const method = message.method;
    const params = hasOwn(message, "params") ? message.params : undefined;
    if (typeof method !== "string" || (params !== undefined && !isRecord(params))) {
      return errorResponse(replyId, ErrorCode.InvalidRequest, "Invalid Request");
    }
    if (id === undefined) return undefined; // Notification (notifications/initialized, cancelled, unknown): no reply.
    if (!isRequestId(id)) return errorResponse(null, ErrorCode.InvalidRequest, "Invalid Request");
    const result = await this.#dispatch(method, params);
    if ("error" in result) return errorResponse(id, result.error.code, result.error.message);
    return { jsonrpc: "2.0", id, result: result.result };
  }

  /** Handles one input line (without the newline); returns the response or undefined. */
  async handleLine(line: string): Promise<JsonRpcResponse | undefined> {
    if (jsonDepthExceeds(line)) return errorResponse(null, ErrorCode.InvalidRequest, "Invalid Request");
    let message: unknown;
    try {
      message = parseJsonLine(line);
    } catch (error) {
      if (error instanceof ForbiddenKey) return errorResponse(null, ErrorCode.InvalidRequest, "Invalid Request");
      return errorResponse(null, ErrorCode.ParseError, "Parse error");
    }
    return this.handleMessage(message);
  }

  /** In-process transport (SDK-compatible shape). Messages are handled one after another, in order. */
  async connect(transport: MessageTransport): Promise<void> {
    transport.onmessage = (message: unknown) => {
      this.#enqueue(async () => {
        const response = await this.handleMessage(message);
        if (response) await (transport.send as (message: JsonRpcResponse) => Promise<void>).call(transport, response);
      });
    };
    await transport.start();
  }

  #enqueue(task: () => Promise<void>): Promise<void> {
    // Failures of one task (e.g. a closed transport) must not stop later ones; handleMessage itself never throws.
    this.#queue = this.#queue.then(task).catch(() => undefined);
    return this.#queue;
  }

  async #dispatch(
    method: string,
    params: Record<string, unknown> | undefined,
  ): Promise<{ result: Record<string, unknown> } | { error: { code: number; message: string } }> {
    switch (method) {
      case "initialize": {
        const parsed = InitializeParams.safeParse(params);
        if (!parsed.success) return { error: { code: ErrorCode.InvalidParams, message: "Invalid params" } };
        const requested = parsed.data.protocolVersion;
        const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION;
        return {
          result: { protocolVersion, capabilities: { tools: { listChanged: true } }, serverInfo: { ...this.#info } },
        };
      }
      case "ping":
        return { result: {} };
      case "tools/list":
        return {
          result: {
            tools: [...this.#tools].map(([name, tool]) => ({
              name,
              description: tool.description,
              inputSchema: tool.inputSchema,
              execution: { taskSupport: "forbidden" },
            })),
          },
        };
      case "tools/call": {
        const parsed = CallToolParams.safeParse(params);
        if (!parsed.success) return { error: { code: ErrorCode.InvalidParams, message: "Invalid params" } };
        return { result: await this.#callTool(parsed.data.name, parsed.data.arguments) };
      }
      default:
        return { error: { code: ErrorCode.MethodNotFound, message: "Method not found" } };
    }
  }

  async #callTool(name: string, args: Record<string, unknown> | undefined): Promise<ToolResult> {
    const tool = this.#tools.get(name);
    if (!tool) return toolError(ErrorCode.InvalidParams, `Tool ${name} not found`);
    let input: Record<string, unknown> = {};
    if (tool.schema) {
      const parsed = await tool.schema.safeParseAsync(args ?? {});
      if (!parsed.success) {
        const detail = parsed.error.issues
          .map((issue) => (issue.path.length ? `${issue.message} at ${dotPath(issue.path)}` : issue.message))
          .join("\n");
        return toolError(ErrorCode.InvalidParams, `Input validation error: Invalid arguments for tool ${name}: ${detail}`);
      }
      input = parsed.data;
    }
    try {
      return await tool.handler(input);
    } catch {
      // The exception text may contain paths; it never reaches the client.
      return toolError(ErrorCode.InternalError, `Internal error in tool ${name}`);
    }
  }
}

export interface StdioOptions {
  input?: Readable;
  output?: Writable;
  /** Diagnostics only. */
  diagnostics?: Writable;
  maxLineBytes?: number;
  /** Pending received lines before the input is paused (default MAX_PENDING_LINES). */
  maxPendingLines?: number;
}

/**
 * Serves the server over newline-delimited stdio until the input ends. Resolves with "overflow" when a line exceeded the
 * limit (the session is then closed after an error reply), "closed" when the output failed, otherwise "end".
 * An unterminated last line is ignored (as in the SDK).
 * Back-pressure: above maxPendingLines queued lines the input is paused and resumed once the queue is empty; each
 * response waits for `drain` when write() returns false. Memory stays bounded and no response is dropped.
 */
export function serveStdio(server: McpStdioServer, options: StdioOptions = {}): Promise<"end" | "overflow" | "closed"> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const diagnostics = options.diagnostics ?? process.stderr;
  const max = options.maxLineBytes ?? MAX_LINE_BYTES;
  const maxPending = options.maxPendingLines ?? MAX_PENDING_LINES;
  let pending = 0;
  /** Rest of an input chunk not yet split into lines because the queue was full. */
  let held: Buffer | undefined;
  let ended = false;
  let parts: Buffer[] = [];
  let size = 0;
  let queue: Promise<void> = Promise.resolve();
  let stopped = false;
  let finished = false;

  return new Promise((resolveServe) => {
    let outcome: "end" | "overflow" | "closed" = "end";
    const write = async (response: JsonRpcResponse | undefined): Promise<void> => {
      if (!response || stopped || output.writableEnded || output.destroyed) return;
      if (output.write(`${JSON.stringify(response)}\n`)) return;
      await new Promise<void>((resolveDrain) => {
        const done = (): void => {
          output.off("drain", done);
          output.off("error", done);
          output.off("close", done);
          resolveDrain();
        };
        output.on("drain", done);
        output.on("error", done);
        output.on("close", done);
      });
    };
    const finish = (): void => {
      if (finished) return;
      finished = true;
      input.off("data", onData);
      input.off("end", onEnd);
      input.off("close", onEnd);
      // onInputError stays registered (finish is idempotent): a late error must not become an uncaught exception.
      void queue.then(() => resolveServe(outcome));
    };
    const stop = (why: "overflow" | "closed"): void => {
      if (stopped) return;
      outcome = why;
      if (why === "overflow") {
        queue = queue.then(() =>
          write(errorResponse(null, ErrorCode.InvalidRequest, `Invalid Request: line exceeds ${max} bytes`)).catch(() => undefined),
        );
        diagnostics.write(`mcp: input line exceeds ${max} bytes, closing the session\n`);
      }
      queue = queue.then(() => {
        stopped = true;
      });
      input.pause();
      input.destroy();
      finish();
    };
    const enqueue = (line: string): void => {
      pending++;
      queue = queue.then(async () => {
        try {
          if (stopped || line.length === 0) return;
          try {
            await write(await server.handleLine(line));
          } catch {
            await write(errorResponse(null, ErrorCode.InternalError, "Internal error"));
          }
        } finally {
          pending--;
          if (pending === 0 && !finished && !stopped) {
            if (held) {
              const rest = held;
              held = undefined;
              onData(rest);
            }
            if (!held && pending < maxPending) {
              if (ended) finish();
              else if (input.isPaused()) input.resume();
            }
          }
        }
      });
    };
    const onData = (chunk: Buffer | string): void => {
      if (stopped || outcome !== "end") return;
      const data = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
      let start = 0;
      for (let nl = data.indexOf(0x0a, start); nl !== -1; nl = data.indexOf(0x0a, start)) {
        if (pending >= maxPending) {
          held = data.subarray(start);
          input.pause();
          return;
        }
        const piece = data.subarray(start, nl);
        if (size + piece.length > max) return stop("overflow");
        const line = size === 0 ? piece : Buffer.concat([...parts, piece]);
        parts = [];
        size = 0;
        enqueue(line.toString("utf8").replace(/\r$/, ""));
        start = nl + 1;
      }
      const rest = data.subarray(start);
      if (size + rest.length > max) return stop("overflow");
      if (rest.length > 0) {
        parts.push(rest);
        size += rest.length;
      }
      if (pending >= maxPending) input.pause();
    };
    const onEnd = (): void => {
      ended = true;
      if (!held) finish();
    };
    const onInputError = (): void => finish();
    output.on("error", () => stop("closed"));
    input.on("data", onData);
    input.on("end", onEnd);
    input.on("error", onInputError);
    input.on("close", onEnd);
  });
}
