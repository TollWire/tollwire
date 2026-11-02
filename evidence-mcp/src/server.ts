#!/usr/bin/env node
// Evidence MCP server (stdio only, no network listener). Writes only to the configured evidence log.
import { dirname, join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { anchorTagName, AnchorSchema, createAnchor, MAX_ANCHORS, recordEvent, signedTagCommand, verifyLogWithAnchors } from "./anchor.js";
import { controlsFor, EVENT_TYPES } from "./controls.js";
import { isEntryPoint } from "./entry.js";
import { assertNoSymlinkedDirs, EventInputSchema, EvidenceError, readEntries, readLog, resolveLogRoot, verifyLogRead } from "./log.js";
import { renderReport } from "./report.js";

export const DEFAULT_LOG = join(".tollgate", "evidence", "log.jsonl");

export function resolveLogPath(env: NodeJS.ProcessEnv, projectDir: string): string {
  return env.TOLLGATE_EVIDENCE_LOG || join(projectDir, DEFAULT_LOG);
}

function text(payload: unknown, isError = false) {
  return { content: [{ type: "text" as const, text: typeof payload === "string" ? payload : JSON.stringify(payload) }], isError };
}

/**
 * Error text for every tool result: EvidenceError messages are user-facing and carry no paths; anything else (fs errors
 * contain absolute paths) is replaced by a generic message. Stack traces never reach the client.
 */
export function errorReason(error: unknown, action: string): string {
  return error instanceof EvidenceError ? error.message : `Internal error while ${action}.`;
}

/** Real calendar dates and UTC timestamps only (rejects e.g. 2026-99-99 or T99:99Z). */
export function isValidIsoDate(value: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?Z)?$/.exec(value);
  if (!m) return false;
  const [, y, mo, d, h = "00", mi = "00", s = "00"] = m;
  const date = new Date(Date.UTC(+y!, +mo! - 1, +d!, +h, +mi, +s));
  return (
    date.getUTCFullYear() === +y! && date.getUTCMonth() === +mo! - 1 && date.getUTCDate() === +d! &&
    date.getUTCHours() === +h && date.getUTCMinutes() === +mi && date.getUTCSeconds() === +s
  );
}

const isoDate = z.string().refine(isValidIsoDate, "ISO date (YYYY-MM-DD) or UTC timestamp (YYYY-MM-DDThh:mm[:ss[.sss]]Z)");

export interface ServerOptions {
  /** Trusted root of the log location (resolveLogRoot); directories below it must not be symbolic links. */
  root?: string;
}

export function createServer(configuredLogPath: string, options: ServerOptions = {}): McpServer {
  const server = new McpServer({ name: "tollgate-evidence", version: "0.1.0" });
  // Resolved once: every check and every read/write of all tools refers to the same absolute path.
  const logPath = resolve(configuredLogPath);
  const root = options.root;
  /** Every file-reading tool refuses a log location redirected through a symlinked directory. */
  const checkLocation = () => assertNoSymlinkedDirs(logPath, root ?? dirname(resolve(logPath)));

  server.registerTool(
    "record_event",
    {
      description:
        "Append an evidence event (change, review, scan, approval, deployment, incident, access_change, agent_action, anchor) to the " +
        "tamper-evident log. Never include secrets. `anchor` documents that the human stored an anchor externally: needs ref (tag name " +
        "or comment URL), details.anchor {seq, hash, ts, count} matching the log and details.storage (signed_tag | digest_comment).",
      inputSchema: EventInputSchema.shape,
    },
    (input) => {
      try {
        const entry = recordEvent(logPath, input, new Date(), root ? { root } : {});
        return text({ recorded: true, seq: entry.seq, hash: entry.hash, controls: controlsFor(entry.type) });
      } catch (error) {
        return text({ recorded: false, reason: errorReason(error, "recording the event") }, true);
      }
    },
  );

  server.registerTool(
    "list_events",
    {
      description: "List recorded evidence events, newest last.",
      inputSchema: { type: z.enum(EVENT_TYPES).optional(), limit: z.number().int().min(1).max(500).default(50) },
    },
    ({ type, limit }) => {
      try {
        checkLocation();
        const entries = readEntries(logPath).filter((e) => !type || e.type === type);
        return text(entries.slice(-limit));
      } catch (error) {
        return text({ listed: false, reason: errorReason(error, "reading the evidence log") }, true);
      }
    },
  );

  server.registerTool(
    "verify_log",
    {
      description:
        "Verify the integrity of the evidence hash chain, the local anchor file (if present) and optional external anchors " +
        "({seq, hash, ts, count}, e.g. copied from a signed git tag). Detects rewritten or truncated logs relative to the anchors.",
      inputSchema: { anchors: z.array(AnchorSchema).max(MAX_ANCHORS).optional() },
    },
    ({ anchors }) => {
      try {
        checkLocation();
        return text(verifyLogWithAnchors(logPath, anchors ?? []));
      } catch (error) {
        return text({ valid: false, reason: errorReason(error, "verifying the evidence log") }, true);
      }
    },
  );

  server.registerTool(
    "create_anchor",
    {
      description:
        "Anchor the latest evidence entry ({seq, hash, ts, count}) in the local, hash-linked anchor file and return a line for " +
        "external storage. Does not sign or upload anything: the human stores the line outside this machine (e.g. a signed git tag).",
    },
    () => {
      try {
        const { created, anchor, record, line } = createAnchor(logPath, root ? { root } : {});
        return text({
          created,
          anchor,
          line,
          created_at: record.created_at,
          anchor_hash: record.anchor_hash,
          external: {
            signed_tag: signedTagCommand(anchor, record.created_at),
            tag_name: anchorTagName(anchor, record.created_at),
            note:
              "Human step: run the signed tag with the owner's key (agents never sign) and push it, or store the line outside this machine in another tamper-evident place. " +
              "Afterwards the human records an `anchor` event (record_event) referencing the stored copy.",
          },
        });
      } catch (error) {
        return text({ created: false, reason: errorReason(error, "creating the anchor") }, true);
      }
    },
  );

  server.registerTool(
    "map_controls",
    {
      description: "Show which ISO/IEC 27001:2022 Annex A and NIS2 Art. 21 controls an event type supports (draft mapping).",
      inputSchema: { type: z.enum(EVENT_TYPES) },
    },
    // Cannot fail: input is a validated enum over a static map; no file access.
    ({ type }) => text(controlsFor(type)),
  );

  server.registerTool(
    "export_report",
    {
      description: "Render a Markdown evidence report with chain integrity and control coverage.",
      inputSchema: { from: isoDate.optional(), to: isoDate.optional() },
    },
    ({ from, to }) => {
      try {
        checkLocation();
        const read = readLog(logPath);
        return text(renderReport(read.entries, { ...(from ? { from } : {}), ...(to ? { to } : {}) }, verifyLogRead(read)));
      } catch (error) {
        return text({ exported: false, reason: errorReason(error, "rendering the evidence report") }, true);
      }
    },
  );

  return server;
}

export async function main(): Promise<void> {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const logPath = resolveLogPath(process.env, projectDir);
  await createServer(logPath, { root: resolveLogRoot(logPath, projectDir) }).connect(new StdioServerTransport());
}

if (isEntryPoint(import.meta.url)) {
  await main();
}
