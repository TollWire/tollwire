#!/usr/bin/env node
// Anchor CLI for the human. Uses dist/; no network, never signs.
//   node scripts/anchor.mjs create                  anchor the latest entry, print line + signed-tag command
//   node scripts/anchor.mjs verify ['<anchor json>' ...]  verify chain, anchor file and given anchors
//   node scripts/anchor.mjs record '<anchor json>' <signed_tag|digest_comment> <ref> <actor>
//                                                   AFTER storing the anchor externally: record an `anchor` event
// Log path: TOLLGATE_EVIDENCE_LOG, else <CLAUDE_PROJECT_DIR or cwd>/.tollgate/evidence/log.jsonl.
import { anchorTagName, createAnchor, recordEvent, signedTagCommand, verifyLogWithAnchors } from "../dist/anchor.js";
import { assertNoSymlinkedDirs, EvidenceError, resolveLogRoot } from "../dist/log.js";
import { resolveLogPath } from "../dist/server.js";

const [command, ...args] = process.argv.slice(2);
const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const log = resolveLogPath(process.env, projectDir);
const root = resolveLogRoot(log, projectDir);

try {
  if (command === "create") {
    const { created, anchor, record, line } = createAnchor(log, { root });
    console.log(created ? "Anker erstellt:" : "Kopf unverändert, bestehender Anker:");
    console.log(line);
    console.log("\nExtern sichern (Mensch, eigener Schlüssel):");
    console.log(signedTagCommand(anchor, record.created_at));
    console.log("\nDanach Ablage festhalten:");
    console.log(`node scripts/anchor.mjs record '${line}' signed_tag ${anchorTagName(anchor, record.created_at)} <akteur>`);
  } else if (command === "verify") {
    const anchors = args.map((arg) => JSON.parse(arg));
    assertNoSymlinkedDirs(log, root);
    const result = verifyLogWithAnchors(log, anchors);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.valid ? 0 : 1;
  } else if (command === "record" && args.length === 4) {
    const [anchorJson, storage, ref, actor] = args;
    const anchor = JSON.parse(anchorJson);
    const entry = recordEvent(
      log,
      { type: "anchor", summary: `Evidenz-Anker seq ${anchor?.seq} extern abgelegt (${storage})`, actor, ref, details: { anchor, storage } },
      new Date(),
      { root },
    );
    console.log(`Anker-Ereignis erfasst: seq ${entry.seq}, hash ${entry.hash}`);
  } else {
    console.error("Usage: anchor.mjs create | verify ['<anchor json>' ...] | record '<anchor json>' <signed_tag|digest_comment> <ref> <actor>");
    process.exitCode = 2;
  }
} catch (error) {
  const reason =
    error instanceof EvidenceError ? error.message : error instanceof SyntaxError ? "Anchor argument is not valid JSON." : error?.name === "ZodError" ? "Invalid event (summary, actor or ref)." : "Internal error.";
  console.error(`Fehler: ${reason}`);
  process.exitCode = 2;
}
