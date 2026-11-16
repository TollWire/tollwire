// Smoke test of dist/: starts the server over stdio and checks initialize + record + verify, concurrency and anchors.
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const log = join(mkdtempSync(join(tmpdir(), "ev-smoke-")), "log.jsonl");
const msgs = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "record_event", arguments: { type: "change", summary: "smoke", actor: "ci" } } },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "verify_log", arguments: {} } },
];
const run = spawnSync(process.execPath, ["dist/server.js"], {
  cwd: root,
  input: msgs.map((m) => JSON.stringify(m)).join("\n") + "\n",
  env: { ...process.env, TOLLGATE_EVIDENCE_LOG: log },
  encoding: "utf8",
  timeout: 10_000,
});
const ok = run.stdout.includes('"tollgate-evidence"') && run.stdout.includes('\\"recorded\\":true') && run.stdout.includes('\\"valid\\":true');
console.log(ok ? "PASS  evidence server initialize/record/verify" : `FAIL\n${run.stdout}\n${run.stderr}`);
if (!ok) process.exit(1);

// Concurrency: 5 processes append 10 events each to one log; the chain must stay valid with 50 entries.
const shared = join(mkdtempSync(join(tmpdir(), "ev-conc-")), "log.jsonl");
const worker = `import { appendEntry } from "./dist/log.js";
for (let i = 0; i < 10; i++) appendEntry(process.env.LOG, { type: "agent_action", summary: "w" + i, actor: "smoke" });`;
const { spawn } = await import("node:child_process");
const runs = Array.from({ length: 5 }, () =>
  new Promise((resolve) => {
    const p = spawn(process.execPath, ["--input-type=module", "-e", worker], { cwd: root, env: { ...process.env, LOG: shared } });
    p.on("exit", resolve);
  }),
);
const codes = await Promise.all(runs);
const { verifyLog } = await import(new URL("../dist/log.js", import.meta.url).href);
const result = verifyLog(shared);
const concurrentOk = codes.every((c) => c === 0) && result.valid && result.count === 50;
console.log(concurrentOk ? "PASS  5 concurrent writers, 50 entries, chain valid" : `FAIL  concurrency ${JSON.stringify({ codes, result })}`);
if (!concurrentOk) process.exit(1);

// Anchor round trip over stdio: create_anchor, then verify_log with the external anchor (ok), then a
// rewritten log (new valid chain, local anchor file removed) must be detected by the external anchor.
const { appendFileSync, existsSync, readFileSync, renameSync, rmSync } = await import("node:fs");
const serve = (logPath, calls) => {
  const init = msgs.slice(0, 2);
  const tools = calls.map((params, i) => ({ jsonrpc: "2.0", id: 10 + i, method: "tools/call", params }));
  const out = spawnSync(process.execPath, ["dist/server.js"], {
    cwd: root,
    input: [...init, ...tools].map((m) => JSON.stringify(m)).join("\n") + "\n",
    env: { ...process.env, TOLLGATE_EVIDENCE_LOG: logPath },
    encoding: "utf8",
    timeout: 10_000,
  });
  const byId = new Map(out.stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l)).map((m) => [m.id, m]));
  const parse = (t) => {
    try {
      return JSON.parse(t ?? "null");
    } catch {
      return { raw: t };
    }
  };
  return calls.map((_, i) => parse(byId.get(10 + i)?.result?.content?.[0]?.text));
};
const anchored = join(mkdtempSync(join(tmpdir(), "ev-anchor-")), "log.jsonl");
// One session per step: the SDK may run tool calls of one session concurrently, so order is not guaranteed.
serve(anchored, [{ name: "record_event", arguments: { type: "change", summary: "anchor smoke 1", actor: "ci" } }]);
serve(anchored, [{ name: "record_event", arguments: { type: "scan", summary: "anchor smoke 2", actor: "ci" } }]);
const [created] = serve(anchored, [{ name: "create_anchor", arguments: {} }]);
const [okVerify] = serve(anchored, [{ name: "verify_log", arguments: { anchors: [created?.anchor] } }]);
const [localOnly] = serve(anchored, [{ name: "verify_log", arguments: {} }]);
const { appendEntry } = await import(new URL("../dist/log.js", import.meta.url).href);
const forged = `${anchored}.forged`;
appendEntry(forged, { type: "change", summary: "forged 1", actor: "ci" });
appendEntry(forged, { type: "scan", summary: "forged 2", actor: "ci" });
renameSync(forged, anchored);
rmSync(`${anchored}.anchors.jsonl`);
const [badVerify] = serve(anchored, [{ name: "verify_log", arguments: { anchors: [created?.anchor] } }]);
const anchorOk =
  created?.created === true && created.anchor.seq === 2 && okVerify?.valid === true && okVerify.checked === 2 &&
  okVerify.anchored === true && okVerify.externalAnchorsChecked === 1 && localOnly?.valid === true && localOnly.anchored === false &&
  badVerify?.valid === false && badVerify.anchored === false && badVerify.failedSource === "input";
console.log(anchorOk ? "PASS  anchor round trip (create, verify, rewritten log detected)" : `FAIL  anchor ${JSON.stringify({ created, okVerify, badVerify })}`);
if (!anchorOk) process.exit(1);

// CLI: create + verify against the line it printed; then truncation is detected (exit 1).
const cliLog = join(mkdtempSync(join(tmpdir(), "ev-cli-")), "log.jsonl");
for (let i = 0; i < 3; i++) appendEntry(cliLog, { type: "agent_action", summary: `cli ${i}`, actor: "smoke" });
const cli = (...a) => spawnSync(process.execPath, ["scripts/anchor.mjs", ...a], { cwd: root, env: { ...process.env, TOLLGATE_EVIDENCE_LOG: cliLog }, encoding: "utf8" });
const createdCli = cli("create");
const line = createdCli.stdout.split("\n").find((l) => l.startsWith("{"));
const verifiedCli = cli("verify", line ?? "");
writeTruncated(cliLog, 2);
rmSync(`${cliLog}.anchors.jsonl`);
const truncatedCli = cli("verify", line ?? "");
const cliOk = createdCli.status === 0 && createdCli.stdout.includes("git tag -s evidence-anchor-") && verifiedCli.status === 0 && truncatedCli.status === 1 && truncatedCli.stdout.includes("truncated");
console.log(cliOk ? "PASS  anchor CLI create/verify, truncation detected" : `FAIL  cli ${JSON.stringify({ createdCli, verifiedCli, truncatedCli })}`);
if (!cliOk) process.exit(1);

function writeTruncated(path, keep) {
  const kept = readFileSync(path, "utf8").trim().split("\n").slice(0, keep).join("\n") + "\n";
  rmSync(path);
  appendFileSync(path, kept, { mode: 0o600 });
}

// Anchor event via CLI: create, record the external storage, verify; a forged anchor is refused (exit 2).
const eventLog = join(mkdtempSync(join(tmpdir(), "ev-cli-event-")), "log.jsonl");
for (let i = 0; i < 2; i++) appendEntry(eventLog, { type: "change", summary: `e ${i}`, actor: "smoke" });
const cliEv = (...a) => spawnSync(process.execPath, ["scripts/anchor.mjs", ...a], { cwd: root, env: { ...process.env, TOLLGATE_EVIDENCE_LOG: eventLog }, encoding: "utf8" });
const evCreated = cliEv("create");
const evLine = evCreated.stdout.split("\n").find((l) => l.startsWith("{")) ?? "";
const evRecorded = cliEv("record", evLine, "signed_tag", "evidence-anchor-smoke-seq2", "owner");
const evForged = cliEv("record", evLine.replace(/"hash":"[0-9a-f]{64}"/, `"hash":"${"c".repeat(64)}"`), "signed_tag", "x", "owner");
const evVerified = cliEv("verify", evLine);
const { readEntries } = await import(new URL("../dist/log.js", import.meta.url).href);
const evEntries = readEntries(eventLog);
const eventOk =
  evCreated.status === 0 && evCreated.stdout.includes("scripts/anchor.mjs record") && evRecorded.status === 0 && evForged.status === 2 &&
  evForged.stderr.includes("does not match") && evVerified.status === 0 && evEntries.length === 3 && evEntries[2].type === "anchor";
console.log(eventOk ? "PASS  anchor event recorded after external storage (CLI), forged anchor refused" : `FAIL  anchor event ${JSON.stringify({ evCreated, evRecorded, evForged, evVerified })}`);
if (!eventOk) process.exit(1);

// Parent-directory symlink (default layout): a linked .tollgate is refused by the server started from dist/.
const { mkdirSync, symlinkSync } = await import("node:fs");
const project = mkdtempSync(join(tmpdir(), "ev-proj-"));
const elsewhere = mkdtempSync(join(tmpdir(), "ev-elsewhere-"));
mkdirSync(join(elsewhere, "evidence"));
symlinkSync(elsewhere, join(project, ".tollgate"));
const baseEnv = { ...process.env };
delete baseEnv.TOLLGATE_EVIDENCE_LOG;
const linked = spawnSync(process.execPath, ["dist/server.js"], {
  cwd: root,
  input: [...msgs.slice(0, 3)].map((m) => JSON.stringify(m)).join("\n") + "\n",
  env: { ...baseEnv, CLAUDE_PROJECT_DIR: project },
  encoding: "utf8",
  timeout: 10_000,
});
const linkedOk = linked.stdout.includes("directory is a symbolic link") && !existsSync(join(elsewhere, "evidence", "log.jsonl"));
console.log(linkedOk ? "PASS  symlinked .tollgate refused (default layout)" : `FAIL  parent symlink ${linked.stdout}\n${linked.stderr}`);
if (!linkedOk) process.exit(1);

// Concurrency with anchors: 4 processes append and anchor in turn; log and anchor file must stay consistent.
const mixed = join(mkdtempSync(join(tmpdir(), "ev-anchor-conc-")), "log.jsonl");
const anchorWorker = `import { appendEntry } from "./dist/log.js";
import { createAnchor } from "./dist/anchor.js";
for (let i = 0; i < 8; i++) { appendEntry(process.env.LOG, { type: "agent_action", summary: "a" + i, actor: "smoke" }); createAnchor(process.env.LOG); }`;
const anchorCodes = await Promise.all(
  Array.from({ length: 4 }, () =>
    new Promise((resolve) => {
      const p = spawn(process.execPath, ["--input-type=module", "-e", anchorWorker], { cwd: root, env: { ...process.env, LOG: mixed } });
      p.on("exit", resolve);
    }),
  ),
);
const { verifyLogWithAnchors } = await import(new URL("../dist/anchor.js", import.meta.url).href);
const mixedResult = verifyLogWithAnchors(mixed);
const mixedOk = anchorCodes.every((c) => c === 0) && mixedResult.valid && mixedResult.count === 32 && mixedResult.anchorFile.valid && mixedResult.checked >= 1;
console.log(
  mixedOk
    ? `PASS  4 concurrent writers with anchors, 32 entries, ${mixedResult.checked} anchors valid`
    : `FAIL  anchor concurrency ${JSON.stringify({ anchorCodes, mixedResult })}`,
);
process.exit(mixedOk ? 0 : 1);
