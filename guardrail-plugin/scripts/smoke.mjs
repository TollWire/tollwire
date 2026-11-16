// Smoke test of the built artifacts (dist/): runs the hook as Claude Code would and starts the MCP server.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
// The hook writes a decision log; keep it out of the real home directory.
const scratch = mkdtempSync(join(tmpdir(), "tg-smoke-"));
const logEnv = { XDG_STATE_HOME: join(scratch, "state"), XDG_CONFIG_HOME: join(scratch, "config") };
const hook = (event, env = {}) =>
  spawnSync(process.execPath, ["dist/hook.js"], {
    cwd: root,
    input: JSON.stringify(event),
    env: { ...process.env, ...logEnv, CLAUDE_PROJECT_DIR: "/repo", ...env },
    encoding: "utf8",
  });

const failures = [];
const expect = (name, ok) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures.push(name);
};

expect("hook allows safe command", hook({ tool_name: "Bash", tool_input: { command: "ls" } }).status === 0);
const taintCli = spawnSync(process.execPath, ["dist/taintCli.js"], { cwd: root, env: { ...process.env, ...logEnv }, encoding: "utf8" });
expect("tollgate-taint without a command prints the usage (exit 2)", taintCli.status === 2 && taintCli.stderr.includes("tollgate-taint release"));
const blocked = hook({ tool_name: "Bash", tool_input: { command: "git push --force" } });
expect("hook blocks force push with exit 2", blocked.status === 2 && blocked.stderr.includes("Force push"));
expect("hook blocks protected path", hook({ tool_name: "Edit", tool_input: { file_path: "/repo/AGENTS.md" } }).status === 2);

// The manifest command (shell wrapper) must pass decisions through and fail closed if the hook cannot run.
const manifestCommand = JSON.parse(readFileSync(new URL("../hooks/hooks.json", import.meta.url), "utf8")).hooks.PreToolUse[0].hooks[0].command;
const viaManifest = (event, pluginRoot = root) =>
  spawnSync("sh", ["-c", manifestCommand], {
    input: JSON.stringify(event),
    env: { ...process.env, ...logEnv, CLAUDE_PROJECT_DIR: "/repo", CLAUDE_PLUGIN_ROOT: pluginRoot },
    encoding: "utf8",
  });
expect("manifest command allows safe command", viaManifest({ tool_name: "Bash", tool_input: { command: "ls" } }).status === 0);
expect("manifest command blocks Bash write to protected path", viaManifest({ tool_name: "Bash", tool_input: { command: "echo x > /repo/AGENTS.md" } }).status === 2);
expect("manifest command fails closed without dist", viaManifest({ tool_name: "Bash", tool_input: { command: "ls" } }, "/nonexistent-plugin-root").status === 2);

// Decision log: parallel hook processes append to one chain; the verifier accepts it.
const logDir = join(logEnv.XDG_STATE_HOME, "tollgate", "events");
const workers = Array.from({ length: 4 }, () => new Promise((resolve) => {
  let done = 0;
  const next = () => {
    if (done === 8) return resolve(true);
    const child = spawn(process.execPath, ["dist/hook.js"], { cwd: root, env: { ...process.env, ...logEnv, CLAUDE_PROJECT_DIR: "/repo" } });
    child.on("close", () => { done += 1; next(); });
    child.stdin.end(JSON.stringify({ session_id: "smoke", tool_name: "Bash", tool_input: { command: "ls" } }));
  };
  next();
}));
await Promise.all(workers);
const verify = spawnSync(process.execPath, ["dist/events/verifyBin.js", "verify", logDir], { cwd: root, encoding: "utf8", env: { ...process.env, ...logEnv } });
expect("events: 4 parallel writers, chain valid", verify.status === 0 && /^OK: \d+ events in 1 files, 1 chains$/m.test(verify.stdout) && Number(/(\d+) events/.exec(verify.stdout)?.[1]) >= 32);
const defaultDir = spawnSync(process.execPath, ["dist/events/verifyBin.js", "verify"], { cwd: root, encoding: "utf8", env: { ...process.env, ...logEnv } });
expect("events: verify finds the default location", defaultDir.status === 0);

// tollgate-taint release in a real pseudo-terminal (field test 2026-10-30: "Not confirmed" without waiting for input).
// A host with an enterprise installation (/etc/tollgate) refuses the user release by design; then this part is reported.
if (existsSync("/etc/tollgate") || process.platform === "win32") {
  console.log("SKIP  tollgate-taint release in a pseudo-terminal (enterprise host or Windows; unit tests cover the input)");
} else {
  const ptyState = mkdtempSync(join(tmpdir(), "tg-smoke-pty-"));
  const ptyEnv = { ...process.env, XDG_STATE_HOME: join(ptyState, "state"), XDG_CONFIG_HOME: join(ptyState, "config"), CLAUDE_PROJECT_DIR: "/repo" };
  for (const name of ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "TOLLGATE_ENTERPRISE", "TOLLGATE_POLICY"]) delete ptyEnv[name];
  const ptyHook = (event) => spawnSync(process.execPath, ["dist/hook.js"], { cwd: root, input: JSON.stringify(event), env: ptyEnv, encoding: "utf8" });
  ptyHook({ session_id: "smoke-pty", hook_event_name: "SessionStart", source: "startup" });
  ptyHook({ session_id: "smoke-pty", hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://x.example" } });
  const release = (answer) => {
    const r = spawnSync("python3", [join(root, "scripts", "ptyRelease.py"), join(root, "dist", "taintCli.js"), "smoke-pty", answer], { cwd: root, env: ptyEnv, encoding: "utf8", timeout: 30_000 });
    try {
      return JSON.parse(r.stdout);
    } catch {
      return { prompt: false, early: false, exit: null, output: `${r.stdout}${r.stderr}` };
    }
  };
  const wrong = release("wrong");
  expect("taint release (pty): waits for input, wrong code refused", wrong.prompt && !wrong.early && wrong.exit === 1 && wrong.output.includes("Not confirmed"));
  const eof = release("eof");
  expect("taint release (pty): waits for input, end of input refused", eof.prompt && !eof.early && eof.exit === 1 && eof.output.includes("Not confirmed"));
  const right = release("right");
  expect("taint release (pty): right code releases", right.prompt && !right.early && right.exit === 0 && right.output.includes("Released"));
  if (!right.prompt || right.early || right.exit !== 0) console.error(right.output);
  const after = spawnSync(process.execPath, ["dist/taintCli.js", "status", "--session", "smoke-pty"], { cwd: root, env: ptyEnv, encoding: "utf8" });
  expect("taint release (pty): status shows the session released", after.status === 0 && !after.stdout.includes("smoke-pty: tainted"));
}

const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } };
const mcp = spawnSync(process.execPath, ["dist/mcp/server.js"], {
  cwd: root,
  input: `${JSON.stringify(init)}\n`,
  encoding: "utf8",
  timeout: 10_000,
});
expect("mcp server answers initialize", mcp.stdout.includes('"tollgate-guardrail"'));

if (failures.length) {
  console.error(`Smoke test failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("Smoke test passed.");
