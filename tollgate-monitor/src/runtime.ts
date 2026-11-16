// Process wiring shared by the entry points: real system facts in, signals and token expiry handled.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { startFromArgs, type AdminStarter } from "./cli.js";

function readPasswd(): string | null {
  try {
    return readFileSync("/etc/passwd", "utf8");
  } catch {
    return null;
  }
}

export async function runMain(admin?: AdminStarter): Promise<void> {
  const result = await startFromArgs(
    process.argv.slice(2),
    {
      env: process.env,
      euid: process.geteuid?.(),
      ruid: process.getuid?.(),
      cwd: process.cwd(),
      platform: process.platform,
      home: homedir(),
      pid: process.pid,
      stderrIsTty: process.stderr.isTTY === true,
      readPasswd,
    },
    { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) },
    admin,
  );
  if (!result.ok) {
    process.exit(result.code);
    return;
  }
  const started = result.started;
  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    void started.stop().finally(() => process.exit(0));
  };
  process.on("exit", () => started.cleanupSync());
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(signal, stop);
  // The token ends the usefulness of the view; the process ends with it.
  setTimeout(stop, Math.max(1, started.expiresAtMs - Date.now())).unref();
}
