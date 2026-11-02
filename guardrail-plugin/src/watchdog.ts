// Hard time limit for the hook process. A timer in the main thread does not fire when
// the main thread is blocked (a loop, a stuck synchronous call). This watchdog runs in a worker thread with its own event loop
// and kills the whole process after the limit. On POSIX the Linux wrapper uses `timeout 25` instead; the watchdog is used by the
// Windows entry (`hookCliWin`), where `timeout` does not exist.
//
// The process ends with SIGKILL (on Windows: forceful termination, a non-zero exit code). The exit code is not 2: the Windows
// wrapper turns every code other than 0 into 2 for the checked tools (`&& exit /b 0 || exit /b 2`).
import { Worker } from "node:worker_threads";

export const DEFAULT_WATCHDOG_MS = 25_000;
export const WATCHDOG_MESSAGE = "TollGate guardrail: hook did not finish within the time limit; fail closed.\n";

// The worker is a data: URL, so no second file has to be shipped and found at run time. It uses only the numbers and the
// message passed in `workerData`.
const WORKER_SOURCE = [
  'import { workerData } from "node:worker_threads";',
  'import { writeSync } from "node:fs";',
  "setTimeout(() => {",
  "  try { writeSync(workerData.fd, workerData.message); } catch { /* nothing to report to */ }",
  '  process.kill(workerData.pid, "SIGKILL");',
  "}, workerData.ms);",
].join("\n");

export interface WatchdogOptions {
  /** Time limit in milliseconds (default 25 s). */
  ms?: number;
  /** Process to kill (default: this process). Tests pass a blocked child. */
  pid?: number;
  /** File descriptor for the message (default 2, stderr). */
  fd?: number;
}

/** Starts the watchdog. The worker does not keep the process alive; it dies with it. */
export function startWatchdog(options: WatchdogOptions = {}): Worker {
  const ms = options.ms ?? DEFAULT_WATCHDOG_MS;
  if (!Number.isInteger(ms) || ms < 1 || ms > 600_000) throw new RangeError("watchdog time limit is out of range");
  const worker = new Worker(new URL(`data:text/javascript,${encodeURIComponent(WORKER_SOURCE)}`), {
    workerData: { ms, pid: options.pid ?? process.pid, fd: options.fd ?? 2, message: WATCHDOG_MESSAGE },
  });
  worker.unref();
  return worker;
}
