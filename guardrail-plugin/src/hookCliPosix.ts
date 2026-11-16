#!/usr/bin/env node
// POSIX entry of the hook with a hard time limit: macOS has no `timeout`, and Linux may lack it too. Same hook as
// `hookCli`; the watchdog starts first, then the hook runs. The command of the manifest uses this entry only if no `timeout` program
// was found, and turns every exit code other than 0 and 2 -- also the forceful termination by the watchdog (SIGKILL, 137) -- into 2
// for the checked tools. Windows has its own entry (`hookCliWin`).
import { startWatchdog } from "./watchdog.js";

startWatchdog();
await import("./hookCli.js");
