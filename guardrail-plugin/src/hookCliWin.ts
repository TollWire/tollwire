#!/usr/bin/env node
// Windows entry of the PreToolUse hook: the same hook as `hookCli`, with a hard time limit. The
// watchdog starts first, then the hook runs. The command of the Windows manifest turns every exit code other than 0 -- also the
// forceful termination by the watchdog -- into 2 for the checked tools. Linux and macOS keep using `hookCli` with `timeout`.
import { startWatchdog } from "./watchdog.js";

startWatchdog();
await import("./hookCli.js");
