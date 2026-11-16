#!/usr/bin/env node
// Executable entry of the PreToolUse hook. Runs unconditionally: no entry-point detection, which could
// silently skip the check (exit 0 = allowed). Any failure to load ends with a non-zero exit code; the
// hook command in the plugin manifest turns every code other than 0 and 2 into 2 (fail closed).
import { eventFromArgs, readStdin, runMain } from "./hook.js";

process.exit(await runMain(readStdin, process.env, process.cwd(), (text) => process.stderr.write(text), { event: eventFromArgs(process.argv.slice(2)) }));
