#!/usr/bin/env node
// Executable entry of the xAI Grok Build `PreToolUse` adapter (see docs/multi-agent.md).
// Fails closed to an explicit deny (Grok is fail-open otherwise). stdout/stderr written synchronously.
import { writeSync } from "node:fs";
import { runGrokMain } from "./adapters/grok.js";
import { readStdin } from "./hook.js";

process.exit(
  await runGrokMain(
    readStdin,
    process.env,
    process.cwd(),
    (text) => writeSync(1, text),
    (text) => writeSync(2, text),
  ),
);
