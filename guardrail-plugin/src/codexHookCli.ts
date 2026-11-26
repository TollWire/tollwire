#!/usr/bin/env node
// Executable entry of the OpenAI Codex CLI `PreToolUse` adapter (see docs/multi-agent.md).
// Fails closed: any failure to read or evaluate ends with a deny (stdout decision JSON + exit 2).
// stdout/stderr are written synchronously (writeSync) so the decision is never truncated by process.exit.
import { writeSync } from "node:fs";
import { runCodexMain } from "./adapters/codex.js";
import { readStdin } from "./hook.js";

process.exit(
  await runCodexMain(
    readStdin,
    process.env,
    process.cwd(),
    (text) => writeSync(1, text),
    (text) => writeSync(2, text),
  ),
);
