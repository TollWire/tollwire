#!/usr/bin/env node
// Executable entry of the GitHub Copilot CLI `preToolUse` adapter. Register with a PascalCase `PreToolUse`
// matcher (see docs/multi-agent.md). Fails closed: any failure to read or evaluate ends with a deny.
// stdout is written synchronously (writeSync) so the one decision object is never truncated by process.exit.
import { writeSync } from "node:fs";
import { runCopilotMain } from "./adapters/copilot.js";
import { readStdin } from "./hook.js";

process.exit(await runCopilotMain(readStdin, process.env, process.cwd(), (text) => writeSync(1, text)));
