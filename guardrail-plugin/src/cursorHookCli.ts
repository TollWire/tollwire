#!/usr/bin/env node
// Executable entry of the Cursor Agent `preToolUse` adapter (see docs/multi-agent.md).
// Register with failClosed: true and a matcher scoped to the checked tools. stdout written synchronously.
import { writeSync } from "node:fs";
import { runCursorMain } from "./adapters/cursor.js";
import { readStdin } from "./hook.js";

process.exit(await runCursorMain(readStdin, process.env, process.cwd(), (text) => writeSync(1, text)));
