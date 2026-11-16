#!/usr/bin/env node
// Executable entry of `tollgate-events` (covered by the smoke test; the logic is in verifyCli.ts).
import { standaloneLayout } from "./layout.js";
import { locationEnv, systemRuntime } from "./runtime.js";
import { runVerifyCli } from "./verifyCli.js";

const rt = systemRuntime();
const layout = standaloneLayout(locationEnv(process.env), rt.platform, rt.home, rt.uid);
process.exit(runVerifyCli(process.argv.slice(2), { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) }, { dir: layout.eventsDir }));
