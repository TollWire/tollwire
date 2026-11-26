#!/usr/bin/env node
// `tollgate-guard-status`: which coding agents are guarded on this host (ENFORCED, DEGRADED, UNPROTECTED, NOT_INSTALLED).
//
//   tollgate-guard-status [--json] [--record] [--project DIR]
//
// Static check of the documented hook configuration locations plus an in-process self-test. It never blocks a tool call.
// Exit code: 0 = no agent is UNPROTECTED, 1 = at least one is (or recording failed), 2 = usage error.
// `--record` writes one `enforcement_status` event per agent into the decision log (for the monitor and the SIEM).
import { isAbsolute } from "node:path";
import { detectEnterprise, resolvePolicy } from "./enterprise.js";
import { isEntryPoint } from "./entry.js";
import { systemRuntime, type Runtime } from "./events/runtime.js";
import { loggerFor } from "./hook.js";
import { checkAll, formatText, systemStatusDeps, type StatusDeps, type StatusReport } from "./status.js";

const USAGE = "Usage: tollgate-guard-status [--json] [--record] [--project DIR]\n";

export interface StatusCliIo {
  out: (text: string) => void;
  err: (text: string) => void;
}

export interface StatusCliOptions {
  json: boolean;
  record: boolean;
  project: string | undefined;
}

export function parseArgs(args: readonly string[]): StatusCliOptions | null {
  const opts: StatusCliOptions = { json: false, record: false, project: undefined };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === "--json") opts.json = true;
    else if (a === "--record") opts.record = true;
    else if (a === "--project") {
      const v = args[i + 1];
      if (v === undefined || !isAbsolute(v) || opts.project !== undefined) return null;
      opts.project = v;
      i += 1;
    } else return null;
  }
  return opts;
}

export interface StatusCliDeps {
  /** Builds the check dependencies for the (optional) project directory. */
  status: (project: string | undefined) => StatusDeps;
  /** Writes the report into the decision log; returns false if a write failed. */
  record: (report: StatusReport) => boolean;
}

export function runStatusCli(args: readonly string[], io: StatusCliIo, deps: StatusCliDeps): number {
  const opts = parseArgs(args);
  if (opts === null) {
    io.err(USAGE);
    return 2;
  }
  let report: StatusReport;
  try {
    report = checkAll(deps.status(opts.project));
  } catch {
    io.err("tollgate-guard-status: the check failed unexpectedly.\n");
    return 1;
  }
  let recorded = true;
  if (opts.record) {
    try {
      recorded = deps.record(report);
    } catch {
      recorded = false;
    }
  }
  io.out(opts.json ? `${JSON.stringify(report, null, 2)}\n` : formatText(report));
  if (!recorded) io.err("tollgate-guard-status: the decision log could not be written.\n");
  return !recorded || report.agents.some((a) => a.status === "UNPROTECTED") ? 1 : 0;
}

export function recordToLog(report: StatusReport, rt: Runtime, env: NodeJS.ProcessEnv, cwd: string): boolean {
  const resolution = resolvePolicy({ env, projectDir: cwd, platform: rt.platform });
  const logger = loggerFor(rt, env, resolution, detectEnterprise(env, rt.platform).active, {});
  let ok = true;
  for (const a of report.agents) {
    const result = logger.recordEnforcementStatus({
      agent: a.agent,
      data: {
        status: a.status,
        reason: a.reason,
        hook_registered: a.hook_registered,
        target_exists: a.target_exists,
        fail_closed: a.fail_closed,
        self_test: a.self_test,
        config_source: a.config_source,
        human_session: env.TOLLGATE_HUMAN_SESSION === "1",
      },
    });
    if (!result.ok) ok = false;
  }
  return ok;
}

if (isEntryPoint(import.meta.url)) {
  const rt = systemRuntime();
  const env = process.env;
  process.exit(
    runStatusCli(process.argv.slice(2), { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) }, {
      status: (project) => systemStatusDeps(env, project),
      record: (report) => recordToLog(report, rt, env, process.cwd()),
    }),
  );
}
