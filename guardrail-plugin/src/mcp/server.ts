#!/usr/bin/env node
// MCP server (stdio only, no network listener) exposing the guardrail checks to agents.
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { isEntryPoint } from "../entry.js";
import { resolvePolicy, type Resolved } from "../enterprise.js";
import type { Context } from "../evaluate.js";
import { packageVersion, systemRuntime, type Runtime } from "../events/runtime.js";
import { decisionLogLayout, guardContext } from "../guardContext.js";
import type { Policy } from "../policy.js";
import { McpStdioServer, serveStdio } from "../vendor/mcpStdio.js";
import { checkCommandTool, checkDependenciesTool, checkPathTool, describePolicyTool } from "./tools.js";

const MAX_INPUT = 100_000;

/**
 * Context of the check tools: the same builder as the hook (home directory, TMPDIR, active policy, always protected paths),
 * agent view (never a human session), relative Bash targets against the project directory.
 */
export function serverContext(projectDir: string, env: NodeJS.ProcessEnv, rt: Runtime, resolution: Resolved): Context {
  return guardContext({ projectDir, humanSession: false, cwd: projectDir, env, rt, resolution, layout: decisionLogLayout(rt, env, resolution) });
}

/** `context`: see serverContext; without it, the tools know only the project directory (no home directory, no TMPDIR). */
export function createServer(policy: Policy, projectDir: string, context?: Context): McpStdioServer {
  const server = new McpStdioServer({ name: "tollgate-guardrail", version: packageVersion(fileURLToPath(new URL("../..", import.meta.url))) });

  server.registerTool(
    "check_command",
    {
      description: "Check whether a shell command is allowed by the TollWire policy.",
      inputSchema: { command: z.string().max(MAX_INPUT) },
    },
    ({ command }) => checkCommandTool(policy, command, projectDir, context),
  );

  server.registerTool(
    "check_path",
    {
      description: "Check whether an agent may write to a file path (protected paths need human review).",
      inputSchema: { path: z.string().min(1).max(4096) },
    },
    ({ path }) => checkPathTool(policy, projectDir, path, context),
  );

  server.registerTool(
    "check_dependencies",
    {
      description: "Check a package.json or requirements.txt against the dependency allowlist.",
      inputSchema: { ecosystem: z.enum(["npm", "pypi"]), manifest: z.string().max(MAX_INPUT) },
    },
    ({ ecosystem, manifest }) => checkDependenciesTool(policy, ecosystem, manifest),
  );

  server.registerTool(
    "describe_policy",
    { description: "Show the active guardrail policy (paths, blocked command reasons, allowlist)." },
    () => describePolicyTool(policy),
  );

  return server;
}

export async function main(): Promise<void> {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const resolution = resolvePolicy({ env: process.env, projectDir, platform: process.platform });
  if (!resolution.ok) throw new Error(resolution.message);
  // A line over the limit ends the session (fail closed); the exit code shows it.
  const context = serverContext(projectDir, process.env, systemRuntime(), resolution);
  if ((await serveStdio(createServer(resolution.policy, projectDir, context))) === "overflow") process.exitCode = 1;
}

if (isEntryPoint(import.meta.url)) {
  await main();
}
