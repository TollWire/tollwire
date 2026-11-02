#!/usr/bin/env node
// MCP server (stdio only, no network listener) exposing the guardrail checks to agents.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { isEntryPoint } from "../entry.js";
import { resolvePolicy } from "../enterprise.js";
import type { Policy } from "../policy.js";
import { checkCommandTool, checkDependenciesTool, checkPathTool, describePolicyTool } from "./tools.js";

const MAX_INPUT = 100_000;

export function createServer(policy: Policy, projectDir: string): McpServer {
  const server = new McpServer({ name: "tollgate-guardrail", version: "0.1.0" });

  server.registerTool(
    "check_command",
    {
      description: "Check whether a shell command is allowed by the TollGate policy.",
      inputSchema: { command: z.string().max(MAX_INPUT) },
    },
    ({ command }) => checkCommandTool(policy, command, projectDir),
  );

  server.registerTool(
    "check_path",
    {
      description: "Check whether an agent may write to a file path (protected paths need human review).",
      inputSchema: { path: z.string().min(1).max(4096) },
    },
    ({ path }) => checkPathTool(policy, projectDir, path),
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
  await createServer(resolution.policy, projectDir).connect(new StdioServerTransport());
}

if (isEntryPoint(import.meta.url)) {
  await main();
}
