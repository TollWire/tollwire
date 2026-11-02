import { checkNpm, checkPypi } from "../deps.js";
import { checkBashCommandWrites, checkCommand, checkPath } from "../evaluate.js";
import type { Policy } from "../policy.js";

export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
}

function result(payload: object): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

/** Command rules and, if the project directory is known, the protected-path check for Bash writes (agent view). */
export function checkCommandTool(policy: Policy, command: string, projectDir?: string): ToolResult {
  const decision = checkCommand(command, policy);
  if (!decision.allowed || projectDir === undefined) return result(decision);
  return result(checkBashCommandWrites(command, policy, { projectDir, humanSession: false }));
}

export function checkPathTool(policy: Policy, projectDir: string, path: string): ToolResult {
  // MCP callers are always treated as agents, never as a human session.
  return result(checkPath(path, policy, { projectDir, humanSession: false }));
}

export function checkDependenciesTool(
  policy: Policy,
  ecosystem: "npm" | "pypi",
  manifest: string,
): ToolResult {
  try {
    const violations =
      ecosystem === "npm"
        ? checkNpm(manifest, policy.allowedDependencies.npm)
        : checkPypi(manifest, policy.allowedDependencies.pypi);
    return result({ allowed: violations.length === 0, violations });
  } catch {
    return result({ allowed: false, reason: "Manifest could not be parsed." });
  }
}

export function describePolicyTool(policy: Policy): ToolResult {
  return result({
    protectedPaths: policy.protectedPaths,
    blockedCommandReasons: policy.blockedCommands.map((r) => r.reason),
    allowedDependencies: policy.allowedDependencies,
  });
}
