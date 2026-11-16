import { checkNpm, checkPypi } from "../deps.js";
import { credentialPathDecision } from "../credentials.js";
import { checkBashCommandWrites, checkBashCredentialReads, checkCommand, checkPath, type Context } from "../evaluate.js";
import { homeProjectProblem } from "../guardContext.js";
import { installProblems } from "../installs.js";
import type { Policy } from "../policy.js";

export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
}

function result(payload: object): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

/**
 * Agent view of the hook context: the given context (home directory, temporary directory, active policy, always protected
 * paths; see guardContext.ts) with the project directory of the call, never a human session.
 */
function agentContext(projectDir: string, context: Context | undefined): Context {
  return { ...context, projectDir, humanSession: false };
}

/** Same refusal as the hook (stand-alone): a project directory that is a home directory or above it. */
function projectDirRefusal(projectDir: string, context: Context | undefined): ToolResult | null {
  const homes = [...(context?.home === undefined ? [] : [context.home]), ...(context?.homes ?? [])];
  const problem = homeProjectProblem(projectDir, homes);
  return problem === null ? null : result({ allowed: false, reason: `${problem}.` });
}

/** Command rules and, if the project directory is known, the protected-path check for Bash writes (agent view). */
export function checkCommandTool(policy: Policy, command: string, projectDir?: string, context?: Context): ToolResult {
  if (projectDir !== undefined) {
    const refused = projectDirRefusal(projectDir, context);
    if (refused !== null) return refused;
  }
  const decision = checkCommand(command, policy);
  if (!decision.allowed) return result(decision);
  // #161: parity with the hook (evaluate.ts Bash branch) — install commands are checked against the allowlist, so
  // `check_command` no longer reports `npm install left-pad` as allowed while the PreToolUse hook blocks it.
  const installs = installProblems(command, policy.allowedDependencies);
  if (installs.length > 0) return result({ allowed: false, reason: `Dependencies not on the allowlist: ${installs.join(", ")}.` });
  if (projectDir === undefined) return result(decision);
  const reads = checkBashCredentialReads(command, agentContext(projectDir, context));
  if (!reads.allowed) return result(reads);
  return result(checkBashCommandWrites(command, policy, agentContext(projectDir, context)));
}

export function checkPathTool(policy: Policy, projectDir: string, path: string, context?: Context): ToolResult {
  // MCP callers are always treated as agents, never as a human session.
  const refused = projectDirRefusal(projectDir, context);
  if (refused !== null) return refused;
  // Same credential store rule as the read tools of the hook (#160), so that check_path also answers for reads.
  const ctx = agentContext(projectDir, context);
  const credentials = credentialPathDecision(path, ctx);
  if (credentials !== null) return result({ allowed: false, reason: credentials.reason });
  return result(checkPath(path, policy, ctx));
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
