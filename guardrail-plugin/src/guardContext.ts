// Evaluation context shared by the PreToolUse hook and the MCP check tools, so that both decide on the same facts:
// home directory, temporary directory, active policy file and the always protected paths of the host.
import { realpathSync } from "node:fs";
import { isAbsolute, parse, resolve, sep } from "node:path";
import { alwaysProtectedPaths, type Resolved } from "./enterprise.js";
import type { CredentialContext } from "./credentials.js";
import type { Context } from "./evaluate.js";
import { foldPath } from "./paths.js";
import { enterpriseLayout, standaloneLayout, type Layout } from "./events/layout.js";
import { locationEnv, type Runtime } from "./events/runtime.js";

export interface GuardContextInput {
  projectDir: string;
  humanSession: boolean;
  /** Working directory of the Bash tool, if known. */
  cwd?: string | undefined;
  env: NodeJS.ProcessEnv;
  rt: Runtime;
  /** Usable policy resolution (stand-alone or enterprise). */
  resolution: Resolved;
  /** Layout of the decision log (its directories are always protected). */
  layout: Layout;
}

function usableHome(path: string | undefined): string | undefined {
  if (path === undefined || path === "" || !isAbsolute(path)) return undefined;
  const clean = resolve(path);
  return parse(clean).root === clean ? undefined : clean;
}

/**
 * Home directories whose protected files are guarded. Enterprise mode: only the home directory from the user database.
 * Stand-alone: `HOME` and the home directory from the user database (both, if they differ), so that an unset or changed
 * `HOME` does not leave the real home directory unguarded. A root directory (fallback of the runtime) does not count.
 */
export function knownHomes(env: NodeJS.ProcessEnv, rt: Runtime, enterprise: boolean): string[] {
  const all = enterprise ? [usableHome(rt.home)] : [usableHome(env.HOME), usableHome(rt.home)];
  return [...new Set(all.filter((h): h is string => h !== undefined))];
}

function physical(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    return path;
  }
}

/**
 * Reason why a project directory is not acceptable, or null: the file system root, `/home`, `/Users`, or a home directory or
 * one of its ancestors (as written and with symlinks resolved). Writes would then reach shell profiles, credentials and agent
 * configuration of the whole home directory; the guardrail refuses to work there (fail closed).
 */
export function homeProjectProblem(projectDir: string, homes: readonly string[]): string | null {
  if (!isAbsolute(projectDir)) return "the project directory is not an absolute path";
  const lexical = resolve(projectDir);
  const dirs = [...new Set([lexical, physical(lexical)])];
  const message = "the project directory is the home directory (or above); start Claude Code in a project folder";
  if (dirs.some((d) => parse(d).root === d || ["/home", "/Users"].includes(d))) return message;
  const homeKeys = homes.flatMap((h) => [h, physical(h)]).map(foldPath);
  for (const dir of dirs.map(foldPath)) {
    const prefix = dir.endsWith(sep) || dir.endsWith("/") ? dir : `${dir}${sep}`;
    if (homeKeys.some((h) => h === dir || h.startsWith(prefix) || h.startsWith(`${dir}/`))) return message;
  }
  return null;
}

/**
 * Context for `evaluate`. Enterprise mode takes the home directory from the user database and ignores TMPDIR; stand-alone
 * takes TMPDIR from the environment and `HOME` (falling back to the user database) for `~`; protected home files are guarded
 * below every known home directory (see knownHomes).
 */
export function guardContext(input: GuardContextInput): Context {
  const { rt, env, resolution } = input;
  const enterprise = resolution.enterprise !== null;
  const homes = knownHomes(env, rt, enterprise);
  return {
    projectDir: input.projectDir,
    humanSession: input.humanSession,
    cwd: input.cwd,
    home: enterprise ? rt.home : (usableHome(env.HOME) ?? homes[0]),
    homes,
    tmpdir: enterprise ? undefined : env.TMPDIR,
    policyFile: resolution.policyFile,
    extraProtected: [...alwaysProtectedPaths(rt.platform, locationEnv(env), rt.home, rt.uid, input.layout), ...resolution.protectedFiles],
  };
}

/**
 * Context of the credential store read lock for the read tools (#160): the same home directories as guardContext, without a
 * policy (the lock does not depend on it, so it also applies when the policy cannot be loaded).
 */
export function credentialContext(projectDir: string, cwd: string | undefined, env: NodeJS.ProcessEnv, rt: Runtime, enterprise: boolean): CredentialContext {
  const homes = knownHomes(env, rt, enterprise);
  return { projectDir, cwd, home: enterprise ? usableHome(rt.home) : (usableHome(env.HOME) ?? homes[0]), homes };
}

/** Layout of the decision log for a usable policy resolution (same choice as the event logger of the hook). */
export function decisionLogLayout(rt: Runtime, env: NodeJS.ProcessEnv, resolution: Resolved): Layout {
  return resolution.enterprise !== null
    ? enterpriseLayout(resolution.enterprise.settings.layout, rt.uid ?? 0, rt.home, rt.platform)
    : standaloneLayout(locationEnv(env), rt.platform, rt.home, rt.uid);
}
