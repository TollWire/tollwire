import { existsSync } from "node:fs";
import { dirname, join, parse } from "node:path";

/** Nearest ancestor of `start` (inclusive) that contains a `.git` entry, or undefined. Never throws. */
function gitRoot(start: string): string | undefined {
  try {
    let dir = start;
    const root = parse(dir).root;
    // Bounded walk up the filesystem tree (fail safe on any odd path).
    for (let i = 0; i < 128; i += 1) {
      if (existsSync(join(dir, ".git"))) return dir;
      if (dir === root || dir === "") return undefined;
      dir = dirname(dir);
    }
  } catch {
    // fall through to undefined
  }
  return undefined;
}

/**
 * Project directory for the guardrail. Codex and Copilot do not set `CLAUDE_PROJECT_DIR`, and the hook's `cwd` is the
 * agent's working directory, which may be a subfolder of the repository. Protected paths are defined relative to the
 * repository root, so an agent started in a subfolder must not shift that root. Resolution order: an explicit
 * `CLAUDE_PROJECT_DIR` wins, else the nearest git root at or above `cwd`, else `cwd` itself.
 */
export function resolveProjectDir(cwd: string, env: NodeJS.ProcessEnv): string {
  const explicit = env.CLAUDE_PROJECT_DIR;
  if (typeof explicit === "string" && explicit !== "") return explicit;
  return gitRoot(cwd) ?? cwd;
}
