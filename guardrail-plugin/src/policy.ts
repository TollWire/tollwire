import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { Match } from "./matchers.js";
import { TaintSectionSchema, taintFromSection, type TaintPolicy } from "./taintPolicy.js";

export const PolicySchema = z.object({
  version: z.literal(1),
  protectedPaths: z.array(z.string().min(1)),
  blockedCommands: z.array(
    z.object({
      pattern: z.string().min(1).max(500),
      reason: z.string().min(1),
    }),
  ),
  allowedDependencies: z.object({
    npm: z.array(z.string()),
    pypi: z.array(z.string()),
  }),
  /** Session taint. Absent: off. */
  taint: TaintSectionSchema.optional(),
});

/**
 * A command rule: a regular expression (`pattern`, only from trusted layers) or a safe matcher (`match`, lower layers in
 * enterprise mode). `id` identifies the rule in the log and in the merge of layers.
 */
export interface Rule {
  id?: string | undefined;
  pattern?: string | undefined;
  match?: Match | undefined;
  reason: string;
}

/** Effective policy. Version 1 is the file format of the bundled and project policies; the merged policy is in memory only. */
export interface Policy {
  version: 1 | 2;
  protectedPaths: string[];
  blockedCommands: Rule[];
  allowedDependencies: { npm: string[]; pypi: string[] };
  /** Session taint; absent means off. */
  taint?: TaintPolicy | undefined;
}

export const BUNDLED_POLICY_PATH = fileURLToPath(new URL("../policy/default.json", import.meta.url));
export const PROJECT_POLICY_FILE = join(".tollgate", "policy.json");

export function parsePolicy(raw: unknown): Policy {
  const { taint, ...rest } = PolicySchema.parse(raw);
  const policy: Policy = taint === undefined ? rest : { ...rest, taint: taintFromSection(taint) };
  for (const rule of policy.blockedCommands) {
    // Fail early on invalid patterns instead of at hook time.
    new RegExp(rule.pattern as string);
  }
  return policy;
}

/**
 * Base policy file: project policy (.tollgate/policy.json) > bundled default. `TOLLGATE_POLICY` never replaces the base;
 * it is a further layer that can only tighten (`resolvePolicy` in enterprise.ts). Policy files are trusted
 * configuration and belong to protected paths.
 */
export function resolvePolicyPath(_env: NodeJS.ProcessEnv, projectDir: string): string {
  const projectPolicy = join(projectDir, PROJECT_POLICY_FILE);
  return existsSync(projectPolicy) ? projectPolicy : BUNDLED_POLICY_PATH;
}

export function loadPolicy(path: string): Policy {
  return parsePolicy(JSON.parse(readFileSync(path, "utf8")));
}
