// Policy section `taint`: schema, defaults and the tightening merge. Kept apart from `taint.ts` so that `policy.ts`
// and `enterprise.ts` can use it without an import cycle.
import { z } from "zod";
import { TOOL_PATTERN } from "./vendor/locks.js";

export type TaintMode = "off" | "observe" | "enforce";
const MODE_RANK: Readonly<Record<TaintMode, number>> = { off: 0, observe: 1, enforce: 2 };

/** A tool name, `mcp__<server>__*` (the locks rule) or `mcp__*` for every MCP tool. */
export const TAINT_TOOL_PATTERN = new RegExp(`^(?:${TOOL_PATTERN.source.slice(1, -1)}|mcp__\\*)$`);

// Defaults of a `taint` section that leaves the lists out. One place to change them (owner questions Q2 of the design notes):
// every web and MCP tool is a source, and in a tainted session also a restricted egress channel.
export const DEFAULT_SOURCE_TOOLS: readonly string[] = ["WebFetch", "WebSearch", "mcp__*"];
export const DEFAULT_RESTRICT_TOOLS: readonly string[] = ["WebFetch", "WebSearch", "mcp__*"];

/** Section `taint` of a policy file (version 1 and 2). Unknown keys are rejected. */
export const TaintSectionSchema = z
  .object({
    mode: z.enum(["off", "observe", "enforce"]),
    sources: z
      .object({
        tools: z.array(z.string().regex(TAINT_TOOL_PATTERN)).max(200).optional(),
        bashNetwork: z.boolean().optional(),
        readOutsideProject: z.boolean().optional(),
      })
      .strict()
      .optional(),
    restrictTools: z.array(z.string().regex(TAINT_TOOL_PATTERN)).max(200).optional(),
    /** Enterprise policy only: who lifts a taint. `admin` (default): root-owned release file; `user`: the user in a terminal. */
    release: z.enum(["admin", "user"]).optional(),
  })
  .strict();
export type TaintSection = z.infer<typeof TaintSectionSchema>;

export interface TaintPolicy {
  mode: TaintMode;
  /** Tools whose result is untrusted content. */
  sourceTools: string[];
  /** A Bash command with a network effect (curl, wget, gh, git fetch ...) is a source. */
  bashNetwork: boolean;
  /** Reading a file outside the project directory is a source. */
  readOutsideProject: boolean;
  /** Tools that count as network egress (blocked in a tainted session). */
  restrictTools: string[];
  release: "admin" | "user";
}

export const TAINT_OFF: TaintPolicy = { mode: "off", sourceTools: [], bashNetwork: false, readOutsideProject: false, restrictTools: [], release: "admin" };

/** The effective policy of one section; defaults apply to the fields that the section leaves out. */
export function taintFromSection(section: TaintSection | undefined): TaintPolicy {
  if (section === undefined) return { ...TAINT_OFF, sourceTools: [], restrictTools: [] };
  return {
    mode: section.mode,
    sourceTools: [...new Set(section.sources?.tools ?? DEFAULT_SOURCE_TOOLS)],
    bashNetwork: section.sources?.bashNetwork ?? true,
    readOutsideProject: section.sources?.readOutsideProject ?? true,
    restrictTools: [...new Set(section.restrictTools ?? DEFAULT_RESTRICT_TOOLS)],
    release: section.release ?? "admin",
  };
}

/** Tightening merge: the stricter mode, the union of the lists, OR of the switches. `release` stays with `a` (the higher layer). */
export function mergeTaint(a: TaintPolicy, b: TaintPolicy): TaintPolicy {
  return {
    mode: MODE_RANK[a.mode] >= MODE_RANK[b.mode] ? a.mode : b.mode,
    sourceTools: [...new Set([...a.sourceTools, ...b.sourceTools])],
    bashNetwork: a.bashNetwork || b.bashNetwork,
    readOutsideProject: a.readOutsideProject || b.readOutsideProject,
    restrictTools: [...new Set([...a.restrictTools, ...b.restrictTools])],
    release: a.release,
  };
}

export function taintToolMatches(name: string, pattern: string): boolean {
  if (pattern === "mcp__*") return name.startsWith("mcp__") && name.length > 5;
  if (!pattern.endsWith("__*")) return name === pattern;
  const prefix = pattern.slice(0, -1);
  if (!name.startsWith(prefix)) return false;
  const rest = name.slice(prefix.length);
  return rest.length > 0 && !rest.includes("__");
}

