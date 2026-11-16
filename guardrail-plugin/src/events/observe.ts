// Facts about tools that are only observed (no evaluation): affected paths, effects, target domain.
import { isAbsolute, resolve } from "node:path";
import { pathSummarizable, projectRelative, type Effect } from "./commandInfo.js";
import { validPath } from "./fields.js";
import { INVALID } from "./types.js";

export interface ObservedTool {
  paths: string[];
  effects: Effect[];
  domain?: string;
  /** Read-only tool whose paths lie inside the project and are not sensitive: subject to the flood limit. */
  suppressible: boolean;
}

const READ_TOOLS = new Set(["Read", "Glob", "Grep", "LS", "NotebookRead"]);
const NETWORK_TOOLS = new Set(["WebFetch", "WebSearch"]);
const NO_EFFECT_TOOLS = new Set(["TodoWrite", "ExitPlanMode", "BashOutput", "TaskOutput", "TaskList", "TaskGet"]);

function stringField(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === "string" && v !== "" ? v : undefined;
}

export function observedTool(name: string, input: Record<string, unknown>, ctx: { projectDir: string; cwd?: string | undefined }): ObservedTool {
  const candidates = ["file_path", "path", "notebook_path"].map((k) => stringField(input, k)).filter((v): v is string => v !== undefined);
  const paths: string[] = [];
  let summarizable = READ_TOOLS.has(name);
  for (const candidate of candidates) {
    if (validPath(candidate) === null) {
      paths.push(INVALID);
      summarizable = false;
      continue;
    }
    const absolute = isAbsolute(candidate) ? resolve(candidate) : resolve(ctx.cwd ?? ctx.projectDir, candidate);
    paths.push(projectRelative(absolute, ctx.projectDir));
    if (!pathSummarizable(absolute, ctx.projectDir)) summarizable = false;
  }
  const out: ObservedTool = { paths, effects: [], suppressible: summarizable };
  if (READ_TOOLS.has(name) || NO_EFFECT_TOOLS.has(name)) return out;
  if (NETWORK_TOOLS.has(name)) {
    out.effects = ["network"];
    const url = stringField(input, "url");
    if (url !== undefined) {
      try {
        out.domain = new URL(url).hostname;
      } catch {
        out.domain = INVALID;
      }
    }
    return out;
  }
  out.effects = name === "Task" || name === "Agent" ? ["exec"] : ["unknown"];
  return out;
}
