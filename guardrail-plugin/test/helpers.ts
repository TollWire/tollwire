import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPolicy, BUNDLED_POLICY_PATH, type Policy } from "../src/policy.js";

export const PROJECT = "/repo";

/**
 * The bundled default policy without its `taint` section, as a file for `resolve.bundledPolicy`. For tests of other
 * features that run tool calls without a session start: with session taint on, such a session counts as tainted (no state).
 * Identical to the bundled file as long as that has no `taint` section.
 */
export const BUNDLED_WITHOUT_TAINT: string = (() => {
  const raw = JSON.parse(readFileSync(BUNDLED_POLICY_PATH, "utf8")) as Record<string, unknown>;
  delete raw.taint;
  const path = join(mkdtempSync(join(tmpdir(), "tg-policy-")), "default.json");
  writeFileSync(path, JSON.stringify(raw));
  return path;
})();

export function defaultPolicy(overrides: Partial<Policy> = {}): Policy {
  return { ...loadPolicy(BUNDLED_POLICY_PATH), ...overrides };
}
