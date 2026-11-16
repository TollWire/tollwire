// The verifier lists a directory exactly once and turns a listing error into a finding (review point 2: no second
// readdir, no swallowed error, no time-of-check gap between user and service files).
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ calls: [] as string[], failFor: null as string | null }));

vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const readdirSync = ((path: string, ...rest: unknown[]) => {
    state.calls.push(String(path));
    if (state.failFor !== null && String(path) === state.failFor) throw Object.assign(new Error("EIO"), { code: "EIO" });
    return (fs.readdirSync as (...a: unknown[]) => unknown)(path, ...rest);
  }) as typeof fs.readdirSync;
  return { ...fs, default: { ...fs, readdirSync }, readdirSync };
});

const { listEventGroups, expandPaths } = await import("../../src/events/verify.js");
const { runVerifyCli } = await import("../../src/events/verifyCli.js");
const { tempDir } = await import("./helpers.js");

describe("directory listing of the verifier", () => {
  beforeEach(() => {
    state.calls = [];
    state.failFor = null;
  });
  it("reads the directory once for user and service files", () => {
    const dir = tempDir();
    for (const n of ["u1-20261011.jsonl", "control-20261011.jsonl"]) writeFileSync(join(dir, n), "");
    const listing = listEventGroups(dir);
    expect(listing.groups).toHaveLength(2);
    expect(state.calls.filter((c) => c === dir)).toHaveLength(1);
  });
  it("reports a listing error as unreadable and fails the check", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "control-20261011.jsonl"), "");
    state.failFor = dir;
    expect(expandPaths([dir]).findings).toEqual([{ kind: "unreadable", file: dir, detail: "directory cannot be listed" }]);
    let out = "";
    const code = runVerifyCli(["verify", dir], { out: (t) => (out += t), err: () => undefined }, { dir });
    expect(code).toBe(1);
    expect(out).toContain("unreadable: ");
    expect(out).not.toContain("no_event_files");
    expect(runVerifyCli(["verify"], { out: () => undefined, err: () => undefined }, { dir })).toBe(1);
  });
});
