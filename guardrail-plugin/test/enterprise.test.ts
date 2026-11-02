import { execFileSync } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  alwaysProtectedPaths,
  detectEnterprise,
  enterprisePaths,
  mergePolicies,
  parseEnterprisePolicy,
  parseLowerLayer,
  projectDirProblem,
  readTrustedFile,
  resolvePolicy,
  systemProtectedPaths,
  type LowerLayer,
} from "../src/enterprise.js";
import { evaluateDetailed } from "../src/evaluate.js";
import { enterpriseLayout } from "../src/events/layout.js";
import { BUNDLED_POLICY_PATH, loadPolicy, type Policy } from "../src/policy.js";
import { sha256Hex } from "../src/vendor/hashchain.js";
import { tempDir } from "./events/helpers.js";

const uid = process.getuid?.() ?? 0;

const ENTERPRISE = {
  version: 2,
  revision: "acme-2026-10-01",
  protectedPaths: ["secrets/"],
  blockedCommands: [{ id: "no-curl-bash", pattern: "curl.*\\|\\s*bash", reason: "Piping downloads into a shell is not allowed." }],
  allowedDependencies: { npm: ["zod", "vitest"], pypi: ["requests"] },
};

interface Fixture {
  root: string;
  project: string;
  policyFile: string;
  options: Parameters<typeof resolvePolicy>[0];
}

function fixture(policy: unknown = ENTERPRISE, env: NodeJS.ProcessEnv = { TOLLGATE_ENTERPRISE: "1" }): Fixture {
  const root = tempDir("tg-ent-");
  const admin = join(root, "etc", "tollgate");
  mkdirSync(admin, { recursive: true });
  chmodSync(join(root, "etc"), 0o755);
  chmodSync(admin, 0o755);
  const policyFile = join(admin, "policy.json");
  writeFileSync(policyFile, typeof policy === "string" ? policy : JSON.stringify(policy), { mode: 0o644 });
  chmodSync(policyFile, 0o644);
  const project = join(root, "project");
  mkdirSync(project);
  return { root, project, policyFile, options: { env, projectDir: project, platform: "linux", ownerUid: uid, stopAt: root, paths: { adminDir: admin, policyFile } } };
}

function writeProject(f: Fixture, content: unknown): string {
  mkdirSync(join(f.project, ".tollgate"), { recursive: true });
  const path = join(f.project, ".tollgate", "policy.json");
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
  return path;
}

describe("enterprise signals (T5)", () => {
  it("knows the fixed locations per platform", () => {
    expect(enterprisePaths("linux")).toEqual({ adminDir: "/etc/tollgate", policyFile: "/etc/tollgate/policy.json" });
    expect(enterprisePaths("win32").policyFile).toBe("C:\\ProgramData\\TollGate\\policy.json");
    expect(enterprisePaths("darwin").adminDir).toBe("/Library/Application Support/TollGate");
  });
  it("is inactive without a signal", () => {
    expect(detectEnterprise({}, "linux", () => false)).toEqual({ active: false, reasons: [] });
  });
  it("is active with the admin directory or TOLLGATE_ENTERPRISE=1, exactly", () => {
    expect(detectEnterprise({}, "linux", (p) => p === "/etc/tollgate")).toEqual({ active: true, reasons: ["admin_dir"] });
    expect(detectEnterprise({ TOLLGATE_ENTERPRISE: "1" }, "linux", () => false)).toEqual({ active: true, reasons: ["env"] });
    expect(detectEnterprise({ TOLLGATE_ENTERPRISE: "1" }, "linux", () => true).reasons).toEqual(["admin_dir", "env"]);
    expect(detectEnterprise({ TOLLGATE_ENTERPRISE: "true" }, "linux", () => false).active).toBe(false);
    expect(detectEnterprise({ TOLLGATE_ENTERPRISE: "0" }, "linux", () => false).active).toBe(false);
  });
  it("probes the real file system by default", () => {
    expect(typeof detectEnterprise({}, "linux").active).toBe("boolean");
    expect(detectEnterprise({}, "linux", undefined).reasons.includes("env")).toBe(false);
  });
});

describe("readTrustedFile", () => {
  it("reads an admin-owned file and returns its hash", () => {
    const f = fixture();
    const r = readTrustedFile(f.policyFile, { ownerUid: uid, stopAt: f.root });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.sha256).toBe(sha256Hex(JSON.stringify(ENTERPRISE)));
  });
  it("refuses a file that is writable by group or others", () => {
    for (const mode of [0o664, 0o666, 0o646]) {
      const f = fixture();
      chmodSync(f.policyFile, mode);
      expect(readTrustedFile(f.policyFile, { ownerUid: uid, stopAt: f.root })).toEqual({ ok: false, reason: "the policy file is writable by group or others" });
    }
  });
  it("refuses a parent directory that is writable by group or others", () => {
    const f = fixture();
    chmodSync(join(f.root, "etc"), 0o775);
    expect(readTrustedFile(f.policyFile, { ownerUid: uid, stopAt: f.root })).toEqual({ ok: false, reason: "a parent directory is writable by group or others" });
    chmodSync(join(f.root, "etc"), 0o755);
    chmodSync(join(f.root, "etc", "tollgate"), 0o757);
    expect(readTrustedFile(f.policyFile, { ownerUid: uid, stopAt: f.root }).ok).toBe(false);
  });
  it("refuses another owner", () => {
    const f = fixture();
    expect(readTrustedFile(f.policyFile, { ownerUid: uid + 1, stopAt: f.root })).toEqual({ ok: false, reason: "a parent directory is not owned by the administrator" });
    const g = fixture();
    // The parent directories are checked first; test the file owner with a stop directory right above the file.
    expect(readTrustedFile(g.policyFile, { ownerUid: uid + 1, stopAt: join(g.root, "etc", "tollgate") })).toEqual({ ok: false, reason: "the policy file is not owned by the administrator" });
  });
  it("refuses symlinks (file and directory), hard links, directories and large files", () => {
    const f = fixture();
    const link = join(f.root, "etc", "tollgate", "link.json");
    symlinkSync(f.policyFile, link);
    expect(readTrustedFile(link, { ownerUid: uid, stopAt: f.root })).toEqual({ ok: false, reason: "the policy file is a symbolic link" });
    const alias = join(f.root, "etc", "alias");
    symlinkSync(join(f.root, "etc", "tollgate"), alias);
    expect(readTrustedFile(join(alias, "policy.json"), { ownerUid: uid, stopAt: f.root }).ok).toBe(false);
    linkSync(f.policyFile, join(f.root, "etc", "tollgate", "second.json"));
    expect(readTrustedFile(f.policyFile, { ownerUid: uid, stopAt: f.root })).toEqual({ ok: false, reason: "the policy file is not a regular file with a single link" });
    const dirAsFile = join(f.root, "etc", "tollgate", "dir.json");
    mkdirSync(dirAsFile);
    expect(readTrustedFile(dirAsFile, { ownerUid: uid, stopAt: f.root }).ok).toBe(false);
    const big = fixture(`{"pad":"${"x".repeat(70_000)}"}`);
    expect(readTrustedFile(big.policyFile, { ownerUid: uid, stopAt: big.root })).toEqual({ ok: false, reason: "the policy file is larger than 64 KiB" });
  });
  it("reports a missing file", () => {
    const f = fixture();
    expect(readTrustedFile(join(f.root, "etc", "tollgate", "none.json"), { ownerUid: uid, stopAt: f.root })).toEqual({ ok: false, reason: "the policy file does not exist" });
  });
  it("checks every directory up to the file system root when stopAt is not set", () => {
    const f = fixture();
    // The temporary directory lies below /tmp (world-writable): refused.
    expect(readTrustedFile(f.policyFile, { ownerUid: uid }).ok).toBe(false);
  });
});

describe("parseEnterprisePolicy", () => {
  it("parses the policy and fills logging defaults", () => {
    const p = parseEnterprisePolicy(JSON.stringify(ENTERPRISE));
    expect(p.revision).toBe("acme-2026-10-01");
    expect(p.blockedCommands[0]?.id).toBe("no-curl-bash");
    expect(p.logging).toMatchObject({ enabled: true, tools: "all", commandDetail: "redacted", commandHash: false, onWriteError: "block", layout: "per_user", rateLimit: 600, projectDir: true });
    expect(p.humanSessionAllowed).toBe(false);
    expect(p.projectMode).toBe("tighten");
  });
  it("takes logging, humanSession and project from the file and tolerates forwarding", () => {
    const p = parseEnterprisePolicy(
      JSON.stringify({
        ...ENTERPRISE,
        logging: { enabled: false, layout: "shared", tools: "checked", commandDetail: "hash", commandHash: true, projectDir: false, onWriteError: "warn", rateLimit: 5 },
        humanSession: { allowed: true },
        project: { mode: "ignore" },
        forwarding: { targets: [], internalZones: [] },
      }),
    );
    expect(p.logging).toEqual({ enabled: false, layout: "shared", tools: "checked", commandDetail: "hash", commandHash: true, projectDir: false, onWriteError: "warn", rateLimit: 5 });
    expect(p.humanSessionAllowed).toBe(true);
    expect(p.projectMode).toBe("ignore");
  });
  it.each([
    ["version 1", { ...ENTERPRISE, version: 1 }],
    ["missing revision", { ...ENTERPRISE, revision: undefined }],
    ["missing dependencies", { ...ENTERPRISE, allowedDependencies: undefined }],
    ["invalid regex", { ...ENTERPRISE, blockedCommands: [{ id: "x", pattern: "(", reason: "r" }] }],
    ["duplicate ids", { ...ENTERPRISE, blockedCommands: [{ id: "x", pattern: "a", reason: "r" }, { id: "x", pattern: "b", reason: "r" }] }],
    ["rule without id", { ...ENTERPRISE, blockedCommands: [{ pattern: "a", reason: "r" }] }],
    ["too many rules", { ...ENTERPRISE, blockedCommands: Array.from({ length: 201 }, (_, i) => ({ id: `r${i}`, pattern: "a", reason: "r" })) }],
    ["pattern too long", { ...ENTERPRISE, blockedCommands: [{ id: "x", pattern: "a".repeat(501), reason: "r" }] }],
    ["bad logging value", { ...ENTERPRISE, logging: { commandDetail: "full" } }],
  ])("rejects %s", (_name, value) => {
    expect(() => parseEnterprisePolicy(JSON.stringify(value))).toThrow();
  });
  it("rejects text that is not JSON", () => {
    expect(() => parseEnterprisePolicy("{nope")).toThrow();
  });
});

describe("parseLowerLayer (safe subset)", () => {
  it("keeps literal, tokens and glob rules and protected paths", () => {
    const { layer, findings } = parseLowerLayer(
      JSON.stringify({
        version: 1,
        protectedPaths: ["docs/"],
        blockedCommands: [
          { id: "a", match: { literal: "rm -rf" }, reason: "no" },
          { match: { tokens: ["git", "push"] }, reason: "no" },
          { match: { glob: "*--force*" }, reason: "no" },
        ],
        allowedDependencies: { npm: ["zod"], pypi: [] },
      }),
      "project",
    );
    expect(findings).toEqual([]);
    expect(layer.protectedPaths).toEqual(["docs/"]);
    expect(layer.blockedCommands.map((r) => r.match)).toEqual([{ literal: "rm -rf" }, { tokens: ["git", "push"] }, { glob: "*--force*" }]);
    expect(layer.allowedDependencies).toEqual({ npm: ["zod"], pypi: [] });
  });
  it("ignores regular expression rules and reports policy_error (also copies of default.json)", () => {
    // A copy of the file (not the parsed policy: its `taint` section is normalized in memory).
    const copy = JSON.parse(readFileSync(BUNDLED_POLICY_PATH, "utf8")) as ReturnType<typeof loadPolicy>;
    const { layer, findings } = parseLowerLayer(JSON.stringify({ ...copy, blockedCommands: [{ ...copy.blockedCommands[0], reason: "changed" }] }), "project");
    expect(layer.blockedCommands).toEqual([]);
    expect(findings).toEqual([{ type: "policy_error", level: "project", id: "blockedCommands[0]", detail: expect.stringContaining("regular expression") }]);
  });
  it("ignores a glob with more than two stars", () => {
    const { layer, findings } = parseLowerLayer(JSON.stringify({ version: 1, blockedCommands: [{ id: "g", match: { glob: "a*b*c*d" }, reason: "r" }] }), "explicit");
    expect(layer.blockedCommands).toEqual([]);
    expect(findings[0]).toMatchObject({ type: "policy_error", level: "explicit", id: "g" });
  });
  it("reports sections that only the enterprise policy may set", () => {
    const { findings } = parseLowerLayer(JSON.stringify({ version: 2, logging: { enabled: false }, humanSession: { allowed: true }, project: { mode: "ignore" }, forwarding: {} }), "project");
    expect(findings.map((f) => f.detail)).toEqual([
      "section 'logging' is only valid in the enterprise policy",
      "section 'humanSession' is only valid in the enterprise policy",
      "section 'project' is only valid in the enterprise policy",
      "section 'forwarding' is only valid in the enterprise policy",
    ]);
    expect(findings.every((f) => f.type === "policy_override_ignored")).toBe(true);
  });
  it("rejects invalid structures", () => {
    expect(() => parseLowerLayer("{nope", "project")).toThrow();
    expect(() => parseLowerLayer(JSON.stringify({ version: 3 }), "project")).toThrow();
    expect(() => parseLowerLayer(JSON.stringify({ version: 1, blockedCommands: [{ match: { literal: "x", extra: 1 }, reason: "r" }] }), "project")).toThrow();
    expect(() => parseLowerLayer(JSON.stringify({ version: 1, blockedCommands: [{ match: { tokens: [] }, reason: "r" }] }), "project")).toThrow();
  });
});

describe("mergePolicies (only tightening)", () => {
  const enterprise = parseEnterprisePolicy(JSON.stringify(ENTERPRISE));
  const base = loadPolicy(BUNDLED_POLICY_PATH);
  const lower = (patch: Partial<LowerLayer> = {}): LowerLayer => ({ level: "project", protectedPaths: [], blockedCommands: [], ...patch });

  it("unites protected paths and rules; the enterprise rules come first", () => {
    const { policy, findings } = mergePolicies(enterprise, base, [lower({ protectedPaths: ["docs/"], blockedCommands: [{ id: "p1", match: { literal: "x" }, reason: "r" }] })]);
    expect(findings).toEqual([]);
    expect(policy.protectedPaths).toEqual(expect.arrayContaining(["secrets/", "AGENTS.md", "docs/"]));
    expect(policy.blockedCommands[0]?.id).toBe("no-curl-bash");
    expect(policy.blockedCommands.at(-1)?.id).toBe("p1");
    expect(policy.blockedCommands.map((r) => r.id)).toContain("default-0");
    expect(policy.blockedCommands).toHaveLength(1 + base.blockedCommands.length + 1);
  });
  it("ignores a rule with an id that exists above and reports it", () => {
    const { policy, findings } = mergePolicies(enterprise, base, [lower({ blockedCommands: [{ id: "no-curl-bash", match: { literal: "nothing" }, reason: "weaker" }] })]);
    expect(policy.blockedCommands.filter((r) => r.id === "no-curl-bash")).toHaveLength(1);
    expect(policy.blockedCommands.find((r) => r.id === "no-curl-bash")?.pattern).toBeDefined();
    expect(findings).toEqual([{ type: "policy_override_ignored", level: "project", id: "no-curl-bash", detail: expect.any(String) }]);
  });
  it("intersects dependencies; empty means nothing allowed", () => {
    const merged = mergePolicies(enterprise, base, [lower({ allowedDependencies: { npm: ["zod", "left-pad"], pypi: [] } })]);
    expect(merged.policy.allowedDependencies).toEqual({ npm: ["zod"], pypi: [] });
    expect(merged.findings).toEqual([{ type: "policy_override_ignored", level: "project", detail: expect.stringContaining("dependencies") }]);
    const none = mergePolicies(enterprise, base, [lower({ allowedDependencies: { npm: [], pypi: [] } })]);
    expect(none.policy.allowedDependencies).toEqual({ npm: [], pypi: [] });
    expect(none.findings).toEqual([]);
    expect(mergePolicies(enterprise, base, [lower()]).policy.allowedDependencies).toEqual(enterprise.allowedDependencies);
  });

  it("property: the result never allows more than the base, for random lower layers", () => {
    let seed = 12345;
    const rnd = (n: number): number => {
      seed = (seed * 1664525 + 1013904223) % 4294967296;
      return seed % n;
    };
    const words = ["a", "b", "c", "zod", "vitest", "requests", "left-pad", "docs/", "secrets/", "AGENTS.md", "x"];
    const pick = (): string => words[rnd(words.length)] as string;
    for (let round = 0; round < 300; round += 1) {
      const lowers: LowerLayer[] = Array.from({ length: rnd(3) }, (_, i) => ({
        level: i === 0 ? "project" : "explicit",
        protectedPaths: Array.from({ length: rnd(3) }, pick),
        blockedCommands: Array.from({ length: rnd(3) }, (_x, j) => ({ id: rnd(2) === 0 ? pick() : `r${round}-${j}`, match: { literal: pick() }, reason: "r" })),
        ...(rnd(2) === 0 ? { allowedDependencies: { npm: Array.from({ length: rnd(4) }, pick), pypi: Array.from({ length: rnd(3) }, pick) } } : {}),
      }));
      const { policy } = mergePolicies(enterprise, base, lowers);
      for (const p of [...enterprise.protectedPaths, ...base.protectedPaths]) expect(policy.protectedPaths).toContain(p);
      for (const r of enterprise.blockedCommands) expect(policy.blockedCommands.some((x) => x.id === r.id && x.pattern === r.pattern)).toBe(true);
      for (const r of base.blockedCommands) expect(policy.blockedCommands.some((x) => x.pattern === r.pattern)).toBe(true);
      for (const n of policy.allowedDependencies.npm) expect(enterprise.allowedDependencies.npm).toContain(n);
      for (const n of policy.allowedDependencies.pypi) expect(enterprise.allowedDependencies.pypi).toContain(n);
      for (const l of lowers) {
        for (const p of l.protectedPaths) expect(policy.protectedPaths).toContain(p);
        if (l.allowedDependencies) for (const n of policy.allowedDependencies.npm) expect(l.allowedDependencies.npm).toContain(n);
      }
      const ids = policy.blockedCommands.map((r) => r.id).filter(Boolean);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });
});

describe("resolvePolicy", () => {
  it("without a signal: project policy > bundled default", () => {
    const f = fixture(ENTERPRISE, {});
    const bundled = resolvePolicy({ ...f.options, exists: () => false });
    expect(bundled).toMatchObject({ ok: true, policyFile: BUNDLED_POLICY_PATH, enterprise: null, revision: null, findings: [], protectedFiles: [] });
    if (bundled.ok) expect(bundled.layers).toEqual([{ level: "default", sha256: expect.stringMatching(/^[0-9a-f]{64}$/) }]);
    const valid = { version: 1, protectedPaths: ["x/"], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
    const projectFile = writeProject(f, valid);
    const project = resolvePolicy({ ...f.options, exists: () => false });
    // `exists` only decides the enterprise signal here; the project file is found on disk.
    expect(project).toMatchObject({ ok: true, policyFile: projectFile });
  });
  it("without a signal TOLLGATE_POLICY is only a further layer: the base stays, tightening works", () => {
    const f = fixture(ENTERPRISE, {});
    const projectFile = writeProject(f, { version: 1, protectedPaths: ["x/"], blockedCommands: [{ pattern: "ZZ-BASE", reason: "base" }], allowedDependencies: { npm: ["a", "b"], pypi: [] } });
    const explicitFile = join(f.root, "explicit.json");
    writeFileSync(explicitFile, JSON.stringify({ version: 1, protectedPaths: ["y/"], blockedCommands: [{ id: "e1", match: { tokens: ["make", "deploy"] }, reason: "no" }], allowedDependencies: { npm: ["a"], pypi: [] } }));
    const r = resolvePolicy({ ...f.options, env: { TOLLGATE_POLICY: explicitFile }, exists: () => false });
    expect(r).toMatchObject({ ok: true, policyFile: projectFile, findings: [], enterprise: null });
    if (r.ok) {
      expect(r.policy.protectedPaths).toEqual(["x/", "y/"]);
      expect(r.policy.blockedCommands.map((x) => x.pattern ?? x.id)).toEqual(["ZZ-BASE", "e1"]);
      expect(r.policy.allowedDependencies.npm).toEqual(["a"]);
      expect(r.layers.map((l) => l.level)).toEqual(["project", "explicit"]);
      expect(r.protectedFiles).toEqual([explicitFile]);
    }
  });
  it("without a signal a loosening TOLLGATE_POLICY is ignored and reported as policy_override_ignored", () => {
    const f = fixture(ENTERPRISE, {});
    writeProject(f, { version: 1, protectedPaths: ["x/"], blockedCommands: [{ pattern: "ZZ-BASE", reason: "base" }], allowedDependencies: { npm: ["a"], pypi: [] } });
    const explicitFile = join(f.root, "explicit.json");
    // empty lists, a wider dependency list, a regular expression rule and an enterprise-only section
    writeFileSync(explicitFile, JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [{ pattern: "ZZ-REGEX", reason: "r" }], allowedDependencies: { npm: ["a", "evil"], pypi: ["p"] }, logging: { enabled: false } }));
    const r = resolvePolicy({ ...f.options, env: { TOLLGATE_POLICY: explicitFile }, exists: () => false });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.protectedPaths).toEqual(["x/"]);
      expect(r.policy.blockedCommands.map((x) => x.pattern)).toEqual(["ZZ-BASE"]);
      expect(r.policy.allowedDependencies).toEqual({ npm: ["a"], pypi: [] });
      expect(r.findings.filter((x) => x.type === "policy_override_ignored").map((x) => x.level)).toEqual(["explicit", "explicit"]);
      expect(r.findings.some((x) => x.type === "policy_error" && x.level === "explicit")).toBe(true);
    }
  });
  it("without a signal an empty TOLLGATE_POLICY does not replace the bundled default", () => {
    const f = fixture(ENTERPRISE, {});
    const explicitFile = join(f.root, "explicit.json");
    writeFileSync(explicitFile, JSON.stringify({ version: 1 }));
    const bundled = loadPolicy(BUNDLED_POLICY_PATH);
    const r = resolvePolicy({ ...f.options, env: { TOLLGATE_POLICY: explicitFile }, exists: () => false });
    expect(r).toMatchObject({ ok: true, policyFile: BUNDLED_POLICY_PATH });
    if (r.ok) {
      expect(r.policy.blockedCommands).toHaveLength(bundled.blockedCommands.length);
      expect(r.policy.protectedPaths).toEqual(bundled.protectedPaths);
    }
  });
  it("without a signal an unusable policy is an error", () => {
    const f = fixture(ENTERPRISE, { TOLLGATE_POLICY: "/does/not/exist.json" });
    expect(resolvePolicy({ ...f.options, exists: () => false })).toEqual({ ok: false, kind: "policy_error", message: "policy could not be loaded (fail closed)." });
  });

  it("merges the layers in enterprise mode", () => {
    const f = fixture();
    writeProject(f, { version: 1, protectedPaths: ["docs/"], blockedCommands: [{ id: "p1", match: { literal: "rm -rf" }, reason: "no" }, { pattern: "x", reason: "regex" }], allowedDependencies: { npm: ["zod"], pypi: ["requests"] } });
    const r = resolvePolicy(f.options);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.revision).toBe("acme-2026-10-01");
    expect(r.layers.map((l) => l.level)).toEqual(["enterprise", "default", "project"]);
    expect(r.policy.protectedPaths).toEqual(expect.arrayContaining(["secrets/", "docs/", ".github/"]));
    expect(r.policy.allowedDependencies).toEqual({ npm: ["zod"], pypi: ["requests"] });
    expect(r.findings.map((x) => x.type)).toEqual(["policy_error"]);
    expect(r.enterprise?.settings.onWriteError).toBe("block");
    expect(r.policyFile).toBe(f.policyFile);
    expect(r.protectedFiles).toEqual([f.policyFile, join(f.project, ".tollgate", "policy.json")]);
  });
  it("activates through the admin directory signal alone", () => {
    const f = fixture(ENTERPRISE, {});
    const r = resolvePolicy({ ...f.options, exists: (p) => p === f.options.paths?.adminDir });
    expect(r.ok).toBe(true);
  });
  it("applies TOLLGATE_POLICY as a further lower layer and keeps the project layer", () => {
    const explicit = join(tempDir(), "p.json");
    const f = fixture(ENTERPRISE, { TOLLGATE_ENTERPRISE: "1", TOLLGATE_POLICY: explicit });
    writeFileSync(explicit, JSON.stringify({ version: 1, blockedCommands: [{ id: "e1", match: { tokens: ["make", "deploy"] }, reason: "no" }] }));
    writeProject(f, { version: 1, protectedPaths: ["docs/"] });
    const r = resolvePolicy(f.options);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.layers.map((l) => l.level)).toEqual(["enterprise", "default", "project", "explicit"]);
      expect(r.policy.blockedCommands.some((x) => x.id === "e1")).toBe(true);
    }
  });
  it("ignores the lower layers with project.mode = ignore, even broken ones", () => {
    const f = fixture({ ...ENTERPRISE, project: { mode: "ignore" } });
    writeProject(f, "{broken");
    const r = resolvePolicy(f.options);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.layers.map((l) => l.level)).toEqual(["enterprise", "default"]);
  });
  it("fails closed on a broken project policy and on a missing TOLLGATE_POLICY file", () => {
    const f = fixture();
    writeProject(f, "{broken");
    expect(resolvePolicy(f.options)).toEqual({ ok: false, kind: "policy_error", message: "project policy could not be loaded (fail closed)." });
    const g = fixture(ENTERPRISE, { TOLLGATE_ENTERPRISE: "1", TOLLGATE_POLICY: "/does/not/exist.json" });
    expect(resolvePolicy(g.options)).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("explicit") });
  });
  describe("lower policy files are read with the hardened reader (security review finding 4)", () => {
    const VALID = { version: 1, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
    const failed = (level: string) => ({ ok: false, kind: "policy_error", message: `${level} policy could not be loaded (fail closed).` });

    it("refuses a project policy that is a symbolic link, in enterprise and stand-alone mode", () => {
      for (const [env, expected] of [[{ TOLLGATE_ENTERPRISE: "1" }, failed("project")], [{}, { ok: false, kind: "policy_error", message: "policy could not be loaded (fail closed)." }]] as const) {
        const f = fixture(ENTERPRISE, env);
        const target = join(f.root, "elsewhere.json");
        writeFileSync(target, JSON.stringify(VALID));
        mkdirSync(join(f.project, ".tollgate"));
        symlinkSync(target, join(f.project, ".tollgate", "policy.json"));
        expect(resolvePolicy({ ...f.options, exists: () => false })).toEqual(expected);
      }
    });
    it("refuses a FIFO without blocking (project policy, TOLLGATE_POLICY, stand-alone)", () => {
      const f = fixture();
      mkdirSync(join(f.project, ".tollgate"));
      execFileSync("mkfifo", [join(f.project, ".tollgate", "policy.json")]);
      expect(resolvePolicy(f.options)).toEqual(failed("project"));
      const g = fixture(ENTERPRISE, { TOLLGATE_ENTERPRISE: "1", TOLLGATE_POLICY: join(f.root, "fifo.json") });
      execFileSync("mkfifo", [join(f.root, "fifo.json")]);
      expect(resolvePolicy(g.options)).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("explicit") });
      const h = fixture(ENTERPRISE, {});
      mkdirSync(join(h.project, ".tollgate"));
      execFileSync("mkfifo", [join(h.project, ".tollgate", "policy.json")]);
      expect(resolvePolicy({ ...h.options, exists: () => false })).toEqual({ ok: false, kind: "policy_error", message: "policy could not be loaded (fail closed)." });
    });
    it("refuses a file over 64 KiB", () => {
      const f = fixture();
      writeProject(f, JSON.stringify({ ...VALID, protectedPaths: ["x/"], pad: "a".repeat(70_000) }));
      expect(resolvePolicy(f.options)).toEqual(failed("project"));
    });
    it("still reads a regular lower policy file", () => {
      const f = fixture();
      writeProject(f, VALID);
      expect(resolvePolicy(f.options)).toMatchObject({ ok: true });
    });
  });
  it("fails closed with policy_error if the enterprise policy is missing, unsafe or invalid", () => {
    const missing = fixture();
    expect(resolvePolicy({ ...missing.options, paths: { adminDir: join(missing.root, "etc", "tollgate"), policyFile: join(missing.root, "etc", "tollgate", "gone.json") } })).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("does not exist") });
    const unsafe = fixture();
    chmodSync(unsafe.policyFile, 0o666);
    expect(resolvePolicy(unsafe.options)).toMatchObject({ ok: false, kind: "policy_error", message: expect.stringContaining("writable by group or others") });
    const invalid = fixture("{nope");
    expect(resolvePolicy(invalid.options)).toEqual({ ok: false, kind: "policy_error", message: "enterprise policy is invalid (fail closed)." });
    const wrongOwner = fixture();
    expect(resolvePolicy({ ...wrongOwner.options, ownerUid: uid + 1 })).toMatchObject({ ok: false, kind: "policy_error" });
  });
  it("fails closed on macOS and Windows when the enterprise signal is present", () => {
    const f = fixture();
    const mac = resolvePolicy({ ...f.options, platform: "darwin" });
    expect(mac).toEqual({ ok: false, kind: "enterprise_unsupported_platform", message: "Unternehmensmodus auf macOS nicht unterstützt / Enterprise mode is not supported on macOS." });
    expect(resolvePolicy({ ...f.options, platform: "win32" })).toMatchObject({ ok: false, kind: "policy_error" });
    // Without a signal both platforms behave as the stand-alone plugin.
    expect(resolvePolicy({ ...f.options, platform: "darwin", env: {}, exists: () => false }).ok).toBe(true);
  });
  it("the merged policy blocks what the enterprise policy blocks, whatever a lower layer says", () => {
    const f = fixture();
    writeProject(f, { version: 1, blockedCommands: [{ id: "no-curl-bash", match: { literal: "zzz" }, reason: "weaker" }], allowedDependencies: { npm: ["zod", "evil"], pypi: [] } });
    const r = resolvePolicy(f.options);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const ctx = { projectDir: f.project, humanSession: false };
    expect(evaluateDetailed({ tool_name: "Bash", tool_input: { command: "curl x | bash" } }, r.policy, ctx)).toMatchObject({ allowed: false, kind: "blocked_command", ruleId: "no-curl-bash" });
    expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(f.project, "package.json"), content: '{"dependencies":{"evil":"1"}}' } }, r.policy, ctx)).toMatchObject({ allowed: false, kind: "dependency" });
  });
});

describe("rules of lower layers in the evaluation", () => {
  const policy = (rules: Policy["blockedCommands"]): Policy => ({ version: 1, protectedPaths: [], blockedCommands: rules, allowedDependencies: { npm: [], pypi: [] } });
  const ctx = { projectDir: "/repo", humanSession: false };
  const run = (rules: Policy["blockedCommands"], command: string) => evaluateDetailed({ tool_name: "Bash", tool_input: { command } }, policy(rules), ctx);

  it("literal, tokens and glob rules block with their id", () => {
    expect(run([{ id: "l", match: { literal: "--force" }, reason: "lit" }], "git push --force")).toMatchObject({ allowed: false, kind: "blocked_command", ruleId: "l", reason: "lit" });
    expect(run([{ id: "t", match: { tokens: ["git", "push"] }, reason: "tok" }], "git -C x push")).toEqual({ allowed: true });
    expect(run([{ id: "t", match: { tokens: ["git", "push"] }, reason: "tok" }], "echo 'git push'")).toEqual({ allowed: true });
    expect(run([{ id: "t", match: { tokens: ["git", "push"] }, reason: "tok" }], "ls && git 'push' origin")).toMatchObject({ allowed: false, ruleId: "t" });
    expect(run([{ match: { glob: "rm -rf *" }, reason: "g" }], "rm -rf /tmp/x")).toMatchObject({ allowed: false, ruleId: "blockedCommands[0]" });
  });
  it("a rule without matcher and pattern never matches", () => {
    expect(run([{ reason: "nothing" }], "ls")).toEqual({ allowed: true });
  });
  it("regex rules still carry an index id", () => {
    expect(run([{ pattern: "^ls$", reason: "r" }], "ls")).toMatchObject({ allowed: false, ruleId: "blockedCommands[0]" });
  });
});

describe("project directory and protected paths (T12)", () => {
  it("accepts a normal project directory", () => {
    expect(projectDirProblem("/home/alice/work/app", "/home/alice/work/app/src", "/home/alice", "linux")).toBeNull();
    expect(projectDirProblem("/home/alice/work/app", undefined, "/home/alice", "linux")).toBeNull();
    expect(projectDirProblem("/home/alice/work/app/", "/home/alice/work/app", "/home/alice", "linux")).toBeNull();
  });
  it.each([
    ["relative", "work/app", "is not an absolute path"],
    ["root", "/", "file system root"],
    ["home parent", "/home", "file system root"],
    ["home", "/home/alice", "file system root"],
    ["etc tollgate", "/etc/tollgate", "protected system path"],
    ["below log", "/var/log/tollgate/events", "protected system path"],
    ["opt", "/opt/tollgate/bin", "protected system path"],
    ["managed settings", "/etc/claude-code", "protected system path"],
    ["ancestor of a protected path", "/etc", "contains a protected system path"],
    ["ancestor /var", "/var", "contains a protected system path"],
  ])("rejects %s", (_name, dir, reason) => {
    expect(projectDirProblem(dir, undefined, "/home/alice", "linux")).toContain(reason);
  });
  it("rejects a working directory outside the project directory", () => {
    expect(projectDirProblem("/home/alice/app", "/home/alice/other", "/home/alice", "linux")).toContain("working directory");
    expect(projectDirProblem("/home/alice/app", "/home/alice/app-evil", "/home/alice", "linux")).toContain("working directory");
  });
  it("lists the always-protected paths", () => {
    expect(systemProtectedPaths("linux")).toEqual(["/etc/tollgate/", "/var/log/tollgate/", "/var/lib/tollgate/", "/opt/tollgate/", "/etc/claude-code/"]);
    expect(systemProtectedPaths("darwin")).toContain("/Library/Application Support/ClaudeCode/");
    const all = alwaysProtectedPaths("linux", { XDG_CONFIG_HOME: "/c", XDG_STATE_HOME: "/s" }, "/home/a", 1000);
    expect(all).toEqual(expect.arrayContaining(["/opt/tollgate/", "/c/tollgate/", "/s/tollgate/", "/s/tollgate/events/"]));
  });
  it("always protects the fixed shared-layout directory and the directories of the active layout (security review finding 3)", () => {
    const all = alwaysProtectedPaths("linux", { XDG_STATE_HOME: "/s" }, "/home/a", 1000);
    expect(all).toContain("/home/a/.local/state/tollgate/");
    const active = alwaysProtectedPaths("linux", { XDG_STATE_HOME: "/s" }, "/home/a", 1000, { ...enterpriseLayout("per_user", 1000, "/home/a"), eventsDir: "/x/events", lockDir: "/x/lock" });
    expect(active).toEqual(expect.arrayContaining(["/x/events/", "/x/lock/", "/home/a/.local/state/tollgate/"]));
  });
});

