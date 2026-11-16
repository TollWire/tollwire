import { describe, expect, it } from "vitest";
import { checkNpm, checkPypi, normalizePypi, npmAliasTarget, npmDependencies, requirementNames } from "../src/deps.js";

describe("deps", () => {
  it("collects npm dependencies from all sections", () => {
    const pkg = JSON.stringify({ dependencies: { b: "1" }, devDependencies: { a: "1" }, peerDependencies: { c: "1" } });
    expect(npmDependencies(pkg)).toEqual(["a", "b", "c"]);
    expect(npmDependencies("{}")).toEqual([]);
  });
  it("parses requirement names and ignores comments", () => {
    expect(requirementNames("# header\nDjango>=4 # web\n\nrequests_oauthlib==1\n")).toEqual(["django", "requests-oauthlib"]);
    expect(normalizePypi("Foo_Bar.baz")).toBe("foo-bar-baz");
  });
  it("reports violations", () => {
    expect(checkNpm('{"dependencies":{"zod":"4","x":"1"}}', ["zod"])).toEqual([{ ecosystem: "npm", name: "x" }]);
    expect(checkPypi("requests\nflask\n", ["Requests"])).toEqual([{ ecosystem: "pypi", name: "flask" }]);
  });
});

describe("deps hardening (Copilot review PR #7)", () => {
  it("checks npm alias targets", () => {
    expect(npmAliasTarget("npm:left-pad@1.3.0")).toBe("left-pad");
    expect(npmAliasTarget("npm:@scope/pkg@1")).toBe("@scope/pkg");
    expect(npmAliasTarget("npm:plain")).toBe("plain");
    expect(npmAliasTarget("^1.0.0")).toBeNull();
    expect(checkNpm('{"dependencies":{"zod":"npm:left-pad@1.3.0"}}', ["zod"])).toEqual([{ ecosystem: "npm", name: "left-pad" }]);
  });
  it("rejects non-registry npm specs", () => {
    for (const spec of ["github:a/b", "git+https://x/y.git", "file:../x", "https://x/y.tgz", "a/b"]) {
      expect(checkNpm(JSON.stringify({ dependencies: { zod: spec } }), ["zod"]).length).toBe(1);
    }
    expect(checkNpm('{"dependencies":{"zod":"^4.0.0"}}', ["zod"])).toEqual([]);
  });
  it("rejects pip include, editable, index and direct-reference lines", () => {
    for (const line of ["-r deps.in", "-e ./pkg", "--index-url https://evil", "requests @ https://x/r.whl", "./local", "https://x/p.whl"]) {
      expect(checkPypi(`${line}\n`, ["requests"]).length).toBe(1);
    }
  });
  it("rejects non-object package.json", () => {
    expect(() => checkNpm("[]", [])).toThrow();
    expect(() => checkNpm("null", [])).toThrow();
  });
});

describe("deps hardening (Copilot review PR #9)", () => {
  it("rejects local paths and tarballs", () => {
    for (const spec of ["/tmp/payload", "./vendor/payload", "../x", "~/x", "payload.tgz", "pkg.tar.gz"]) {
      expect(checkNpm(JSON.stringify({ dependencies: { zod: spec } }), ["zod"]).length).toBe(1);
    }
  });
  it("checks overrides and resolutions, including nested and pnpm forms", () => {
    const pkg = (o: object) => JSON.stringify({ dependencies: { zod: "4" }, ...o });
    expect(checkNpm(pkg({ overrides: { foo: "github:evil/foo" } }), ["zod"]).map((v) => v.name)).toEqual(["override overrides>foo (github:evil/foo)"]);
    expect(checkNpm(pkg({ overrides: { foo: { bar: "npm:left-pad@1" } } }), ["zod"]).map((v) => v.name)).toEqual(["override overrides>foo>bar -> left-pad"]);
    expect(checkNpm(pkg({ resolutions: { "a/b": "file:../x" } }), ["zod"]).length).toBe(1);
    expect(checkNpm(pkg({ pnpm: { overrides: { foo: "./local" } } }), ["zod"]).length).toBe(1);
    expect(checkNpm(pkg({ overrides: { foo: "1.2.3", bar: "npm:zod@4" } }), ["zod"])).toEqual([]);
  });
  it("rejects compact PEP 508 direct references with extras", () => {
    for (const line of ["requests@https://x/r.whl", "requests[security]@https://x/r.whl", "requests [socks] @ git+https://x"]) {
      expect(checkPypi(`${line}\n`, ["requests"]).length).toBe(1);
    }
    expect(checkPypi("requests[security]>=2\n", ["requests"])).toEqual([]);
  });
});
