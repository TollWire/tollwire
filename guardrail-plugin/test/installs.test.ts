import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import { npmAliasTarget } from "../src/deps.js";
import { detailFor } from "../src/blockMessage.js";
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

  it("checks the install behind sudo itself (sudo is also blocked by a command rule from 0.1.1 on)", () => {
    expect(installProblems("sudo npm install lodash", policy.allowedDependencies)).toEqual(["npm:lodash"]);
  });
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
    // The install path behind sudo, checked directly (the command rule alone would also block these).
    expect(installProblems("sudo -u root npm i lodash", policy.allowedDependencies)).toEqual(["npm:lodash"]);
    expect(installProblems("sudo -- npm i lodash", policy.allowedDependencies)).toEqual(["npm:lodash"]);
    // sudo itself is blocked by a command rule from version 0.1.1 on; the install check behind it stays exact.
    expect(installProblems("sudo -u root npm i zod", policy.allowedDependencies)).toEqual([]);
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
    for (const c of ["sudo -Hu root npm i lodash", "sudo -nu root npm i lodash", "sudo -iu root npm i lodash", "sudo -ku root npm i lodash", "sudo -Eu root npm i lodash", "sudo -uroot npm i lodash"]) {
      expect(installProblems(c, policy.allowedDependencies), c).toEqual(["npm:lodash"]);
    }
    expect(installProblems("sudo -Hu root npm i zod", policy.allowedDependencies)).toEqual([]);
    expect(installProblems("sudo -uroot npm i zod", policy.allowedDependencies)).toEqual([]);
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

describe("Version 0.1.1: Pakete ausfuehren ohne Manifest (npx, dlx, npm exec, bunx, uvx, uv run --with)", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  const problems = (cmd: string) => installProblems(cmd, policy.allowedDependencies);
  it("npx und npm exec pruefen das Paket bzw. --package (fail closed)", () => {
    for (const c of [
      "npx lodash",
      "npx -y lodash@4",
      "npx --yes lodash",
      "npx -p lodash some-bin",
      "npx --package=lodash some-bin",
      "npx -p zod -p lodash some-bin",
      "npx github:a/b",
      "npx ./local-dir",
      "npx $PKG",
      "npx -c 'npm i lodash'",
      "npx --registry=https://evil.example zod",
      "npm exec lodash",
      "npm exec -- lodash",
      "npm x lodash",
      "npm --package=lodash exec some-bin",
      "npm exec --package lodash -- some-bin",
    ]) blocked(c);
    for (const c of ["npx zod", "npx -p zod some-bin", "npm exec zod", "npm exec -- zod", "npx --no lodash", "npx --no-install lodash", "npm exec --yes=false lodash", "npm exec", "npx -c 'npm test'"]) allowed(c);
    expect(problems("npx -p lodash some-bin")).toEqual(["npm:lodash"]);
    expect(problems("npx tsc")).toEqual(["npm:tsc"]);
  });
  it("pnpm dlx, yarn dlx, bunx, bun x", () => {
    for (const c of ["pnpm dlx lodash", "pnpm dlx --package=lodash some-bin", "pnpm --package=lodash dlx some-bin", "pnpm dlx -c 'echo x'", "pnpx lodash", "yarn dlx lodash", "yarn dlx -p lodash some-bin", "bunx lodash", "bun x lodash", "bunx --bun lodash"]) blocked(c);
    for (const c of ["pnpm dlx zod", "pnpm --package=zod dlx -c 'zod-cli x'", "yarn dlx zod", "bunx zod", "bun x zod", "pnpm exec some-bin", "yarn exec some-bin", "bun run build"]) allowed(c);
  });
  it("uvx, uv tool run, uv run --with, pipx run", () => {
    for (const c of [
      "uvx flask",
      "uvx flask@3.0",
      "uvx --from flask flask-cli",
      "uvx --with flask requests",
      "uvx --index https://evil.example requests",
      "uv tool run flask",
      "uv run --with flask pytest",
      "uv run --with=flask pytest",
      "uv run --with 'requests,flask' pytest",
      "uv run --with-requirements r.txt pytest",
      "uv run --with-editable ./x pytest",
      "uv run pip install flask",
      "pipx run flask",
      "pipx run --spec flask flask-cli",
    ]) blocked(c);
    for (const c of ["uvx requests", "uvx requests@2.32", "uvx --from requests req-cli", "uv run --with requests pytest", "uv run --with 'requests>=2,<3' pytest", "uv run pytest", "pipx run requests", "pipx list"]) allowed(c);
    expect(problems("uv run --with 'requests,flask' pytest")).toEqual(["pypi:flask"]);
  });
});

describe("Version 0.1.1: poetry, pipenv, conda", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  const problems = (cmd: string) => installProblems(cmd, policy.allowedDependencies);
  it("poetry add und poetry run", () => {
    for (const c of ["poetry add flask", "poetry add flask@^3", "poetry add 'flask>=3'", "poetry add --group dev flask", "poetry -C sub add flask", "poetry add git+https://x.example/r.git", "poetry add ./local", "poetry add --source private requests", "poetry self add flask", "poetry run pip install flask", "poetry add $PKG"]) blocked(c);
    for (const c of ["poetry add requests", "poetry add requests@^2", "poetry add -G dev 'requests[socks]>=2'", "poetry install", "poetry lock", "poetry run pytest"]) allowed(c);
  });
  it("pipenv install und pipenv run", () => {
    for (const c of ["pipenv install flask", "pipenv install --dev flask", "pipenv install -r requirements.txt", "pipenv install -e ./x", "pipenv install --index https://evil.example requests", "pipenv install --extra-pip-args='--index-url https://evil.example' requests", "pipenv run pip install flask"]) blocked(c);
    for (const c of ["pipenv install", "pipenv install requests", "pipenv install --dev requests", "pipenv sync", "pipenv run pytest"]) allowed(c);
  });
  it("conda ist ein eigenes Oekosystem ohne Allowlist: jedes Paket wird blockiert (fail closed)", () => {
    for (const c of ["conda install numpy", "conda install requests", "conda install -c conda-forge numpy", "conda install conda-forge::numpy", "conda create -n env python=3.12", "conda install --file spec.txt", "conda env create -f environment.yml", "conda env update", "mamba install numpy", "micromamba install -n x numpy", "conda run -n env pip install flask"]) blocked(c);
    for (const c of ["conda list", "conda info", "conda env list", "conda create -n empty", "conda run -n env pytest", "conda activate myenv"]) allowed(c);
    expect(problems("conda install requests")).toEqual(["conda:requests"]);
    expect(problems("conda install conda-forge::NumPy=1.26")).toEqual(["conda:numpy"]);
    expect(detailFor("dependency", "Dependencies not on the allowlist: conda:numpy, npm:lodash.")).toBe("Dependencies not on the allowlist: conda:numpy, npm:lodash.");
  });
});

describe("Version 0.1.1: Wrapper su -c, xargs, find -exec und weitere Shells", () => {
  const problems = (cmd: string) => installProblems(cmd, policy.allowedDependencies);
  it("su und runuser pruefen ihre Befehlszeichenkette", () => {
    for (const c of ["su -c 'npm i lodash'", "su - root -c 'npm i lodash'", "su -lc 'pip install flask'", "su --command='npm i lodash'", "su --command 'npm i lodash'", "su -s /bin/sh -c 'npm i lodash' nobody", "runuser -u x -- sh -c 'npm i lodash'"]) {
      expect(problems(c), c).not.toEqual([]);
      expect(run(c).allowed, c).toBe(false);
    }
    for (const c of ["su -c 'npm i zod'", "su - root", "su -c 'npm test'"]) expect(problems(c), c).toEqual([]);
  });
  it("xargs haengt unbekannte Woerter an: eine Installation dahinter ist fail closed", () => {
    for (const c of ["xargs npm install", "echo lodash | xargs npm i", "xargs -n1 npm i", "xargs -I{} npm i {}", "xargs -a list.txt pip install", "xargs pip", "xargs npx"]) {
      expect(problems(c), c).not.toEqual([]);
      expect(run(c).allowed, c).toBe(false);
    }
    for (const c of ["xargs -n1 npm test", "xargs rm", "find . -name '*.o' | xargs -0 rm", "xargs"]) expect(problems(c), c).toEqual([]);
  });
  it("find -exec, -execdir, -ok, -okdir", () => {
    for (const c of ["find . -exec npm i lodash \\;", "find . -execdir npm i {} +", "find . -ok pip install flask ';'", "find . -okdir npx lodash \\;"]) {
      expect(problems(c), c).not.toEqual([]);
      expect(run(c).allowed, c).toBe(false);
    }
    for (const c of ["find . -name x -exec npm test \\;", "find . -type f -exec grep -l npm {} +", "find . -name x"]) expect(problems(c), c).toEqual([]);
  });
  it("Shells csh, tcsh, fish, mksh, rbash und busybox/toybox als Wrapper", () => {
    for (const c of ["csh -c 'npm i lodash'", "tcsh -fc 'pip install flask'", "fish -c 'npm i lodash'", "fish --command='npm i lodash'", "fish --command 'npm i lodash'", "mksh -c 'npm i lodash'", "rbash -c 'npm i lodash'", "busybox sh -c 'npm i lodash'", "toybox sh -c 'npm i lodash'"]) {
      expect(problems(c), c).not.toEqual([]);
      expect(run(c).allowed, c).toBe(false);
    }
    for (const c of ["csh -c 'npm i zod'", "tcsh -c 'echo npm install lodash'", "fish -c 'npm test'"]) expect(run(c).allowed, c).toBe(true);
  });
});

describe("Review PR #128: M2-M4, N1", () => {
  const blocked = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(false);
  const allowed = (cmd: string) => expect(run(cmd).allowed, cmd).toBe(true);
  const problems = (cmd: string) => installProblems(cmd, policy.allowedDependencies);
  it("M2: --yes nach --no hebt --no auf (das letzte Flag gilt, wie in npm)", () => {
    for (const c of ["npx --no --yes lodash", "npx --no -y lodash", "npx --no-install --yes=true lodash", "npm exec --no --yes -- lodash"]) blocked(c);
    for (const c of ["npx --yes --no lodash", "npx -y --no-install lodash", "npm exec --yes --yes=false lodash"]) allowed(c);
  });
  it("M3: npm init <name>, npm create, pnpm/yarn/bun create pruefen create-<name>", () => {
    for (const c of ["npm init vite", "npm init vite@5 my-app", "npm create vite", "npm innit vite", "npm init @scope", "npm init @scope/app", "pnpm create vite", "yarn create react-app x", "bun create vite", "bun create user/repo", "npm init github:a/b", "npm init $X", "npm init --bogus vite"]) blocked(c);
    expect(problems("npm init vite")).toEqual(["npm:create-vite"]);
    expect(problems("npm init @scope")).toEqual(["npm:@scope/create"]);
    expect(problems("npm init @scope/app@1")).toEqual(["npm:@scope/create-app"]);
    expect(problems("yarn create react-app x")).toEqual(["npm:create-react-app"]);
    for (const c of ["npm init", "npm init -y", "npm init --yes", "pnpm init", "yarn init -y"]) allowed(c);
    const withCreate = { npm: ["create-vite"], pypi: [] };
    expect(installProblems("npm create vite my-app -- --template react", withCreate)).toEqual([]);
    expect(installProblems("pnpm create vite", withCreate)).toEqual([]);
  });
  it("M4: unbekannte Optionen in npx/exec/dlx/bunx/uv run/uvx/pipx run sind fail closed", () => {
    for (const c of ["npx --script-shell bash zod", "npx --unknown zod", "npm exec --bogus zod", "pnpm dlx --bogus zod", "yarn dlx --bogus zod", "bunx --bogus zod", "uv run --bogus x pytest", "uvx --strange requests", "uv tool run --strange requests", "pipx run --strange requests"]) blocked(c);
    expect(problems("npx --unknown zod")).toEqual(["npm:--unknown (unknown option)"]);
    expect(problems("uv run --bogus x pytest")).toEqual(["pypi:--bogus (unknown option)"]);
    for (const c of ["npx -y zod", "npx -yq zod", "npm exec --ignore-scripts zod", "npx --prefer-offline zod", "uv run --group dev pytest", "uv run --extra x --frozen pytest", "uv run --package p -q pytest", "uv run --only-group g --no-sync pytest", "uvx --python 3.12 requests", "uv run -m pytest", "pipx run --python python3 requests"]) allowed(c);
  });
  it("N1: runuser -u, env -S, flock, watch, chronic, unbuffer, fakeroot, strace, unshare, parallel, python -m pipx|uv|poetry|pipenv", () => {
    for (const c of [
      "runuser -u x -- npm i lodash", "runuser -u x npm i lodash", "env -S 'npm i lodash'", "env -S'npm i' lodash", "env --split-string='npm i lodash'",
      "flock /tmp/l npm i lodash", "flock -w 5 /tmp/l npm i lodash", "flock /tmp/l -c 'npm i lodash'", "watch -n 5 npm i lodash", "watch 'npm i lodash'", "watch -x npm i lodash",
      "chronic npm i lodash", "unbuffer npm i lodash", "fakeroot npm i lodash", "strace -o f npm i lodash", "ltrace -o f npm i lodash", "unshare -r npm i lodash",
      "parallel npm i ::: lodash", "parallel -j 2 pip install ::: flask",
      "python3 -m pipx run flask", "python3 -m pipx install flask", "python3 -m uv pip install flask", "python3 -m poetry add flask", "python -m pipenv install flask",
    ]) {
      expect(problems(c), c).not.toEqual([]);
      blocked(c);
    }
    for (const c of ["runuser -u x -- npm test", "env -S 'npm test'", "flock /tmp/l npm i zod", "watch -n 5 npm test", "chronic npm test", "parallel echo ::: a b", "python3 -m uv run pytest", "python3 -m pip install requests"]) {
      expect(problems(c), c).toEqual([]);
    }
  });
});

describe("Version 0.1.1: Installpruefung gilt auch in der Mensch-Session (inklusive conda-Sperre)", () => {
  it("blockiert auch mit humanSession", () => {
    for (const c of ["npm install lodash", "npx lodash", "conda install numpy"]) {
      expect(run(c, { projectDir: PROJECT, humanSession: true }).allowed, c).toBe(false);
    }
  });
});
