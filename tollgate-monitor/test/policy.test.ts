import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../", import.meta.url).pathname;
const SRC = join(ROOT, "src");
const NETWORK = /^(?:node:)?(net|http|https|http2|tls|dgram|dns|dns\/promises|cluster|inspector|worker_threads|vm|child_process)$/;

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (path.endsWith(".ts")) out.push(path);
  }
  return out;
}

function imports(text: string): string[] {
  return [...text.matchAll(/(?:from|import|require)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1] as string);
}

const strip = (text: string): string => text.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");

describe("no outgoing calls and no process control (static import test)", () => {
  it("only the server module imports the HTTP stack; no module opens a connection or fetches", () => {
    for (const file of files(SRC)) {
      const rel = relative(SRC, file);
      const text = readFileSync(file, "utf8");
      for (const spec of imports(text)) {
        if (!NETWORK.test(spec)) continue;
        const allowed = (rel === "http.ts" && (spec === "node:http" || spec === "node:net")) || (rel === "admin/acl.ts" && spec === "node:child_process") || (rel === "control/client.ts" && spec === "node:net");
        expect(allowed, `${rel} imports ${spec}`).toBe(true);
      }
      if (rel === "web/assets.ts") continue; // the page script runs in the browser and only calls its own origin (checked below)
      expect(strip(text), rel).not.toMatch(/\bfetch\s*\(|new\s+WebSocket|XMLHttpRequest|\.connect\s*\(|\.request\s*\(|createConnection|\bspawn\w*\s*\(|\beval\s*\(|new Function/);
      if (rel !== "admin/acl.ts") expect(strip(text), rel).not.toMatch(/\bexec(?:File)?(?:Sync)?\s*\(\s*["'`\/]/);
    }
  });

  // The control client belongs to the commercial admin package; the public package has no such file.
  it.skipIf(!existsSync(join(SRC, "control", "client.ts")))("the control client connects to a Unix socket path only: no host, no port, no TCP", () => {
    const text = strip(readFileSync(join(SRC, "control", "client.ts"), "utf8"));
    expect(text).toMatch(/connect\(\{ path \}\)/);
    expect(text).not.toMatch(/\bhost\b|\bport\b|createServer|listen\(/);
    expect(text).toContain('"/run/tollgate-control/control.sock"');
  });

  it.skipIf(!existsSync(join(SRC, "admin", "acl.ts")))("child_process is used only to run setfacl and getfacl, with an absolute program, no shell and an empty environment", () => {
    const text = readFileSync(join(SRC, "admin", "acl.ts"), "utf8");
    expect(text).toContain("shell: false");
    expect(text).toContain("env: {}");
    expect(text).toContain('SETFACL = "/usr/bin/setfacl"');
    expect(text).toContain('GETFACL = "/usr/bin/getfacl"');
    expect(text).not.toMatch(/execSync|spawn|shell: true/);
  });

  it("the page script only calls paths of its own origin", () => {
    const text = readFileSync(join(SRC, "web", "assets.ts"), "utf8");
    const urls = [...text.matchAll(/(?:fetch|api)\(\s*"([^"]*)"/g)].map((m) => m[1] as string);
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) expect(url.startsWith("/"), url).toBe(true);
    expect(text).not.toMatch(/https?:\/\/|\/\/[a-z0-9.-]+\.[a-z]{2,}/i);
  });

  it("the token never comes from, or goes to, the command line or the environment of a child", () => {
    for (const file of ["main.ts", "runtime.ts", "admin/main.ts"].filter((f) => existsSync(join(SRC, f)))) expect(strip(readFileSync(join(SRC, file), "utf8")), file).not.toMatch(/token(?!\s*file)/i);
    expect(readFileSync(join(SRC, "runtime.ts"), "utf8")).toContain("process.argv.slice(2)");
    const cli = strip(readFileSync(join(SRC, "cli.ts"), "utf8"));
    expect(cli).not.toMatch(/--token\b(?!-file)/);
    expect(cli).not.toMatch(/xdg-open|open\(/);
  });
});

describe("the plugin never starts the monitor", () => {
  const plugin = join(ROOT, "..", "guardrail-plugin");
  it.skipIf(!existsSync(plugin))("neither the hook code, the manifest nor the patches mention or start the monitor", () => {
    const targets = [...files(join(plugin, "src")), join(plugin, "hooks", "hooks.json")];
    const patches = join(ROOT, "..", "..", "org", "patches");
    if (existsSync(patches)) for (const n of readdirSync(patches)) if (n.endsWith("hooks.patch")) targets.push(join(patches, n));
    for (const file of targets) expect(readFileSync(file, "utf8"), relative(ROOT, file)).not.toMatch(/tollgate-monitor|monitor\s+serve/i);
  });
});

// Installation files of the commercial admin view; they are not part of the public package, so this block is skipped there.
describe.skipIf(!existsSync(join(ROOT, "templates")))("installation files (admin view)", () => {
  const sudoers = (): string => readFileSync(join(ROOT, "templates", "tollgate-monitor.sudoers"), "utf8");
  const rulesOf = (text: string): string[] => text.split("\n").filter((l) => l.trim() !== "" && !l.trim().startsWith("#"));

  it("the sudo rule allows exactly one program with exactly two fixed argument lists", () => {
    const rules = rulesOf(sudoers());
    // `timestamp_timeout=0` (the admin view can ask for locks) arrives through a separate review of the template, which is a
    // protected path; both states are accepted. `--print-token` (token on the terminal instead of the file) is the second list.
    const base = ["Cmnd_Alias TOLLGATE_MONITOR = /opt/tollgate/bin/tollgate-monitor serve --admin, /opt/tollgate/bin/tollgate-monitor serve --admin --print-token", "Defaults!TOLLGATE_MONITOR env_reset"];
    const last = "%tollgate-admins ALL=(tollgate-mon) CWD=/ TOLLGATE_MONITOR";
    expect([[...base, last], [...base, "Defaults!TOLLGATE_MONITOR timestamp_timeout=0", last]]).toContainEqual(rules);
    expect(rules.join("\n")).not.toMatch(/\*|env_keep|NOPASSWD|SETENV|ALL\s*$|NODE_OPTIONS|!env_reset|!authenticate/);
    expect(sudoers()).toContain("%tollgate-admins ALL=(tollgate-mon)");
  });

  it("is accepted by visudo (when installed)", () => {
    let available = true;
    try {
      execFileSync("visudo", ["-V"], { stdio: "ignore" });
    } catch {
      available = false;
    }
    if (!available) return;
    expect(() => execFileSync("visudo", ["-c", "-f", join(ROOT, "templates", "tollgate-monitor.sudoers")], { stdio: "pipe" })).not.toThrow();
  });

  it("the entry program has an absolute interpreter, ignores arguments and the environment", () => {
    const bin = readFileSync(join(ROOT, "bin", "tollgate-monitor"), "utf8");
    expect(bin.split("\n")[0]).toBe("#!/opt/tollgate/node/bin/node");
    expect(bin).not.toMatch(/\/usr\/bin\/env|process\.argv|process\.env/);
    expect(bin).toContain('import("/opt/tollgate/monitor/dist/admin/main.js")');
    expect(statSync(join(ROOT, "bin", "tollgate-monitor")).mode & 0o111).not.toBe(0);
  });

  it("the runtime directory template matches the intended permissions", () => {
    const t = readFileSync(join(ROOT, "templates", "tmpfiles-monitor.conf"), "utf8");
    expect(t).toMatch(/^d \/run\/tollgate-monitor 0711 tollgate-mon tollgate-mon -$/m);
  });

  const sysusers = join(ROOT, "..", "tollgate-enterprise", "systemd", "sysusers.d", "tollgate.conf");
  it.skipIf(!existsSync(sysusers))("the service account has the login shell nologin and reads only the spool group", () => {
    const text = readFileSync(sysusers, "utf8");
    expect(text).toMatch(/^u tollgate-mon\s+-\s+"[^"]*"\s+\/nonexistent\s+\/usr\/sbin\/nologin$/m);
    expect(text).toMatch(/^m tollgate-mon\s+tollgate-spool$/m);
    expect(text).toMatch(/^g tollgate-admins\s+-$/m);
    expect(text).not.toMatch(/^m tollgate-mon\s+tollgate-fwd/m);
  });
});
