import { normalizePypi, npmAliasTarget } from "./deps.js";
import { parseShell, type ShellWord } from "./shell.js";

/**
 * Dependency check for package-manager install commands in Bash (`npm install x`, `pnpm add x`,
 * `yarn add x`, `pip install x`). The manifest check only sees writes by the agent's own file tools;
 * the package manager writes package.json itself. Returns the list of problems (empty = allowed).
 * Installs without package arguments (`npm install`, `npm ci`, `yarn install`) read the manifest and
 * stay allowed; the manifest content is guarded by the write check.
 */

/** Wrapper commands and the flags that consume a value (the value is skipped when looking for the real command). */
const WRAPPERS: Record<string, { value: Set<string>; positional: number }> = {
  sudo: { value: new Set(["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user", "--group", "--host", "--prompt", "--close-from", "--chdir", "--chroot", "--role", "--type"]), positional: 0 },
  doas: { value: new Set(["-u", "-C"]), positional: 0 },
  env: { value: new Set(["-u", "-C", "--unset", "--chdir"]), positional: 0 },
  timeout: { value: new Set(["-s", "-k", "--signal", "--kill-after"]), positional: 1 },
  nice: { value: new Set(["-n", "--adjustment"]), positional: 0 },
  ionice: { value: new Set(["-c", "-n", "-p", "-P", "-u"]), positional: 0 },
  stdbuf: { value: new Set(["-i", "-o", "-e"]), positional: 0 },
  nohup: { value: new Set(), positional: 0 },
  command: { value: new Set(), positional: 0 },
  exec: { value: new Set(["-a"]), positional: 0 },
  time: { value: new Set(["-f", "-o", "--format", "--output"]), positional: 0 },
  setsid: { value: new Set(), positional: 0 },
  corepack: { value: new Set(), positional: 0 },
};
/** Shell keywords and grouping words that can precede a command in a simple command. */
const KEYWORDS = new Set(["{", "}", "(", ")", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "select", "function", "coproc"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ash", "ksh"]);
const NPM_TOOLS = new Set(["npm", "pnpm", "yarn", "bun"]);
const NPM_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add", "install-test", "it"]);
const NPM_VALUE_FLAGS = new Set(["--prefix", "--registry", "-C", "--cwd", "--workspace", "--tag", "--filter", "-F", "--userconfig", "--globalconfig", "--save-prefix", "--cache", "--loglevel", "--otp", "--dir", "--store-dir", "--cafile", "--ca"]);
/** `-w` takes a value for npm (--workspace) but is --workspace-root for pnpm, so it is only a value flag for npm. */
const NPM_ONLY_VALUE_FLAGS = new Set(["-w"]);
const UV_VALUE_FLAGS = new Set(["--directory", "--project", "--python", "-p", "--config-file", "--cache-dir", "--color", "--env-file", "--python-preference", "--python-fetch", "--allow-insecure-host", "--index-strategy", "--keyring-provider", "--native-tls-ca", "--link-mode", "--refresh-package", "--no-binary-package"]);
/** uv subcommands; a word that is none of them after the global options is treated as an unknown option value and skipped. */
const UV_SUBCOMMANDS = new Set(["run", "init", "add", "remove", "version", "sync", "lock", "export", "tree", "tool", "python", "pip", "venv", "build", "publish", "cache", "self", "help", "format", "audit"]);
const PIP_VALUE_FLAGS = new Set(["-c", "--constraint", "-t", "--target", "--prefix", "--root", "--python", "--platform", "--python-version", "--implementation", "--abi", "--cache-dir", "--log", "--proxy", "--retries", "--timeout", "--trusted-host", "--src", "--upgrade-strategy", "--only-binary", "--no-binary", "--progress-bar", "--root-user-action", "--report", "--exists-action", "--cert", "--client-cert", "--keyring-provider", "--use-feature", "--use-deprecated", "--config-settings", "-C", "--global-option", "--install-option", "--config-file", "-p"]);
/** pip flags that redirect or add package sources, or read package lists we cannot see. */
const PIP_UNVERIFIABLE = new Set(["-r", "--requirement", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--no-index"]);
/**
 * True if `token` is a flag that consumes the next word as its value. Handles bundled short flags
 * (`-Hu root`: the value letter must be last; `-uroot` carries its value inline).
 */
function takesNext(token: string, flags: ReadonlySet<string>): boolean {
  if (token.startsWith("--")) return flags.has(token);
  for (let k = 1; k < token.length; k++) {
    if (flags.has(`-${token[k]}`)) return k === token.length - 1;
  }
  return false;
}

/** Bundled short pip flags that contain -r, -e, -i or -f before any value letter (`-qr file`). */
function bundledUnverifiable(token: string): boolean {
  if (token.startsWith("--") || token.length < 2) return false;
  for (let k = 1; k < token.length; k++) {
    if (PIP_VALUE_FLAGS.has(`-${token[k]}`)) return false;
    if ("reif".includes(token[k] as string)) return true;
  }
  return false;
}
const MAX_DEPTH = 4;
const TOO_DEEP = "command nesting too deep to verify";

export interface InstallPolicy {
  npm: readonly string[];
  pypi: readonly string[];
}

function cleanWord(w: ShellWord): string | null {
  return w.expands || w.splittable || w.executes ? null : w.value;
}

/** File-descriptor prefix of a redirection (`2>`, `10>&1`, bash `{fd}>`); same form as in the write check. */
const FD_PREFIX = /^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})$/;

/**
 * The words of a simple command without its redirections (`2>&1`, `>file`, `>>file`, `<file`, `2>/dev/null`, `&>file`,
 * `N>&M`, here-documents): the operator, its target and a descriptor prefix are removed, as the shell removes them before
 * it starts the program (also in front of the command name: `2>/dev/null npm i x`). A descriptor counts only like in bash:
 * unquoted and directly touching the operator; `2 >x` and `"2">x` pass "2" as an argument and keep it. Commands inside a
 * target (`>$(...)`, `>(...)`) are separate simple commands of the parse and are checked on their own.
 */
function withoutRedirections(words: ShellWord[]): ShellWord[] {
  const out: ShellWord[] = [];
  for (let k = 0; k < words.length; k++) {
    const w = words[k] as ShellWord;
    if (!w.redirect) {
      out.push(w);
      continue;
    }
    const prev = out.at(-1);
    if (prev !== undefined && !prev.quoted && prev.end === w.start && /^[<>]/.test(w.value) && FD_PREFIX.test(prev.value)) out.pop();
    const target = words[k + 1];
    if (target !== undefined && !target.redirect) k++;
  }
  return out;
}

const NON_REGISTRY = /^(git(\+[a-z]+)?:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:|workspace:|\.{0,2}\/|~|\/)/i;

/** Registry package names an npm spec installs (spec name plus alias target), or null if it installs from outside the registry. */
function npmSpecNames(spec: string, depth = 0): string[] | null {
  if (depth > 3) return null;
  const alias = npmAliasTarget(spec);
  if (alias !== null) return alias === "" ? null : [alias];
  if (NON_REGISTRY.test(spec) || /\.(tgz|tar\.gz|tar)$/i.test(spec)) return null;
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  const name = at === -1 ? spec : spec.slice(0, at);
  if (!/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name)) return null;
  const range = at === -1 ? "" : spec.slice(at + 1);
  if (range === "") return [name.toLowerCase()];
  if (/^npm:/i.test(range)) {
    const target = npmSpecNames(range, depth + 1);
    return target === null ? null : [name.toLowerCase(), ...target];
  }
  if (NON_REGISTRY.test(range) || range.includes("/")) return null;
  return [name.toLowerCase()];
}

function pipSpecName(spec: string): string | null {
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(.*)$/.exec(spec);
  if (!m) return null;
  const rest = m[3] ?? "";
  if (/[@/\\]|:\/\//.test(rest)) return null;
  return normalizePypi(m[1] as string);
}

const REGISTRY_FLAG = /^--(?:[^=]*:)?registry(?:=|$)/;

function npmProblems(exe: string, args: ShellWord[], allowed: Set<string>): string[] {
  const valueFlags = exe === "npm" ? new Set([...NPM_VALUE_FLAGS, ...NPM_ONLY_VALUE_FLAGS]) : NPM_VALUE_FLAGS;
  const problems: string[] = [];
  let sub: string | null = null;
  let subAt = -1;
  for (let i = 0; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return ["unresolved argument in package-manager command"];
    if (v.startsWith("-")) {
      if (REGISTRY_FLAG.test(v)) problems.push(`npm:${v} (unverifiable source)`);
      if (takesNext(v, valueFlags)) i++;
      continue;
    }
    const lower = v.toLowerCase();
    if (exe === "yarn" && lower === "global") continue;
    if (exe === "yarn" && lower === "workspace") {
      i++;
      continue;
    }
    sub = lower;
    subAt = i;
    break;
  }
  if (sub === null || !NPM_INSTALL.has(sub)) return [];
  for (let j = subAt + 1; j < args.length; j++) {
    const v = cleanWord(args[j] as ShellWord);
    if (v === null) {
      problems.push("unresolved package argument");
      continue;
    }
    if (v.startsWith("-")) {
      if (REGISTRY_FLAG.test(v)) problems.push(`npm:${v} (unverifiable source)`);
      if (takesNext(v, valueFlags)) {
        if (REGISTRY_FLAG.test(v)) problems.push(`npm:${v} (unverifiable source)`);
        j++;
      }
      continue;
    }
    const names = npmSpecNames(v);
    if (names === null) problems.push(`npm:${v} (unverifiable source)`);
    else for (const name of names) if (!allowed.has(name)) problems.push(`npm:${name}`);
  }
  return [...new Set(problems)];
}

/** pip-style install: global options may precede the subcommand. `forceInstall` is for `uv add`. */
function pipProblems(args: ShellWord[], allowed: Set<string>, forceInstall = false): string[] {
  const problems: string[] = [];
  let sub: string | null = forceInstall ? "install" : null;
  for (let j = 0; j < args.length; j++) {
    const v = cleanWord(args[j] as ShellWord);
    if (v === null) {
      problems.push("unresolved package argument");
      continue;
    }
    if (v.startsWith("-")) {
      const flag = v.split("=", 1)[0] as string;
      if (PIP_UNVERIFIABLE.has(flag) || /^-[reif]./.test(v) || bundledUnverifiable(v)) {
        problems.push(`pypi:${v} (unverifiable source)`);
        if (!v.includes("=") && (PIP_UNVERIFIABLE.has(v) || (!v.startsWith("--") && takesNext(v, PIP_UNVERIFIABLE)))) j++;
      } else if (takesNext(v, PIP_VALUE_FLAGS)) j++;
      continue;
    }
    if (sub === null) {
      sub = v.toLowerCase();
      continue;
    }
    if (sub !== "install") continue;
    const name = pipSpecName(v);
    if (name === null) problems.push(`pypi:${v} (unverifiable source)`);
    else if (!allowed.has(name)) problems.push(`pypi:${name}`);
  }
  return sub === "install" ? [...new Set(problems)] : [];
}

/** Index of the real command after env assignments, keywords and wrappers (with their flags), or -1. */
function commandStart(words: ShellWord[]): number {
  let i = 0;
  while (i < words.length) {
    const w = words[i] as ShellWord;
    if (!w.quoted && KEYWORDS.has(w.value)) {
      i++;
      continue;
    }
    const v = cleanWord(w);
    if (v === null) return -1;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(v)) {
      i++;
      continue;
    }
    const wrapper = WRAPPERS[(v.split("/").pop() as string).toLowerCase()];
    if (wrapper === undefined) return i;
    i++;
    let positional = wrapper.positional;
    while (i < words.length) {
      const a = cleanWord(words[i] as ShellWord);
      if (a === null) return -1;
      if (a === "--") {
        i++;
        break;
      }
      if (a.startsWith("-")) i += takesNext(a, wrapper.value) ? 2 : 1;
      else if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) i++;
      else if (positional > 0) {
        positional--;
        i++;
      } else break;
    }
  }
  return -1;
}

function commandProblems(all: ShellWord[], allowed: InstallPolicy, depth: number): string[] {
  const words = withoutRedirections(all);
  const at = commandStart(words);
  if (at === -1) return [];
  const head = cleanWord(words[at] as ShellWord);
  if (head === null) return [];
  const exe = (head.split("/").pop() as string).toLowerCase().replace(/\.(exe|cmd)$/, "");
  const args = words.slice(at + 1);
  if (SHELLS.has(exe)) {
    const c = args.findIndex((w) => /^-[a-z]*c[a-z]*$/.test(w.value));
    if (c === -1) return [];
    let k = c + 1;
    while (args[k]?.value === "--") k++;
    const script = args[k];
    if (script === undefined) return [];
    if (depth >= MAX_DEPTH) return [TOO_DEEP];
    try {
      return installProblems(script.value, allowed, depth + 1);
    } catch {
      return ["nested command cannot be parsed"];
    }
  }
  if (exe === "env" || exe === "xargs") return [];
  const npm = new Set(allowed.npm.map((n) => n.toLowerCase()));
  const pypi = new Set(allowed.pypi.map(normalizePypi));
  if (NPM_TOOLS.has(exe)) return npmProblems(exe, args, npm);
  if (exe === "pip" || /^pip\d*(\.\d+)?$/.test(exe) || exe === "pipx") return pipProblems(args, pypi);
  if (/^python[\d.]*$/.test(exe) || exe === "py") {
    const m = args.findIndex((w) => /^-m/.test(w.value));
    if (m === -1) return [];
    const inline = (args[m] as ShellWord).value.slice(2);
    const mod = inline !== "" ? inline : args[m + 1]?.value;
    const rest = args.slice(inline !== "" ? m + 1 : m + 2);
    return mod === "pip" || mod === "pipx" ? pipProblems(rest, pypi) : [];
  }
  if (exe === "uv" || exe === "uvx") {
    let sub = 0;
    for (; sub < args.length; ) {
      const w = (args[sub] as ShellWord).value;
      if (w.startsWith("-")) sub += takesNext(w, UV_VALUE_FLAGS) ? 2 : 1;
      else if (UV_SUBCOMMANDS.has(w)) break;
      else sub += 1; // value of an unknown global option: keep looking for the subcommand
    }
    const first = args[sub]?.value;
    if (first === "pip") return pipProblems(args.slice(sub + 1), pypi);
    if (first === "add") return pipProblems(args.slice(sub + 1), pypi, true);
    if (first === "tool" && args[sub + 1]?.value === "install") return pipProblems(args.slice(sub + 1), pypi);
  }
  return [];
}

/** Dependency problems in install commands of a Bash command line; empty when none. */
export function installProblems(command: string, allowed: InstallPolicy, depth = 0): string[] {
  const problems = new Set<string>();
  for (const cmd of parseShell(command).commands) {
    for (const p of commandProblems(cmd.words, allowed, depth)) problems.add(p);
  }
  return [...problems];
}
