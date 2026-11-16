import { normalizePypi, npmAliasTarget } from "./deps.js";
import { parseShell, type ShellWord } from "./shell.js";

/**
 * Dependency check for package-manager install commands in Bash (`npm install x`, `pnpm add x`,
 * `yarn add x`, `pip install x`). The manifest check only sees writes by the agent's own file tools;
 * the package manager writes package.json itself. Returns the list of problems (empty = allowed).
 * Installs without package arguments (`npm install`, `npm ci`, `yarn install`) read the manifest and
 * stay allowed; the manifest content is guarded by the write check.
 * Commands that fetch and run a package without changing a manifest (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`,
 * `uvx`, `uv tool run`, `uv run --with`, `pipx run`) and the installers of poetry, pipenv and conda are checked the same way.
 * conda packages are a separate ecosystem without an allowlist: any conda package argument is blocked (fail closed).
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
  busybox: { value: new Set(), positional: 0 },
  toybox: { value: new Set(), positional: 0 },
  chronic: { value: new Set(), positional: 0 },
  unbuffer: { value: new Set(), positional: 0 },
  fakeroot: { value: new Set(["-l", "-s", "-i", "-b", "--lib", "--faked"]), positional: 0 },
  strace: { value: new Set(["-a", "-b", "-e", "-E", "-I", "-o", "-O", "-p", "-P", "-s", "-S", "-u", "-U", "-X", "-A", "-n", "--output", "--attach", "--trace", "--signal", "--user"]), positional: 0 },
  ltrace: { value: new Set(["-a", "-b", "-e", "-E", "-I", "-o", "-O", "-p", "-P", "-s", "-S", "-u", "-U", "-X", "-A", "-n", "--output", "--attach", "--trace", "--signal", "--user"]), positional: 0 },
  unshare: { value: new Set(["-S", "-G", "-R", "-w", "--setuid", "--setgid", "--root", "--wd", "--propagation", "--map-user", "--map-group", "--map-users", "--map-groups", "--setgroups"]), positional: 0 },
};
/** Shell keywords and grouping words that can precede a command in a simple command. */
const KEYWORDS = new Set(["{", "}", "(", ")", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "select", "function", "coproc"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "rbash", "fish", "csh", "tcsh"]);
const NPM_TOOLS = new Set(["npm", "pnpm", "yarn", "bun"]);
const NPM_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add", "install-test", "it"]);
const NPM_VALUE_FLAGS = new Set(["--prefix", "--registry", "-C", "--cwd", "--workspace", "--tag", "--filter", "-F", "--userconfig", "--globalconfig", "--save-prefix", "--cache", "--loglevel", "--otp", "--dir", "--store-dir", "--cafile", "--ca"]);
/** `-w` takes a value for npm (--workspace) but is --workspace-root for pnpm, so it is only a value flag for npm. */
const NPM_ONLY_VALUE_FLAGS = new Set(["-w"]);
const UV_VALUE_FLAGS = new Set(["--directory", "--project", "--python", "-p", "--config-file", "--cache-dir", "--color", "--env-file", "--python-preference", "--python-fetch", "--allow-insecure-host", "--index-strategy", "--keyring-provider", "--native-tls-ca", "--link-mode", "--refresh-package", "--no-binary-package",
  "--group", "--only-group", "--no-group", "--extra", "--no-extra", "--package", "--exclude-newer", "--resolution", "--prerelease", "--fork-strategy",
  "--config-setting", "-C", "--reinstall-package", "--upgrade-package", "-P", "--no-build-package", "--python-platform", "--backend"]);
/** Boolean options of uv run / uvx / uv tool run / pipx run; any other option is unknown there and fails closed. */
const PY_RUN_BOOL_FLAGS = new Set([
  "--isolated", "--no-project", "--frozen", "--locked", "--no-sync", "--all-extras", "--all-groups", "--no-dev", "--dev", "--only-dev",
  "--no-default-groups", "--offline", "-q", "--quiet", "-v", "--verbose", "--no-cache", "-n", "--native-tls", "--reinstall", "--upgrade", "-U",
  "--refresh", "--no-config", "--no-progress", "--script", "-s", "--module", "-m", "--active", "--no-active", "--no-editable", "--exact",
  "--inexact", "--compile-bytecode", "--no-env-file", "--managed-python", "--no-managed-python", "--no-python-downloads", "--no-build",
  "--no-binary", "--no-build-isolation", "--no-sources", "--preview", "--no-preview", "--system-site-packages", "--path", "--gui-script",
  "--fetch-missing-python", "-h", "--help",
]);
/** Boolean options of npx / npm exec / dlx / bunx / create; any other option (not a value flag) is unknown there and fails closed. */
const EXEC_BOOL_FLAGS = new Set([
  "-y", "--yes", "--no", "--no-install", "-q", "--quiet", "--silent", "-s", "--ignore-scripts", "--prefer-offline", "--prefer-online",
  "--offline", "--workspaces", "--include-workspace-root", "--verbose", "-d", "--bun", "--shell-mode", "-f", "--force", "-h", "--help",
]);
/** uv subcommands; a word that is none of them after the global options is treated as an unknown option value and skipped. */
const UV_SUBCOMMANDS = new Set(["run", "init", "add", "remove", "version", "sync", "lock", "export", "tree", "tool", "python", "pip", "venv", "build", "publish", "cache", "self", "help", "format", "audit"]);
const PIP_VALUE_FLAGS = new Set(["-c", "--constraint", "-t", "--target", "--prefix", "--root", "--python", "--platform", "--python-version", "--implementation", "--abi", "--cache-dir", "--log", "--proxy", "--retries", "--timeout", "--trusted-host", "--src", "--upgrade-strategy", "--only-binary", "--no-binary", "--progress-bar", "--root-user-action", "--report", "--exists-action", "--cert", "--client-cert", "--keyring-provider", "--use-feature", "--use-deprecated", "--config-settings", "-C", "--global-option", "--install-option", "--config-file", "-p"]);
/** pip flags that redirect or add package sources, or read package lists we cannot see. */
const PIP_UNVERIFIABLE = new Set(["-r", "--requirement", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--no-index"]);
/** xargs options that consume the next word (GNU; `-e`, `-i`, `-l` take their value only attached). */
const XARGS_VALUE_FLAGS = new Set(["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"]);
const FIND_EXEC = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
/** Options of uvx / uv tool run / uv run / pipx run that name an extra package (checked against the allowlist). */
const PY_RUN_PACKAGE_FLAGS = new Set(["--from", "--with", "--spec"]);
/** Options of those commands that add a package source or read a package list we cannot see (fail closed). */
const PY_RUN_UNVERIFIABLE = new Set(["--with-requirements", "--with-editable", "--index", "--default-index", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--pip-args"]);
/** poetry options that consume the next word. */
const POETRY_VALUE_FLAGS = new Set(["-G", "--group", "-E", "--extras", "--python", "--platform", "--markers", "-C", "--directory", "-P", "--project"]);
/** pipenv options that consume the next word; the source and file options are unverifiable. */
const PIPENV_VALUE_FLAGS = new Set(["--python", "--categories", "--site-packages"]);
const PIPENV_UNVERIFIABLE = new Set(["-r", "--requirements", "-e", "--editable", "-i", "--index", "--extra-index-url", "--extra-pip-args"]);
/** conda / mamba / micromamba options that consume the next word. */
const CONDA_VALUE_FLAGS = new Set(["-n", "--name", "-p", "--prefix", "-c", "--channel", "--cwd", "--repodata-fn", "--experimental-solver", "--solver", "-r", "--root-prefix"]);
const CONDA_TOOLS = new Set(["conda", "mamba", "micromamba"]);
const UNRESOLVED_COMMAND = "unresolved argument in package-manager command";
/** Stands for the words xargs appends from its input: unknown, so an install that receives them fails closed. */
const XARGS_INPUT: ShellWord = { value: "(xargs input)", start: -1, end: -1, quoted: false, executes: false, splittable: true, expands: true, redirect: false };
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

/** PyPI name of a requirement or of a `name@version` spec (uvx, poetry), or null if it installs from outside the index. */
function pySpecName(spec: string): string | null {
  const at = /^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)@([^@/\\:\s]*)$/.exec(spec);
  return pipSpecName(at === null ? spec : (at[1] as string));
}

/** Splits `--flag=value` into flag and value (value null without `=`). */
function splitFlag(token: string): [string, string | null] {
  const eq = token.startsWith("--") ? token.indexOf("=") : -1;
  return eq === -1 ? [token, null] : [token.slice(0, eq), token.slice(eq + 1)];
}

/** True if every part of the option is known: a long option (`--x`, `--x=v`) or each letter of bundled short options. */
function knownFlag(token: string, bool: ReadonlySet<string>, value: ReadonlySet<string>): boolean {
  if (token.startsWith("--")) {
    const [flag] = splitFlag(token);
    return bool.has(flag) || value.has(flag);
  }
  for (let k = 1; k < token.length; k++) {
    const letter = `-${token[k]}`;
    if (value.has(letter)) return true; // the rest of the word is its attached value
    if (!bool.has(letter)) return false;
  }
  return token.length > 1;
}

const REGISTRY_FLAG = /^--(?:[^=]*:)?registry(?:=|$)/;

/** Subcommands that fetch and run a package (npx semantics, pnpm/yarn dlx, bun x). */
const EXEC_SUBCOMMANDS: Readonly<Record<string, Readonly<Record<string, ExecKind>>>> = {
  npm: { exec: "npx", x: "npx" },
  pnpm: { dlx: "dlx" },
  yarn: { dlx: "dlx" },
  bun: { x: "bunx" },
};
type ExecKind = "npx" | "dlx" | "bunx";
/** Subcommands that run an initializer package `create-<name>` (`npm init <name>` and its aliases, `pnpm|yarn|bun create`). */
const CREATE_SUBCOMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  npm: new Set(["init", "create", "innit"]),
  pnpm: new Set(["create"]),
  yarn: new Set(["create"]),
  bun: new Set(["create", "c"]),
};

/** Package an initializer name stands for (npm rules: `x` → `create-x`, `@s` → `@s/create`, `@s/x` → `@s/create-x`, version kept). */
function createPackage(spec: string): string {
  if (spec.startsWith("@")) {
    const slash = spec.indexOf("/");
    if (slash === -1) {
      const at = spec.indexOf("@", 1);
      return at === -1 ? `${spec}/create` : `${spec.slice(0, at)}/create${spec.slice(at)}`;
    }
    return `${spec.slice(0, slash)}/create-${spec.slice(slash + 1)}`;
  }
  // Sources outside the registry (`github:x/y`, `x/y`, paths, URLs) stay as they are: the spec check marks them unverifiable.
  return NON_REGISTRY.test(spec) || spec.includes("/") || spec.includes(":") ? spec : `create-${spec}`;
}

/**
 * `npm init <name>` / `npm create <name>`, `pnpm|yarn|bun create <name>`: download and run the initializer package
 * `create-<name>`, which is checked against the allowlist like an install argument (fail closed). Without a name
 * (`npm init`, `npm init -y`) only package.json is written: allowed.
 */
function createProblems(args: ShellWord[], allowed: Set<string>, valueFlags: ReadonlySet<string>): string[] {
  const problems: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return ["unresolved package argument"];
    if (v === "--") continue;
    if (v.startsWith("-")) {
      if (REGISTRY_FLAG.test(v)) problems.push(`npm:${v} (unverifiable source)`);
      else if (takesNext(v, valueFlags)) i++;
      else if (!knownFlag(v, EXEC_BOOL_FLAGS, new Set([...valueFlags, "--scope", "--init-module"]))) problems.push(`npm:${v} (unknown option)`);
      continue;
    }
    const names = npmSpecNames(createPackage(v));
    if (names === null) problems.push(`npm:${v} (unverifiable source)`);
    else for (const name of names) if (!allowed.has(name)) problems.push(`npm:${name}`);
    break; // later words are arguments of the initializer
  }
  return [...new Set(problems)];
}

/**
 * `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`: the packages named with `-p/--package`, otherwise the command
 * itself, are fetched from the registry when they are not installed, so they are checked like install arguments. npx and
 * npm exec with `--no` (`--no-install`, `--yes=false`) never fetch and run only installed binaries: allowed. A command
 * string (`npx -c '...'`) is checked as a nested command line; pnpm's shell mode without `--package` fails closed.
 */
function execProblems(kind: ExecKind, args: ShellWord[], allowed: Set<string>, valueFlags: ReadonlySet<string>, policy: InstallPolicy, depth: number): string[] {
  const problems: string[] = [];
  const packages: (ShellWord | string)[] = [];
  let call: ShellWord | string | null = null;
  let shellMode = false;
  let noInstall = false;
  let i = 0;
  for (; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
    if (v === "--") {
      i++;
      break;
    }
    if (!v.startsWith("-") || v === "-") break;
    const [flag, inline] = splitFlag(v);
    if (REGISTRY_FLAG.test(v)) {
      problems.push(`npm:${v} (unverifiable source)`);
      if (inline === null) i++;
    } else if (flag === "-p" || flag === "--package") {
      const value = inline ?? args[++i];
      if (value !== undefined) packages.push(value);
    } else if (kind === "npx" && (flag === "-c" || flag === "--call")) {
      call = inline ?? args[++i] ?? null;
    } else if (kind === "dlx" && (flag === "-c" || flag === "--shell-mode")) {
      shellMode = true;
    } else if (kind === "npx" && (v === "--no" || v === "--no-install" || v === "--yes=false")) {
      noInstall = true;
    } else if (kind === "npx" && (v === "-y" || v === "--yes" || v === "--yes=true")) {
      noInstall = false; // the last of --no/--yes wins, as in npm
    } else if (takesNext(v, valueFlags) || (kind === "dlx" && flag === "--allow-build" && inline === null)) {
      i++;
    } else if (!knownFlag(v, EXEC_BOOL_FLAGS, new Set([...valueFlags, "--allow-build", "--call", "--package"]))) {
      // An unknown option may take the next word as its value; then the command would be a different word (fail closed).
      problems.push(`npm:${v} (unknown option)`);
    }
  }
  const check = (word: ShellWord | string): void => {
    const v = typeof word === "string" ? word : cleanWord(word);
    if (v === null) {
      problems.push("unresolved package argument");
      return;
    }
    const names = npmSpecNames(v);
    if (names === null) problems.push(`npm:${v} (unverifiable source)`);
    else for (const name of names) if (!allowed.has(name)) problems.push(`npm:${name}`);
  };
  for (const p of packages) check(p);
  const command = args[i];
  if (call !== null) {
    const script = typeof call === "string" ? call : cleanWord(call);
    problems.push(...(script === null ? ["unresolved package argument"] : nested(script, policy, depth)));
  } else if (shellMode && command !== undefined) {
    if (packages.length === 0) problems.push("npm:(shell-mode command without --package) (unverifiable source)");
    const script = cleanWord(command);
    problems.push(...(script === null ? ["unresolved package argument"] : nested(script, policy, depth)));
  } else if (command !== undefined && packages.length === 0 && !noInstall) {
    check(command);
  }
  return [...new Set(problems)];
}

/** Problems of a nested command line (`bash -c`, `su -c`, `npx -c`), fail closed beyond the nesting limit or on a parse error. */
function nested(script: string, policy: InstallPolicy, depth: number): string[] {
  if (depth >= MAX_DEPTH) return [TOO_DEEP];
  try {
    return installProblems(script, policy, depth + 1);
  } catch {
    return ["nested command cannot be parsed"];
  }
}

/**
 * Python run commands that fetch packages: `uvx` / `uv tool run` / `pipx run` (mode "tool": the packages of
 * `--from`/`--spec`/`--with`, otherwise the command itself) and `uv run` (mode "run": only the `--with` packages; the
 * command runs in the project environment and is checked as a command of its own).
 */
function pyRunProblems(mode: "tool" | "run", args: ShellWord[], pypi: Set<string>, policy: InstallPolicy, depth: number): string[] {
  const problems: string[] = [];
  let named = false;
  let i = 0;
  const checkSpec = (spec: string): void => {
    const name = pySpecName(spec);
    if (name === null) problems.push(`pypi:${spec} (unverifiable source)`);
    else if (!pypi.has(name)) problems.push(`pypi:${name}`);
  };
  for (; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
    if (v === "--") {
      i++;
      break;
    }
    if (!v.startsWith("-") || v === "-") break;
    const [flag, inline] = splitFlag(v);
    if (PY_RUN_PACKAGE_FLAGS.has(flag)) {
      named = true;
      const word = inline ?? (args[i + 1] === undefined ? null : cleanWord(args[++i] as ShellWord));
      if (word === null) {
        problems.push("unresolved package argument");
        continue;
      }
      // `--with a,b`: several requirements; a part starting with a comparison continues the previous one (`x>=1,<2`).
      for (const part of word.split(",")) if (part !== "" && !/^[<>=!~]/.test(part)) checkSpec(part);
    } else if (PY_RUN_UNVERIFIABLE.has(flag)) {
      problems.push(`pypi:${v} (unverifiable source)`);
      if (inline === null) i++;
    } else if (flag === "--no-index") {
      problems.push(`pypi:${v} (unverifiable source)`);
    } else if (takesNext(v, UV_VALUE_FLAGS)) {
      i++;
    } else if (!knownFlag(v, PY_RUN_BOOL_FLAGS, UV_VALUE_FLAGS)) {
      // An unknown option may take the next word as its value; then the command would be a different word (fail closed).
      problems.push(`pypi:${v} (unknown option)`);
    }
  }
  const command = args[i];
  if (mode === "tool") {
    if (command !== undefined && !named) {
      const v = cleanWord(command);
      if (v === null) problems.push("unresolved package argument");
      else checkSpec(v);
    }
  } else if (command !== undefined) {
    problems.push(...commandProblems(args.slice(i), policy, depth));
  }
  return [...new Set(problems)];
}

/** `poetry add` (and `poetry self add`) installs packages; `poetry run` runs a command. */
function poetryProblems(args: ShellWord[], pypi: Set<string>, policy: InstallPolicy, depth: number): string[] {
  let i = 0;
  for (; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
    if (!v.startsWith("-")) break;
    if (takesNext(v, POETRY_VALUE_FLAGS)) i++;
  }
  let sub = args[i] === undefined ? null : cleanWord(args[i] as ShellWord);
  if (sub === "self") sub = args[++i] === undefined ? null : cleanWord(args[i] as ShellWord);
  if (sub === "run") return commandProblems(args.slice(i + 1), policy, depth);
  if (sub !== "add") return [];
  const problems: string[] = [];
  for (let j = i + 1; j < args.length; j++) {
    const v = cleanWord(args[j] as ShellWord);
    if (v === null) {
      problems.push("unresolved package argument");
      continue;
    }
    if (v.startsWith("-")) {
      const [flag, inline] = splitFlag(v);
      if (flag === "--source") {
        problems.push(`pypi:${v} (unverifiable source)`);
        if (inline === null) j++;
      } else if (takesNext(v, POETRY_VALUE_FLAGS)) j++;
      continue;
    }
    const name = pySpecName(v);
    if (name === null) problems.push(`pypi:${v} (unverifiable source)`);
    else if (!pypi.has(name)) problems.push(`pypi:${name}`);
  }
  return [...new Set(problems)];
}

/** `pipenv install <pkg>` installs packages (without one it reads the Pipfile and stays allowed); `pipenv run` runs a command. */
function pipenvProblems(args: ShellWord[], pypi: Set<string>, policy: InstallPolicy, depth: number): string[] {
  let i = 0;
  for (; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
    if (!v.startsWith("-")) break;
    if (takesNext(v, PIPENV_VALUE_FLAGS)) i++;
  }
  const sub = args[i] === undefined ? null : cleanWord(args[i] as ShellWord);
  if (sub === "run") return commandProblems(args.slice(i + 1), policy, depth);
  if (sub !== "install") return [];
  const problems: string[] = [];
  for (let j = i + 1; j < args.length; j++) {
    const v = cleanWord(args[j] as ShellWord);
    if (v === null) {
      problems.push("unresolved package argument");
      continue;
    }
    if (v.startsWith("-")) {
      const [flag, inline] = splitFlag(v);
      if (PIPENV_UNVERIFIABLE.has(flag)) {
        problems.push(`pypi:${v} (unverifiable source)`);
        if (inline === null) j++;
      } else if (takesNext(v, PIPENV_VALUE_FLAGS)) j++;
      continue;
    }
    const name = pipSpecName(v);
    if (name === null) problems.push(`pypi:${v} (unverifiable source)`);
    else if (!pypi.has(name)) problems.push(`pypi:${name}`);
  }
  return [...new Set(problems)];
}

/**
 * conda, mamba, micromamba: conda packages come from conda channels, not from PyPI, and the allowlist has no conda
 * ecosystem. `install`/`create` with a package argument or `--file`, and `env create`/`env update` (environment file)
 * are therefore blocked (fail closed). `run` runs a command, checked on its own.
 */
function condaProblems(args: ShellWord[], policy: InstallPolicy, depth: number): string[] {
  let i = 0;
  for (; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
    if (!v.startsWith("-")) break;
    if (takesNext(v, CONDA_VALUE_FLAGS)) i++;
  }
  const sub = args[i] === undefined ? null : cleanWord(args[i] as ShellWord);
  const rest = args.slice(i + 1);
  if (sub === "env") {
    const action = rest[0] === undefined ? null : cleanWord(rest[0]);
    return action === "create" || action === "update" ? ["conda:environment file (unverifiable source)"] : [];
  }
  if (sub === "run") {
    let k = 0;
    for (; k < rest.length; k++) {
      const v = cleanWord(rest[k] as ShellWord);
      if (v === null) return [UNRESOLVED_COMMAND];
      if (!v.startsWith("-")) break;
      if (takesNext(v, CONDA_VALUE_FLAGS)) k++;
    }
    return commandProblems(rest.slice(k), policy, depth);
  }
  if (sub !== "install" && sub !== "create") return [];
  const problems: string[] = [];
  for (let j = 0; j < rest.length; j++) {
    const v = cleanWord(rest[j] as ShellWord);
    if (v === null) {
      problems.push("unresolved package argument");
      continue;
    }
    if (v.startsWith("-")) {
      const [flag, inline] = splitFlag(v);
      if (flag === "--file" || flag === "--clone") {
        problems.push(`conda:${v} (unverifiable source)`);
        if (inline === null) j++;
      } else if (takesNext(v, CONDA_VALUE_FLAGS)) j++;
      continue;
    }
    const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(v.includes("::") ? v.slice(v.lastIndexOf("::") + 2) : v);
    problems.push(name === null ? `conda:${v} (unverifiable source)` : `conda:${(name[1] as string).toLowerCase()}`);
  }
  return [...new Set(problems)];
}

function npmProblems(exe: string, args: ShellWord[], allowed: Set<string>, policy: InstallPolicy, depth: number): string[] {
  const valueFlags = exe === "npm" ? new Set([...NPM_VALUE_FLAGS, ...NPM_ONLY_VALUE_FLAGS]) : NPM_VALUE_FLAGS;
  const problems: string[] = [];
  let sub: string | null = null;
  let subAt = -1;
  for (let i = 0; i < args.length; i++) {
    const v = cleanWord(args[i] as ShellWord);
    if (v === null) return [UNRESOLVED_COMMAND];
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
  if (sub !== null && CREATE_SUBCOMMANDS[exe]?.has(sub) === true) return [...new Set([...problems, ...createProblems(args.slice(subAt + 1), allowed, valueFlags)])];
  const exec = sub === null ? undefined : EXEC_SUBCOMMANDS[exe]?.[sub];
  if (exec !== undefined) return [...new Set([...problems, ...execProblems(exec, [...args.slice(0, subAt), ...args.slice(subAt + 1)], allowed, valueFlags, policy, depth)])];
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
      // Before the subcommand an unknown word may itself be `install` (`xargs pip`, `pip $SUB flask`): fail closed.
      if (sub === null) return [UNRESOLVED_COMMAND];
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

/**
 * Index of the real command after env assignments, keywords and wrappers (with their flags), or -1. `env -S STRING`
 * (`--split-string`) splits the string into the command: then -2 and `split.script` holds the command line to check.
 */
function commandStart(words: ShellWord[], split: { script?: string } = {}): number {
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
    const name = (v.split("/").pop() as string).toLowerCase();
    const wrapper = WRAPPERS[name];
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
      const splitString = name === "env" ? /^(?:-[a-zA-Z0-9]*S|--split-string(?:=|$))(.*)$/s.exec(a) : null;
      if (splitString !== null) {
        const inline = (splitString[1] as string).replace(/^=/, "");
        const first = inline !== "" ? inline : words[i + 1]?.value;
        const rest = words.slice(inline !== "" ? i + 1 : i + 2).map((w) => w.value);
        split.script = [first ?? "", ...rest].join(" ");
        return -2;
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

/** A plain word for a command name that the check puts in front of words (`python -m uv ...` → `uv ...`). */
function syntheticWord(value: string): ShellWord {
  return { value, start: -1, end: -1, quoted: false, executes: false, splittable: false, expands: false, redirect: false };
}

/** Index of the first operand after options (value flags consume the next word), or args.length; null on an unresolved word. */
function afterOptions(args: ShellWord[], start: number, valueFlags: ReadonlySet<string>): number | null {
  let k = start;
  for (; k < args.length; k++) {
    const v = cleanWord(args[k] as ShellWord);
    if (v === null) return null;
    if (v === "--") return k + 1;
    if (!v.startsWith("-") || v === "-") return k;
    if (takesNext(v, valueFlags)) k++;
  }
  return k;
}

const RUNUSER_VALUE_FLAGS = new Set(["-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell", "-w", "--whitelist-environment", "-c", "--command", "--session-command"]);
const FLOCK_VALUE_FLAGS = new Set(["-w", "--wait", "--timeout", "-E", "--conflict-exit-code"]);
const WATCH_VALUE_FLAGS = new Set(["-n", "--interval", "-q", "--equexit"]);
const PARALLEL_VALUE_FLAGS = new Set(["-j", "--jobs", "-P", "--max-procs", "-S", "--sshlogin", "-a", "--arg-file", "-d", "--delimiter", "-I", "-n", "--max-args", "-N", "--colsep", "-C", "--joblog", "--results", "--tmpdir", "--workdir", "--timeout", "--delay", "-E"]);

function commandProblems(all: ShellWord[], allowed: InstallPolicy, depth: number): string[] {
  const words = withoutRedirections(all);
  const split: { script?: string } = {};
  const at = commandStart(words, split);
  if (at === -2) return nested(split.script ?? "", allowed, depth);
  if (at === -1) return [];
  const head = cleanWord(words[at] as ShellWord);
  if (head === null) return [];
  const exe = (head.split("/").pop() as string).toLowerCase().replace(/\.(exe|cmd)$/, "");
  const args = words.slice(at + 1);
  if (SHELLS.has(exe)) {
    const c = args.findIndex((w) => /^-[a-z]*c[a-z]*$/.test(w.value) || w.value === "--command" || w.value.startsWith("--command="));
    if (c === -1) return [];
    const flag = (args[c] as ShellWord).value;
    let script: string | undefined;
    if (flag.startsWith("--command=")) script = flag.slice("--command=".length);
    else {
      let k = c + 1;
      while (args[k]?.value === "--") k++;
      script = args[k]?.value;
    }
    if (script === undefined) return [];
    return nested(script, allowed, depth);
  }
  if (exe === "runuser" && args.some((w) => w.value === "-u" || w.value === "--user" || w.value.startsWith("--user="))) {
    // `runuser [options] -u user [--] command [args]`: the command runs directly (no shell string).
    const k = afterOptions(args, 0, RUNUSER_VALUE_FLAGS);
    if (k === null) return [UNRESOLVED_COMMAND];
    const c = args.findIndex((w) => /^-[A-Za-z]*c$/.test(w.value) || w.value === "--command" || w.value.startsWith("--command="));
    if (c === -1) return k < args.length ? commandProblems(args.slice(k), allowed, depth + 1) : [];
  }
  if (exe === "su" || exe === "runuser") {
    // `su [-l] [user] -c 'cmd'` (also `-lc`, `--command`, `--session-command`): the command string is a nested command line.
    const problems: string[] = [];
    for (let k = 0; k < args.length; k++) {
      const v = (args[k] as ShellWord).value;
      const [flag, inline] = splitFlag(v);
      if (inline !== null && (flag === "--command" || flag === "--session-command")) problems.push(...nested(inline, allowed, depth));
      else if (v === "--command" || v === "--session-command" || /^-[A-Za-z]*c$/.test(v)) {
        const script = args[k + 1];
        if (script !== undefined) problems.push(...nested(script.value, allowed, depth));
        k++;
      }
    }
    return [...new Set(problems)];
  }
  if (exe === "xargs") {
    // xargs runs the command with words from its input appended: an install there gets unknown package arguments.
    let k = 0;
    for (; k < args.length; k++) {
      const v = cleanWord(args[k] as ShellWord);
      if (v === null) return [UNRESOLVED_COMMAND];
      if (v === "--") {
        k++;
        break;
      }
      if (!v.startsWith("-") || v === "-") break;
      if (takesNext(v, XARGS_VALUE_FLAGS)) k++;
    }
    if (k >= args.length) return [];
    if (depth >= MAX_DEPTH) return [TOO_DEEP];
    return commandProblems([...args.slice(k), XARGS_INPUT], allowed, depth + 1);
  }
  if (exe === "flock") {
    // `flock [opts] FILE -c 'cmd'` (string) or `flock [opts] FILE cmd args` (words).
    const c = args.findIndex((w) => w.value === "-c" || w.value === "--command" || w.value.startsWith("--command="));
    if (c !== -1) {
      const v = (args[c] as ShellWord).value;
      const script = v.startsWith("--command=") ? v.slice("--command=".length) : args[c + 1]?.value;
      return script === undefined ? [] : nested(script, allowed, depth);
    }
    const k = afterOptions(args, 0, FLOCK_VALUE_FLAGS);
    if (k === null) return [UNRESOLVED_COMMAND];
    return k + 1 < args.length ? commandProblems(args.slice(k + 1), allowed, depth + 1) : [];
  }
  if (exe === "watch") {
    // watch runs its arguments through `sh -c` (joined with spaces); with -x/--exec directly.
    const k = afterOptions(args, 0, WATCH_VALUE_FLAGS);
    if (k === null) return [UNRESOLVED_COMMAND];
    if (k >= args.length) return [];
    const exec = args.slice(0, k).some((w) => w.value === "-x" || w.value === "--exec" || /^-[a-zA-Z]*x[a-zA-Z]*$/.test(w.value));
    return exec ? commandProblems(args.slice(k), allowed, depth + 1) : nested(args.slice(k).map((w) => w.value).join(" "), allowed, depth);
  }
  if (exe === "parallel" || exe === "sem") {
    // GNU parallel: arguments come from its input or after ::: / ::::, like xargs (an install there fails closed). Without a
    // command it runs input lines as commands; that is no visible install (the write check treats it as opaque for agents).
    const k = afterOptions(args, 0, PARALLEL_VALUE_FLAGS);
    if (k === null) return [UNRESOLVED_COMMAND];
    const end = args.findIndex((w, n) => n >= k && (w.value === ":::" || w.value === "::::" || w.value === ":::+" || w.value === "::::+"));
    const command = args.slice(k, end === -1 ? args.length : end);
    if (command.length === 0) return [];
    if (depth >= MAX_DEPTH) return [TOO_DEEP];
    return commandProblems([...command, XARGS_INPUT], allowed, depth + 1);
  }
  if (exe === "find") {
    // `find ... -exec cmd {} ;` (also -execdir, -ok, -okdir, `+`): each embedded command is checked; `{}` is no known package.
    const problems: string[] = [];
    for (let k = 0; k < args.length; k++) {
      if (!FIND_EXEC.has((args[k] as ShellWord).value)) continue;
      let end = k + 1;
      while (end < args.length && (args[end] as ShellWord).value !== ";" && (args[end] as ShellWord).value !== "+") end++;
      if (depth >= MAX_DEPTH) return [TOO_DEEP];
      problems.push(...commandProblems(args.slice(k + 1, end), allowed, depth + 1));
      k = end;
    }
    return [...new Set(problems)];
  }
  if (exe === "env") return [];
  const npm = new Set(allowed.npm.map((n) => n.toLowerCase()));
  const pypi = new Set(allowed.pypi.map(normalizePypi));
  if (NPM_TOOLS.has(exe)) return npmProblems(exe, args, npm, allowed, depth);
  if (exe === "npx") return execProblems("npx", args, npm, new Set([...NPM_VALUE_FLAGS, ...NPM_ONLY_VALUE_FLAGS]), allowed, depth);
  if (exe === "pnpx") return execProblems("dlx", args, npm, NPM_VALUE_FLAGS, allowed, depth);
  if (exe === "bunx") return execProblems("bunx", args, npm, NPM_VALUE_FLAGS, allowed, depth);
  if (exe === "pipx" && args[0] !== undefined && cleanWord(args[0]) === "run") return pyRunProblems("tool", args.slice(1), pypi, allowed, depth);
  if (exe === "pip" || /^pip\d*(\.\d+)?$/.test(exe) || exe === "pipx") return pipProblems(args, pypi);
  if (/^python[\d.]*$/.test(exe) || exe === "py") {
    const m = args.findIndex((w) => /^-m/.test(w.value));
    if (m === -1) return [];
    const inline = (args[m] as ShellWord).value.slice(2);
    const mod = inline !== "" ? inline : args[m + 1]?.value;
    const rest = args.slice(inline !== "" ? m + 1 : m + 2);
    if (mod === "pip") return pipProblems(rest, pypi);
    // `python -m pipx|uv|poetry|pipenv ...` behaves like the command of the same name.
    if (mod === "pipx" || mod === "uv" || mod === "poetry" || mod === "pipenv") return commandProblems([syntheticWord(mod), ...rest], allowed, depth + 1);
    return [];
  }
  if (exe === "uvx") return pyRunProblems("tool", args, pypi, allowed, depth);
  if (exe === "uv") {
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
    if (first === "tool" && args[sub + 1]?.value === "run") return pyRunProblems("tool", args.slice(sub + 2), pypi, allowed, depth);
    if (first === "run") return pyRunProblems("run", args.slice(sub + 1), pypi, allowed, depth);
  }
  if (exe === "poetry") return poetryProblems(args, pypi, allowed, depth);
  if (exe === "pipenv") return pipenvProblems(args, pypi, allowed, depth);
  if (CONDA_TOOLS.has(exe)) return condaProblems(args, allowed, depth);
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
