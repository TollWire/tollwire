/**
 * Heuristic check of inline interpreter code (python -c, node -e, perl/ruby -e, php -r, awk and sed
 * programs) for APIs that can write files or start programs.
 *
 * This is a list-based heuristic (defense in depth): it recognizes the common write and process APIs
 * of each language and the common ways to hide them (computed names, dynamic imports, non-literal file
 * modes). Unknown libraries or language constructs are not recognized. Reading stays allowed.
 *
 * All scanners are linear in the code length (no regular expressions with nested or overlapping
 * quantifiers). Mirrored 1:1 by a Python port; keep both in sync.
 */

const PYTHON = /^(?:python|pypy)[0-9.]*$/;
const PERL = /^perl[0-9.]*$/;
const RUBY = /^ruby[0-9.]*$/;
const PHP = /^php[0-9.]*$/;
const AWKS = new Set(["awk", "gawk", "mawk", "nawk"]);

// Literal alternatives with word boundaries only (linear). ASCII only; same syntax in JavaScript and Python.
const INDICATORS: Readonly<Record<string, string>> = {
  python:
    "\\bos[ \\t]*\\.[ \\t]*(?:remove|unlink|rename|renames|replace|rmdir|removedirs|makedirs|mkdir|mkfifo|mknod|symlink|link|chmod|lchmod|chown|lchown|chflags|truncate|ftruncate|utime|open|fdopen|write|pwrite|writev|system|popen|exec[a-z]*|spawn[a-z]*|posix_spawn[a-z]*|fork|forkpty|sendfile|copy_file_range)\\b" +
    "|\\b(?:shutil|subprocess|pty|ctypes|importlib|fileinput|tarfile|zipfile|sqlite3|shelve|dbm|runpy|FileIO|__import__|__builtins__|builtins|__loader__|__spec__)\\b" +
    "|(?:^|[^.\\w])(?:eval|exec|compile|getattr|setattr|delattr|globals|locals|vars|breakpoint)[ \\t]*\\(" +
    "|\\.(?:touch|unlink|rename|replace|rmdir|mkdir|symlink_to|hardlink_to|link_to|chmod|lchmod|write_text|write_bytes)[ \\t]*\\(" +
    "|\\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)\\b|\\b(?:posix|_posixsubprocess|_io|nt)\\b|\\bsys[ \\t]*\\.[ \\t]*modules\\b" +
    // Imports that bind write functions to other names: `from os import remove`, `import os as o`.
    "|\\bfrom[ \\t]+(?:os|shutil|subprocess|pathlib|io|codecs|posix|nt|pty|ctypes|importlib|fileinput|tarfile|zipfile|tempfile|builtins)\\b[^\\n]*\\bimport\\b" +
    "|\\bimport[ \\t]+[^\\n]*\\b(?:os|shutil|subprocess|pathlib|io|codecs|posix|nt|pty|ctypes|importlib|fileinput|tarfile|zipfile|tempfile|builtins)(?:[ \\t]*\\.[ \\t]*\\w+)?[ \\t]+as\\b",
  js:
    "\\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|writev|writevSync|rename|renameSync|unlink|unlinkSync|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|mkdtemp|mkdtempSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync|lchmod|chown|chownSync|lchown|truncate|truncateSync|ftruncate|ftruncateSync|copyFile|copyFileSync|cpSync|rm|cp|utimes|utimesSync|lutimes|writeTextFile|writeTextFileSync|execSync|execFile|execFileSync|spawn|spawnSync|fork|child_process|worker_threads|Function|Reflect|globalThis|dlopen|constructor|__proto__|runInThisContext|runInNewContext|runInContext|compileFunction|Worker)\\b" +
    "|\\b(?:fs|fsp|promises)[ \\t]*\\.[ \\t]*(?:rm|cp|write|writeSync|open|openSync)\\b" +
    "|\\bprocess[ \\t]*\\.[ \\t]*(?:binding|dlopen|mainModule)|\\b(?:Deno|Bun)[ \\t]*\\.|(?:^|[^.\\w])eval[ \\t]*\\(",
  perl:
    "\\b(?:unlink|rename|rmdir|mkdir|symlink|link|chmod|chown|truncate|utime|system|exec|eval|qx|sysopen|syscall|fork|CORE|IO|File)\\b|`|&[ \\t]*[{$]|->[ \\t]*can\\b|\\bdo[ \\t]*['\"$]|\\brequire[ \\t]*[$]",
  ruby:
    "\\b(?:File|IO)[ \\t]*\\.[ \\t]*(?:write|binwrite|open|new|delete|unlink|rename|symlink|link|chmod|lchmod|chown|lchown|truncate|utime|mkfifo|popen|sysopen)\\b" +
    "|\\b(?:FileUtils|Open3|PTY|Pathname|Kernel|Process|ObjectSpace|Fiddle)\\b|\\bDir[ \\t]*\\.[ \\t]*(?:mkdir|rmdir|delete|unlink)\\b" +
    "|\\b(?:system|exec|spawn|eval|instance_eval|class_eval|module_eval|instance_exec|send|public_send|__send__|syscall|fork|open|const_get|method|define_method|instance_variable_set)\\b|%x|`",
  php:
    "\\b(?:file_put_contents|fopen|fwrite|fputs|fputcsv|unlink|rename|rmdir|mkdir|symlink|link|chmod|chown|chgrp|touch|copy|tempnam|tmpfile|system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|eval|assert|create_function|call_user_func|call_user_func_array|forward_static_call|forward_static_call_array|include|include_once|require|require_once|move_uploaded_file|ftruncate|lchown|lchgrp|SplFileObject|ZipArchive|PharData|array_map|array_walk|array_walk_recursive|array_filter|array_reduce|usort|uasort|uksort|register_shutdown_function|register_tick_function|iterator_apply|preg_replace_callback|preg_replace_callback_array|mb_ereg_replace_callback|ob_start|set_error_handler|set_exception_handler|spl_autoload_register|header_register_callback|Closure|ReflectionFunction|ReflectionMethod|ReflectionClass)\\b" +
    "|`|\\$[A-Za-z_][A-Za-z0-9_]*[ \\t]*\\(|\\$\\$|\\$\\{|\\bnew[ \\t]+\\$",
  awk: "\\bsystem[ \\t]*\\(|[|][ \\t]*getline",
  sed: "(?:^|[\\n;{}!/0-9$,])[ \\t]*[wWe](?:[ \\t\\n;}]|$)",
};
const INDICATOR_RES: Readonly<Record<string, RegExp>> = Object.fromEntries(Object.entries(INDICATORS).map(([k, v]) => [k, new RegExp(v)]));

/** Language of an interpreter name (first word of a finding's `via`). */
export function codeLanguage(via: string): string {
  const name = via.split(" ")[0] ?? "";
  if (PYTHON.test(name)) return "python";
  if (name === "node" || name === "nodejs" || name === "bun" || name === "deno") return "js";
  if (PERL.test(name)) return "perl";
  if (RUBY.test(name)) return "ruby";
  if (PHP.test(name)) return "php";
  if (AWKS.has(name)) return "awk";
  return name === "sed" ? "sed" : "unknown";
}

function isIdentStart(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_";
}

function isIdentChar(c: string): boolean {
  return isIdentStart(c) || (c >= "0" && c <= "9");
}

/** End index (exclusive) of the string literal starting at i (quote at i); code.length if unterminated. */
function stringEnd(code: string, i: number): number {
  const q = code.charAt(i);
  const triple = (q === "'" || q === '"') && code.startsWith(q + q + q, i);
  const closer = triple ? q + q + q : q;
  let j = i + closer.length;
  while (j < code.length) {
    const c = code.charAt(j);
    if (c === "\\") {
      j += 2;
      continue;
    }
    if (code.startsWith(closer, j)) return j + closer.length;
    j += 1;
  }
  return code.length;
}

function isQuote(c: string, lang: string): boolean {
  return c === "'" || c === '"' || (lang === "js" && c === "`");
}

/** Python string prefix letters right before index i (e.g. "rb", "f"); "" if none. */
function stringPrefix(code: string, i: number): string {
  let j = i;
  while (j > 0 && j > i - 2 && "rRbBuUfF".includes(code.charAt(j - 1))) j -= 1;
  if (j > 0 && isIdentChar(code.charAt(j - 1))) return "";
  return code.slice(j, i);
}

interface Call {
  name: string;
  /** Preceded by "." (method call or attribute access). */
  member: boolean;
  /** Top-level argument texts, or null if the call is not followed by "(" or is unterminated. */
  args: string[] | null;
}

/**
 * Finds identifiers (outside string literals) and the argument lists of their calls. Python f-strings
 * and JavaScript template literals are scanned as code (their expressions run). Perl and PHP variables
 * (`$open`) are not identifiers. Optional `noParens` reads Perl-style calls without parentheses up to ";".
 */
function scanCalls(code: string, lang: string, names: ReadonlySet<string>, noParens = false): Call[] {
  const calls: Call[] = [];
  let i = 0;
  while (i < code.length) {
    const c = code.charAt(i);
    if (isQuote(c, lang)) {
      const prefix = lang === "python" ? stringPrefix(code, i) : "";
      if (prefix.toLowerCase().includes("f") || c === "`") {
        i += 1; // contents are code
        continue;
      }
      i = stringEnd(code, i);
      continue;
    }
    if (isIdentStart(c) && (i === 0 || !isIdentChar(code.charAt(i - 1)))) {
      let j = i;
      while (j < code.length && isIdentChar(code.charAt(j))) j += 1;
      const name = code.slice(i, j);
      const before = i > 0 ? code.charAt(i - 1) : "";
      if (names.has(name) && (before === "" || !"$@%&".includes(before))) {
        let k = i - 1;
        while (k >= 0 && (code.charAt(k) === " " || code.charAt(k) === "\t")) k -= 1;
        const member = k >= 0 && (code.charAt(k) === "." || (code.charAt(k) === ">" && code.charAt(k - 1) === "-"));
        let m = j;
        while (m < code.length && (code.charAt(m) === " " || code.charAt(m) === "\t")) m += 1;
        if (code.charAt(m) === "(") calls.push({ name, member, args: splitArgs(code, m + 1, ")", lang) });
        else if (noParens && m < code.length && code.charAt(m) !== ";" && code.charAt(m) !== "\n") calls.push({ name, member, args: splitArgs(code, m, ";", lang) });
        else calls.push({ name, member, args: null });
      }
      i = j;
      continue;
    }
    i += 1;
  }
  return calls;
}

/** Splits top-level arguments from index start up to the closer (")" or ";"); null if unterminated. */
function splitArgs(code: string, start: number, closer: string, lang: string): string[] | null {
  const args: string[] = [];
  let depth = 0;
  let from = start;
  let i = start;
  while (i < code.length) {
    const c = code.charAt(i);
    if (isQuote(c, lang)) {
      i = stringEnd(code, i);
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if ((c === ")" || c === "]" || c === "}") && depth > 0) depth -= 1;
    else if (depth === 0 && c === ",") {
      args.push(code.slice(from, i).trim());
      from = i + 1;
    } else if (depth === 0 && (c === closer || (closer === ";" && c === "\n"))) {
      const last = code.slice(from, i).trim();
      if (last !== "" || args.length > 0) args.push(last);
      return args;
    }
    i += 1;
  }
  if (closer === ";") {
    const last = code.slice(from).trim();
    if (last !== "" || args.length > 0) args.push(last);
    return args;
  }
  return null;
}

/** Content of a plain string literal ('x' or "x", optional Python prefix without f), or null. */
function literal(arg: string, lang: string): string | null {
  let s = arg;
  if (lang === "python") {
    let p = 0;
    while (p < s.length && p < 2 && "rRbBuU".includes(s.charAt(p))) p += 1;
    s = s.slice(p);
  }
  if (s.length < 2) return null;
  const q = s.charAt(0);
  if ((q !== "'" && q !== '"') || s.charAt(s.length - 1) !== q) return null;
  const body = s.slice(1, -1);
  if (body.includes(q) || body.includes("\\")) return null;
  if (lang === "perl" && q === '"' && (body.includes("$") || body.includes("@"))) return null;
  return body;
}

const PY_READ_MODES = new Set(["", "r", "rb", "rt", "br", "tr", "U", "rU", "Ur"]);

/** Python: every `open` must be a call whose mode is a literal read mode; no opener, no unpacking. */
function pythonOpenUnsafe(code: string): boolean {
  for (const call of scanCalls(code, "python", new Set(["open"]))) {
    if (call.args === null) return true;
    const positional: string[] = [];
    let mode: string | null = null;
    for (const arg of call.args) {
      if (arg.startsWith("*")) return true;
      const eq = /^([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(?!=)/.exec(arg);
      if (eq === null) {
        positional.push(arg);
        continue;
      }
      const key = eq[1] as string;
      if (key === "opener") return true;
      if (key === "mode") mode = arg.slice(eq[0].length).trim();
    }
    const modeArg = mode ?? positional[call.member ? 0 : 1] ?? null;
    if (modeArg === null) continue;
    const value = literal(modeArg, "python");
    if (value === null || !PY_READ_MODES.has(value)) return true;
  }
  return false;
}

/** Perl: `open` with a literal read mode ('<', '<:encoding(..)') or a 2-argument literal without write prefix. */
function perlOpenUnsafe(code: string): boolean {
  for (const call of scanCalls(code, "perl", new Set(["open", "sysopen"]), true)) {
    if (call.name === "sysopen" || call.args === null || call.args.length < 2) return true;
    const mode = literal(call.args[1] as string, "perl");
    if (mode === null) return true;
    const m = mode.trim();
    if (call.args.length >= 3) {
      if (!(m === "<" || m.startsWith("<:"))) return true;
    } else if (m.startsWith(">") || m.startsWith("+") || m.startsWith("|") || m.endsWith("|")) {
      return true;
    }
  }
  return false;
}

const JS_MODULES = ["fs", "fs/promises", "child_process", "worker_threads", "vm", "module", "inspector", "wasi", "process", "os"];
/** Modules whose import alone counts as write- or process-capable (every function writes or runs code). */
const JS_WRITE_MODULES = ["fs/promises", "child_process", "worker_threads", "vm", "module", "inspector", "wasi"];

/** JavaScript: dynamic require/import, bare require references, computed member access next to dangerous modules. */
function jsDynamicUnsafe(code: string): boolean {
  let dangerous = /\bprocess\b/.test(code);
  for (const call of scanCalls(code, "js", new Set(["require", "import"]))) {
    if (call.member) continue;
    if (call.args === null) {
      if (call.name === "require") return true;
      continue; // static `import x from "y"`; module specifier checked below
    }
    if (call.args.length !== 1) return true;
    const spec = jsLiteral(call.args[0] as string);
    if (spec === null) return true;
    if (JS_WRITE_MODULES.includes(spec.replace(/^node:/, ""))) return true;
    if (JS_MODULES.includes(spec.replace(/^node:/, ""))) dangerous = true;
  }
  for (const m of code.matchAll(/\bfrom[ \t]*(['"])([^'"\n]*)\1/g)) {
    const mod = (m[2] as string).replace(/^node:/, "");
    if (JS_WRITE_MODULES.includes(mod)) return true;
    if (JS_MODULES.includes(mod)) dangerous = true;
  }
  return dangerous && computedAccess(code);
}

function jsLiteral(arg: string): string | null {
  if (arg.length >= 2 && arg.charAt(0) === "`" && arg.charAt(arg.length - 1) === "`") {
    const body = arg.slice(1, -1);
    return body.includes("`") || body.includes("${") || body.includes("\\") ? null : body;
  }
  return literal(arg, "js");
}

/** `x[expr]` (outside strings) whose expression is not a number or a plain string literal. */
function computedAccess(code: string): boolean {
  let i = 0;
  while (i < code.length) {
    const c = code.charAt(i);
    if (isQuote(c, "js")) {
      if (c === "`") {
        i += 1;
        continue;
      }
      i = stringEnd(code, i);
      continue;
    }
    if (c === "[") {
      let k = i - 1;
      while (k >= 0 && (code.charAt(k) === " " || code.charAt(k) === "\t")) k -= 1;
      const prev = k >= 0 ? code.charAt(k) : "";
      if (isIdentChar(prev) || prev === "$" || prev === ")" || prev === "]") {
        const args = splitArgs(code, i + 1, "]", "js");
        if (args === null || args.length !== 1) return true;
        const inner = args[0] as string;
        if (!/^[0-9]+$/.test(inner) && jsLiteral(inner) === null) return true;
      }
    }
    i += 1;
  }
  return false;
}

/** Quoted literal that is a file mode for writing ('w', 'a+', '>x', '|cmd', 'cmd|'); linear scan. */
function writeModeLiteral(code: string): boolean {
  let i = 0;
  while (i < code.length) {
    const c = code.charAt(i);
    if (c !== "'" && c !== '"') {
      i += 1;
      continue;
    }
    const end = code.indexOf(c, i + 1);
    if (end < 0) return false;
    const body = code.slice(i + 1, end);
    let modeChars = body.length > 0;
    let writes = false;
    for (const ch of body) {
      if (!"rbtUwax+".includes(ch)) modeChars = false;
      if ("wax+".includes(ch)) writes = true;
    }
    const t = body.replace(/^\+/, "");
    if ((modeChars && writes) || t.startsWith("<") || t.startsWith(">") || body.startsWith("|") || body.endsWith("|")) return true;
    i = end + 1;
  }
  return false;
}

/** awk: print/printf with an output redirection or pipe in the same statement (linear). */
function awkRedirect(code: string): boolean {
  for (const statement of code.split(/[;{}\n]/)) {
    const m = /\bprintf?\b/.exec(statement);
    if (m === null) continue;
    const rest = statement.slice(m.index);
    if (rest.includes(">") || rest.includes("|")) return true;
  }
  return false;
}

/** sed: s///w or s///e flags (maximal flag run after a delimiter, linear). */
function sedFlags(code: string): boolean {
  const delims = "/|#:,@!";
  const flags = "gpiImMe0123456789w";
  for (let i = 0; i < code.length; i += 1) {
    if (!delims.includes(code.charAt(i))) continue;
    let j = i + 1;
    let hit = false;
    while (j < code.length && flags.includes(code.charAt(j))) {
      if (code.charAt(j) === "w" || code.charAt(j) === "e") hit = true;
      j += 1;
    }
    if (hit && (j === code.length || " \t\n;}".includes(code.charAt(j)))) return true;
  }
  return false;
}

/** True if the code contains an API that can write files or run programs (per language). */
export function writeIndicator(code: string, language: string): boolean {
  const re = INDICATOR_RES[language];
  if (re === undefined) return true;
  if (re.test(code)) return true;
  switch (language) {
    case "python":
      return pythonOpenUnsafe(code);
    case "js":
      return jsDynamicUnsafe(code) || (/\bopen(?:Sync)?\b/.test(code) && writeModeLiteral(code));
    case "perl":
      return perlOpenUnsafe(code);
    case "ruby":
    case "php":
      return /\b(?:f|sys)?open\b/.test(code) && writeModeLiteral(code);
    case "awk":
      return awkRedirect(code);
    case "sed":
      return sedFlags(code);
    default:
      return true;
  }
}
