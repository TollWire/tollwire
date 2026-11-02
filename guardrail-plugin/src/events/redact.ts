// Redaction of Bash command text for the decision log. A heuristic: it removes the values of
// well-known secret formats, credential-like names, headers, user names/passwords and known password options.
// Works on the unquoted words of the shell tokenizer, so quoting tricks (`--pass''word=`, `--$'pass'word=`) do not help.
import { parseShell, type ShellWord } from "../shell.js";
import { plainParts, resolveProgram } from "./commandInfo.js";

export interface Redacted {
  text: string;
  redactions: number;
}

type Kind = "secret" | "credential" | "header" | "userinfo" | "password" | "heredoc";
const marker = (kind: Kind): string => `[REDACTED:${kind}]`;

// Prefix-anchored secret formats; the same list as the evidence log (product/evidence-mcp/src/log.ts, SECRET_PATTERNS).
// All patterns are linear (bounded or anchored character classes).
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/g,
  /\bhooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g,
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
];
const URL_USERINFO = /(\b[a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@?#]{1,256}@/gi;
// JSON string members with a credential-like key: "api_key": "value". Bounded, so no catastrophic backtracking.
const JSON_MEMBER = /("(?:[^"\\]|\\.){1,64}"\s{0,8}:\s{0,8})"((?:[^"\\]|\\.){1,512})"/g;
const JSON_KEY = /^"((?:[^"\\]|\\.)*)"/;
const QUERY_PARAM = /([?&;])([^=&#\s]{1,64})=([^&#\s]+)/g;
// libpq / ODBC / mount option strings inside one word or free text: `password=x`, `Pwd=x;`, `-o user=u,password=x`. The name is anchored at a
// separator, the value is bounded (quoted or up to the next separator), so the scan stays linear.
const KEYWORD_VALUE =
  /((?:^|[\s;,])(?:password|passwd|pwd|sslpassword|secret[_-]?access[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?key)[ \t]{0,3}=[ \t]{0,3})('[^']{1,256}'|"[^"]{1,256}"|[^\s;,'"]{1,256})/gi;

const SECRET_WORDS = new Set([
  "token", "secret", "password", "passwd", "pwd", "pass", "passphrase", "apikey", "auth", "authorization", "credential", "credentials",
  "cookie", "bearer", "pw",
]);
const SECRET_SUFFIX = /(?:password|passwd|passphrase|apikey)$/;
const SECRET_HEADERS = new Set([
  "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "x-auth-token", "x-amz-security-token", "x-goog-api-key",
  "private-token", "x-vault-token",
]);
// Header names that are credentials although the list above does not know them: any name that `secretName` accepts (X-Custom-Token) plus session,
// signature and anti-forgery names.
const HEADER_EXTRA_WORDS = new Set(["session", "sid", "sig", "signature", "csrf", "xsrf", "jwt"]);
const QUERY_EXTRA_WORDS = new Set(["sig", "signature"]);
const HEADER_TEXT = /^(\s*([A-Za-z0-9-]+)\s*:\s*)([\s\S]*)$/;
// Short options of known programs whose value is a password; `attached` allows the value in the same word (getopt style).
const SHORT_PASSWORD_OPTIONS: Readonly<Record<string, { option: string; attached: boolean }>> = {
  "redis-cli": { option: "-a", attached: false },
  ldapsearch: { option: "-w", attached: true },
  ldapmodify: { option: "-w", attached: true },
  ldapadd: { option: "-w", attached: true },
  ldapdelete: { option: "-w", attached: true },
  ldapmodrdn: { option: "-w", attached: true },
  ldapcompare: { option: "-w", attached: true },
  ldappasswd: { option: "-w", attached: true },
  openssl: { option: "-k", attached: false },
  az: { option: "-p", attached: false },
  sqlcmd: { option: "-P", attached: true },
  bcp: { option: "-P", attached: true },
  osql: { option: "-P", attached: true },
  twine: { option: "-p", attached: false },
};
// git config keys that hold a whole header line: http.extraheader, http.<url>.extraheader.
const EXTRA_HEADER_KEY = /(?:^|\.)extraheader$/i;
const SMB = new Set(["smbclient", "rpcclient", "smbtree", "smbcacls", "smbget"]);
const CONFIG_SET = new Set(["npm", "yarn", "pnpm", "git", "pip", "pip3", "twine", "poetry", "conan"]);
const MYSQL = new Set(["mysql", "mysqldump", "mysqladmin", "mariadb", "mariadb-dump", "mysqlpump", "mysqlcheck"]);

/** Name parts: NFKC, format characters removed, split at `_`, `-`, `.`, whitespace and camel-case boundaries. */
function nameParts(name: string): string[] {
  const normalized = name.normalize("NFKC").replace(/\p{Cf}/gu, "").replace(/^-+/, "");
  return normalized
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .split(/[_\-.\s]+/)
    .filter((p) => p !== "")
    .map((p) => p.toLowerCase());
}

function lastPart(name: string): string {
  const parts = nameParts(name);
  return parts[parts.length - 1] ?? "";
}

/** Header names that carry a credential. */
function secretHeader(name: string): boolean {
  return SECRET_HEADERS.has(name.toLowerCase()) || secretName(name) || nameParts(name).some((p) => HEADER_EXTRA_WORDS.has(p));
}

/** True for names that look like credentials: an exact part from the list, a last part `key`, or a known compound. */
export function secretName(name: string): boolean {
  const parts = nameParts(name);
  if (parts.length === 0) return false;
  if (parts.some((p) => SECRET_WORDS.has(p))) return true;
  if (parts[parts.length - 1] === "key") return true;
  return SECRET_SUFFIX.test(parts.join(""));
}

function maskPatterns(text: string, bump: () => void): string {
  let out = text;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, () => {
      bump();
      return marker("secret");
    });
  }
  out = out.replace(URL_USERINFO, (m, scheme: string) => {
    if (m.includes("[REDACTED:")) return m; // already replaced
    bump();
    return `${scheme}${marker("userinfo")}@`;
  });
  out = out.replace(JSON_MEMBER, (m, head: string, value: string) => {
    const key = JSON_KEY.exec(head);
    if (key === null || !secretName(key[1] as string) || value.startsWith("[REDACTED:")) return m;
    bump();
    return `${head}"${marker("credential")}"`;
  });
  out = out.replace(QUERY_PARAM, (m, sep: string, name: string, value: string) => {
    if (!(secretName(name) || QUERY_EXTRA_WORDS.has(lastPart(name))) || value.startsWith("[REDACTED:")) return m;
    bump();
    return `${sep}${name}=${marker("credential")}`;
  });
  return out.replace(KEYWORD_VALUE, (m, head: string, value: string) => {
    if (value.startsWith("[REDACTED:")) return m;
    bump();
    return `${head}${marker("credential")}`;
  });
}

/** Free text (decision reasons and similar): secret formats, URL user info and query credentials. */
export function redactText(text: string): Redacted {
  let redactions = 0;
  const masked = maskPatterns(text, () => (redactions += 1));
  return { text: masked, redactions };
}

/** Replaces command/process substitutions inside a word by a short marker; their commands are listed separately. */
function summarizeSubstitutions(value: string): string {
  let out = "";
  let i = 0;
  while (i < value.length) {
    const c = value.charAt(i);
    if ((c === "$" || c === "<" || c === ">") && value.charAt(i + 1) === "(") {
      let depth = 1;
      let j = i + 2;
      while (j < value.length && depth > 0) {
        if (value.charAt(j) === "(") depth += 1;
        else if (value.charAt(j) === ")") depth -= 1;
        j += 1;
      }
      out += `${c}(…)`;
      i = j;
    } else if (c === "`") {
      const close = value.indexOf("`", i + 1);
      out += "`…`";
      i = close < 0 ? value.length : close + 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

function redactHeaderText(text: string, bump: () => void): string {
  const m = HEADER_TEXT.exec(text);
  if (m === null || !secretHeader(m[2] as string)) return text;
  bump();
  return `${m[1] as string}${marker("header")}`;
}

function isOption(value: string): boolean {
  return value.length > 1 && value.startsWith("-");
}

function renderCommand(words: readonly ShellWord[], src: string, bump: () => void): string {
  const values = words.map((w) => summarizeSubstitutions(w.value));
  const skip = words.map(() => false);
  words.forEach((w, i) => {
    if (w.redirect) {
      skip[i] = true;
      if (i + 1 < words.length) skip[i + 1] = true;
    }
  });
  const extra: string[] = [];
  const program = resolveProgram(plainParts(words).parts, src);
  const prog = program === null || program.dynamic ? "" : program.name.toLowerCase();
  // Index of the next word that is not a redirection operator or its target.
  const nextFree = (from: number): number => {
    let j = from;
    while (j < words.length && skip[j] === true) j += 1;
    return j;
  };
  const redactNext = (i: number, kind: Kind): number => {
    const j = nextFree(i + 1);
    if (j < words.length && !isOption(values[j] as string) && values[j] !== "") {
      values[j] = marker(kind);
      bump();
      return j;
    }
    return i;
  };
  const original = [...values];
  // Previous word that is not a redirection operator or its target, nor an option (`git config --global <key> <value>`).
  const prevFree = (i: number): string => {
    let j = i - 1;
    while (j >= 0 && (skip[j] === true || isOption(original[j] as string))) j -= 1;
    return j >= 0 ? (original[j] as string) : "";
  };
  // vault login [options] <token>: the first positional word after `login` is the token.
  const vaultToken = (i: number): boolean => {
    if (prog !== "vault") return false;
    const login = original.findIndex((w, k) => w === "login" && skip[k] !== true);
    if (login < 0 || login >= i) return false;
    return original.slice(login + 1, i).every((w, k) => skip[login + 1 + k] === true || isOption(w) || w.includes("="));
  };
  const htpasswdBatch = prog === "htpasswd" && values.some((v, i) => skip[i] !== true && /^-[a-zA-Z]*b/.test(v) && !v.startsWith("--"));
  let aws: { set: boolean; seen: number } | null = prog === "aws" ? { set: false, seen: 0 } : null;

  for (let i = 0; i < values.length; i += 1) {
    if (skip[i] === true) continue;
    const v = values[i] as string;
    const eq = v.indexOf("=");
    // 1. Headers: --header=<text>, curl -H<text>, curl -H <text>, --header <text>.
    if (v.startsWith("--header=")) {
      values[i] = `--header=${redactHeaderText(v.slice(9), bump)}`;
      continue;
    }
    if (prog === "curl" && v.startsWith("-H") && v.length > 2 && !v.startsWith("--")) {
      values[i] = `-H${redactHeaderText(v.slice(2), bump)}`;
      continue;
    }
    if (v === "--header" || (prog === "curl" && v === "-H")) {
      const j = nextFree(i + 1);
      if (j < words.length) {
        values[j] = redactHeaderText(values[j] as string, bump);
        i = j;
      }
      continue;
    }
    if ((prog === "http" || prog === "https" || prog === "xh") && !isOption(v) && /^[A-Za-z0-9-]+:/.test(v)) {
      values[i] = redactHeaderText(v, bump);
      continue;
    }
    // 2. curl users.
    if (prog === "curl") {
      if (v === "-u" || v === "--user" || v === "--proxy-user") {
        i = redactNext(i, "credential");
        continue;
      }
      if (v.startsWith("--user=") || v.startsWith("--proxy-user=")) {
        values[i] = `${v.slice(0, eq + 1)}${marker("credential")}`;
        bump();
        continue;
      }
      if (/^-u./.test(v) && !v.startsWith("--")) {
        values[i] = `-u${marker("credential")}`;
        bump();
        continue;
      }
    }
    // 2b. curl cookies (name=value pairs; a file name stays visible) and SMB `user%password`.
    if (prog === "curl") {
      if (v === "-b" || v === "--cookie") {
        const j = nextFree(i + 1);
        if (j < words.length && (values[j] as string).includes("=")) {
          values[j] = marker("credential");
          bump();
          i = j;
        }
        continue;
      }
      if (/^-b./.test(v) && !v.startsWith("--") && v.includes("=")) {
        values[i] = `-b${marker("credential")}`;
        bump();
        continue;
      }
    }
    if (SMB.has(prog)) {
      const user = v === "-U" || v === "--user" ? nextFree(i + 1) : -1;
      const target = user >= 0 && user < words.length ? user : -1;
      const word = target >= 0 ? (values[target] as string) : v;
      const attached = /^-U./.test(v) ? 2 : v.startsWith("--user=") ? 7 : 0;
      if (target >= 0 || attached > 0) {
        const head = target >= 0 ? "" : v.slice(0, attached);
        const cut = word.indexOf("%", head.length);
        if (cut >= 0 && cut < word.length - 1) {
          const masked = `${word.slice(0, cut + 1)}${marker("password")}`;
          if (target >= 0) {
            values[target] = masked;
            i = target;
          } else {
            values[i] = masked;
          }
          bump();
          continue;
        }
        if (target >= 0) {
          i = target;
          continue;
        }
      }
    }
    // 2c. Positional secrets and key/value pairs given as separate words.
    if (prog === "vault" && !isOption(v) && eq < 0 && vaultToken(i)) {
      values[i] = marker("credential");
      bump();
      continue;
    }
    if (prog === "rclone") {
      if (v === "obscure") {
        i = redactNext(i, "password");
        continue;
      }
      if (!isOption(v) && eq < 0 && secretName(v) && prevFree(i) !== "") {
        i = redactNext(i, "credential");
        continue;
      }
    }
    if (CONFIG_SET.has(prog) && !isOption(v) && eq < 0 && (secretName(v) || EXTRA_HEADER_KEY.test(v)) && ["set", "config", "add"].includes(prevFree(i))) {
      i = redactNext(i, "credential");
      continue;
    }
    // 3. Password options of known programs.
    if (MYSQL.has(prog) && /^-p./.test(v) && !v.startsWith("--")) {
      values[i] = `-p${marker("password")}`;
      bump();
      continue;
    }
    if ((prog === "sshpass" || (prog === "docker" && values.includes("login"))) && /^-p./.test(v) && !v.startsWith("--") && !(prog === "docker" && v === "-p")) {
      values[i] = `-p${marker("password")}`;
      bump();
      continue;
    }
    if ((prog === "sshpass" || prog === "docker") && v === "-p") {
      i = redactNext(i, "password");
      continue;
    }
    const shortPassword = SHORT_PASSWORD_OPTIONS[prog];
    if (shortPassword !== undefined) {
      if (v === shortPassword.option) {
        i = redactNext(i, "password");
        continue;
      }
      if (shortPassword.attached && v.startsWith(shortPassword.option) && v.length > 2 && !v.startsWith("--")) {
        values[i] = `${shortPassword.option}${marker("password")}`;
        bump();
        continue;
      }
    }
    if (prog === "openssl" && v.startsWith("pass:") && v.length > 5) {
      values[i] = `pass:${marker("password")}`;
      bump();
      continue;
    }
    if (aws !== null) {
      // aws configure set <name> <value>
      if (v === "configure" || v === "set") {
        if (v === "set") aws = { set: true, seen: 0 };
        continue;
      }
      if (aws.set && !isOption(v)) {
        aws.seen += 1;
        if (aws.seen === 1 && secretName(v)) {
          i = redactNext(i, "credential");
          aws = { set: false, seen: 0 };
        }
        continue;
      }
    }
    // 4. NAME=value, --name=value.
    if (eq > 0 && eq < v.length - 1 && (secretName(v.slice(0, eq)) || EXTRA_HEADER_KEY.test(v.slice(0, eq)))) {
      values[i] = `${v.slice(0, eq + 1)}${marker("credential")}`;
      bump();
      continue;
    }
    // 5. --name value (the value is the next word). `openssl -pass pass:x` is handled by its own word; a single-dash word
    //    only counts as a flag name if it is all lower case (`-password`), not a short-option cluster (`-pSECRET`).
    if (prog === "openssl" && /^-pass/.test(v)) continue;
    if (eq < 0 && (v.startsWith("--") || /^-[a-z][a-z0-9_-]{2,}$/.test(v)) && secretName(v)) {
      i = redactNext(i, "credential");
      continue;
    }
    // 6. Secret formats, URL user info and query credentials anywhere in the word.
    values[i] = maskPatterns(v, bump);
  }
  if (htpasswdBatch) {
    const positional = values.map((v, i) => ({ v, i })).filter(({ v, i }) => skip[i] !== true && !isOption(v) && i > (program === null ? -1 : words.findIndex((w) => baseNameOf(w.value) === "htpasswd")));
    const last = positional[positional.length - 1];
    if (positional.length >= 2 && last !== undefined && values[last.i] !== marker("password")) {
      values[last.i] = marker("password");
      bump();
    }
  }
  // Here-document bodies are never logged.
  for (const w of words) {
    if (w.heredoc !== undefined) {
      extra.push(marker("heredoc"));
      bump();
    }
  }
  // Last pass over the whole text: formats that span several words (private key header).
  return maskPatterns([...values, ...extra].join(" "), bump);
}

function baseNameOf(value: string): string {
  const parts = value.split(/[\\/]/);
  return parts[parts.length - 1] ?? value;
}

/**
 * Redacted, normalized command text: simple commands (also those in substitutions and subshells) joined by ` ; `, words
 * unquoted and separated by one space, comments and here-document bodies left out. Returns null if the command cannot
 * be tokenized, in which case no command text must be logged.
 */
export function redactCommand(command: string): Redacted | null {
  let parsed;
  try {
    parsed = parseShell(command);
  } catch {
    return null;
  }
  let redactions = 0;
  const bump = (): void => {
    redactions += 1;
  };
  const text = parsed.commands.map((c) => renderCommand(c.words, command, bump)).join(" ; ");
  return { text, redactions };
}
