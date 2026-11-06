/**
 * Write-target detection for Bash commands.
 *
 * DEFENSE IN DEPTH, NOT A SECURITY BOUNDARY. This check stops the common and moderately obfuscated
 * ways an agent writes protected files from a shell. A determined process can always write files in
 * ways a static command-line check cannot see (script files, build tools, programs it starts). The
 * security boundary is review on the server side (protected paths, code owners, branch rules) plus
 * operating-system isolation (sandbox, read-only mounts, least privilege).
 *
 * Collects the files a command line may write (redirections, known writer commands, interpreters with
 * inline code, recursive `bash -c`) using the shell tokenizer and decides whether any of them can hit
 * a protected path. Where a target is only known at run time, it fails closed.
 *
 * Finding kinds:
 * - path:    absolute path (relative paths joined with every candidate working directory; ".." kept and
 *            resolved physically at decision time)
 * - glob:    unquoted glob/brace pattern, matched statically against the protected patterns
 * - dynamic: contains a parameter expansion; blocked unless it is a plain file below "$TMPDIR/"
 * - opaque:  command substitution, xargs input, dynamic command name, editor, unparseable script; blocked
 * - patch:   git apply/git am/patch (may write anywhere); blocked unless check-only
 * - code:    inline interpreter code (python -c, node -e, awk/sed scripts, literal here-documents);
 *            blocked if a list-based heuristic finds a write or process API (see codeScan.ts)
 * - stdin:   not used for decisions any more (code from a pipe or file is opaque); kept for compatibility
 * - assign:  the line assigns variables in a way the check cannot follow (voids the $TMPDIR exception)
 * - git:     git option or configuration that runs commands or redirects the repository; blocked
 * - link:    link created by the command line; later writes through it are blocked
 *
 * Mirrored 1:1 by a Python port; shared cases: test/fixtures/command-cases.json ("writes").
 */
import { lstatSync, readlinkSync, statSync } from "node:fs";
import { codeLanguage, writeIndicator } from "./codeScan.js";
import { foldGlob, foldPath } from "./paths.js";
import { parseShell, ShellSyntaxError, type ShellWord } from "./shell.js";

export { codeLanguage, writeIndicator } from "./codeScan.js";

/** Always protected for agents, in addition to the configured protected paths. */
export const ALWAYS_PROTECTED_PATHS: readonly string[] = [".git/config", ".git/config.worktree", ".git/hooks/", ".tollgate/"];
/** @deprecated kept for callers of the first version; equals ALWAYS_PROTECTED_PATHS. */
export const GIT_PROTECTED_PATHS = ALWAYS_PROTECTED_PATHS;

/** Files below the home directory that configure shells, git, agents or credentials. */
export const HOME_PROTECTED_PATHS: readonly string[] = [
  ".gitconfig", ".git-credentials", ".config/git/", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
  ".profile", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".claude/", ".claude.json", ".config/claude/",
  ".ssh/", ".gnupg/", ".npmrc", ".yarnrc", ".pypirc", ".netrc", ".config/gh/", ".config/pip/", ".docker/",
  ".bash_aliases", ".aws/", ".kube/", ".config/systemd/", ".config/autostart/", ".config/fish/", ".local/bin/", "bin/",
  ".vimrc", ".inputrc",
  // macOS persistence and agent configuration: launch agents and Claude Desktop. Not all of `.config/`.
  "Library/LaunchAgents/", "Library/Application Support/Claude/",
];

/** Commands longer than this (UTF-8 bytes) are blocked: bounds the run time of the checks. */
export const MAX_COMMAND_BYTES = 32768;

export type FindingKind = "path" | "glob" | "dynamic" | "opaque" | "patch" | "code" | "stdin" | "git" | "link" | "assign";

export interface WriteFinding {
  kind: FindingKind;
  value: string;
  /** Command or construct that produced the finding (for messages and language detection). */
  via: string;
}

export interface WriteAnalysis {
  findings: WriteFinding[];
  /** Raw scripts and all word values seen (including decoded quotes and inline scripts). */
  texts: string[];
}

export interface WriteOptions {
  /** Absolute project directory. */
  root: string;
  /** Working directory of the Bash tool (hook input `cwd`), if known; must be absolute. */
  cwd?: string | undefined;
  /** Home directory for `~` and the protected home files; undefined or empty: unknown. */
  home?: string | undefined;
  /** Directory probe for copy destinations; default: filesystem. */
  isDir?: ((path: string) => boolean) | undefined;
  /** Value of TMPDIR for the "$TMPDIR/..." exception (only below a fixed temporary root); undefined: no exception. */
  tmpdir?: string | undefined;
  /** Project boundary for write targets (see DecideOptions.boundary); undefined: no boundary check. */
  boundary?: ((path: string) => boolean) | undefined;
}

/** A block by the project boundary carries `kind: "outside_project"` (same kind as for the write tools). */
export type WriteDecision = { allowed: true } | { allowed: false; reason: string; kind?: "outside_project" };

const MAX_DEPTH = 8;
const MAX_BASES = 64;
const MAX_LINKS = 40;
const WRITE_REDIRECTS = new Set([">", ">>", ">|", "<>", "&>", "&>>"]);
const FD_PREFIX = /^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})$/;
const FD_TARGET = /^(?:[0-9]+-?|-)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
const KEYWORDS = new Set(["{", "}", "!", "if", "then", "else", "elif", "do", "while", "until"]);
const PROCESS_SUBSTITUTION = /^[<>]\(/;
const TOPLEVEL = /^"?\$\(git rev-parse --show-toplevel\)"?$/;
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "rbash", "fish", "csh", "tcsh"]);
/** C shells: their scripts are read with the POSIX tokenizer, which does not know the csh forms below. */
const CSH_SHELLS = new Set(["csh", "tcsh"]);
/** csh-only redirections (`>!`, `>>!`, `>&!`, `>>&`, `>>&!`) that the POSIX tokenizer would not see as a file target. */
const CSH_REDIRECT = />>?&?!|>>&/;
const AWKS = new Set(["awk", "gawk", "mawk", "nawk"]);
const EDITORS = new Set(["ed", "red", "ex", "vi", "vim", "nvim", "view", "vimdiff", "nano", "pico", "emacs", "joe", "micro", "kak", "hx"]);
const COMPRESSORS = new Set([
  "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "lzma", "unlzma", "zstd", "unzstd", "lz4", "unlz4",
  "compress", "uncompress", "pigz", "unpigz", "lzip", "brotli",
]);
const COMPRESSED_SUFFIX = /\.(?:gz|bz2|xz|lzma|zst|lz4|Z|lz|br|tgz|taz)$/;
const PYTHON = /^(?:python|pypy)[0-9.]*$/;
const PERL = /^perl[0-9.]*$/;
const RUBY = /^ruby[0-9.]*$/;
const PHP = /^php[0-9.]*$/;

interface Tok {
  value: string;
  /** Source text of the word ("" for synthetic tokens). */
  raw: string;
  quoted: boolean;
  executes: boolean;
  splittable: boolean;
  expands: boolean;
  redirect: boolean;
  heredoc: string | null;
  start: number;
  end: number;
}

type ItemKind = "static" | "glob" | "dynamic" | "opaque";
interface Item {
  kind: ItemKind;
  value: string;
}

interface Spec {
  /** Short options with a required argument (rest of the cluster or next word). */
  arg: string;
  /** Short options with an optional argument (only the rest of the cluster). */
  opt: string;
  /** Long options with a required argument (`--x=v` or `--x v`). */
  long: readonly string[];
  /** Long options without argument whose names matter (for GNU abbreviations like `--no-t`). */
  flags: readonly string[];
}

interface Opt {
  name: string;
  value: Tok | null;
}

interface Parsed {
  index: number;
  opts: Opt[];
  operands: Tok[];
  /** An option word may hide an argument (ambiguous abbreviation, expanding word before `--`). */
  uncertain: boolean;
}

interface Stdin {
  kind: "heredoc" | "herestring" | "file";
  text: string;
}

function spec(arg = "", opt = "", long: readonly string[] = [], flags: readonly string[] = []): Spec {
  return { arg, opt, long, flags };
}

const NO_OPTIONS = spec();
const WRAPPERS: Readonly<Record<string, Spec>> = {
  sudo: spec("ugCDhprtUTR", "", ["--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout", "--chroot"]),
  doas: spec("uC"),
  nice: spec("n", "", ["--adjustment"]),
  stdbuf: spec("ioe", "", ["--input", "--output", "--error"]),
  ionice: spec("cn", "", ["--class", "--classdata"]),
  exec: spec("a"),
  setsid: NO_OPTIONS,
  chronic: NO_OPTIONS,
  unbuffer: NO_OPTIONS,
  nohup: NO_OPTIONS,
  builtin: NO_OPTIONS,
  command: NO_OPTIONS,
  busybox: NO_OPTIONS,
  toybox: NO_OPTIONS,
};
const TIMEOUT = spec("sk", "", ["--signal", "--kill-after"]);
const TIME = spec("of", "", ["--output", "--format"]);
const ENV = spec("uCSP", "", ["--unset", "--chdir", "--split-string"]);
const XARGS = spec("adEILnPs", "eil", ["--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"]);
const FLOCK = spec("wEc", "", ["--timeout", "--wait", "--conflict-exit-code", "--command"]);
const SU = spec("csgGw", "", ["--command", "--session-command", "--shell", "--group", "--supp-group", "--whitelist-environment"]);
const SCRIPT = spec("cEIOBTm", "t", ["--command", "--echo", "--log-in", "--log-out", "--log-io", "--log-timing", "--logging-format"]);
const UNSHARE = spec("SGRw", "", ["--setuid", "--setgid", "--root", "--wd", "--propagation", "--map-user", "--map-group", "--map-users", "--map-groups", "--setgroups"]);
const SUDO_SHELL = ["-s", "-i", "--shell", "--login"];
const TASKSET = spec("", "", [], ["--all-tasks", "--pid", "--cpu-list"]);
const CHRT = spec("T", "", ["--sched-runtime", "--sched-period", "--sched-deadline"]);
const FAKEROOT = spec("lsib", "", ["--lib", "--faked"]);
const TRACE = spec("abeEIoOpPsSuUXAn", "", ["--output", "--attach", "--trace", "--signal", "--user"]);
const XVFB = spec("efnpsw", "", ["--error-file", "--auth-file", "--server-num", "--xauth-protocol", "--server-args", "--wait"]);
const WATCH = spec("nq", "d", ["--interval", "--equexit"], ["--exec", "--differences"]);
const CURL = spec("bcCdDeEFHKmorTuUwxXyYzAQt", "", [
  "--output", "--dump-header", "--cookie-jar", "--trace", "--trace-ascii", "--stderr", "--etag-save", "--libcurl",
  "--output-dir", "--config", "--hsts", "--alt-svc", "--data", "--header", "--user-agent", "--url", "--request",
  "--user", "--proxy", "--cookie", "--form", "--referer", "--max-time", "--connect-timeout", "--retry", "--range",
  "--upload-file", "--write-out", "--cacert", "--cert", "--key",
], ["--remote-name", "--remote-name-all", "--create-dirs", "--silent", "--location", "--fail", "--insecure", "--include", "--head", "--verbose", "--compressed"]);
const WGET = spec("OoaPiBeTtUwQYlADRIX", "", [
  "--output-document", "--output-file", "--append-output", "--directory-prefix", "--input-file", "--base", "--execute",
  "--timeout", "--tries", "--user-agent", "--wait", "--quota", "--level", "--domains", "--reject", "--accept",
  "--include-directories", "--exclude-directories", "--header", "--post-data", "--post-file", "--save-cookies",
  "--load-cookies", "--warc-file", "--rejected-log", "--hsts-file", "--config",
], ["--spider", "--quiet", "--no-verbose", "--continue", "--recursive", "--mirror", "--page-requisites", "--force-directories", "--no-directories"]);
const UNIQ = spec("fsw", "", ["--skip-fields", "--skip-chars", "--check-chars", "--all-repeated", "--group"]);
const SHUF = spec("inoe", "", ["--input-range", "--head-count", "--output", "--random-source"], ["--echo", "--repeat", "--zero-terminated"]);
const YQ = spec("oIpe", "", ["--output-format", "--input-format", "--indent", "--expression", "--arg", "--argjson"], ["--inplace", "--in-place"]);
const XXD = spec("cglosnC", "", ["-cols", "-groupsize", "-len", "-seek", "-name"]);
const LESS = spec("bhjkoOpPtTxyz#", "", ["--log-file", "--LOG-FILE", "--tag", "--pattern", "--prompt", "--tabs", "--shift", "--window", "--max-back-scroll", "--max-forw-scroll", "--buffers", "--jump-target"]);
const INFO = spec("odfnI", "", ["--output", "--directory", "--file", "--node"]);
const BASE64 = spec("oiwb", "", ["--output", "--input", "--wrap", "--break"]);
const SDIFF = spec("ow", "", ["--output", "--width", "--diff-program"]);
const ASSIGNING = new Set(["export", "declare", "typeset", "readonly", "local", "env", "read", "printf", "mapfile", "readarray", "getopts", "let", "unset"]);
/** Assignments to these variables run code later (prompt, trace prefix, startup file, exported function). */
const CODE_VARIABLE = /^(?:PS[0-4]|PROMPT_COMMAND|BASH_ENV|BASH_FUNC_[^=]*|PROMPT_DIRTRIM)\+?=[\s\S]/;
/** Commands whose arguments are data; the generic wrapper rule does not look into them. */
const DATA_COMMANDS = new Set([
  "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "head", "tail", "less", "more", "wc", "jq", "yq",
  "cut", "tr", "diff", "cmp", "comm", "ls", "stat", "file", "which", "type", "whereis", "man", "help", "info", "test", "[",
  "[[", "true", "false", ":", "printenv", "basename", "dirname", "realpath", "readlink", "date", "sleep", "expr", "seq",
  "column", "fold", "nl", "od", "hexdump", "xxd", "base64", "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum",
  "kill", "pkill", "pgrep", "ps", "id", "whoami", "hostname", "uname", "tput", "clear", "history", "export", "declare",
  "typeset", "readonly", "local", "unset", "set", "shopt", "return", "exit", "wait", "jobs", "pwd", "cd", "pushd", "popd",
  "dirs", "hash", "umask", "ulimit", "getopts", "let", "shift", "break", "continue", "read", "case", "for", "select", "in",
  "esac", "fi", "done", "return", "logger", "notify-send", "say",
]);
/** Writers whose operands are all targets. */
const ALL_OPERANDS: Readonly<Record<string, Spec>> = {
  tee: NO_OPTIONS,
  rm: NO_OPTIONS,
  rmdir: NO_OPTIONS,
  unlink: NO_OPTIONS,
  shred: spec("ns", "", ["--iterations", "--size", "--random-source"]),
  truncate: spec("sr", "", ["--size", "--reference"]),
  touch: spec("drt", "", ["--date", "--reference"]),
  chmod: NO_OPTIONS,
  chown: NO_OPTIONS,
  chgrp: NO_OPTIONS,
  mkdir: spec("m", "", ["--mode"]),
  mkfifo: spec("m", "", ["--mode"]),
  mktemp: spec("p"),
  rename: NO_OPTIONS,
  prename: NO_OPTIONS,
  "file-rename": NO_OPTIONS,
  "perl-rename": NO_OPTIONS,
  rsync: spec("efTBM", "", ["--rsh", "--filter", "--exclude", "--include", "--files-from", "--exclude-from", "--include-from", "--temp-dir", "--log-file", "--rsync-path", "--backup-dir", "--partial-dir", "--compare-dest", "--copy-dest", "--link-dest", "--chmod", "--chown", "--block-size", "--max-size", "--min-size", "--timeout", "--port", "--password-file", "--remote-option"]),
};
/** Option values that are write targets too. */
const TARGET_OPTIONS: Readonly<Record<string, readonly string[]>> = { mktemp: ["-p"] };
const COPY_LIKE: Readonly<Record<string, Spec>> = {
  link: NO_OPTIONS,
  cp: spec("St", "", ["--suffix", "--target-directory", "--no-preserve", "--sparse"], [
    "--no-target-directory", "--link", "--symbolic-link", "--strip-trailing-slashes", "--no-clobber", "--no-dereference",
    "--parents", "--preserve", "--recursive", "--remove-destination", "--reflink", "--update", "--verbose", "--archive",
    "--attributes-only", "--backup", "--copy-contents", "--dereference", "--force", "--interactive", "--one-file-system",
    "--debug", "--keep-directory-symlink",
  ]),
  mv: spec("St", "", ["--suffix", "--target-directory"], [
    "--no-target-directory", "--backup", "--force", "--interactive", "--no-clobber", "--strip-trailing-slashes", "--update",
    "--verbose", "--context", "--exchange", "--no-copy", "--debug",
  ]),
  ln: spec("St", "", ["--suffix", "--target-directory"], [
    "--symbolic", "--no-target-directory", "--backup", "--directory", "--force", "--interactive", "--logical",
    "--no-dereference", "--physical", "--relative", "--verbose",
  ]),
  install: spec("Stmog", "", ["--suffix", "--target-directory", "--mode", "--owner", "--group", "--strip-program"], [
    "--directory", "--no-target-directory", "--strip", "--backup", "--compare", "--preserve-timestamps", "--verbose",
    "--context", "--debug", "--preserve-context",
  ]),
};
const SED = spec("efl", "i", ["--expression", "--file", "--line-length"], [
  "--in-place", "--quiet", "--silent", "--null-data", "--zero-terminated", "--regexp-extended", "--separate",
  "--unbuffered", "--posix", "--sandbox", "--debug", "--follow-symlinks", "--binary",
]);
const SORT = spec("kotST", "", ["--output", "--key", "--field-separator", "--buffer-size", "--temporary-directory", "--compress-program", "--files0-from", "--parallel", "--batch-size", "--random-source", "--sort"]);
const SPLIT = spec("abClnt", "dx", ["--suffix-length", "--bytes", "--line-bytes", "--lines", "--number", "--separator", "--additional-suffix", "--filter"]);
const COMPRESS = spec("So", "", ["--suffix", "--output"], ["--stdout", "--to-stdout", "--test", "--list", "--keep", "--decompress", "--uncompress", "--force"]);
const CPIO = spec("FOIDHRCME", "", ["--file", "--directory", "--format", "--owner", "--io-size", "--message", "--pattern-file"], ["--extract", "--create", "--pass-through", "--to-stdout", "--list"]);
const PERL_SPEC = spec("eEIMm", "il0xCdDF");
const RUBY_SPEC = spec("eIrEC", "ixF0KTW");
const PYTHON_SPEC = spec("cWXm", "", ["--check-hash-based-pycs"]);
const PHP_SPEC = spec("rBREcdfz");
const AWK_SPEC = spec("Fvfeil", "", ["--field-separator", "--assign", "--file", "--source", "--include", "--exec", "--load"]);
const TAR_SPEC = spec("fCTXbFHKLNVgI", "", ["--file", "--directory", "--files-from", "--exclude-from", "--blocking-factor", "--format", "--info-script", "--new-volume-script", "--starting-file", "--newer", "--after-date", "--label", "--listed-incremental", "--use-compress-program", "--exclude"], [
  "--extract", "--get", "--to-stdout", "--create", "--append", "--update", "--catenate", "--concatenate", "--delete", "--list", "--diff", "--compare",
]);
const UNZIP_SPEC = spec("d");
const GIT_GLOBAL_WITH_ARG = new Set(["-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"]);
const GIT_CHECKOUT = spec("bB", "", ["--orphan", "--conflict", "--pathspec-from-file"]);
const GIT_RESTORE = spec("s", "", ["--source", "--conflict", "--pathspec-from-file"], [
  "--staged", "--worktree", "--patch", "--quiet", "--progress", "--no-progress", "--ours", "--theirs", "--merge",
  "--ignore-unmerged", "--overlay", "--no-overlay", "--recurse-submodules", "--pathspec-file-nul",
]);
const GIT_RM = spec("", "", ["--pathspec-from-file"], ["--cached", "--force", "--dry-run", "--quiet", "--ignore-unmatch", "--sparse", "--pathspec-file-nul"]);
const GIT_CONFIG = spec("f", "", ["--file", "--blob", "--default", "--comment", "--value", "--url"], [
  "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list", "--edit", "--add",
  "--replace-all", "--unset", "--unset-all", "--rename-section", "--remove-section",
]);
const GIT_CLONE = spec("cbojuh", "", ["--config", "--branch", "--origin", "--jobs", "--upload-pack", "--template", "--reference", "--depth", "--separate-git-dir"]);
const GIT_INIT = spec("b", "", ["--template", "--separate-git-dir", "--initial-branch", "--object-format", "--shared"]);
const GIT_OUTPUT = spec("o", "", ["--output", "--output-directory"]);
const GIT_REBASE = spec("xsXC", "", ["--exec", "--strategy", "--strategy-option", "--onto", "--whitespace"]);
const GIT_READ_CONFIG = ["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list", "-l"];
const GIT_EXEC_OPTIONS = /^--(?:upload-pack|receive-pack|exec)(?:=|$)/;
const DANGEROUS_SECTIONS = new Set(["alias", "filter", "credential", "pager", "protocol", "include", "includeif", "browser", "man", "difftool", "mergetool", "instaweb", "sendemail", "gpg", "ssh", "trace2"]);
const DANGEROUS_NAMES = new Set([
  "fsmonitor", "sshcommand", "editor", "pager", "askpass", "gitproxy", "hookspath", "external", "program", "templatedir",
  "packobjectshook", "uploadpack", "receivepack", "driver", "command", "textconv", "helper", "cmd", "browser", "proxycommand",
  "vcs", "alternaterefscommand",
]);
const NODE_CODE_FLAGS = new Set(["-e", "--eval", "-p", "--print", "-pe", "-ep"]);
const NODE_WITH_ARG = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type", "--env-file"]);
const STDIN_PATHS = new Set(["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"]);
/** Names that start a command the analysis understands (writers, shells, interpreters, wrappers, builtins). */
const STARTERS = new Set([
  ...Object.keys(ALL_OPERANDS), ...Object.keys(COPY_LIKE), ...Object.keys(WRAPPERS), ...SHELLS, ...AWKS, ...EDITORS, ...COMPRESSORS,
  "timeout", "time", "env", "xargs", "flock", "unshare", "taskset", "chrt", "setarch", "linux32", "linux64", "fakeroot",
  "strace", "ltrace", "xvfb-run", "firejail", "watch", "parallel", "sem", "sed", "perl", "ruby", "python", "python3", "node",
  "nodejs", "bun", "deno", "php", "dd", "sort", "split", "mmv", "cpio", "tar", "unzip", "patch", "find", "git", "su", "runuser",
  "script", "chroot", "fc", "eval", "source", ".", "curl", "wget", "uniq", "shuf", "sponge", "trap", "alias", "complete",
  "compgen", "mapfile", "readarray", "enable", "sudoedit", "yq", "xxd", "history", "less", "info", "base64", "sdiff",
]);
/** Starter names that are also common subcommands or words (`gh pr view`, `kubectl patch`, `npm view`): not used by the generic rule. */
const AMBIGUOUS_STARTERS = new Set(["view", "patch", "script", "time", "watch", "sort", "split", "uniq", "shuf", "find", "link", "enable", "complete", "compgen", "fc", "sem", "ed", "red", "ex", "kak", "hx", "micro", "joe", "mapfile", "readarray"]);

function toTok(word: ShellWord, src: string): Tok {
  return {
    value: word.value,
    raw: src.slice(word.start, word.end),
    quoted: word.quoted,
    executes: word.executes,
    splittable: word.splittable,
    expands: word.expands,
    redirect: word.redirect,
    heredoc: word.heredoc ?? null,
    start: word.start,
    end: word.end,
  };
}

function synthetic(item: Item): Tok {
  return {
    value: item.value,
    raw: "",
    quoted: false,
    executes: item.kind === "opaque",
    splittable: item.kind === "glob",
    expands: item.kind === "dynamic" || item.kind === "opaque",
    redirect: false,
    heredoc: null,
    start: -1,
    end: -1,
  };
}

/** Token for an attached option value (`-tDIR`, `--target-directory=DIR`, `of=FILE`). */
function attached(word: Tok, value: string): Tok {
  return { ...word, value, heredoc: null };
}

function plain(word: Tok | undefined): word is Tok {
  return word !== undefined && !word.executes && !word.splittable && !word.redirect && !word.expands;
}

/** One synthetic word joining the values of several words with spaces (command strings for `sh -c`). */
function joined(words: Tok[]): Tok {
  return {
    value: words.map((w) => w.value).join(" "),
    raw: "",
    quoted: false,
    executes: words.some((w) => w.executes),
    splittable: false,
    expands: words.some((w) => w.expands || w.executes),
    redirect: false,
    heredoc: null,
    start: -1,
    end: -1,
  };
}

function dynamicWord(word: Tok): boolean {
  return word.executes || word.expands || word.splittable;
}

/** Lexically normalized absolute path ("." and ".." resolved, repeated slashes collapsed). */
export function normalizeAbsolute(path: string): string {
  const out: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  return `/${out.join("/")}`;
}

/** Absolute path with "." and empty segments removed; ".." is kept (resolved physically later). */
export function cleanPath(path: string): string {
  return `/${path.split("/").filter((s) => s !== "" && s !== ".").join("/")}`;
}

function join(base: string, path: string): string {
  return cleanPath(path.startsWith("/") ? path : `${base}/${path}`);
}

function isMissing(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * Resolves a path the way the kernel does: component by component, following symlinks (also dangling
 * ones), ".." applied to the resolved parent. Missing components are kept literally. Throws on more
 * than 40 links or unexpected filesystem errors (callers fail closed).
 */
export function physicalPath(path: string): string {
  const queue = path.split("/").filter((s) => s !== "" && s !== ".");
  let out: string[] = [];
  let links = 0;
  while (queue.length > 0) {
    const seg = queue.shift() as string;
    if (seg === "..") {
      out.pop();
      continue;
    }
    const candidate = `/${[...out, seg].join("/")}`;
    let link = false;
    try {
      link = lstatSync(candidate).isSymbolicLink();
    } catch (error) {
      if (!isMissing(error)) throw error;
    }
    if (link) {
      links += 1;
      if (links > MAX_LINKS) throw new Error(`Too many symlink levels: ${path}`);
      const target = readlinkSync(candidate);
      if (target.startsWith("/")) out = [];
      queue.unshift(...target.split("/").filter((s) => s !== "" && s !== "."));
      continue;
    }
    out.push(seg);
  }
  return `/${out.join("/")}`;
}

function baseName(path: string): string {
  let end = path.length;
  while (end > 0 && path.charAt(end - 1) === "/") end -= 1;
  const trimmed = path.slice(0, end);
  return trimmed.slice(trimmed.lastIndexOf("/") + 1);
}

function dirName(path: string): string {
  let end = path.length;
  while (end > 0 && path.charAt(end - 1) === "/") end -= 1;
  const trimmed = path.slice(0, end);
  const i = trimmed.lastIndexOf("/");
  return i < 0 ? "." : i === 0 ? "/" : trimmed.slice(0, i);
}

function unique<T>(values: T[]): T[] {
  return values.filter((v, i) => values.indexOf(v) === i);
}

/** GNU-style option parser; with stopAtOperand it stops at the first operand (wrappers, interpreters). */
function parseOptions(args: Tok[], start: number, sp: Spec, stopAtOperand: boolean): Parsed {
  const opts: Opt[] = [];
  const operands: Tok[] = [];
  let uncertain = false;
  let ended = false;
  for (let j = start; j < args.length; j += 1) {
    const a = args[j] as Tok;
    // Option words may contain brace/glob characters (`-I{}`); expansions make the option unknown.
    const optionLike = !ended && a.value.startsWith("-") && a.value !== "-" && !a.executes && !a.expands && !a.redirect;
    if (!optionLike) {
      // An expanding word before "--" may turn into an option (e.g. "$X" = "-t"); globs only match file names.
      if (!ended && (a.expands || a.executes)) uncertain = true;
      if (stopAtOperand) return { index: j, opts, operands, uncertain };
      operands.push(a);
      continue;
    }
    if (a.value === "--") {
      ended = true;
      if (stopAtOperand) return { index: j + 1, opts, operands, uncertain };
      continue;
    }
    if (a.value.startsWith("--")) {
      const eq = a.value.indexOf("=");
      const given = eq < 0 ? a.value : a.value.slice(0, eq);
      let name = given;
      const known = [...sp.long, ...sp.flags];
      if (!known.includes(given)) {
        const candidates = known.filter((n) => n.startsWith(given));
        if (candidates.length === 1) name = candidates[0] as string;
        else if (candidates.length > 1) uncertain = true;
      }
      if (eq >= 0) {
        opts.push({ name, value: attached(a, a.value.slice(eq + 1)) });
      } else if (sp.long.includes(name)) {
        opts.push({ name, value: args[j + 1] ?? null });
        j += 1;
      } else {
        opts.push({ name, value: null });
      }
      continue;
    }
    const chars = Array.from(a.value);
    for (let c = 1; c < chars.length; c += 1) {
      const ch = chars[c] as string;
      const rest = chars.slice(c + 1).join("");
      if (sp.arg.includes(ch)) {
        if (rest !== "") {
          opts.push({ name: `-${ch}`, value: attached(a, rest) });
        } else {
          opts.push({ name: `-${ch}`, value: args[j + 1] ?? null });
          j += 1;
        }
        break;
      }
      if (sp.opt.includes(ch)) {
        opts.push({ name: `-${ch}`, value: attached(a, rest) });
        break;
      }
      opts.push({ name: `-${ch}`, value: null });
    }
  }
  return { index: args.length, opts, operands, uncertain };
}

function has(p: Parsed, ...names: string[]): boolean {
  return p.opts.some((o) => names.includes(o.name));
}

function values(p: Parsed, ...names: string[]): Tok[] {
  return p.opts.filter((o) => names.includes(o.name) && o.value !== null).map((o) => o.value as Tok);
}

/** True if setting this git configuration key can run a command, load other configuration or disable hooks. */
export function dangerousGitKey(key: string): boolean {
  const parts = key.toLowerCase().split(".");
  if (parts.length < 2) return false;
  const section = parts[0] as string;
  const name = parts[parts.length - 1] as string;
  if (section === "submodule" && name === "update") return true; // "!command" runs on submodule update
  if (section === "core" && name === "worktree") return true; // moves the working tree
  return DANGEROUS_SECTIONS.has(section) || DANGEROUS_NAMES.has(name);
}

class Analyzer {
  readonly findings: WriteFinding[] = [];
  readonly texts: string[] = [];
  private readonly seen = new Set<string>();

  constructor(private readonly opts: WriteOptions) {}

  private add(kind: FindingKind, value: string, via: string): void {
    const key = `${kind}\0${value}\0${via}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.findings.push({ kind, value, via });
  }

  private classify(tok: Tok | null | undefined): Item | null {
    if (tok === null || tok === undefined) return null;
    if (tok.executes) {
      // Process substitution: the commands inside are analyzed on their own.
      if (PROCESS_SUBSTITUTION.test(tok.raw) && tok.raw.endsWith(")")) return null;
      return { kind: "opaque", value: tok.value };
    }
    let value = tok.value;
    if (tok.raw.startsWith("~")) {
      const home = this.opts.home;
      if ((value === "~" || value.startsWith("~/")) && home) value = home + value.slice(1);
      else return { kind: "dynamic", value };
    }
    if (tok.expands) return { kind: "dynamic", value };
    if (value === "") return null;
    return { kind: tok.splittable ? "glob" : "static", value };
  }

  private emit(item: Item | null, bases: string[] | null, via: string, kind: FindingKind | null = null): void {
    if (item === null) return;
    if (item.kind === "dynamic" || item.kind === "opaque") {
      this.add(item.kind, item.value, via);
      return;
    }
    const out: FindingKind = kind ?? (item.kind === "glob" ? "glob" : "path");
    if (item.value.startsWith("/")) {
      this.add(out, cleanPath(item.value), via);
    } else if (bases === null) {
      this.add("dynamic", item.value, via);
    } else {
      for (const b of bases) this.add(out, join(b, item.value), via);
    }
  }

  private emitTok(tok: Tok | null | undefined, bases: string[] | null, via: string): void {
    this.emit(this.classify(tok), bases, via);
  }

  /** Path written when copying src into the directory dest. */
  private child(dest: Item | null, src: Item | null): Item | null {
    if (dest === null || dest.kind === "dynamic" || dest.kind === "opaque") return dest;
    if (src === null || src.kind === "dynamic" || src.kind === "opaque") return dest;
    const name = baseName(src.value);
    if (name === "" || name === "." || name === "..") return dest;
    return { kind: dest.kind === "glob" || src.kind === "glob" ? "glob" : "static", value: `${dest.value}/${name}` };
  }

  private isDir(item: Item | null, bases: string[] | null): boolean {
    if (item === null || item.kind !== "static") return false;
    const probe = this.opts.isDir ?? defaultIsDir;
    if (item.value.startsWith("/")) return probe(cleanPath(item.value));
    return bases !== null && bases.some((b) => probe(join(b, item.value)));
  }

  private rebase(bases: string[] | null, dir: Tok | null | undefined): string[] | null {
    const item = this.classify(dir);
    if (bases === null || item === null || item.kind !== "static") return null;
    return unique(bases.map((b) => join(b, item.value)));
  }

  script(src: string, bases: string[] | null, depth: number, via: string): void {
    if (depth > MAX_DEPTH) {
      this.add("opaque", "nested inline scripts", via);
      return;
    }
    let commands: Tok[][];
    try {
      commands = parseShell(src).commands.map((c) => c.words.map((w) => toTok(w, src)));
    } catch (err) {
      if (depth === 0 || !(err instanceof ShellSyntaxError)) throw err;
      this.add("opaque", "unparseable inline script", via);
      return;
    }
    this.texts.push(src);
    for (const words of commands) for (const w of words) this.texts.push(w.value);
    const scriptBases = this.directoryChanges(commands, bases);
    for (const words of commands) this.command(words, scriptBases, depth);
  }

  /** Union of all directories the command may run in: start bases plus every static `cd`/`pushd` target. */
  private directoryChanges(commands: Tok[][], bases: string[] | null): string[] | null {
    let result = bases;
    for (const words of commands) {
      const args = words.filter((w, k) => !w.redirect && !(k > 0 && (words[k - 1] as Tok).redirect));
      let i = 0;
      while (i < args.length && (ASSIGNMENT.test((args[i] as Tok).raw) || (!(args[i] as Tok).quoted && KEYWORDS.has((args[i] as Tok).value)))) i += 1;
      while (i < args.length && plain(args[i]) && ["command", "builtin"].includes((args[i] as Tok).value)) {
        i += 1;
        while (i < args.length && plain(args[i]) && (args[i] as Tok).value === "-p") i += 1;
      }
      const name = args[i];
      if (!plain(name) || (name.value !== "cd" && name.value !== "pushd")) continue;
      let j = i + 1;
      while (j < args.length && plain(args[j]) && (args[j] as Tok).value.startsWith("-") && (args[j] as Tok).value !== "-") {
        j += 1;
        if ((args[j - 1] as Tok).value === "--") break;
      }
      const target = args[j];
      let dir: string | null = null;
      if (target === undefined) {
        dir = this.opts.home ? this.opts.home : null;
      } else if (TOPLEVEL.test(target.raw)) {
        dir = this.opts.root;
      } else {
        const item = this.classify(target);
        if (item !== null && item.kind === "static" && item.value !== "-" && !/^[+-][0-9]+$/.test(item.value)) dir = item.value;
      }
      if (dir === null) {
        result = null;
        continue;
      }
      if (result === null) continue;
      const next = unique([...result, ...result.map((b) => join(b, dir))]);
      if (next.length > MAX_BASES) {
        this.add("opaque", "too many directory changes", "cd");
        return null;
      }
      result = next;
    }
    return result;
  }

  private command(words: Tok[], bases: string[] | null, depth: number): void {
    const args: Tok[] = [];
    let stdin: Stdin | null = null;
    for (let k = 0; k < words.length; k += 1) {
      const w = words[k] as Tok;
      if (w.redirect) {
        const t = words[k + 1];
        if (t !== undefined && !t.redirect) {
          k += 1;
          if (WRITE_REDIRECTS.has(w.value) || (w.value === ">&" && !(FD_TARGET.test(t.value) && !t.expands))) {
            this.emitTok(t, bases, "redirect");
          }
          if (w.value === "<<" || w.value === "<<-") stdin = { kind: "heredoc", text: t.heredoc ?? "" };
          else if (w.value === "<<<") stdin = { kind: "herestring", text: t.value };
          else if (w.value === "<" || w.value === "<>") stdin = { kind: "file", text: t.value };
        }
        continue;
      }
      const n = words[k + 1];
      if (n !== undefined && n.redirect && /^[<>]/.test(n.value) && w.end === n.start && !w.quoted && FD_PREFIX.test(w.value)) continue;
      args.push(w);
    }
    for (const w of args) if (CODE_VARIABLE.test(w.raw)) this.add("opaque", w.value, "shell variable that runs code");
    this.invocation(args, bases, depth, stdin);
  }

  private invocation(initial: Tok[], initialBases: string[] | null, depth: number, stdin: Stdin | null): void {
    let args = initial;
    let bases = initialBases;
    let i = 0;
    for (let guard = 0; guard < 64; guard += 1) {
      while (i < args.length && (ASSIGNMENT.test((args[i] as Tok).raw) || (!(args[i] as Tok).quoted && KEYWORDS.has((args[i] as Tok).value)))) i += 1;
      const w = args[i];
      if (w === undefined) return;
      if (dynamicWord(w)) {
        // The program is only known at run time ("$r" file, $(echo rm) file, /bin/r? file).
        this.add("opaque", w.value, "dynamic command name");
        return;
      }
      const name = baseName(w.value);
      if (ASSIGNING.has(name)) {
        const rest = args.slice(i + 1);
        const indirect = name !== "printf" || rest.some((a) => a.value.startsWith("-v"));
        if (indirect && rest.some((a) => a.expands || a.executes || a.value.includes("TMPDIR"))) this.add("assign", "", name);
      }
      if (!w.quoted && name === "function" && w.value === "function") {
        i += 2; // function NAME { body } - the body follows as commands
        continue;
      }
      if (!w.quoted && name === "coproc" && w.value === "coproc") {
        i += args[i + 2]?.value === "{" && !args[i + 2]?.quoted ? 2 : 1;
        continue;
      }
      if (name === "sudo" || name === "doas") {
        const p = parseOptions(args, i + 1, WRAPPERS[name] as Spec, true);
        if (has(p, "-e", "--edit")) {
          this.add("opaque", "sudo -e", "editor");
          return;
        }
        if (has(p, ...SUDO_SHELL) && p.index < args.length) {
          // The command is passed to a shell: analyze the joined words as a script.
          this.inlineScript(joined(args.slice(p.index)), bases, depth, `${name} -s`);
          return;
        }
        i = p.index;
        continue;
      }
      if (name === "command" || name === "builtin") {
        const p = parseOptions(args, i + 1, NO_OPTIONS, true);
        if (has(p, "-v", "-V")) return; // lookup only
        i = p.index;
        continue;
      }
      const wrapper = WRAPPERS[name];
      if (wrapper !== undefined) {
        i = parseOptions(args, i + 1, wrapper, true).index;
        continue;
      }
      if (name === "timeout") {
        i = parseOptions(args, i + 1, TIMEOUT, true).index + 1;
        continue;
      }
      if (name === "taskset" || name === "chrt") {
        const p = parseOptions(args, i + 1, name === "taskset" ? TASKSET : CHRT, true);
        if (has(p, "-p", "--pid")) return;
        i = p.index + 1; // CPU mask or priority
        continue;
      }
      if (name === "setarch" || name === "linux32" || name === "linux64") {
        i = parseOptions(args, i + (name === "setarch" ? 2 : 1), NO_OPTIONS, true).index;
        continue;
      }
      if (name === "fakeroot" || name === "strace" || name === "ltrace" || name === "xvfb-run" || name === "firejail") {
        const sp = name === "fakeroot" ? FAKEROOT : name === "xvfb-run" ? XVFB : name === "firejail" ? NO_OPTIONS : TRACE;
        const p = parseOptions(args, i + 1, sp, true);
        const outputs = name === "fakeroot" ? ["-s"] : name === "xvfb-run" ? ["-e", "-f", "--error-file", "--auth-file"] : ["-o", "--output", "--output-stderr"];
        for (const v of values(p, ...outputs)) this.emitTok(v, bases, name);
        if (has(p, "-p", "--attach")) return;
        i = p.index;
        continue;
      }
      if (name === "watch") {
        const p = parseOptions(args, i + 1, WATCH, true);
        if (p.index >= args.length) return;
        if (has(p, "-x", "--exec")) {
          i = p.index;
          continue;
        }
        this.inlineScript(joined(args.slice(p.index)), bases, depth, "watch");
        return;
      }
      if (name === "parallel" || name === "sem") {
        this.add("opaque", name, "parallel");
        return;
      }
      if (name === "time") {
        const p = parseOptions(args, i + 1, TIME, true);
        for (const v of values(p, "-o", "--output")) this.emitTok(v, bases, "time");
        i = p.index;
        continue;
      }
      if (name === "env") {
        const p = parseOptions(args, i + 1, ENV, true);
        for (const dir of values(p, "-C", "--chdir")) bases = this.rebase(bases, dir);
        const split = values(p, "-S", "--split-string");
        if (split.length > 0) {
          const s = split[split.length - 1] as Tok;
          if (dynamicWord(s)) {
            this.add("opaque", s.value, "env -S");
            return;
          }
          let parsed;
          try {
            parsed = parseShell(s.value);
          } catch {
            this.add("opaque", s.value, "env -S");
            return;
          }
          if (parsed.commands.length > 1 || parsed.operators.length > 0) {
            this.add("opaque", s.value, "env -S");
            return;
          }
          const head = (parsed.commands[0]?.words ?? []).map((x) => toTok(x, s.value));
          args = [...head, ...args.slice(p.index)];
          i = 0;
          continue;
        }
        i = p.index;
        continue;
      }
      if (name === "xargs") {
        const p = parseOptions(args, i + 1, XARGS, true);
        const repl = p.opts.filter((o) => ["-I", "-i", "--replace"].includes(o.name)).map((o) => (o.name === "-I" ? (o.value?.value ?? "") : o.value?.value || "{}"));
        const input = synthetic({ kind: "opaque", value: "<xargs input>" });
        const sub = args.slice(p.index);
        if (sub.length === 0) return;
        const r = repl[repl.length - 1];
        args = r ? sub.map((t) => (t.value.includes(r) ? input : t)) : [...sub, input];
        i = 0;
        continue;
      }
      if (name === "flock") {
        const p = parseOptions(args, i + 1, FLOCK, true);
        const lock = args[p.index];
        if (lock !== undefined && !/^[0-9]+$/.test(lock.value)) this.emitTok(lock, bases, "flock");
        const rest = args.slice(p.index + 1);
        const scripts = values(p, "-c", "--command");
        const after = rest[0];
        if (after !== undefined && plain(after) && (after.value === "-c" || after.value === "--command")) {
          scripts.push(...(rest[1] === undefined ? [] : [rest[1]]));
        }
        if (scripts.length > 0) {
          for (const s of scripts) this.inlineScript(s, bases, depth, "flock -c");
          return;
        }
        args = rest;
        i = 0;
        continue;
      }
      if (name === "unshare") {
        const p = parseOptions(args, i + 1, UNSHARE, true);
        if (has(p, "-R", "--root")) {
          this.add("opaque", "unshare --root", "unshare");
          return;
        }
        for (const dir of values(p, "-w", "--wd")) bases = this.rebase(bases, dir);
        i = p.index;
        continue;
      }
      if (this.dispatch(name, args.slice(i + 1), bases, depth, stdin)) return;
      if (DATA_COMMANDS.has(name)) return;
      // Unknown program: if one of its arguments names a known writer, shell, interpreter or wrapper and is
      // followed by further words, the program may run it (e.g. a wrapper we do not model). Analyze from there.
      for (let k = i + 1; k < args.length - 1; k += 1) {
        const t = args[k] as Tok;
        if (plain(t) && STARTERS.has(baseName(t.value)) && !AMBIGUOUS_STARTERS.has(baseName(t.value))) {
          this.invocation(args.slice(k), bases, depth, stdin);
          return;
        }
      }
      return;
    }
    this.add("opaque", "too many command wrappers", "wrapper");
  }

  private inlineScript(tok: Tok, bases: string[] | null, depth: number, via: string): void {
    if (tok.executes || tok.expands) this.add("opaque", tok.value, via);
    else this.script(tok.value, bases, depth + 1, via);
  }

  /** Analyzes a known command; false if the name is not handled (caller applies the generic rule). */
  private dispatch(name: string, args: Tok[], bases: string[] | null, depth: number, stdin: Stdin | null): boolean {
    const all = ALL_OPERANDS[name];
    if (all !== undefined) {
      const p = parseOptions(args, 0, all, false);
      for (const t of p.operands) this.emitTok(t, bases, name);
      for (const t of values(p, ...(TARGET_OPTIONS[name] ?? []))) this.emitTok(t, bases, name);
      return true;
    }
    const copy = COPY_LIKE[name];
    if (copy !== undefined) {
      this.copyLike(name, parseOptions(args, 0, copy, false), bases, name);
      return true;
    }
    if (SHELLS.has(name)) this.shell(name, args, bases, depth, stdin);
    else if (EDITORS.has(name) || name === "sudoedit") this.add("opaque", name, "editor");
    else if (COMPRESSORS.has(name)) this.compressor(name, args, bases);
    else if (name === "sed") this.sed(args, bases);
    else if (AWKS.has(name)) this.awk(name, args, bases);
    else if (PERL.test(name) || RUBY.test(name)) this.perlRuby(name, args, bases, stdin);
    else if (PYTHON.test(name)) this.python(name, args, stdin);
    else if (name === "node" || name === "nodejs" || name === "bun") this.node(name, args, stdin);
    else if (name === "deno") this.deno(args);
    else if (PHP.test(name)) this.php(name, args, stdin);
    else if (name === "dd") this.dd(args, bases);
    else if (name === "sort") this.sort(args, bases);
    else if (name === "split") this.split(args, bases, depth);
    else if (name === "mmv") for (const t of args) this.pathspec(t, bases, "mmv");
    else if (name === "cpio") this.cpio(args, bases);
    else if (name === "tar") this.tar(args, bases);
    else if (name === "unzip") this.unzip(args, bases);
    else if (name === "patch") this.patch(args);
    else if (name === "find") this.find(args, bases, depth);
    else if (name === "git") this.git(args, bases, depth);
    else if (name === "su" || name === "runuser") this.su(name, args, bases, depth);
    else if (name === "script") this.scriptCommand(args, bases, depth);
    else if (name === "chroot" || name === "fc" || name === "eval") this.add("opaque", name, name);
    else if (name === "source" || name === ".") this.source(name, args, bases, depth, stdin);
    else if (name === "curl") this.curl(args, bases);
    else if (name === "wget") this.wget(args, bases);
    else if (name === "uniq") this.emitTok(parseOptions(args, 0, UNIQ, false).operands[1], bases, "uniq");
    else if (name === "shuf") for (const t of values(parseOptions(args, 0, SHUF, false), "-o", "--output")) this.emitTok(t, bases, "shuf -o");
    else if (name === "sponge") for (const t of parseOptions(args, 0, NO_OPTIONS, false).operands) this.emitTok(t, bases, "sponge");
    else if (name === "trap") this.trap(args, bases, depth);
    else if (name === "yq") this.yq(args, bases);
    else if (name === "xxd") this.emitTok(parseOptions(args, 0, XXD, false).operands[1], bases, "xxd");
    else if (name === "history") this.history(args, bases);
    else if (name === "less") for (const t of values(parseOptions(args, 0, LESS, false), "-o", "-O", "--log-file", "--LOG-FILE")) this.emitTok(t, bases, "less -o");
    else if (name === "info") for (const t of values(parseOptions(args, 0, INFO, false), "-o", "--output")) this.emitTok(t, bases, "info -o");
    else if (name === "base64") {
      for (const t of values(parseOptions(args, 0, BASE64, false), "-o", "--output")) if (t.value !== "-") this.emitTok(t, bases, "base64 -o");
    }
    else if (name === "sdiff") for (const t of values(parseOptions(args, 0, SDIFF, false), "-o", "--output")) this.emitTok(t, bases, "sdiff -o");
    else if (name === "alias") this.alias(args, bases, depth);
    else if (name === "complete" || name === "compgen" || name === "mapfile" || name === "readarray") this.callback(name, args, bases, depth);
    else if (name === "enable" && args.some((a) => !plain(a) || a.value.startsWith("-f"))) this.add("opaque", "enable -f", "enable");
    else return false;
    return true;
  }

  /** `yq -i expr file...` edits the files in place (mikefarah and python yq). */
  private yq(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, YQ, false);
    if (!has(p, "-i", "--inplace", "--in-place")) return;
    const exprs = values(p, "-e", "--expression");
    for (const t of exprs.length > 0 ? p.operands : p.operands.slice(1)) this.emitTok(t, bases, "yq -i");
  }

  /** `history -w/-a [file]` writes the history file. */
  private history(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, NO_OPTIONS, false);
    if (has(p, "-w", "-a")) this.emitTok(p.operands[0], bases, "history -w");
  }

  /** `trap 'cmd' SIGNAL...`: the handler is a script; `trap - SIG`, `trap SIG`, `trap -l/-p` are not. */
  private trap(args: Tok[], bases: string[] | null, depth: number): void {
    const p = parseOptions(args, 0, NO_OPTIONS, false);
    if (has(p, "-l", "-p", "-P") || p.operands.length < 2) return;
    const handler = p.operands[0] as Tok;
    if (handler.value === "-" || (handler.value === "" && !dynamicWord(handler))) return;
    this.inlineScript(handler, bases, depth, "trap");
  }

  /** `alias name='cmd'`: the value runs when the alias is used. */
  private alias(args: Tok[], bases: string[] | null, depth: number): void {
    for (const a of args) {
      const eq = a.value.indexOf("=");
      if (eq > 0) this.inlineScript(attached(a, a.value.slice(eq + 1)), bases, depth, "alias");
      else if (dynamicWord(a)) this.add("opaque", a.value, "alias");
    }
  }

  /** `complete/compgen -C cmd`, `mapfile/readarray -C callback`: the command string runs. */
  private callback(name: string, args: Tok[], bases: string[] | null, depth: number): void {
    const p = parseOptions(args, 0, spec("CFGWXAoPSdnOsuc"), false);
    for (const v of values(p, "-C")) this.inlineScript(v, bases, depth, `${name} -C`);
  }

  private curl(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, CURL, false);
    if (has(p, "-K", "--config")) this.add("opaque", "curl --config", "curl");
    const dirs = values(p, "--output-dir");
    const dir: Tok | null = dirs.length > 0 ? (dirs[dirs.length - 1] as Tok) : null;
    for (const v of values(p, "-o", "--output")) {
      if (v.value === "-") continue;
      if (dir === null || v.value.startsWith("/")) this.emitTok(v, bases, "curl -o");
      else this.emit(this.child(this.classify(dir), this.classify(v)), bases, "curl -o");
    }
    for (const v of values(p, "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii", "--stderr", "--etag-save", "--libcurl", "--hsts", "--alt-svc")) {
      if (v.value !== "-") this.emitTok(v, bases, "curl");
    }
    // -O/--remote-name: the file name comes from the URL; the whole output directory counts.
    if (has(p, "-O", "--remote-name", "--remote-name-all", "-J", "--remote-header-name")) {
      if (dir === null) this.emit({ kind: "static", value: "." }, bases, "curl -O");
      else this.emitTok(dir, bases, "curl -O");
    }
  }

  private wget(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, WGET, false);
    if (has(p, "-e", "--execute", "--config", "-i", "--input-file")) this.add("opaque", "wget -e/-i/--config", "wget");
    for (const v of values(p, "-o", "--output-file", "-a", "--append-output", "--save-cookies", "--warc-file", "--rejected-log", "--hsts-file")) {
      this.emitTok(v, bases, "wget");
    }
    if (has(p, "--spider")) return;
    const documents = values(p, "-O", "--output-document");
    if (documents.length > 0) {
      for (const v of documents) if (v.value !== "-") this.emitTok(v, bases, "wget -O");
      return;
    }
    const dirs = values(p, "-P", "--directory-prefix");
    if (dirs.length === 0) this.emit({ kind: "static", value: "." }, bases, "wget");
    for (const d of dirs) this.emitTok(d, bases, "wget -P");
  }

  private copyLike(name: string, p: Parsed, bases: string[] | null, via: string): void {
    const items = p.operands.map((t) => this.classify(t));
    const linking = name === "ln" || name === "link" || has(p, "-l", "--link", "-s", "--symbolic-link");
    if (p.uncertain || (name === "install" && has(p, "-d", "--directory"))) {
      for (const item of items) this.emit(item, bases, via);
      for (const o of p.opts) if (o.value !== null) this.emitTok(o.value, bases, via);
      if (linking) this.add("link", "", via);
      return;
    }
    const symbolic = name === "ln" ? has(p, "-s", "--symbolic") : has(p, "-s", "--symbolic-link");
    const removed = name === "mv";
    const written: (Item | null)[] = [];
    const sources: (Item | null)[] = [];
    const tdirs = values(p, "-t", "--target-directory");
    if (tdirs.length > 0) {
      const dest = this.classify(tdirs[tdirs.length - 1]);
      for (const src of items) {
        sources.push(src);
        written.push(this.child(dest, src));
      }
    } else if (items.length === 1 && name === "ln") {
      sources.push(items[0] as Item | null);
      written.push(this.child({ kind: "static", value: "." }, items[0] as Item | null));
    } else if (items.length >= 2) {
      const dest = items[items.length - 1] as Item | null;
      sources.push(...items.slice(0, -1));
      const destTok = p.operands[p.operands.length - 1] as Tok;
      if (has(p, "-T", "--no-target-directory")) written.push(dest);
      else if (items.length > 2 || destTok.value.endsWith("/") || this.isDir(dest, bases)) {
        for (const src of sources) written.push(this.child(dest, src));
      } else written.push(dest);
    }
    if (removed) for (const src of sources) this.emit(src, bases, via);
    if (linking) {
      // A link to a protected file is a second name for it; also writes through the new link are blocked.
      for (const src of sources) {
        this.emit(src, bases, `${via} source`);
        if (symbolic && src !== null && src.kind === "static" && !src.value.startsWith("/")) {
          for (const w of written) if (w !== null && w.kind === "static") this.emit({ kind: "static", value: `${dirName(w.value)}/${src.value}` }, bases, `${via} source`);
        }
      }
      for (const w of written) {
        if (w === null || w.kind === "dynamic" || w.kind === "opaque" || (w.kind === "static" && !w.value.startsWith("/") && bases === null)) this.add("link", "", via);
        else this.emit(w, bases, via, "link");
      }
    }
    for (const w of written) this.emit(w, bases, via);
  }

  private inline(code: Tok | null | undefined, via: string): void {
    if (code === null || code === undefined) return;
    this.add("code", code.value, via);
  }

  /**
   * Code read from standard input: literal here-documents/here-strings are analyzed; anything else
   * (pipe, file, process substitution) is opaque, except /dev/null.
   */
  private stdinCode(stdin: Stdin | null, via: string): void {
    if (stdin === null) this.add("opaque", "code from a pipe", via);
    else if (stdin.kind !== "file") this.add("code", stdin.text, via);
    else if (stdin.text !== "/dev/null") this.add("opaque", `code from ${stdin.text}`, via);
  }

  /** Script operand of an interpreter: "-" and /dev/stdin read stdin; fd and /proc paths or dynamic words are opaque. */
  private scriptOperand(operand: Tok | undefined, stdin: Stdin | null, via: string, onStdin: () => void): void {
    if (operand === undefined || operand.value === "-" || STDIN_PATHS.has(operand.value)) {
      onStdin();
      return;
    }
    if (dynamicWord(operand) || operand.value.startsWith("/dev/fd/") || operand.value.startsWith("/proc/")) {
      this.add("opaque", operand.value, via);
    }
    // Otherwise a script file: its contents are not analyzed (documented limit).
  }

  private shell(name: string, args: Tok[], bases: string[] | null, depth: number, stdin: Stdin | null): void {
    let j = 0;
    let inline = false;
    let fromStdin = false;
    while (j < args.length) {
      const a = args[j] as Tok;
      if (!plain(a) || a.value.length < 2 || !"-+".includes(a.value.charAt(0))) break;
      j += 1;
      if (a.value === "--") break;
      if (["-o", "+o", "-O", "+O", "--rcfile", "--init-file"].includes(a.value)) j += 1;
      else if (!a.value.startsWith("--")) {
        if (a.value.slice(1).includes("c")) inline = true;
        if (a.value.slice(1).includes("s")) fromStdin = true;
      }
    }
    const operand = args[j];
    const csh = CSH_SHELLS.has(name);
    if (inline) {
      if (operand !== undefined && csh && CSH_REDIRECT.test(operand.value)) this.add("opaque", operand.value, `${name} -c`);
      else if (operand !== undefined) this.inlineScript(operand, bases, depth, `${name} -c`);
      return;
    }
    const readStdin = (): void => {
      if (stdin === null) this.add("opaque", "script from a pipe", name);
      else if (stdin.kind !== "file" && csh && CSH_REDIRECT.test(stdin.text)) this.add("opaque", "csh redirection", name);
      else if (stdin.kind !== "file") this.script(stdin.text, bases, depth + 1, name);
      else if (stdin.text !== "/dev/null") this.add("opaque", `script from ${stdin.text}`, name);
    };
    if (fromStdin) readStdin(); // -s: operands are arguments, the script comes from stdin
    else this.scriptOperand(operand, stdin, name, readStdin);
  }

  private source(name: string, args: Tok[], bases: string[] | null, depth: number, stdin: Stdin | null): void {
    const file = args[0];
    if (file === undefined) return;
    this.scriptOperand(file, stdin, name, () => {
      if (stdin === null) this.add("opaque", "script from a pipe", name);
      else if (stdin.kind !== "file") this.script(stdin.text, bases, depth + 1, name);
      else if (stdin.text !== "/dev/null") this.add("opaque", `script from ${stdin.text}`, name);
    });
  }

  private su(name: string, args: Tok[], bases: string[] | null, depth: number): void {
    const p = parseOptions(args, 0, SU, false);
    for (const s of values(p, "-c", "--command", "--session-command")) this.inlineScript(s, bases, depth, `${name} -c`);
  }

  private scriptCommand(args: Tok[], bases: string[] | null, depth: number): void {
    const p = parseOptions(args, 0, SCRIPT, false);
    for (const s of values(p, "-c", "--command")) this.inlineScript(s, bases, depth, "script -c");
    for (const t of values(p, "-O", "-B", "-I", "-T", "--log-out", "--log-io", "--log-in", "--log-timing")) this.emitTok(t, bases, "script");
    if (p.operands.length === 0) this.emit({ kind: "static", value: "typescript" }, bases, "script");
    for (const t of p.operands) this.emitTok(t, bases, "script");
  }

  private sed(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, SED, false);
    const inPlace = has(p, "-i", "--in-place");
    let scripts = values(p, "-e", "--expression");
    let files = p.operands;
    if (scripts.length === 0 && !has(p, "-f", "--file") && files.length > 0) {
      scripts = [files[0] as Tok];
      files = files.slice(1);
    }
    for (const s of scripts) this.inline(s, "sed");
    if (inPlace) for (const f of files) this.emitTok(f, bases, "sed -i");
  }

  private awk(name: string, args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, AWK_SPEC, false);
    let programs = values(p, "-e", "--source");
    let files = p.operands;
    if (programs.length === 0 && !has(p, "-f", "--file", "-E", "--exec") && files.length > 0) {
      programs = [files[0] as Tok];
      files = files.slice(1);
    }
    for (const prog of programs) this.inline(prog, name);
    const inPlace = values(p, "-i", "--include").some((v) => v.value === "inplace" || v.value === "inplace.awk");
    if (inPlace) for (const f of files) this.emitTok(f, bases, `${name} -i inplace`);
  }

  private perlRuby(name: string, args: Tok[], bases: string[] | null, stdin: Stdin | null): void {
    const p = parseOptions(args, 0, PERL.test(name) ? PERL_SPEC : RUBY_SPEC, false);
    const code = values(p, "-e", ...(PERL.test(name) ? ["-E"] : []));
    for (const c of code) this.inline(c, name);
    let files = p.operands;
    if (code.length === 0) {
      this.scriptOperand(files[0], stdin, name, () => this.stdinCode(stdin, name));
      files = files.slice(1);
    }
    if (has(p, "-i")) for (const f of files) this.emitTok(f, bases, `${name} -i`);
  }

  private python(name: string, args: Tok[], stdin: Stdin | null): void {
    const p = parseOptions(args, 0, PYTHON_SPEC, true);
    const code = values(p, "-c");
    if (code.length > 0) {
      for (const c of code) this.inline(c, name);
      return;
    }
    if (has(p, "-m")) return; // module: not analyzed (documented limit)
    this.scriptOperand(args[p.index], stdin, name, () => this.stdinCode(stdin, name));
  }

  private node(name: string, args: Tok[], stdin: Stdin | null): void {
    let code = false;
    let script: Tok | undefined;
    for (let j = 0; j < args.length; j += 1) {
      const a = args[j] as Tok;
      if (plain(a) && NODE_CODE_FLAGS.has(a.value)) {
        this.inline(args[j + 1], name);
        code = true;
        j += 1;
      } else if (plain(a) && (a.value.startsWith("--eval=") || a.value.startsWith("--print="))) {
        this.inline(attached(a, a.value.slice(a.value.indexOf("=") + 1)), name);
        code = true;
      } else if (plain(a) && NODE_WITH_ARG.has(a.value)) {
        j += 1;
      } else if (!(plain(a) && a.value.startsWith("-") && a.value !== "-") && script === undefined) {
        script = a;
        if (name === "bun" && plain(a) && ["run", "x", "exec"].includes(a.value)) script = args[j + 1];
        break; // arguments after the script belong to the script
      }
    }
    if (!code) this.scriptOperand(script, stdin, name, () => this.stdinCode(stdin, name));
  }

  private deno(args: Tok[]): void {
    const first = args[0];
    if (plain(first) && first.value === "eval") this.inline(args[args.length - 1], "deno eval");
  }

  private php(name: string, args: Tok[], stdin: Stdin | null): void {
    const p = parseOptions(args, 0, PHP_SPEC, true);
    const code = values(p, "-r", "-B", "-R", "-E");
    for (const c of code) this.inline(c, name);
    if (code.length > 0) return;
    const files = values(p, "-f");
    this.scriptOperand(files.length > 0 ? files[files.length - 1] : args[p.index], stdin, name, () => this.stdinCode(stdin, name));
  }

  private dd(args: Tok[], bases: string[] | null): void {
    for (const a of args) if (a.value.startsWith("of=")) this.emitTok(attached(a, a.value.slice(3)), bases, "dd");
  }

  private sort(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, SORT, false);
    for (const t of values(p, "-o", "--output")) this.emitTok(t, bases, "sort -o");
  }

  private split(args: Tok[], bases: string[] | null, depth: number): void {
    const p = parseOptions(args, 0, SPLIT, false);
    for (const f of values(p, "--filter")) this.inlineScript(f, bases, depth, "split --filter");
    const prefix = this.classify(p.operands[1]);
    if (prefix !== null && (prefix.kind === "static" || prefix.kind === "glob")) this.emit({ kind: "glob", value: `${prefix.value}*` }, bases, "split");
    else this.emit(prefix, bases, "split");
  }

  private compressor(name: string, args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, COMPRESS, false);
    for (const t of values(p, "-o", "--output")) this.emitTok(t, bases, name);
    if (has(p, "-c", "--stdout", "--to-stdout", "-t", "--test", "-l", "--list")) return;
    for (const t of p.operands) {
      if (t.value === "-") continue;
      this.emitTok(t, bases, name);
      if (COMPRESSED_SUFFIX.test(t.value)) this.emitTok(attached(t, t.value.replace(COMPRESSED_SUFFIX, "")), bases, name);
    }
  }

  private cpio(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, CPIO, false);
    if (p.uncertain || has(p, "-i", "--extract")) {
      const dirs = values(p, "-D", "--directory");
      if (dirs.length === 0) this.emit({ kind: "static", value: "." }, bases, "cpio");
      for (const d of dirs) this.emitTok(d, bases, "cpio");
    }
    if (has(p, "-p", "--pass-through")) this.emit(this.classify(p.operands[0]) ?? { kind: "static", value: "." }, bases, "cpio -p");
    for (const t of values(p, "-O", "-F", "--file")) this.emitTok(t, bases, "cpio");
  }

  private tar(args: Tok[], bases: string[] | null): void {
    let words = args;
    const first = args[0];
    if (first !== undefined && plain(first) && !first.value.startsWith("-")) words = [attached(first, `-${first.value}`), ...args.slice(1)];
    const p = parseOptions(words, 0, TAR_SPEC, false);
    const dirs = values(p, "-C", "--directory");
    if ((p.uncertain || has(p, "-x", "--extract", "--get")) && !has(p, "-O", "--to-stdout")) {
      if (dirs.length === 0) this.emit({ kind: "static", value: "." }, bases, "tar -x");
      for (const d of dirs) this.emitTok(d, bases, "tar -x");
    }
    if (p.uncertain || has(p, "-c", "-r", "-u", "-A", "--create", "--append", "--update", "--catenate", "--concatenate", "--delete")) {
      for (const f of values(p, "-f", "--file")) if (f.value !== "-") this.emitTok(f, bases, "tar");
    }
  }

  private unzip(args: Tok[], bases: string[] | null): void {
    const p = parseOptions(args, 0, UNZIP_SPEC, false);
    if (has(p, "-l", "-t", "-v", "-p", "-z", "-Z")) return;
    const dirs = values(p, "-d");
    if (dirs.length === 0) this.emit({ kind: "static", value: "." }, bases, "unzip");
    for (const d of dirs) this.emitTok(d, bases, "unzip");
  }

  private patch(args: Tok[]): void {
    if (!args.some((a) => plain(a) && a.value === "--dry-run")) this.add("patch", "patch", "patch");
  }

  private find(args: Tok[], bases: string[] | null, depth: number): void {
    let j = 0;
    while (j < args.length && plain(args[j])) {
      const v = (args[j] as Tok).value;
      if (v === "-H" || v === "-L" || v === "-P" || v.startsWith("-O")) j += 1;
      else if (v === "-D") j += 2;
      else break;
    }
    const starts: Tok[] = [];
    while (j < args.length) {
      const a = args[j] as Tok;
      if (plain(a) && (a.value.startsWith("-") || ["(", ")", "!", ","].includes(a.value))) break;
      starts.push(a);
      j += 1;
    }
    if (starts.length === 0) starts.push(synthetic({ kind: "static", value: "." }));
    // Found paths lie below the start paths; resolve those against the outer working directories.
    const found = starts.flatMap((s) => {
      const item = this.classify(s);
      if (item === null) return [];
      if ((item.kind === "static" || item.kind === "glob") && !item.value.startsWith("/") && bases !== null) {
        return bases.map((b) => synthetic({ kind: item.kind, value: join(b, item.value) }));
      }
      return [synthetic(item)];
    });
    const expr = args.slice(j);
    for (let k = 0; k < expr.length; k += 1) {
      const w = expr[k] as Tok;
      if (!plain(w)) continue;
      if (w.value === "-delete") {
        for (const f of found) this.emitTok(f, null, "find -delete");
      } else if (["-fprint", "-fprint0", "-fls", "-fprintf"].includes(w.value)) {
        this.emitTok(expr[k + 1], bases, `find ${w.value}`);
        k += 1;
      } else if (["-exec", "-execdir", "-ok", "-okdir"].includes(w.value)) {
        const sub: Tok[] = [];
        let braces = false;
        let m = k + 1;
        for (; m < expr.length; m += 1) {
          const t = expr[m] as Tok;
          if (t.value === ";" || (t.value === "+" && braces)) break;
          braces = t.value.includes("{}");
          if (braces) sub.push(...found);
          else sub.push(t);
        }
        k = m;
        this.invocation(sub, w.value.endsWith("dir") ? null : bases, depth + 1, null);
      }
    }
  }

  private pathspec(tok: Tok, bases: string[] | null, via: string): void {
    const item = this.classify(tok);
    if (item === null || item.kind === "dynamic" || item.kind === "opaque") {
      this.emit(item, bases, via);
      return;
    }
    if (item.value.startsWith(":")) {
      this.emit({ kind: "static", value: this.opts.root }, bases, via); // pathspec magic, e.g. ":/" = top level
      return;
    }
    // git (and mmv) match patterns themselves (also quoted ones, across "/" and dotfiles): keep the static prefix.
    const segs = item.value.split("/");
    const glob = segs.findIndex((s) => /[*?[]/.test(s));
    if (glob >= 0) this.emit({ kind: "static", value: segs.slice(0, glob).join("/") || "." }, bases, via);
    else this.emit({ kind: "static", value: item.value }, bases, via);
  }

  private gitKey(tok: Tok | null | undefined, via: string): void {
    if (tok === null || tok === undefined) return;
    if (dynamicWord(tok)) {
      this.add("git", `${via} ${tok.value}`, via);
      return;
    }
    const key = tok.value.split("=")[0] as string;
    if (dangerousGitKey(key)) this.add("git", `${via} ${key}`, via);
  }

  private git(args: Tok[], initialBases: string[] | null, depth: number): void {
    let bases = initialBases;
    let j = 0;
    while (j < args.length && !args[j]?.expands && !args[j]?.executes && (args[j] as Tok).value.startsWith("-")) {
      const v = (args[j] as Tok).value;
      const eq = v.indexOf("=");
      const name = v.startsWith("--") && eq > 0 ? v.slice(0, eq) : v;
      if (name === "--git-dir" || name === "--work-tree" || (name === "--exec-path" && eq > 0)) this.add("git", name, "git");
      if (name === "--config-env" && eq > 0) this.gitKey(attached(args[j] as Tok, v.slice(eq + 1)), "git --config-env");
      if (GIT_GLOBAL_WITH_ARG.has(v)) {
        if (v === "-C") bases = this.rebase(bases, args[j + 1]);
        if (v === "-c") this.gitKey(args[j + 1], "git -c");
        if (v === "--config-env") this.gitKey(args[j + 1], "git --config-env");
        j += 2;
      } else {
        j += 1;
      }
    }
    const sub = args[j];
    if (sub === undefined) return;
    if (dynamicWord(sub)) {
      this.add("opaque", sub.value, "git subcommand");
      return;
    }
    const rest = args.slice(j + 1);
    for (const a of rest) if (!a.expands && GIT_EXEC_OPTIONS.test(a.value)) this.add("git", a.value.split("=")[0] as string, `git ${sub.value}`);
    const names = rest.filter((a) => plain(a) && a.value.startsWith("-")).map((a) => a.value.split("=")[0] as string);
    const via = `git ${sub.value}`;
    // --output (diff, log, show, format-patch, archive, range-diff ...) writes a file.
    for (let k = 0; k < rest.length; k += 1) {
      const a = rest[k] as Tok;
      if (a.expands || a.executes) continue;
      if (a.value === "--output" || a.value === "--output-directory") this.emitTok(rest[k + 1], bases, via);
      else if (a.value.startsWith("--output=") || a.value.startsWith("--output-directory=")) this.emitTok(attached(a, a.value.slice(a.value.indexOf("=") + 1)), bases, via);
    }
    const operands = parseOptions(rest, 0, GIT_OUTPUT, false);
    switch (sub.value) {
      case "format-patch":
      case "archive":
        for (const v of values(operands, "-o")) this.emitTok(v, bases, via);
        return;
      case "rebase":
        for (const v of values(parseOptions(rest, 0, GIT_REBASE, false), "-x", "--exec")) this.inlineScript(v, bases, depth, "git rebase --exec");
        return;
      case "bisect":
        if (plain(rest[0]) && rest[0].value === "run") this.invocation(rest.slice(1), bases, depth + 1, null);
        return;
      case "submodule": {
        const k = rest.findIndex((a) => plain(a) && a.value === "foreach");
        if (k >= 0) {
          const words = rest.slice(k + 1).filter((a, n, all) => !(plain(a) && a.value.startsWith("-") && all.slice(0, n).every((b) => plain(b) && b.value.startsWith("-"))));
          if (words.length > 0) this.inlineScript(joined(words), bases, depth, "git submodule foreach");
        }
        return;
      }
      case "filter-branch":
      case "filter-repo":
        this.add("opaque", via, via);
        return;
      case "bundle":
        if (plain(operands.operands[0]) && operands.operands[0].value === "create") this.emitTok(operands.operands[1], bases, via);
        return;
      case "worktree":
        if (plain(operands.operands[0]) && operands.operands[0].value === "add") this.emitTok(operands.operands[1], bases, via);
        return;
      case "apply": {
        const checkOnly = names.some((n) => ["--check", "--stat", "--numstat", "--summary"].includes(n)) && !names.includes("--apply");
        if (!checkOnly) this.add("patch", via, via);
        return;
      }
      case "am":
        if (!names.some((n) => ["--show-current-patch", "--abort", "--quit"].includes(n))) this.add("patch", via, via);
        return;
      case "config":
        this.gitConfig(parseOptions(rest, 0, GIT_CONFIG, false), bases);
        return;
      case "init":
      case "clone": {
        const p = parseOptions(rest, 0, sub.value === "init" ? GIT_INIT : GIT_CLONE, false);
        if (has(p, "--template", "--separate-git-dir") || (sub.value === "clone" && has(p, "-u", "--upload-pack"))) this.add("git", `${via} template/upload-pack`, via);
        for (const c of values(p, "-c", "--config")) this.gitKey(c, `${via} --config`);
        // The new repository directory (init: operand or "."; clone: second operand or the URL's base name).
        if (sub.value === "init") this.emit(this.classify(p.operands[0]) ?? { kind: "static", value: "." }, bases, via);
        else if (p.operands.length >= 2) this.emitTok(p.operands[1], bases, via);
        else if (p.operands[0] !== undefined) {
          const url = this.classify(p.operands[0]);
          const name = url === null || url.kind !== "static" ? null : baseName(url.value.replace(/[/:]+$/, "")).replace(/\.git$/, "");
          this.emit(name === null || name === "" ? url : { kind: "static", value: name }, bases, via);
        }
        return;
      }
      case "checkout":
      case "restore":
      case "rm": {
        const p = parseOptions(rest, 0, sub.value === "checkout" ? GIT_CHECKOUT : sub.value === "restore" ? GIT_RESTORE : GIT_RM, false);
        if (sub.value === "rm" && has(p, "--cached")) return;
        if (sub.value === "restore" && has(p, "-S", "--staged") && !has(p, "-W", "--worktree")) return;
        if (has(p, "--pathspec-from-file")) this.add("opaque", "--pathspec-from-file", via);
        for (const t of p.operands) if (t.value !== "-") this.pathspec(t, bases, via);
        return;
      }
      case "mv":
        this.copyLike("mv", parseOptions(rest, 0, NO_OPTIONS, false), bases, via);
        return;
      default:
        return;
    }
  }

  private gitConfig(p: Parsed, bases: string[] | null): void {
    const mode = p.operands[0];
    const modeName = mode !== undefined && plain(mode) ? mode.value : "";
    if (has(p, "-e", "--edit") || modeName === "edit" || has(p, "--rename-section") || modeName === "rename-section") {
      this.add("git", "git config edit/rename-section", "git config");
      return;
    }
    if (has(p, ...GIT_READ_CONFIG) || ["get", "list", "get-color", "get-colorbool"].includes(modeName)) return;
    for (const f of values(p, "-f", "--file")) this.emitTok(f, bases, "git config --file");
    if (has(p, "--unset", "--unset-all", "--remove-section") || ["unset", "remove-section"].includes(modeName)) return;
    let key: Tok | undefined;
    if (modeName === "set") key = p.operands[1];
    else if (p.operands.length >= 2 || has(p, "--add", "--replace-all")) key = p.operands[0];
    if (key !== undefined) this.gitKey(key, "git config");
  }
}

function defaultIsDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** Collects write findings for a command line. Throws ShellSyntaxError if it cannot be tokenized. */
export function analyzeWrites(command: string, opts: WriteOptions): WriteAnalysis {
  const analyzer = new Analyzer(opts);
  const root = cleanPath(opts.root);
  const bases = unique([root, ...(opts.cwd && opts.cwd.startsWith("/") ? [cleanPath(opts.cwd)] : [])]);
  analyzer.script(command, bases, 0, "bash");
  return { findings: analyzer.findings, texts: analyzer.texts };
}

function stripSlash(pattern: string): string {
  return pattern.endsWith("/") ? pattern.slice(0, -1) : pattern;
}

/**
 * Protected pattern hit by writing to the absolute path: the path is the pattern, lies below it, or is
 * an ancestor of it (recursive operations, directory moves); the root itself and its ancestors hit
 * every pattern.
 */
export function pathHit(path: string, roots: readonly string[], patterns: readonly string[]): string | undefined {
  // Case, Unicode form and Windows name quirks are folded (see foldPath): macOS and Windows file systems treat them as one name.
  const target = foldPath(path);
  for (const rootPath of roots) {
    const root = foldPath(rootPath);
    if (target === "/" || target === root || root.startsWith(`${target}/`)) return patterns[0];
    if (!target.startsWith(`${root}/`)) continue;
    const rel = target.slice(root.length + 1);
    const hit = patterns.find((p) => {
      const s = foldPath(stripSlash(p));
      return rel === s || rel.startsWith(`${s}/`) || s.startsWith(`${rel}/`);
    });
    if (hit !== undefined) return hit;
  }
  return undefined;
}

function segmentMatch(pattern: string, name: string, dotglob: boolean): boolean {
  const pat = Array.from(pattern);
  const str = Array.from(name);
  if (!dotglob && str[0] === "." && pat[0] !== ".") return false;
  // Tokens: literal character, "?" (one), "*" (any); a closed bracket expression counts as "?".
  const toks: string[] = [];
  for (let i = 0; i < pat.length; i += 1) {
    const c = pat[i] as string;
    if (c === "*" || c === "?") {
      toks.push(c === "*" ? "\0*" : "\0?");
    } else if (c === "[") {
      let j = i + 1;
      if (pat[j] === "!" || pat[j] === "^") j += 1;
      if (pat[j] === "]") j += 1;
      while (j < pat.length && pat[j] !== "]") j += 1;
      if (j < pat.length) {
        toks.push("\0?");
        i = j;
      } else {
        toks.push(c);
      }
    } else {
      toks.push(c);
    }
  }
  // Iterative wildcard match with single backtracking point (linear-ish, no regex dialects).
  let t = 0;
  let s = 0;
  let starT = -1;
  let starS = 0;
  while (s < str.length) {
    const tok = toks[t];
    if (tok !== undefined && (tok === "\0?" || tok === str[s])) {
      t += 1;
      s += 1;
    } else if (tok === "\0*") {
      starT = t;
      starS = s;
      t += 1;
    } else if (starT >= 0) {
      t = starT + 1;
      starS += 1;
      s = starS;
    } else {
      return false;
    }
  }
  while (toks[t] === "\0*") t += 1;
  return t === toks.length;
}

/** True if the glob may match the protected path, a path below it (directory pattern) or an ancestor of it. */
export function globMayMatch(glob: string, target: string, isDir: boolean, dotglob: boolean): boolean {
  let g = glob.split("/").filter((s) => s !== "");
  const brace = g.findIndex((s) => s.includes("{") || s.includes("}"));
  if (brace >= 0) g = [...g.slice(0, brace), "**"];
  const t = target.split("/").filter((s) => s !== "");
  const memo = new Map<number, boolean>();
  const may = (gi: number, ti: number): boolean => {
    const key = gi * (t.length + 1) + ti;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    let r: boolean;
    if (gi === g.length) r = true;
    else if (g[gi] === "**") r = may(gi + 1, ti) || (ti < t.length ? may(gi, ti + 1) : isDir);
    else if (ti === t.length) r = isDir;
    else r = segmentMatch(g[gi] as string, t[ti] as string, dotglob) && may(gi + 1, ti + 1);
    memo.set(key, r);
    return r;
  };
  return may(0, 0);
}

/** True if a lexical prefix of the path (before or between ".." steps) is one of the created links. */
function throughLink(path: string, links: ReadonlySet<string>): boolean {
  const out: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
    if (links.has(`/${out.join("/")}`)) return true;
  }
  return false;
}

/**
 * True if the dynamic target is a plain path below $TMPDIR and TMPDIR is not reassigned in the command
 * line (every occurrence is a `$TMPDIR/` or `${TMPDIR}` reference).
 */
export function temporaryTarget(value: string, text: string): boolean {
  return temporaryRest(value, text) !== null;
}

/** Path below $TMPDIR of a "$TMPDIR/rest" target, or null (see temporaryTarget). */
export function temporaryRest(value: string, text: string): string | null {
  const m = /^(?:\$TMPDIR|\$\{TMPDIR\})\/(.*)$/s.exec(value);
  if (m === null) return null;
  const rest = m[1] as string;
  if (rest === "" || /[$`]/.test(rest) || rest.split("/").includes("..")) return null;
  for (let i = text.indexOf("TMPDIR"); i >= 0; i = text.indexOf("TMPDIR", i + 1)) {
    const before = text.slice(Math.max(0, i - 2), i);
    const after = text.charAt(i + 6);
    const reference = (before.endsWith("$") && after === "/") || (before === "${" && after === "}");
    if (!reference) return null;
  }
  return rest;
}

export interface WriteMessages {
  path: (target: string, pattern: string) => string;
  glob: (target: string, pattern: string) => string;
  dynamic: (target: string) => string;
  opaque: (target: string, via: string) => string;
  patch: (via: string) => string;
  code: (via: string) => string;
  git: (detail: string) => string;
  link: (target: string) => string;
  hardlink: (target: string) => string;
  unresolvable: (target: string) => string;
  proc: (target: string) => string;
  outside: (target: string) => string;
}

export const ENGLISH_MESSAGES: WriteMessages = {
  path: (t, p) => `Bash command writes to ${t}, which is or contains the protected path ${p}; changes need human review.`,
  glob: (t, p) => `Bash write target ${t} may match the protected path ${p}; name the files explicitly.`,
  dynamic: (t) => `Bash write target ${t} is only known at run time; fail closed. Name the file explicitly (or use a path below "$TMPDIR/"; TMPDIR counts only below /tmp, /var/tmp or /run/user/<uid>/tollgate-tmp).`,
  opaque: (t, v) => `Bash write target of ${v} (${t}) is only known at run time; fail closed. Name the files explicitly.`,
  patch: (v) => `${v} can write any file including protected paths; only --check/--dry-run or a human session.`,
  code: (v) => `Inline code (${v}) can write files or run programs; use the edit tools or a script reviewed by a human.`,
  git: (d) => `Git option or configuration (${d}) can run commands or bypass hooks; requires a human.`,
  link: (t) => `Bash command writes through ${t}, a link created in the same command line; fail closed.`,
  hardlink: (t) => `${t} has more than one hard link; writing it could change a protected file. Requires a human.`,
  unresolvable: (t) => `Bash write target ${t} cannot be resolved safely (symlink loop or filesystem error).`,
  proc: (t) => `Bash write target ${t} is a process or file-descriptor path whose meaning depends on the running process; fail closed.`,
  outside: (t) => `Bash write target ${t} is outside the project directory (allowed outside it: /tmp, /var/tmp and an accepted TMPDIR).`,
};

export interface DecideOptions {
  /** Home directory: protected home files (shell, git, agent and credential configuration). */
  home?: string | undefined;
  /** Additional absolute paths that are protected (e.g. the active policy file). */
  extraProtected?: readonly string[] | undefined;
  /**
   * Actual TMPDIR; the "$TMPDIR/..." exception applies only if it lies below a fixed temporary root
   * (acceptedTmpdir), outside the project and is unprotected.
   */
  tmpdir?: string | undefined;
  /** Platform and uid for the temporary roots; default: the current process. */
  tempHost?: TempHost | undefined;
  messages?: WriteMessages | undefined;
  /**
   * Project boundary: true if writing the absolute path stays inside the project or a temporary directory. The caller passes
   * the boundary of the write tools, so Bash and Write/Edit share one rule. Checked for the lexical and the physical form of
   * every target that is not a link source; safe devices (/dev/null, /dev/stdout ...) are exempt. Undefined: not checked.
   */
  boundary?: ((path: string) => boolean) | undefined;
}

/** True if a segment of the glob may expand to "..", which would leave the directory the glob names (`.*`, `.?`, braces). */
function globMayClimb(glob: string): boolean {
  return glob.split("/").some((seg) => seg === ".." || segmentMatch(seg, "..", false) || (/[{}]/.test(seg) && seg.includes("..")));
}

/** Device paths that are safe write targets. */
const SAFE_DEVICES = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/full"]);
/** Stream devices: they resolve through /proc/self/fd to the streams of the checking process, so their physical form says nothing. */
const STREAM_DEVICES = new Set(["/dev/stdout", "/dev/stderr"]);

/**
 * A safe device only if the physical form agrees: the directory must be /dev physically (a lexical /dev/null reached through
 * `link/../../dev/null` can be another file), and the device itself must resolve to a safe device (stdout/stderr excepted).
 */
function safeDevice(value: string, lexical: string): boolean {
  if (!SAFE_DEVICES.has(lexical) || safePhysical(dirName(value)) !== "/dev") return false;
  return STREAM_DEVICES.has(lexical) || SAFE_DEVICES.has(safePhysical(value) ?? "");
}

function procPath(path: string): boolean {
  return path === "/proc" || path.startsWith("/proc/") || path === "/dev/fd" || path.startsWith("/dev/fd/");
}

function safePhysical(path: string): string | null {
  try {
    return physicalPath(path);
  } catch {
    return null;
  }
}

/** Platform and user id that decide the fixed temporary roots (injectable for tests). */
export interface TempHost {
  platform: string;
  uid: number | undefined;
  /** System temporary roots; default /tmp and /var/tmp (injectable for tests). */
  systemRoots?: readonly string[] | undefined;
  /** Parent of the per-user runtime directories; default /run/user (injectable for tests). */
  runDir?: string | undefined;
  /** macOS per-user directory trees; default /var/folders and /private/var/folders (injectable for tests). */
  varFolders?: readonly string[] | undefined;
}

export function currentTempHost(): TempHost {
  return { platform: process.platform, uid: typeof process.getuid === "function" ? process.getuid() : undefined };
}

/**
 * Fixed roots below which TMPDIR is accepted as a temporary write zone: /tmp, /var/tmp and
 * /run/user/<own uid>/tollgate-tmp. TMPDIR comes from the agent's environment, so any other value
 * (for example /etc or the home directory) would turn arbitrary directories into write zones.
 * macOS: see darwinUserTemp.
 */
export function temporaryRoots(host: TempHost = currentTempHost()): string[] {
  const roots = [...(host.systemRoots ?? SYSTEM_TEMP_ROOTS)];
  if (host.uid !== undefined && Number.isInteger(host.uid) && host.uid >= 0) roots.push(userTempRoot(host));
  return roots;
}

const SYSTEM_TEMP_ROOTS = ["/tmp", "/var/tmp"];
const VAR_FOLDERS = ["/var/folders", "/private/var/folders"];

function userTempRoot(host: TempHost): string {
  return `${host.runDir ?? "/run/user"}/${host.uid}/tollgate-tmp`;
}

/**
 * Lexical and physical forms of the roots. /tmp and /var/tmp belong to the system, so their physical
 * form (macOS: /private/tmp) is a root too. The per-user root lies in a directory the user owns: if it
 * is a symlink (also a dangling one) it could point anywhere (for example /etc), so it only counts when
 * its physical form equals its resolved parent plus the plain name; otherwise it is dropped.
 */
function rootForms(host: TempHost): string[] {
  const forms: string[] = [];
  for (const r of host.systemRoots ?? SYSTEM_TEMP_ROOTS) forms.push(r, safePhysical(r) ?? r);
  if (host.uid !== undefined && Number.isInteger(host.uid) && host.uid >= 0) {
    const root = userTempRoot(host);
    const physical = safePhysical(root);
    const parent = safePhysical(root.slice(0, root.lastIndexOf("/")));
    if (physical !== null && parent !== null && physical === `${parent}/tollgate-tmp`) forms.push(root, physical);
  }
  return unique(forms).filter((r) => r !== "/");
}

/**
 * macOS: the plugin supports macOS (see README, hook timeout without GNU timeout), where TMPDIR is the
 * per-user temporary directory /var/folders/<xx>/<id>/T/ (physically /private/var/folders/...). On darwin
 * only a T directory at that depth and paths below it are accepted; the sibling cache (C) and user (0)
 * directories and /var/folders itself are not. The check is applied to the lexical and to the physical
 * path, so a T that is a symlink leaving the tree is rejected.
 * Known limit: the shape is not bound to the own user; another user's T directory also matches. The
 * file permissions of /var/folders (per-user directories, mode 0700) protect those.
 */
export function darwinUserTemp(path: string, varFolders: readonly string[] = VAR_FOLDERS): boolean {
  return varFolders.some((f) => {
    if (!path.startsWith(`${f}/`)) return false;
    const segs = path.slice(f.length + 1).split("/");
    return segs.length >= 3 && segs[0] !== "" && segs[1] !== "" && segs[2] === "T";
  });
}

/**
 * Physical path of TMPDIR if it is absolute and lies (lexically and with all symlinks resolved) at or
 * below one of the fixed temporary roots (on darwin also inside darwinUserTemp); otherwise null
 * (TMPDIR is then ignored).
 */
export function acceptedTmpdir(tmpdir: string | undefined, host: TempHost = currentTempHost()): string | null {
  if (!tmpdir || !tmpdir.startsWith("/")) return null;
  const physical = safePhysical(tmpdir);
  if (physical === null) return null;
  const roots = rootForms(host);
  const darwin = host.platform === "darwin";
  const varFolders = host.varFolders ?? VAR_FOLDERS;
  const below = (p: string): boolean => roots.some((r) => p === r || p.startsWith(`${r}/`)) || (darwin && darwinUserTemp(p, varFolders));
  return below(normalizeAbsolute(tmpdir)) && below(physical) ? physical : null;
}

function multiplyLinked(path: string): boolean {
  try {
    const st = statSync(path);
    return st.isFile() && st.nlink > 1;
  } catch {
    return false;
  }
}

/** Decision for a command's write findings against protected patterns (agents only). */
export function decideWrites(
  analysis: WriteAnalysis,
  protectedPaths: readonly string[],
  root: string,
  options: DecideOptions = {},
): WriteDecision {
  const messages = options.messages ?? ENGLISH_MESSAGES;
  const patterns = [...protectedPaths, ...ALWAYS_PROTECTED_PATHS];
  const text = analysis.texts.join("\n");
  const dotglob = text.includes("dotglob") || text.includes("GLOBIGNORE");
  const rootClean = cleanPath(root);
  const physicalRoot = safePhysical(rootClean);
  const roots = unique([rootClean, ...(physicalRoot === null ? [] : [physicalRoot])]);
  const home = options.home ? cleanPath(options.home) : null;
  const physicalHome = home === null ? null : safePhysical(home);
  const homes = home === null ? [] : unique([home, ...(physicalHome === null ? [] : [physicalHome])]);
  // Entries with a trailing "/" are directories: everything below them is protected, too.
  const extraEntries = (options.extraProtected ?? []).map((e) => ({ path: cleanPath(e), dir: e.endsWith("/") }));
  const links = new Set(analysis.findings.filter((f) => f.kind === "link" && f.value !== "").map((f) => normalizeAbsolute(f.value)));
  const unknownLink = analysis.findings.some((f) => f.kind === "link" && f.value === "");
  const assigned = analysis.findings.some((f) => f.kind === "assign");
  const writes = analysis.findings.filter((f) => ["path", "glob", "dynamic"].includes(f.kind));
  const hitAt = (candidate: string): string | undefined =>
    pathHit(candidate, roots, patterns) ??
    pathHit(candidate, homes, HOME_PROTECTED_PATHS) ??
    extraEntries.find((e) => {
      const c = foldPath(candidate);
      const p = foldPath(e.path);
      return c === p || p.startsWith(`${c}/`) || c === "/" || (e.dir && c.startsWith(`${p}/`));
    })?.path;
  const outside = (value: string): WriteDecision => ({ allowed: false, reason: messages.outside(value), kind: "outside_project" });
  const checkPathTarget = (value: string, source = false): WriteDecision | null => {
    const lexical = normalizeAbsolute(value);
    if (safeDevice(value, lexical)) return null;
    if (procPath(lexical)) return { allowed: false, reason: messages.proc(value) };
    const physical = safePhysical(value);
    if (physical === null) return { allowed: false, reason: messages.unresolvable(value) };
    if (procPath(physical)) return { allowed: false, reason: messages.proc(value) };
    for (const candidate of unique([lexical, physical])) {
      const hit = hitAt(candidate);
      if (hit !== undefined) return { allowed: false, reason: messages.path(candidate, hit) };
    }
    if (roots.some((r) => physical.startsWith(`${r}/`)) && multiplyLinked(physical)) return { allowed: false, reason: messages.hardlink(value) };
    // A link source (`ln -s /usr/lib/x y`) is not written; writes through the link are checked when they happen.
    if (!source && options.boundary !== undefined && unique([lexical, physical]).some((c) => !(options.boundary as (path: string) => boolean)(c))) return outside(value);
    return null;
  };
  // The real temporary directory must lie below a fixed temporary root (acceptedTmpdir), outside the
  // project (not an ancestor either) and be unprotected.
  const tmp = acceptedTmpdir(options.tmpdir, options.tempHost);
  const tmpOk =
    tmp !== null &&
    tmp !== "/" &&
    !roots.some((r) => r === tmp || r.startsWith(`${tmp}/`) || tmp.startsWith(`${r}/`)) &&
    hitAt(tmp) === undefined;
  for (const f of analysis.findings) {
    if (f.kind === "link" || f.kind === "assign" || f.kind === "stdin") continue;
    if (unknownLink && (f.kind === "path" || f.kind === "glob" || f.kind === "dynamic") && writes.length > 1) {
      return { allowed: false, reason: messages.link(f.value) };
    }
    if ((f.kind === "path" || f.kind === "glob") && !f.via.endsWith(" source") && throughLink(f.value, links) && !links.has(normalizeAbsolute(f.value))) {
      return { allowed: false, reason: messages.link(f.value) };
    }
    if (f.kind === "path") {
      const decision = checkPathTarget(f.value, f.via.endsWith(" source"));
      if (decision !== null) return decision;
    } else if (f.kind === "glob") {
      if (links.size > 0) return { allowed: false, reason: messages.link(f.value) };
      if (procPath(normalizeAbsolute(f.value))) return { allowed: false, reason: messages.proc(f.value) };
      const globs = [normalizeAbsolute(f.value)];
      const segs = f.value.split("/");
      const up = segs.lastIndexOf("..");
      if (up >= 0) {
        const prefix = segs.slice(0, up + 1).join("/");
        const physical = /[*?[{}]/.test(prefix) ? null : safePhysical(prefix);
        if (physical === null) return { allowed: false, reason: messages.unresolvable(f.value) };
        globs.push(cleanPath(`${physical}/${segs.slice(up + 1).join("/")}`));
      }
      for (const g of globs) {
        for (const [bases, list] of [[roots, patterns], [homes, HOME_PROTECTED_PATHS]] as const) {
          for (const r of bases) {
            const hit = list.find((p) => globMayMatch(foldGlob(g), foldGlob(`${r}/${stripSlash(p)}`), p.endsWith("/"), dotglob));
            if (hit !== undefined) return { allowed: false, reason: messages.glob(f.value, hit) };
          }
        }
        const hitExtra = extraEntries.find((e) => globMayMatch(foldGlob(g), foldGlob(e.path), e.dir, dotglob));
        if (hitExtra !== undefined) return { allowed: false, reason: messages.glob(f.value, hitExtra.path) };
      }
      // Boundary for globs: the files lie below the directory the glob names, unless a segment can expand to "..".
      if (options.boundary !== undefined && !f.via.endsWith(" source") && (globMayClimb(f.value) || globs.some((g) => !(options.boundary as (path: string) => boolean)(g)))) {
        return outside(f.value);
      }
    } else if (f.kind === "dynamic") {
      const rest = temporaryRest(f.value, text);
      if (unknownLink || links.size > 0 || assigned || !tmpOk || rest === null) return { allowed: false, reason: messages.dynamic(f.value) };
      const decision = checkPathTarget(`${tmp}/${rest}`);
      if (decision !== null) return decision;
    } else if (f.kind === "opaque") {
      return { allowed: false, reason: messages.opaque(f.value, f.via) };
    } else if (f.kind === "patch") {
      return { allowed: false, reason: messages.patch(f.via) };
    } else if (f.kind === "git") {
      return { allowed: false, reason: messages.git(f.value) };
    } else if (writeIndicator(f.value, codeLanguage(f.via))) {
      return { allowed: false, reason: messages.code(f.via) };
    }
  }
  return { allowed: true };
}

/** UTF-8 length of a string (the size cap is defined in bytes so that both implementations agree). */
export function utf8Length(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/** Write check for a Bash command (agents only; callers skip it in a human session). */
export function checkBashWrites(
  command: string,
  protectedPaths: readonly string[],
  opts: WriteOptions,
  extraProtected: readonly string[] = [],
): WriteDecision {
  if (utf8Length(command) > MAX_COMMAND_BYTES) {
    return { allowed: false, reason: `Command is longer than ${MAX_COMMAND_BYTES} bytes; fail closed. Split it or use a script file.` };
  }
  let analysis: WriteAnalysis;
  try {
    analysis = analyzeWrites(command, opts);
  } catch (err) {
    const detail = err instanceof ShellSyntaxError ? err.message : "analysis error";
    return { allowed: false, reason: `Command cannot be checked for writes (${detail}); fail closed.` };
  }
  return decideWrites(analysis, protectedPaths, opts.root, { home: opts.home, extraProtected, tmpdir: opts.tmpdir, boundary: opts.boundary });
}
