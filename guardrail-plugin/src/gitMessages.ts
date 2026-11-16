/**
 * Finds commit/tag message arguments (`git commit -m <msg>`, `git tag -m <msg>`) in a tokenized
 * simple command so the command guard does not match rules against message text.
 *
 * Security property: a word is only reported as a message if git is certain to treat it as one.
 * Every unknown option, every word that may expand to several arguments and every message that
 * runs code stops the scan; the remaining text is then matched as before (fail closed: at worst a
 * false positive, never a hidden option). Mirrored 1:1 in the Python repo hook.
 */
import type { ShellParse, ShellWord, SimpleCommand } from "./shell.js";

export interface MessageMask {
  word: ShellWord;
  /** Text that replaces the word for rule matching (message replaced by `_`, option letters kept). */
  replacement: string;
}

interface OptionSpec {
  /** Short options without argument (may be clustered). */
  flags: string;
  /** Short options with a required argument (rest of the cluster or next word). */
  withArg: string;
  /** Short options with an optional argument (only the rest of the cluster). */
  optionalArg: string;
  longFlags: ReadonlySet<string>;
  longWithArg: ReadonlySet<string>;
}

const PLACEHOLDER = "_";

// git commit (git 2.4x): -m/--message is the message option; everything not listed stops the scan.
const COMMIT: OptionSpec = {
  flags: "aenpiqosvz",
  withArg: "CcFt",
  optionalArg: "uS",
  longFlags: new Set([
    "--all", "--patch", "--interactive", "--include", "--only", "--amend", "--reset-author", "--signoff",
    "--no-signoff", "--edit", "--no-edit", "--verify", "--no-verify", "--allow-empty", "--allow-empty-message",
    "--no-post-rewrite", "--short", "--branch", "--porcelain", "--long", "--null", "--quiet", "--verbose",
    "--dry-run", "--status", "--no-status", "--gpg-sign", "--no-gpg-sign", "--untracked-files", "--pathspec-file-nul",
  ]),
  longWithArg: new Set([
    "--author", "--date", "--file", "--template", "--cleanup", "--trailer", "--fixup", "--squash",
    "--reuse-message", "--reedit-message", "--pathspec-from-file",
  ]),
};

const TAG: OptionSpec = {
  flags: "asfdvlei",
  withArg: "uF",
  optionalArg: "n",
  longFlags: new Set([
    "--annotate", "--sign", "--no-sign", "--force", "--delete", "--verify", "--list", "--edit", "--no-edit",
    "--ignore-case", "--create-reflog", "--no-column",
  ]),
  longWithArg: new Set(["--local-user", "--file", "--sort", "--format", "--cleanup", "--trailer"]),
};

const SUBCOMMANDS: ReadonlyMap<string, OptionSpec> = new Map([["commit", COMMIT], ["tag", TAG]]);

const GIT_GLOBAL_FLAGS = new Set([
  "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
  "--no-advice", "--bare", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs",
]);
const GIT_GLOBAL_WITH_ARG = new Set([
  "-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source",
]);

/** Words that may precede the command name without changing which program runs. */
const PREFIX_WORDS = new Set(["{", "!", "if", "then", "else", "elif", "do", "while", "until", "time", "command", "exec", "nohup"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

/** Exactly one argument at a known position that runs no code (may still contain "$NAME"). */
function operand(word: ShellWord): boolean {
  return !word.executes && !word.splittable && !word.redirect;
}

/** Additionally free of any expansion: its value is known statically (needed for option words). */
function plain(word: ShellWord): boolean {
  return operand(word) && !word.expands;
}

/**
 * True if the word at index i exists and is a static, code-free argument; the caller then knows the
 * exact position and meaning of every following word. Redirections (`>-m`) and expansions
 * (`"$X"` could be `-m`) make the rest uncertain, so the scan stops there.
 */
function plainAt(words: ShellWord[], i: number): boolean {
  const w = words[i];
  return w !== undefined && plain(w);
}

function operandAt(words: ShellWord[], i: number): boolean {
  const w = words[i];
  return w !== undefined && operand(w);
}

/** Index of the first git subcommand argument and its option spec, or null if not certain. */
function gitSubcommand(words: ShellWord[], src: string): { index: number; spec: OptionSpec } | null {
  let i = 0;
  for (;;) {
    const w = words[i];
    if (w === undefined) return null;
    if (ASSIGNMENT.test(src.slice(w.start, w.end)) || (!w.quoted && PREFIX_WORDS.has(w.value))) {
      i += 1;
      continue;
    }
    break;
  }
  const name = words[i];
  if (name === undefined || !plain(name) || (name.value !== "git" && !name.value.endsWith("/git"))) return null;
  for (i += 1; plainAt(words, i); i += 1) {
    const v = (words[i] as ShellWord).value;
    if (!v.startsWith("-")) {
      const spec = SUBCOMMANDS.get(v);
      return spec === undefined ? null : { index: i + 1, spec };
    }
    const eq = v.indexOf("=");
    if (v.startsWith("--") && eq > 0 && GIT_GLOBAL_WITH_ARG.has(v.slice(0, eq))) continue;
    if (GIT_GLOBAL_FLAGS.has(v)) continue;
    if (!GIT_GLOBAL_WITH_ARG.has(v) || !plainAt(words, i + 1)) return null;
    i += 1;
  }
  return null;
}

/** Message arguments of `git commit` / `git tag` in one simple command. */
export function messageMasks(command: SimpleCommand, src: string): MessageMask[] {
  const words = command.words;
  const found = gitSubcommand(words, src);
  if (found === null) return [];
  const { spec } = found;
  const masks: MessageMask[] = [];
  // Every word is checked with plainAt before use: a word that may expand to zero or several
  // arguments (or runs code) makes all later positions uncertain, so the scan stops there.
  for (let i = found.index; plainAt(words, i); i += 1) {
    const w = words[i] as ShellWord;
    const v = w.value;
    if (v === "--") break;
    if (v === "-" || !v.startsWith("-")) continue;
    let separateArg: "message" | "other" | null = null;
    if (v.startsWith("--")) {
      const eq = v.indexOf("=");
      const name = eq < 0 ? v : v.slice(0, eq);
      if (name === "--message" && eq >= 0) masks.push({ word: w, replacement: `--message=${PLACEHOLDER}` });
      else if (name === "--message") separateArg = "message";
      else if (eq < 0 && spec.longWithArg.has(name)) separateArg = "other";
      else if (eq < 0 && !spec.longFlags.has(name)) break;
    } else {
      let known = true;
      for (let j = 1; j < v.length; j += 1) {
        const ch = v.charAt(j);
        const last = j + 1 === v.length;
        if (ch === "m" && !last) masks.push({ word: w, replacement: `${v.slice(0, j + 1)} ${PLACEHOLDER}` });
        if (ch === "m" || spec.withArg.includes(ch)) {
          if (last) separateArg = ch === "m" ? "message" : "other";
          break;
        }
        if (spec.optionalArg.includes(ch)) break;
        if (!spec.flags.includes(ch)) {
          known = false;
          break;
        }
      }
      if (!known) break;
    }
    if (separateArg !== null) {
      if (!operandAt(words, i + 1)) break;
      if (separateArg === "message") masks.push({ word: words[i + 1] as ShellWord, replacement: PLACEHOLDER });
      i += 1;
    }
  }
  return masks;
}

// Unambiguous word shapes: unquoted safe characters, '...', and "..." with at most $NAME / ${NAME}.
// Every alternative starts with a different character and names are matched maximally (lookahead),
// so the pattern cannot backtrack catastrophically.
const SIMPLE_WORD =
  /^(?:[^ \t\n\r$`\\'"*?[\]{}()<>|&;]|'[^']*'|"(?:[^"$`\\]|\$[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])|\$\{[A-Za-z_][A-Za-z0-9_]*\})*")+$/;
// "$(cat <<'EOF' ... EOF\n)" as written by Claude Code for multi-line commit messages.
const LITERAL_HEREDOC = /^"\$\(cat << ?'([A-Za-z_][A-Za-z0-9_]*)'\n(?:[\s\S]*\n)?\1\n\)"$/;
const SAFE_REDIRECTS = new Set(["<<<", "<&", "<>", "<", ">>", ">&", ">|", ">", "&>", "&>>"]);
const UNSAFE_OPERATORS = new Set(["(", ";;", "<(", ">(", "`"]);

/**
 * Masking is only applied when the whole command line uses constructs on which shells and this
 * tokenizer cannot disagree: no subshells, case patterns, backquotes or process substitution, every
 * word in an unambiguous shape, and here-documents only inside a literal `"$(cat <<'EOF' ...)"`
 * message. Otherwise a tokenizer/shell divergence could hide real arguments inside a "message".
 */
export function maskingSafe(parsed: ShellParse, src: string): boolean {
  const ops = parsed.operators;
  if (ops.some((o) => UNSAFE_OPERATORS.has(o))) return false;
  if (ops.filter((o) => o === ")").length !== ops.filter((o) => o === "$(").length) return false;
  // A redirection target that looks like an option (`>-m`) is a classic confusion; never mask then.
  for (const { words } of parsed.commands) {
    if (words.some((w, k) => w.redirect && words[k + 1]?.value.startsWith("-") === true)) return false;
  }
  const words = parsed.commands.flatMap((c) => c.words);
  // The tokenizer must agree that the substitution is data (a single `cat` of a quoted here-document
  // ending at the first delimiter line); the shape regex alone would accept text after that line.
  const literals = words.filter((w) => !w.executes && LITERAL_HEREDOC.test(src.slice(w.start, w.end)));
  return words.every((w) => {
    const raw = src.slice(w.start, w.end);
    if (literals.some((l) => l.start <= w.start && w.end <= l.end)) return true;
    return SAFE_REDIRECTS.has(raw) || SIMPLE_WORD.test(raw);
  });
}

/** Replaces masked words in the source text (right to left; overlapping masks are skipped). */
export function applyMasks(src: string, masks: MessageMask[]): string {
  let out = src;
  let floor = src.length;
  for (const m of [...masks].sort((a, b) => b.word.start - a.word.start)) {
    if (m.word.end > floor) continue;
    out = out.slice(0, m.word.start) + m.replacement + out.slice(m.word.end);
    floor = m.word.start;
  }
  return out;
}
