/**
 * Conservative POSIX-ish shell tokenizer for the command guard.
 *
 * This is not a shell interpreter. It splits a command line into simple commands and words the way
 * bash would for the constructs agents actually use, and fails closed (ShellSyntaxError) whenever
 * the structure is ambiguous: unbalanced quotes, unterminated substitutions or here-documents,
 * dangling escapes, NUL bytes, excessive nesting.
 *
 * Supported: single/double quotes, backslash escapes, $'...' (ANSI-C, decoded), $"..." (treated as
 * double quotes), line continuations, comments, control operators (; ;; & && | || |& newline),
 * redirections, here-documents (<< and <<-), subshells ( ... ), command substitution $( ... ) and
 * backticks, process substitution <( ... ) and >( ... ). The contents of subshells and substitutions
 * are tokenized recursively and reported as separate simple commands.
 *
 * The algorithm is mirrored 1:1 in the Python repo hook; keep both in sync (shared cases:
 * test/fixtures/command-cases.json).
 */

export class ShellSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShellSyntaxError";
  }
}

export interface ShellWord {
  /** Word after quote removal. Substitutions keep their source text (e.g. `$(echo x)`). */
  value: string;
  /** Offset of the first source character of the word (inclusive). */
  start: number;
  /** Offset after the last source character of the word (exclusive). */
  end: number;
  /** Any quoting or escaping was used. */
  quoted: boolean;
  /** Contains a command or process substitution that runs code (anything but `cat` of a quoted here-document). */
  executes: boolean;
  /** Contains unquoted expansion or glob characters ($ ` * ? [ {); may expand to several arguments. */
  splittable: boolean;
  /** Contains a parameter, command or process expansion (quoted or not); its value is unknown statically. */
  expands: boolean;
  /** Redirection operator (`>`, `2>`'s `>`, `<<`, `&>` ...); the following word is its target, not an argument. */
  redirect: boolean;
  /** Here-document delimiter word only: the raw body text (between the operator line and the delimiter line). */
  heredoc?: string;
}

export interface SimpleCommand {
  words: ShellWord[];
}

export interface ShellParse {
  /** Simple commands in order of completion, including those inside subshells and substitutions. */
  commands: SimpleCommand[];
  /** Control operators in source order, including the opening/closing tokens of subshells and substitutions. */
  operators: string[];
}

export const MAX_NESTING = 32;

const BLANKS = " \t";
const WORD_END = " \t\n;&|()<>";
const SPLIT_CHARS = "$*?[{";
const DQ_ESCAPABLE = '$`"\\';
const OCTAL = "01234567";
const HEX = "0123456789abcdefABCDEF";
const REDIRECTS = ["<<<", "<<-", "<<", "<&", "<>", "<", ">>", ">&", ">|", ">"];
const ANSI_SIMPLE: Readonly<Record<string, string>> = {
  a: "\x07",
  b: "\b",
  e: "\x1b",
  E: "\x1b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
  "?": "?",
};

interface Scope {
  commands: SimpleCommand[];
  operators: string[];
  heredocs: boolean[];
  nested: number;
}

interface Heredoc {
  delimiter: string;
  quoted: boolean;
  stripTabs: boolean;
  word: ShellWord;
}

/** A substitution whose only command is `cat` reading a quoted here-document produces data, not code. */
function isLiteralSubstitution(scope: Scope): boolean {
  const words = scope.commands[0]?.words ?? [];
  return (
    scope.nested === 0 &&
    scope.commands.length === 1 &&
    scope.operators.every((o) => o === "\n") &&
    scope.heredocs.length > 0 &&
    scope.heredocs.every((quoted) => quoted) &&
    words.length === 3 &&
    words[0]?.value === "cat" &&
    (words[1]?.value === "<<" || words[1]?.value === "<<-")
  );
}

class Lexer {
  private pos = 0;
  private limit: number;
  private depth = 0;
  private pending: Heredoc[] = [];
  readonly commands: SimpleCommand[] = [];
  readonly operators: string[] = [];

  constructor(private readonly src: string) {
    if (src.includes("\0")) throw new ShellSyntaxError("NUL character in command");
    this.limit = src.length;
  }

  private at(offset = 0): string {
    const i = this.pos + offset;
    return i < this.limit ? this.src.charAt(i) : "";
  }

  /** Length of a backslash-newline line continuation at the current position, else 0. */
  private continuation(): number {
    if (this.at() !== "\\") return 0;
    if (this.at(1) === "\n") return 2;
    if (this.at(1) === "\r" && this.at(2) === "\n") return 3;
    return 0;
  }

  /** Parses a command list up to `closer` (")" or "`"; "" = end of input). */
  parseList(closer: string): Scope {
    this.depth += 1;
    if (this.depth > MAX_NESTING) throw new ShellSyntaxError("nesting too deep");
    const scope: Scope = { commands: [], operators: [], heredocs: [], nested: 0 };
    let words: ShellWord[] = [];
    const finish = (): void => {
      if (words.length > 0) {
        const cmd = { words };
        this.commands.push(cmd);
        scope.commands.push(cmd);
      }
      words = [];
    };
    const op = (o: string): void => {
      finish();
      this.operators.push(o);
      scope.operators.push(o);
    };
    for (;;) {
      const c = this.at();
      if (c === "") {
        if (closer === "`") throw new ShellSyntaxError("unterminated backquote");
        if (closer === ")") throw new ShellSyntaxError("unterminated ( or $(");
        finish();
        this.depth -= 1;
        return scope;
      }
      if (c === closer) {
        this.pos += 1;
        finish();
        this.depth -= 1;
        return scope;
      }
      const cont = this.continuation();
      if (cont > 0) {
        this.pos += cont;
      } else if (BLANKS.includes(c)) {
        this.pos += 1;
      } else if (c === "#") {
        while (this.at() !== "" && this.at() !== "\n") this.pos += 1;
      } else if (c === "\n") {
        this.pos += 1;
        op("\n");
        this.readHeredocs(scope);
      } else if (c === ")") {
        // Stray closing parenthesis (e.g. a case pattern): treated as a separator.
        this.pos += 1;
        op(")");
      } else if (c === "(") {
        this.pos += 1;
        op("(");
        scope.nested += 1;
        this.parseList(")");
        op(")");
      } else if (c === ";") {
        const o = this.at(1) === ";" ? ";;" : ";";
        this.pos += o.length;
        op(o);
      } else if (c === "|") {
        const o = this.at(1) === "|" ? "||" : this.at(1) === "&" ? "|&" : "|";
        this.pos += o.length;
        op(o);
      } else if (c === "&" && this.at(1) === "&") {
        this.pos += 2;
        op("&&");
      } else if (c === "&" && this.at(1) === ">") {
        this.redirect(this.at(2) === ">" ? "&>>" : "&>", words, scope, closer);
      } else if (c === "&") {
        this.pos += 1;
        op("&");
      } else if ((c === "<" || c === ">") && this.at(1) !== "(") {
        const o = REDIRECTS.find((r) => this.src.startsWith(r, this.pos) && this.pos + r.length <= this.limit) ?? c;
        this.redirect(o, words, scope, closer);
      } else {
        words.push(this.readWord(closer, scope));
      }
    }
  }

  private redirect(o: string, words: ShellWord[], scope: Scope, closer: string): void {
    const start = this.pos;
    this.pos += o.length;
    words.push({ value: o, start, end: this.pos, quoted: false, executes: false, splittable: false, expands: false, redirect: true });
    if (o !== "<<" && o !== "<<-") return;
    for (;;) {
      const cont = this.continuation();
      if (cont > 0) this.pos += cont;
      else if (this.at() !== "" && BLANKS.includes(this.at())) this.pos += 1;
      else break;
    }
    const c = this.at();
    if (c === "" || WORD_END.includes(c) || c === closer) throw new ShellSyntaxError("missing here-document delimiter");
    const word = this.readWord(closer, scope);
    words.push(word);
    this.pending.push({ delimiter: word.value, quoted: word.quoted, stripTabs: o === "<<-", word });
    scope.heredocs.push(word.quoted);
  }

  /** Consumes the bodies of pending here-documents after a newline. */
  private readHeredocs(scope: Scope): void {
    while (this.pending.length > 0) {
      const doc = this.pending.shift() as Heredoc;
      const bodyStart = this.pos;
      let bodyEnd = -1;
      while (bodyEnd < 0) {
        if (this.pos >= this.limit) throw new ShellSyntaxError(`unterminated here-document (missing ${doc.delimiter})`);
        let lineEnd = this.src.indexOf("\n", this.pos);
        if (lineEnd < 0 || lineEnd > this.limit) lineEnd = this.limit;
        const lineStart = this.pos;
        const line = this.src.slice(lineStart, lineEnd);
        this.pos = Math.min(lineEnd + 1, this.limit);
        const candidate = doc.stripTabs ? line.replace(/^\t+/, "") : line;
        if (candidate === doc.delimiter) bodyEnd = lineStart;
        // bash 5.2 ends a here-document inside $( ) or backquotes at a line that only starts with the
        // delimiter (e.g. `EOF)`) and runs the rest of the line; refuse such lines everywhere.
        else if (candidate.startsWith(doc.delimiter)) throw new ShellSyntaxError("ambiguous here-document delimiter line");
      }
      doc.word.heredoc = this.src.slice(bodyStart, bodyEnd);
      if (!doc.quoted) this.scanExpansions(bodyStart, bodyEnd, scope);
    }
  }

  /** Unquoted here-document bodies run command substitutions; tokenize those, ignore the rest. */
  private scanExpansions(from: number, to: number, scope: Scope): void {
    const resume = this.pos;
    const savedLimit = this.limit;
    const savedPending = this.pending;
    this.pending = [];
    this.limit = to;
    this.pos = from;
    while (this.pos < this.limit) {
      const c = this.at();
      if (c === "\\") {
        this.pos += 2;
      } else if (c === "$" && this.at(1) === "(") {
        this.pos += 2;
        this.substitution("$(", ")", scope);
      } else if (c === "`") {
        this.pos += 1;
        this.substitution("`", "`", scope);
      } else {
        this.pos += 1;
      }
    }
    this.limit = savedLimit;
    this.pending = savedPending;
    this.pos = resume;
  }

  private substitution(open: string, closer: string, scope: Scope): Scope {
    this.operators.push(open);
    scope.nested += 1;
    const inner = this.parseList(closer);
    this.operators.push(closer);
    return inner;
  }

  private readWord(closer: string, scope: Scope): ShellWord {
    const start = this.pos;
    let value = "";
    let quoted = false;
    let executes = false;
    let splittable = false;
    let expands = false;
    for (;;) {
      const c = this.at();
      if (c === "") break;
      if ((c === "<" || c === ">") && this.at(1) === "(") {
        const s = this.pos;
        this.pos += 2;
        this.substitution(`${c}(`, ")", scope);
        value += this.src.slice(s, this.pos);
        executes = true;
        expands = true;
        continue;
      }
      if (WORD_END.includes(c) || c === closer) break;
      const cont = this.continuation();
      if (cont > 0) {
        this.pos += cont;
      } else if (c === "\\") {
        if (this.at(1) === "") throw new ShellSyntaxError("dangling backslash at end of command");
        value += this.at(1);
        quoted = true;
        this.pos += 2;
      } else if (c === "'") {
        const close = this.src.indexOf("'", this.pos + 1);
        if (close < 0 || close >= this.limit) throw new ShellSyntaxError("unterminated single quote");
        value += this.src.slice(this.pos + 1, close);
        quoted = true;
        this.pos = close + 1;
      } else if (c === "$" && this.at(1) === "'") {
        this.pos += 2;
        value += this.ansiC();
        quoted = true;
      } else if (c === '"' || (c === "$" && this.at(1) === '"')) {
        this.pos += c === "$" ? 2 : 1;
        const dq = this.doubleQuoted(scope);
        value += dq.value;
        executes ||= dq.executes;
        expands ||= dq.expands;
        quoted = true;
      } else if ((c === "$" && this.at(1) === "(") || c === "`") {
        const s = this.pos;
        this.pos += c === "`" ? 1 : 2;
        const inner = c === "`" ? this.substitution("`", "`", scope) : this.substitution("$(", ")", scope);
        value += this.src.slice(s, this.pos);
        executes ||= !isLiteralSubstitution(inner);
        splittable = true;
        expands = true;
      } else {
        if (SPLIT_CHARS.includes(c)) splittable = true;
        if (c === "$") expands = true;
        value += c;
        this.pos += 1;
      }
    }
    return { value, start, end: this.pos, quoted, executes, splittable, expands, redirect: false };
  }

  private doubleQuoted(scope: Scope): { value: string; executes: boolean; expands: boolean } {
    let value = "";
    let executes = false;
    let expands = false;
    for (;;) {
      const c = this.at();
      if (c === "") throw new ShellSyntaxError("unterminated double quote");
      if (c === '"') {
        this.pos += 1;
        return { value, executes, expands };
      }
      const cont = this.continuation();
      if (cont > 0) {
        this.pos += cont;
      } else if (c === "\\" && this.at(1) !== "" && DQ_ESCAPABLE.includes(this.at(1))) {
        value += this.at(1);
        this.pos += 2;
      } else if ((c === "$" && this.at(1) === "(") || c === "`") {
        const s = this.pos;
        this.pos += c === "`" ? 1 : 2;
        const inner = c === "`" ? this.substitution("`", "`", scope) : this.substitution("$(", ")", scope);
        value += this.src.slice(s, this.pos);
        executes ||= !isLiteralSubstitution(inner);
        expands = true;
      } else {
        if (c === "$") expands = true;
        value += c;
        this.pos += 1;
      }
    }
  }

  /** Decodes a $'...' string; the position is just after the opening quote. */
  private ansiC(): string {
    let out = "";
    let truncated = false;
    const emit = (s: string): void => {
      if (s === "\0") truncated = true;
      if (!truncated) out += s;
    };
    for (;;) {
      const c = this.at();
      if (c === "") throw new ShellSyntaxError("unterminated $'...' quote");
      if (c === "'") {
        this.pos += 1;
        return out;
      }
      if (c !== "\\") {
        emit(c);
        this.pos += 1;
        continue;
      }
      const n = this.at(1);
      if (n === "") throw new ShellSyntaxError("unterminated $'...' quote");
      const simple = ANSI_SIMPLE[n];
      if (simple !== undefined) {
        emit(simple);
        this.pos += 2;
      } else if (OCTAL.includes(n)) {
        let digits = "";
        while (digits.length < 3 && this.at(1 + digits.length) !== "" && OCTAL.includes(this.at(1 + digits.length))) {
          digits += this.at(1 + digits.length);
        }
        emit(String.fromCharCode(parseInt(digits, 8) & 0xff));
        this.pos += 1 + digits.length;
      } else if (n === "x" || n === "u" || n === "U") {
        const max = n === "x" ? 2 : n === "u" ? 4 : 8;
        let digits = "";
        while (digits.length < max && this.at(2 + digits.length) !== "" && HEX.includes(this.at(2 + digits.length))) {
          digits += this.at(2 + digits.length);
        }
        if (digits === "") {
          emit(`\\${n}`);
        } else {
          const cp = parseInt(digits, 16);
          if (cp > 0x10ffff) throw new ShellSyntaxError("invalid unicode escape in $'...' quote");
          emit(String.fromCodePoint(cp));
        }
        this.pos += 2 + digits.length;
      } else if (n === "c" && this.at(2) !== "" && this.at(2) !== "'" && this.at(2).charCodeAt(0) < 0x80) {
        emit(String.fromCharCode(this.at(2).charCodeAt(0) & 0x1f));
        this.pos += 3;
      } else {
        emit(`\\${n}`);
        this.pos += 2;
      }
    }
  }
}

/** Tokenizes a command line. Throws ShellSyntaxError if it cannot be split unambiguously. */
export function parseShell(src: string): ShellParse {
  const lexer = new Lexer(src);
  lexer.parseList("");
  return { commands: lexer.commands, operators: lexer.operators };
}

/** Simple commands as arrays of unquoted words. */
export function splitCommands(src: string): string[][] {
  return parseShell(src).commands.map((c) => c.words.map((w) => w.value));
}
