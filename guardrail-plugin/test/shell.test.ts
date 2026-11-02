import { describe, expect, it } from "vitest";
import { MAX_NESTING, parseShell, ShellSyntaxError, splitCommands } from "../src/shell.js";

describe("here-document bodies", () => {
  it("attaches the raw body to the delimiter word", () => {
    const words = parseShell("python3 - <<'EOF' && cat <<-X\nprint(1)\nEOF\n\tbody\n\tX\n").commands.flatMap((c) => c.words);
    expect(words.filter((w) => w.heredoc !== undefined).map((w) => [w.value, w.heredoc])).toEqual([
      ["EOF", "print(1)\n"],
      ["X", "\tbody\n"],
    ]);
  });
});

describe("splitCommands", () => {
  it("splits words and removes quoting", () => {
    expect(splitCommands(`git push '--force' "ori"gin \\-\\-x`)).toEqual([["git", "push", "--force", "origin", "--x"]]);
    expect(splitCommands("echo ''")).toEqual([["echo", ""]]);
  });

  it("splits on control operators and reports them", () => {
    const parsed = parseShell("a; b && c || d | e |& f & g\nh ;; i");
    expect(parsed.commands.map((c) => c.words.map((w) => w.value))).toEqual([["a"], ["b"], ["c"], ["d"], ["e"], ["f"], ["g"], ["h"], ["i"]]);
    expect(parsed.operators).toEqual([";", "&&", "||", "|", "|&", "&", "\n", ";;"]);
  });

  it("handles double quotes with escapes and literal backslashes", () => {
    expect(splitCommands(`echo "a \\"b\\" \\$x \\\\ \\n"`)).toEqual([["echo", 'a "b" $x \\ \\n']]);
    expect(splitCommands(`echo $"loc"`)).toEqual([["echo", "loc"]]);
  });

  it("joins line continuations inside and between words", () => {
    expect(splitCommands("git pu\\\nsh \\\n --force")).toEqual([["git", "push", "--force"]]);
    expect(splitCommands('echo "a\\\nb" \\\r\n c')).toEqual([["echo", "ab", "c"]]);
  });

  it("skips comments only at word start", () => {
    expect(splitCommands("ls # it's a comment\necho a#b")).toEqual([["ls"], ["echo", "a#b"]]);
  });

  it("decodes ANSI-C quotes", () => {
    const decoded = splitCommands(
      "echo $'\\x2d\\055\\u00e9\\U0001F600\\t\\'\\cA\\q\\x\\u\\0rest'",
    )[0]?.[1];
    expect(decoded).toBe("--é\u{1F600}\t'\x01\\q\\x\\u");
    expect(splitCommands("echo $'\\ca\\c'")[0]?.[1]).toBe("\x01\\c");
  });

  it("treats redirections as separate words", () => {
    expect(splitCommands("npm test 2>&1 >>log <in &>all &>>more <<<here")).toEqual([
      ["npm", "test", "2", ">&", "1", ">>", "log", "<", "in", "&>", "all", "&>>", "more", "<<<", "here"],
    ]);
  });

  it("tokenizes subshells and substitutions as separate commands", () => {
    expect(splitCommands("(git push --force)")).toEqual([["git", "push", "--force"]]);
    expect(splitCommands("echo $(git push --force) `id` <(printenv) >(cat)")).toEqual([
      ["git", "push", "--force"],
      ["id"],
      ["printenv"],
      ["cat"],
      ["echo", "$(git push --force)", "`id`", "<(printenv)", ">(cat)"],
    ]);
    expect(splitCommands('echo "x $(a "b c") `d`"')).toEqual([["a", "b c"], ["d"], ["echo", 'x $(a "b c") `d`']]);
  });

  it("treats a stray closing parenthesis (case pattern) as a separator", () => {
    expect(splitCommands("case $1 in a) echo x;; esac")).toEqual([["case", "$1", "in", "a"], ["echo", "x"], ["esac"]]);
  });

  it("marks words that run code or may split", () => {
    const words = parseShell(`echo $X "$Y" 'a*' * "$(id)" $(id) <(id)`).commands.at(-1)?.words ?? [];
    expect(words.map((w) => [w.value, w.executes, w.splittable])).toEqual([
      ["echo", false, false],
      ["$X", false, true],
      ["$Y", false, false],
      ["a*", false, false],
      ["*", false, true],
      ["$(id)", true, false],
      ["$(id)", true, true],
      ["<(id)", true, false],
    ]);
  });

  it("marks expansions and redirections", () => {
    const words = parseShell(`git "$X" '$Y' $'\\x24' >-m a$`).commands[0]?.words ?? [];
    expect(words.map((w) => [w.value, w.expands, w.redirect])).toEqual([
      ["git", false, false],
      ["$X", true, false],
      ["$Y", false, false],
      ["$", false, false],
      [">", false, true],
      ["-m", false, false],
      ["a$", true, false],
    ]);
  });

  it("records source spans", () => {
    const words = parseShell("git  commit -m 'a b'").commands[0]?.words ?? [];
    expect(words.map((w) => [w.start, w.end])).toEqual([[0, 3], [5, 11], [12, 14], [15, 20]]);
  });
});

describe("here-documents", () => {
  it("skips quoted bodies and does not treat them as commands", () => {
    const parsed = parseShell("cat <<'EOF' > notes.md\ngit push --force\nit's\nEOF\nls");
    expect(parsed.commands.map((c) => c.words.map((w) => w.value))).toEqual([["cat", "<<", "EOF", ">", "notes.md"], ["ls"]]);
  });

  it("tokenizes substitutions in unquoted bodies", () => {
    expect(splitCommands("cat <<EOF\nx \\$(no) $(git push --force) `id`\nEOF")).toEqual([
      ["cat", "<<", "EOF"],
      ["git", "push", "--force"],
      ["id"],
    ]);
  });

  it("supports <<- with tab stripping and several pending documents", () => {
    expect(splitCommands("cat <<-A <<B\n\tbody\n\tA\nb2\nB\necho done")).toEqual([["cat", "<<-", "A", "<<", "B"], ["echo", "done"]]);
  });

  it("does not let a body substitution consume a later pending document", () => {
    expect(splitCommands("cat <<A <<B\n$(echo\nx)\nA\nB\nls")).toEqual([["cat", "<<", "A", "<<", "B"], ["echo"], ["x"], ["ls"]]);
  });

  it("treats a quoted heredoc fed to cat in a substitution as data", () => {
    const words = parseShell(`git commit -m "$(cat <<'EOF'\nmsg\nEOF\n)"`).commands.at(-1)?.words ?? [];
    expect(words[3]?.executes).toBe(false);
    const unquoted = parseShell(`git commit -m "$(cat <<EOF\nmsg\nEOF\n)"`).commands.at(-1)?.words ?? [];
    expect(unquoted[3]?.executes).toBe(true);
  });

  it("ignores a document that never gets a body line (no newline follows)", () => {
    expect(splitCommands("cat <<EOF")).toEqual([["cat", "<<", "EOF"]]);
  });
});

describe("fail closed", () => {
  it.each([
    ["echo 'a", "unterminated single quote"],
    ['echo "a', "unterminated double quote"],
    ['echo "a\\', "unterminated double quote"],
    ["echo $'a", "unterminated $'...' quote"],
    ["echo $'a\\", "unterminated $'...' quote"],
    ["echo $(ls", "unterminated ( or $("],
    ["(ls", "unterminated ( or $("],
    ["echo `ls", "unterminated backquote"],
    ["echo a\\", "dangling backslash at end of command"],
    ["cat <<", "missing here-document delimiter"],
    ["cat << ;", "missing here-document delimiter"],
    ["cat <<EOF\nbody", "unterminated here-document (missing EOF)"],
    ["cat <<EOF\n", "unterminated here-document (missing EOF)"],
    ["x=\"$(cat <<'EOF'\nhello\nEOF)\" ; echo INJECTED\nEOF\n)\"", "ambiguous here-document delimiter line"],
    ["echo $'\\U00110000'", "invalid unicode escape in $'...' quote"],
    ["echo a\0b", "NUL character in command"],
  ])("rejects %j", (cmd, message) => {
    expect(() => parseShell(cmd)).toThrow(new ShellSyntaxError(message));
  });

  it("limits nesting depth", () => {
    const ok = "$(".repeat(MAX_NESTING - 1) + "x" + ")".repeat(MAX_NESTING - 1);
    expect(() => parseShell(ok)).not.toThrow();
    const deep = "$(".repeat(MAX_NESTING) + "x" + ")".repeat(MAX_NESTING);
    expect(() => parseShell(deep)).toThrow("nesting too deep");
  });

  it("names the error class", () => {
    expect(new ShellSyntaxError("x").name).toBe("ShellSyntaxError");
  });
});
