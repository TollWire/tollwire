import { describe, expect, it } from "vitest";
import { applyMasks, maskingSafe, messageMasks } from "../src/gitMessages.js";
import { parseShell } from "../src/shell.js";

/** Masked words (source text) and replacements of the last simple command. */
function masks(cmd: string): [string, string][] {
  const parsed = parseShell(cmd);
  const last = parsed.commands.at(-1);
  if (!last) return [];
  return messageMasks(last, cmd).map((m) => [cmd.slice(m.word.start, m.word.end), m.replacement]);
}

describe("messageMasks", () => {
  it.each([
    ["git commit -m 'a b'", [["'a b'", "_"]]],
    ["git commit --message 'a'", [["'a'", "_"]]],
    ["git commit --message='a b'", [["--message='a b'", "--message=_"]]],
    ["git commit -am x", [["x", "_"]]],
    ["git commit -nm x", [["x", "_"]]],
    ["git commit -mfoo", [["-mfoo", "-m _"]]],
    ["git commit -nmfoo", [["-nmfoo", "-nm _"]]],
    ["git commit -m a -m b", [["a", "_"], ["b", "_"]]],
    ["git commit -m -- -n", [["--", "_"]]],
    ["git commit file.txt - -m x", [["x", "_"]]],
    ["git commit --author A -F f -C HEAD -Fg -m x", [["x", "_"]]],
    ["git commit --cleanup=strip --no-verify -m x", [["x", "_"]]],
    ["git tag -a v1 -m 'x'", [["'x'", "_"]]],
    ["git tag -n5 -m x", [["x", "_"]]],
    ["/usr/bin/git -C d -c a=b --no-pager --git-dir=.git commit -m x", [["x", "_"]]],
    ["GIT_TRACE=1 time command git commit -m x", [["x", "_"]]],
  ])("masks %j", (cmd, expected) => expect(masks(cmd)).toEqual(expected));

  it.each([
    "git push -m x",
    "git constructor -m x",
    "echo git commit -m x",
    "'X=1' git commit -m x",
    "git --unknown commit -m x",
    "git -c $X commit -m x",
    "git $X commit -m x",
    "git commit -- -m x",
    "git commit --auth -m x",
    "git commit -um x",
    "git commit -Sm x",
    "git commit -Qm x",
    "git commit $X -m x",
    "git commit --author $X -m x",
    "git commit -m $X",
    "git commit -m",
    "git tag -nm x",
    "$(git) commit -m x",
    "X=1",
    "git commit \"$X\" -m x",
    "git commit \"${X}\" -m x",
    "git commit >-m x",
    "git commit 2> log -m x",
    "git \"$C\" -m x",
    "git commit -m\"$X\"",
    "git commit --message=\"$X\"",
  ])("does not mask %j", (cmd) => expect(masks(cmd)).toEqual([]));

  it("stops at a redirection: its target is not an argument", () => {
    expect(masks("git commit -m ok >-m --no-verify")).toEqual([["ok", "_"]]);
  });

  it("accepts an expanding but single message operand", () => {
    expect(masks('git commit -m "Release $V" -n')).toEqual([['"Release $V"', "_"]]);
  });

  it("masks a message word that runs no code but not one that does", () => {
    expect(masks(`git commit -m "$(cat <<'EOF'\nm\nEOF\n)"`)).toHaveLength(1);
    expect(masks(`git commit -m "$(id)" -m x`)).toEqual([]);
  });
});

describe("maskingSafe", () => {
  const safe = (cmd: string): boolean => maskingSafe(parseShell(cmd), cmd);

  it.each([
    "git commit -m 'fix(api): x' && git push",
    'git commit -m "Release $VERSION ${NAME}"',
    "npm test 2>&1 | tee log > out < in",
    `git add -A && git commit -m "$(cat <<'EOF'\nfeat: it's \`x\` $(y)\nEOF\n)"`,
    `git commit -m "$(cat << 'EOF'\nEOF\n)"`,
  ])("accepts %j", (cmd) => expect(safe(cmd)).toBe(true));

  it.each([
    "(cd x && git commit -m 'x')",
    "case a in a) git commit -m 'x';; esac",
    "git commit -m `id`",
    "git commit -m $'x'",
    "git commit -m \"$1\"",
    "git commit -m x\\ y",
    "diff <(ls) a",
    "cat <<'EOF'\nx\nEOF",
    `git commit -m "$(cat <<EOF\nm\nEOF\n)"`,
    "git commit -m *.ts",
    "git commit -m {a,b}",
    "git commit -m ok >-m x",
    "git commit -m ok 2> -m x",
    `git commit -m "$(cat <<'EOF'\nx\nEOF\ngit push --force\nEOF\n)"`,
  ])("rejects %j", (cmd) => expect(safe(cmd)).toBe(false));
});

describe("applyMasks", () => {
  it("replaces spans right to left and skips overlaps", () => {
    const word = (start: number, end: number) => ({
      value: "",
      start,
      end,
      quoted: false,
      executes: false,
      splittable: false,
      expands: false,
      redirect: false,
    });
    expect(applyMasks("abcdef", [{ word: word(0, 2), replacement: "X" }, { word: word(4, 6), replacement: "Y" }])).toBe("XcdY");
    expect(applyMasks("abcdef", [{ word: word(1, 5), replacement: "X" }, { word: word(2, 6), replacement: "Y" }])).toBe("abY");
  });
});
