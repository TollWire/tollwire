// Safe matchers for policy rules of lower layers: literal, token sequence and a glob with at most
// two `*`. None of them uses a regular expression, so a rule from a project file cannot cause catastrophic backtracking.

export type Match = { literal: string } | { tokens: string[] } | { glob: string };

export const MAX_GLOB_STARS = 2;

/** True if the glob has no more than two `*` (`?` matches one character; everything else is literal). */
export function validGlob(glob: string): boolean {
  return [...glob].filter((c) => c === "*").length <= MAX_GLOB_STARS;
}

/** Glob match of the whole text: `*` any sequence, `?` one character. Iterative with one backtracking point. */
export function globMatch(glob: string, text: string): boolean {
  const g = Array.from(glob);
  const t = Array.from(text);
  let gi = 0;
  let ti = 0;
  let starG = -1;
  let starT = 0;
  while (ti < t.length) {
    const c = g[gi];
    if (c !== undefined && c !== "*" && (c === "?" || c === t[ti])) {
      gi += 1;
      ti += 1;
    } else if (c === "*") {
      starG = gi;
      starT = ti;
      gi += 1;
    } else if (starG >= 0) {
      gi = starG + 1;
      starT += 1;
      ti = starT;
    } else {
      return false;
    }
  }
  while (g[gi] === "*") gi += 1;
  return gi === g.length;
}

/** True if `tokens` occur as consecutive words in one of the commands. */
export function containsTokens(commands: readonly (readonly string[])[], tokens: readonly string[]): boolean {
  if (tokens.length === 0) return false;
  return commands.some((words) => {
    for (let start = 0; start + tokens.length <= words.length; start += 1) {
      if (tokens.every((token, i) => words[start + i] === token)) return true;
    }
    return false;
  });
}

/** Evaluates a safe matcher against the matching texts of a command and its simple commands (as unquoted words). */
export function matches(match: Match, variants: readonly string[], commands: readonly (readonly string[])[]): boolean {
  if ("literal" in match) return match.literal !== "" && variants.some((v) => v.includes(match.literal));
  if ("tokens" in match) return containsTokens(commands, match.tokens);
  return variants.some((v) => globMatch(match.glob, v));
}
