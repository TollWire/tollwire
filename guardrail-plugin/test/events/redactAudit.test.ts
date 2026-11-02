import { describe, expect, it } from "vitest";
import { redactCommand, redactText } from "../../src/events/redact.js";

// Security audit 2026-10-22, finding F-03: forms of command lines that still reached the decision log in clear text
// (internal security audit report). Synthetic values only; none of these is a real credential.
const red = (command: string): { text: string; redactions: number } => {
  const r = redactCommand(command);
  if (r === null) throw new Error("not parsable");
  return r;
};

describe("F-03: forms that were logged in clear text", () => {
  it.each([
    ['curl -b "session=abcdef123456" https://x', "curl -b [REDACTED:credential] https://x"],
    ['curl --cookie "session=abcdef123456" https://x', "curl --cookie [REDACTED:credential] https://x"],
    ["curl --cookie=session=abcdef123456 https://x", "curl --cookie=[REDACTED:credential] https://x"],
    ["curl -bsession=abcdef123456 https://x", "curl -b[REDACTED:credential] https://x"],
    ['curl --data-urlencode "pw=hunter2" https://x', "curl --data-urlencode pw=[REDACTED:credential] https://x"],
    ['curl -H "X-Custom-Token: abc123" https://x', "curl -H X-Custom-Token: [REDACTED:header] https://x"],
    ['curl -H "X-Session-Id: abc123" https://x', "curl -H X-Session-Id: [REDACTED:header] https://x"],
    ['curl --header "X-Amz-Signature: abc123" https://x', "curl --header X-Amz-Signature: [REDACTED:header] https://x"],
    ['git -c http.extraheader="AUTHORIZATION: basic dXNlcjpwYXNz" fetch', "git -c http.extraheader=[REDACTED:credential] fetch"],
    ['git config http.https://x/.extraheader "AUTHORIZATION: basic dXNlcjpwYXNz"', "git config http.https://x/.extraheader [REDACTED:credential]"],
    ['psql "host=h password=hunter2 dbname=x"', "psql host=h password=[REDACTED:credential] dbname=x"],
    ["psql 'password=\"hunter 2\" host=h'", "psql password=[REDACTED:credential]"],
    ['run "Server=x;Password=hunter2;Database=d"', "run Server=x;Password=[REDACTED:credential]"],
    ["mount.cifs //h/s /mnt -o username=u,password=hunter2", "mount.cifs //h/s /mnt -o username=u,password=[REDACTED:credential]"],
    ["npm config set //registry.npmjs.org/:_authToken abcdef", "npm config set //registry.npmjs.org/:_authToken [REDACTED:credential]"],
    ['git config --global http.extraheader "AUTHORIZATION: basic dXNlcjpwYXNz"', "git config --global http.extraheader [REDACTED:credential]"],
    ["npm config set --location=user //registry.npmjs.org/:_authToken abcdef", "npm config set --location=user //registry.npmjs.org/:_authToken [REDACTED:credential]"],
    ["yarn config set npmAuthToken abcdef", "yarn config set npmAuthToken [REDACTED:credential]"],
    ["az login -u u -p hunter2", "az login -u u -p [REDACTED:password]"],
    ["vault login hunter2", "vault login [REDACTED:credential]"],
    ["vault login -no-print hunter2", "vault login -no-print [REDACTED:credential]"],
    ["sqlcmd -S s -U u -P hunter2", "sqlcmd -S s -U u -P [REDACTED:password]"],
    ["sqlcmd -S s -U u -Phunter2", "sqlcmd -S s -U u -P[REDACTED:password]"],
    ["smbclient //h/s -U u%hunter2", "smbclient //h/s -U u%[REDACTED:password]"],
    ["smbclient //h/s -Uu%hunter2", "smbclient //h/s -Uu%[REDACTED:password]"],
    ["smbclient //h/s --user=u%hunter2", "smbclient //h/s --user=u%[REDACTED:password]"],
    ["rclone config create x s3 provider AWS secret_access_key hunter2", "rclone config create x s3 provider AWS secret_access_key [REDACTED:credential]"],
    ["rclone obscure hunter2", "rclone obscure [REDACTED:password]"],
    ["twine upload -p hunter2 dist/*", "twine upload -p [REDACTED:password] dist/*"],
    ['curl "https://x/c?sv=2022&sig=abcdef%2Fgh&se=1"', "curl https://x/c?sv=2022&sig=[REDACTED:credential]&se=1"],
    ['curl "https://x/c?X-Amz-Signature=abcdef&X-Amz-Date=1"', "curl https://x/c?X-Amz-Signature=[REDACTED:credential]&X-Amz-Date=1"],
  ])("%s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
    expect(r.text).not.toMatch(/hunter|abcdef|dXNlcj/);
  });

  it("masks keyword=value pairs in free text, too", () => {
    const r = redactText("connect with host=h password=hunter2 dbname=x");
    expect(r.text).toBe("connect with host=h password=[REDACTED:credential] dbname=x");
    expect(r.redactions).toBe(1);
  });

  it.each([
    "curl -b cookies.txt https://x",
    "curl -H 'Content-Type: application/json' https://x",
    "curl -H 'X-Request-Id: 12345' https://x",
    "git config user.name x",
    "git -c core.pager=cat log",
    'psql "host=h dbname=x user=u"',
    "az login --use-device-code",
    "az group create -n x -l y",
    "vault status",
    "vault login -method=oidc",
    "sqlcmd -S s -E",
    "smbclient //h/s -U u",
    "smbclient //h/s -N",
    "rclone config create x s3 provider AWS",
    "npm config set registry https://registry.npmjs.org/",
    'curl "https://x/c?sv=2022&se=1"',
    "echo password",
  ])("counter-example without a hit: %s", (input) => {
    const r = red(input);
    expect(r.redactions).toBe(0);
    expect(r.text).not.toContain("REDACTED");
  });
});

describe("F-03: bounded regular expressions", () => {
  const budgetMs = 250; // catastrophic backtracking takes seconds; 250 ms leaves room for a loaded self-hosted runner
  const timed = (fn: () => unknown): number => {
    const t = process.hrtime.bigint();
    fn();
    return Number(process.hrtime.bigint() - t) / 1e6;
  };
  it.each([
    ["keyword repeated", "password=".repeat(4000)],
    ["keyword with blanks", "password ".repeat(4000)],
    ["separators", ";,; ".repeat(8000)],
    ["long unterminated quote", `password="${"a".repeat(40000)}`],
    ["signature names", "&sig".repeat(8000)],
    ["spaced equals", "pwd   ".repeat(6000) + "="],
  ])("redactText on pathological input (%s) stays below %i ms", (_name, input) => {
    redactText(input.slice(0, 40000)); // warm-up
    expect(timed(() => redactText(input.slice(0, 40000)))).toBeLessThan(budgetMs);
  });
  it("redactCommand on pathological words stays below the budget", () => {
    const input = `psql "${"password=".repeat(2000)}" ${"x ".repeat(2000)}`;
    redactCommand(input);
    expect(timed(() => redactCommand(input))).toBeLessThan(budgetMs);
  });
});
