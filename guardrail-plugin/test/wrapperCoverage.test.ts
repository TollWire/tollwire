import { describe, expect, it } from "vitest";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { defaultPolicy } from "./helpers.js";

// Issue #125: write check and install check must see through the same command wrappers. Measured gaps (2026-11-25):
// write: `runuser -u U -- cmd`, `sg GROUP -c cmd`, container runners (`docker run … node sh -c …`);
// install: `script -c`, `sg`, `setpriv`, `docker|podman|nerdctl run|exec`, `chroot`, `nsenter`, `systemd-run`, `bwrap`, `firejail`.
// `ssh HOST 'cmd'` runs on another host and stays out of scope (owner decision pending, see PR).
const project = "/tg-wrap/repo";
const ctx: Context = { projectDir: project, humanSession: false, home: "/tg-wrap/home", cwd: project };
const policy = defaultPolicy({ allowedDependencies: { npm: ["zod"], pypi: ["requests"] } });
const run = (command: string) => evaluateDetailed({ tool_name: "Bash", tool_input: { command } }, policy, ctx);

const WRITE = "echo x > .tollgate/policy.json";
const INSTALL = "npm install left-pad";
const forms = (c: string): string[] => [
  `su -c '${c}'`,
  `runuser -u bob -- sh -c '${c}'`,
  `runuser -u bob sh -c '${c}'`,
  `sg devs -c '${c}'`,
  `sg - devs -c '${c}'`,
  `echo a | xargs sh -c '${c}'`,
  `find . -maxdepth 0 -exec sh -c '${c}' \;`,
  `docker run --rm -v "$PWD":/w -w /w node sh -c '${c}'`,
  `docker container run --rm node sh -c '${c}'`,
  `podman run --rm -v .:/w alpine sh -c '${c}'`,
  `nerdctl run --rm alpine sh -c '${c}'`,
  `docker exec ctr sh -c '${c}'`,
  `docker compose run app sh -c '${c}'`,
  `watch -n1 '${c}'`,
  `script -qc '${c}' /dev/null`,
  `flock /tmp/l sh -c '${c}'`,
  `timeout 5 sh -c '${c}'`,
  `nohup sh -c '${c}'`,
  `env -S 'sh -c "${c}"'`,
  `unshare -r sh -c '${c}'`,
  `chroot / sh -c '${c}'`,
  `setpriv --reuid 1000 sh -c '${c}'`,
  `nsenter -t 1 -m sh -c '${c}'`,
  `systemd-run --user --wait sh -c '${c}'`,
  `bwrap --bind / / sh -c '${c}'`,
  `firejail --quiet sh -c '${c}'`,
];

describe("#125 wrappers: the write check sees the wrapped command", () => {
  for (const f of forms(WRITE)) it(`blocks: ${f}`, () => expect(run(f).allowed, f).toBe(false));
});

describe("#125 wrappers: the install check sees the wrapped command", () => {
  for (const f of forms(INSTALL)) it(`blocks: ${f}`, () => expect(run(f).allowed, f).toBe(false));
  it("direct container commands with an install are checked too", () => {
    expect(run("docker run --rm node npm install left-pad").allowed).toBe(false);
    expect(run("podman exec app pip install flask").allowed).toBe(false);
  });
});

describe("#125 wrappers: allowed forms stay allowed", () => {
  for (const f of [
    "docker run --rm node npm test",
    "docker run --rm -v \"$PWD\":/w -w /w node npm install zod",
    "docker ps",
    "docker build -t app .",
    "podman exec app ls -la",
    "sg devs -c 'ls -la'",
    "runuser -u bob -- ls",
    "script -qc 'git status' /dev/null",
    "setpriv --reuid 1000 id",
    "echo npm install left-pad",
  ]) it(`allows: ${f}`, () => expect(run(f).allowed, f).toBe(true));
});
