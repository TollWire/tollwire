// TMPDIR as an allowed write zone outside the project: only below fixed temporary roots.
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { evaluate, temporaryDirs } from "../src/evaluate.js";
import { acceptedTmpdir, analyzeWrites, currentTempHost, decideWrites, temporaryRoots } from "../src/writes.js";
import { defaultPolicy } from "./helpers.js";

/** true, wenn der Pfad existiert (auch als Link) oder nicht prüfbar ist (dann ebenfalls meiden). */
function existsLexically(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

const project = realpathSync(mkdtempSync("/tmp/tg-tmpdir-project-"));
const scratch = realpathSync(mkdtempSync("/tmp/tg-tmpdir-"));
// A directory below /tmp that is a symlink to /etc: lexically temporary, physically not.
symlinkSync("/etc", join(scratch, "to-etc"));
const home = homedir();
const policy = defaultPolicy();

afterAll(() => {
  rmSync(project, { recursive: true, force: true });
  rmSync(scratch, { recursive: true, force: true });
});

const write = (filePath: string, tmpdir: string | undefined) =>
  evaluate({ tool_name: "Write", tool_input: { file_path: filePath, content: "" } }, policy, { projectDir: project, humanSession: false, tmpdir }).allowed;
const bash = (command: string, tmpdir: string | undefined) =>
  evaluate({ tool_name: "Bash", tool_input: { command } }, policy, { projectDir: project, humanSession: false, home, tmpdir }).allowed;

describe("Write tools: TMPDIR is a write zone only below a fixed temporary root", () => {
  it("ignores TMPDIR=/etc and blocks writes to /etc", () => {
    expect(write("/etc/tg-tmpdir-x", "/etc")).toBe(false);
  });
  it("ignores TMPDIR=$HOME and blocks writes to the home directory", () => {
    expect(write(join(home, ".bashrc"), home)).toBe(false);
    expect(write(join(home, "tg-tmpdir-notes.txt"), home)).toBe(false);
  });
  it("ignores a TMPDIR below /tmp that is a symlink to /etc", () => {
    expect(write("/etc/tg-tmpdir-x", join(scratch, "to-etc"))).toBe(false);
    expect(write(join(scratch, "to-etc", "tg-tmpdir-x"), join(scratch, "to-etc"))).toBe(false);
  });
  it("ignores lexical escapes, relative values and the root directory", () => {
    expect(write("/etc/tg-tmpdir-x", "/tmp/../etc")).toBe(false);
    expect(write("/etc/tg-tmpdir-x", "etc")).toBe(false);
    expect(write("/etc/tg-tmpdir-x", "/")).toBe(false);
    expect(write("/tmpx/tg-tmpdir-x", "/tmpx")).toBe(false);
  });
  it("keeps /tmp and /var/tmp and accepts a TMPDIR below /tmp", () => {
    expect(write(join(scratch, "x.txt"), scratch)).toBe(true);
    expect(write("/tmp/tg-tmpdir-x", "/tmp")).toBe(true);
    expect(write("/var/tmp/tg-tmpdir-x", "/etc")).toBe(true);
    expect(write("/tmp/tg-tmpdir-x", "relative")).toBe(true);
    expect(write("/tmp/tg-tmpdir-x", undefined)).toBe(true);
  });
});

describe('Bash: the "$TMPDIR/..." exception needs an accepted TMPDIR', () => {
  it("blocks $TMPDIR targets when TMPDIR points outside the temporary roots", () => {
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-x"', "/etc")).toBe(false);
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-notes.txt"', home)).toBe(false);
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-x"', join(scratch, "to-etc"))).toBe(false);
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-x"', "/tmp/../etc")).toBe(false);
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-x"', "relative")).toBe(false);
  });
  it("allows $TMPDIR targets when TMPDIR lies below /tmp", () => {
    expect(bash('echo x > "$TMPDIR/tg-tmpdir-x"', scratch)).toBe(true);
    expect(bash('echo x > "${TMPDIR}/sub/tg-tmpdir-x"', "/var/tmp")).toBe(true);
  });
  it("decideWrites applies the same rule for direct callers", () => {
    const analysis = analyzeWrites('echo x > "$TMPDIR/y"', { root: "/fakeroot/repo" });
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/etc" }).allowed).toBe(false);
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/fakeroot/tmp" }).allowed).toBe(false);
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/tmp/tg-tmpdir-direct" }).allowed).toBe(true);
  });
});

describe("fixed temporary roots", () => {
  const linux = { platform: "linux", uid: 1000 };
  const darwin = { platform: "darwin", uid: 501 };
  it("lists /tmp, /var/tmp and the per-user tollgate-tmp directory", () => {
    expect(temporaryRoots(linux)).toEqual(["/tmp", "/var/tmp", "/run/user/1000/tollgate-tmp"]);
    expect(temporaryRoots({ platform: "linux", uid: undefined })).toEqual(["/tmp", "/var/tmp"]);
    expect(currentTempHost().platform).toBe(process.platform);
  });
  it("accepts TMPDIR at or below a root and rejects everything else", () => {
    expect(acceptedTmpdir("/tmp", linux)).toBe(realpathSync("/tmp"));
    expect(acceptedTmpdir("/var/tmp/", linux)).toBe(realpathSync("/var/tmp"));
    // uid, deren /run/user/<uid> nicht existiert: sonst hängt das Ergebnis von der Umgebung ab (z. B. self-hosted Runner in
    // einer WSL: /run/user/1000 gehört einem anderen Benutzer, ist nicht lesbar und wird zu Recht abgewiesen).
    let uid = 1000;
    while (existsLexically(`/run/user/${uid}`) || existsLexically(`/run/user/${uid + 1}`)) uid++;
    const free = { platform: "linux", uid };
    expect(acceptedTmpdir(`/run/user/${uid}/tollgate-tmp/a`, free)).toBe(`/run/user/${uid}/tollgate-tmp/a`);
    for (const tmpdir of [undefined, "", "tmp", "/", "/etc", "/tmpx", "/tmp/../etc", `/run/user/${uid}`, `/run/user/${uid + 1}/tollgate-tmp/a`, "/var/folders/ab/cd/T"]) {
      expect(acceptedTmpdir(tmpdir, free)).toBeNull();
    }
    for (const tmpdir of [undefined, "", "tmp", "/", "/etc", "/tmpx", "/tmp/../etc", "/run/user/1000", "/run/user/1001/tollgate-tmp/a", "/var/folders/ab/cd/T"]) {
      expect(acceptedTmpdir(tmpdir, linux)).toBeNull();
    }
    expect(acceptedTmpdir(join(scratch, "to-etc"), linux)).toBeNull();
    expect(acceptedTmpdir(join(scratch, "to-etc", "x"), linux)).toBeNull();
  });
  it("accepts only the per-user temporary directory /var/folders/<xx>/<id>/T on macOS", () => {
    expect(temporaryRoots(darwin)).toEqual(["/tmp", "/var/tmp", "/run/user/501/tollgate-tmp"]);
    expect(acceptedTmpdir("/var/folders/ab/cd/T/", darwin)).not.toBeNull();
    expect(acceptedTmpdir("/var/folders/ab/cd/T/x", darwin)).not.toBeNull();
    expect(acceptedTmpdir("/private/var/folders/ab/cd/T", darwin)).not.toBeNull();
    for (const tmpdir of ["/var/folders", "/var/folders/x", "/var/folders/ab", "/var/folders/ab/cd", "/var/folders/ab/cd/C/x",
      "/var/folders/ab/cd/0/x", "/var/folders/ab/cd/Tx", "/private/var/folders/ab/cd/C", "/var/folders/ab/cd/../cd/C/T", "/var/foldersx/T"]) {
      expect(acceptedTmpdir(tmpdir, darwin)).toBeNull();
    }
    expect(acceptedTmpdir(join(scratch, "to-etc"), darwin)).toBeNull();
    expect(temporaryDirs("/var/folders/ab/cd/T", darwin)).toContain("/var/folders/ab/cd/T");
    expect(temporaryDirs("/var/folders/ab/cd/T", linux)).not.toContain("/var/folders/ab/cd/T");
  });
  it("passes the host through decideWrites", () => {
    const analysis = analyzeWrites('echo x > "$TMPDIR/y"', { root: "/fakeroot/repo" });
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/var/folders/ab/cd/T", tempHost: darwin }).allowed).toBe(true);
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/var/folders/ab/cd/T", tempHost: linux }).allowed).toBe(false);
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/var/folders/ab/cd/C", tempHost: darwin }).allowed).toBe(false);
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/var/folders/x", tempHost: darwin }).allowed).toBe(false);
  });
});

describe("roots that are symlinks", () => {
  // Injected runtime directory: <runDir>/<uid>/tollgate-tmp lies in a directory the user owns.
  const runDir = join(scratch, "run");
  mkdirSync(join(runDir, "1000"), { recursive: true });
  mkdirSync(join(runDir, "1001", "tollgate-tmp"), { recursive: true });
  symlinkSync("/etc", join(runDir, "1000", "tollgate-tmp"));
  mkdirSync(join(runDir, "1002"), { recursive: true });
  symlinkSync("/etc/tg-missing-target", join(runDir, "1002", "tollgate-tmp"));
  it("drops a per-user root that is a symlink", () => {
    const host = { platform: "linux", uid: 1000, runDir };
    expect(temporaryRoots(host)).toEqual(["/tmp", "/var/tmp", `${runDir}/1000/tollgate-tmp`]);
    expect(acceptedTmpdir("/etc", host)).toBeNull();
    expect(acceptedTmpdir("/etc/x", host)).toBeNull();
    expect(acceptedTmpdir(`${runDir}/1000/tollgate-tmp`, host)).toBeNull();
    expect(acceptedTmpdir(`${runDir}/1000/tollgate-tmp/x`, host)).toBeNull();
    expect(acceptedTmpdir(`${runDir}/1002/tollgate-tmp/x`, { ...host, uid: 1002 })).toBeNull();
    const analysis = analyzeWrites('echo x > "$TMPDIR/y"', { root: "/fakeroot/repo" });
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/etc", tempHost: host }).allowed).toBe(false);
  });
  it("keeps a per-user root that is a real directory", () => {
    const host = { platform: "linux", uid: 1001, runDir };
    expect(acceptedTmpdir(`${runDir}/1001/tollgate-tmp/x`, host)).toBe(`${runDir}/1001/tollgate-tmp/x`);
    expect(acceptedTmpdir(`${runDir}/1001/tollgate-tmp`, host)).toBe(`${runDir}/1001/tollgate-tmp`);
    expect(acceptedTmpdir("/etc", host)).toBeNull();
  });
  it("rejects a macOS T directory that is a symlink leaving the tree", () => {
    const varFolders = join(scratch, "folders");
    mkdirSync(join(varFolders, "ab", "cd"), { recursive: true });
    mkdirSync(join(varFolders, "ef", "gh", "T"), { recursive: true });
    symlinkSync("/etc", join(varFolders, "ab", "cd", "T"));
    // The injected tree lies below /tmp; without system roots only the macOS rule decides.
    const host = { platform: "darwin", uid: 501, varFolders: [varFolders], systemRoots: [] };
    expect(acceptedTmpdir(join(varFolders, "ab", "cd", "T"), host)).toBeNull();
    expect(acceptedTmpdir(join(varFolders, "ab", "cd", "T", "x"), host)).toBeNull();
    expect(acceptedTmpdir("/etc", host)).toBeNull();
    expect(acceptedTmpdir(join(varFolders, "ef", "gh", "T", "x"), host)).toBe(join(varFolders, "ef", "gh", "T", "x"));
    expect(acceptedTmpdir(join(varFolders, "ef", "gh", "C"), host)).toBeNull();
  });
  it("does not accept a trailing newline after T", () => {
    expect(acceptedTmpdir("/var/folders/ab/cd/T\n", { platform: "darwin", uid: 501 })).toBeNull();
    expect(acceptedTmpdir("/var/folders/ab/cd/T\n/x", { platform: "darwin", uid: 501 })).toBeNull();
  });
});
