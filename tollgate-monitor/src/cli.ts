// Command line of tollgate-monitor:
//   tollgate-monitor serve [--port N] [--token-file] [--enterprise]   user view, runs as the calling user
//   tollgate-monitor serve --admin [--print-token]                    admin view, only through the sudo rule (exactly these lists)
// Everything the process needs from the system is passed in (`CliDeps`), so tests run without root and without sudo.
import { join } from "node:path";
import { Monitor } from "./http.js";
import { DEFAULT_LIMITS, type Limits } from "./limits.js";
import { FileSource } from "./source.js";
import { cleanStaleTokenFiles, createTokenFile, ensureRuntimeDir, processAlive, removeTokenFile } from "./tokenfile.js";
import { standaloneLayout } from "./vendor/layout.js";
import { issueToken } from "./vendor/token.js";
import { VERSION } from "./version.js";

export interface CliPaths {
  enterpriseEvents: string;
}

export const DEFAULT_PATHS: CliPaths = {
  enterpriseEvents: "/var/log/tollgate/events",
};

/** macOS: the enterprise events live under /Library, never under /var. */
export const DARWIN_PATHS: CliPaths = {
  enterpriseEvents: "/Library/Logs/TollGate/events",
};

/** The per-user temporary directory of macOS, `/var/folders/<xx>/<id>/T` (physically below /private); the token file lives below it. */
const DARWIN_USER_TEMP = /^\/(?:private\/)?var\/folders\/[A-Za-z0-9_]{2}\/[A-Za-z0-9_]{1,40}\/T\/?$/;

export interface CliDeps {
  env: Readonly<Record<string, string | undefined>>;
  euid: number | undefined;
  ruid: number | undefined;
  cwd: string;
  platform: NodeJS.Platform;
  home: string;
  pid: number;
  stderrIsTty: boolean;
  /** Content of /etc/passwd, or null. */
  readPasswd: () => string | null;
  /** Runs a program (admin view: setfacl, getfacl). */
  exec?: (file: string, args: readonly string[]) => string;
  alive?: (pid: number) => boolean;
  paths?: CliPaths;
  limits?: Partial<Limits>;
  clock?: () => number;
}

export interface Io {
  out(text: string): void;
  err(text: string): void;
}

export interface Started {
  monitor: Monitor;
  url: string;
  mode: "user" | "admin";
  expiresAtMs: number;
  /** Stops the server, writes the stop entry (admin) and removes the token file. */
  stop(): Promise<void>;
  /** Synchronous removal of the token file (for `process.on("exit")`). */
  cleanupSync(): void;
}

export type StartResult = { ok: true; started: Started } | { ok: false; code: number };

/** Options of the admin view. `printToken`: the token goes to the terminal (stderr) instead of the token file. */
export interface AdminOptions {
  printToken: boolean;
}

/**
 * Starts the admin view. It is part of the commercial package (src/admin/) and passed in by its entry point; the public entry
 * point passes nothing, and `serve --admin` is then refused.
 */
export type AdminStarter = (deps: CliDeps, io: Io, options?: AdminOptions) => Promise<StartResult>;

export const USAGE = "usage: tollgate-monitor serve [--port N] [--token-file] [--enterprise]\n       tollgate-monitor serve --admin [--print-token]\n";

interface UserArgs {
  admin: false;
  port: number;
  tokenFile: boolean;
  enterprise: boolean;
}

function parseArgs(argv: readonly string[]): UserArgs | { admin: true; printToken: boolean } | null {
  if (argv[0] !== "serve") return null;
  const rest = argv.slice(1);
  // The admin view takes no free arguments: the sudo rule allows exactly `serve --admin` and `serve --admin --print-token`
  // (in this order).
  if (rest.includes("--admin")) {
    if (rest.length === 1) return { admin: true, printToken: false };
    if (rest.length === 2 && rest[0] === "--admin" && rest[1] === "--print-token") return { admin: true, printToken: true };
    return null;
  }
  const out: UserArgs = { admin: false, port: 0, tokenFile: false, enterprise: false };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--token-file") out.tokenFile = true;
    else if (a === "--enterprise") out.enterprise = true;
    else if (a === "--port") {
      const v = rest[i + 1];
      if (v === undefined || !/^[0-9]{1,5}$/.test(v) || Number(v) < 1 || Number(v) > 65535) return null;
      out.port = Number(v);
      i += 1;
    } else return null;
  }
  return out;
}

export function listenFailure(error: unknown, io: Io): number {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  // No URL and no token on a failed bind.
  io.err(code === "EADDRINUSE" ? "tollgate-monitor: the port is already in use\n" : "tollgate-monitor: the server could not be started\n");
  return 1;
}

export function tokenFailure(error: unknown, io: Io): number {
  io.err(`tollgate-monitor: ${error instanceof Error && (error.name === "TokenFileError" || error.name === "AclError") ? error.message : "the token could not be handed over"}\n`);
  return 1;
}

export async function startFromArgs(argv: readonly string[], deps: CliDeps, io: Io, admin?: AdminStarter): Promise<StartResult> {
  const args = parseArgs(argv);
  if (args === null) {
    io.err(USAGE);
    return { ok: false, code: 2 };
  }
  if (!args.admin) return startUser(args, deps, io);
  if (admin === undefined) {
    io.err("tollgate-monitor: the admin view is not part of this installation\n");
    return { ok: false, code: 1 };
  }
  return admin(deps, io, { printToken: args.printToken });
}

export function limitsOf(deps: CliDeps): Limits {
  return { ...DEFAULT_LIMITS, ...deps.limits };
}

async function startUser(args: UserArgs, deps: CliDeps, io: Io): Promise<StartResult> {
  const uid = deps.euid;
  if (uid === undefined || deps.platform === "win32") {
    io.err("tollgate-monitor: this platform is not supported yet\n");
    return { ok: false, code: 1 };
  }
  const darwin = deps.platform === "darwin";
  const paths = deps.paths ?? (darwin ? DARWIN_PATHS : DEFAULT_PATHS);
  const clock = deps.clock ?? Date.now;
  const limits = limitsOf(deps);
  // Linux: $XDG_RUNTIME_DIR. macOS has none: the token file goes below $TMPDIR, and only if that is the per-user temporary directory
  // (the form of macOS, owned by the user, mode 0700); otherwise the token is shown in the terminal only.
  const runtime = darwin ? deps.env.TMPDIR : deps.env.XDG_RUNTIME_DIR;
  if (args.tokenFile && darwin && (runtime === undefined || !DARWIN_USER_TEMP.test(runtime))) {
    io.err("tollgate-monitor: TMPDIR is not the per-user temporary directory; use the terminal output\n");
    return { ok: false, code: 1 };
  }
  if (args.tokenFile && (runtime === undefined || !runtime.startsWith("/"))) {
    io.err(darwin ? "tollgate-monitor: TMPDIR is not set\n" : "tollgate-monitor: XDG_RUNTIME_DIR is not set\n");
    return { ok: false, code: 1 };
  }
  if (!args.tokenFile && !deps.stderrIsTty) {
    io.err("tollgate-monitor: no terminal for the access token; use --token-file\n");
    return { ok: false, code: 1 };
  }
  const dir = args.enterprise ? join(paths.enterpriseEvents, String(uid)) : standaloneLayout({ XDG_STATE_HOME: deps.env.XDG_STATE_HOME }, deps.platform, deps.home, uid).eventsDir;
  const source = new FileSource({ kind: "user", dir, uid, maxMode: args.enterprise ? 0o640 : 0o600 }, limits);
  const token = issueToken(clock(), limits.tokenTtlMs);
  const monitor = new Monitor({ mode: "user", source, token, version: VERSION, limits, clock });
  let port: number;
  try {
    port = await monitor.listen(args.port);
  } catch (error) {
    return { ok: false, code: listenFailure(error, io) };
  }
  let tokenPath: string | null = null;
  if (args.tokenFile) {
    const tokenDir = join(runtime as string, "tollgate-monitor");
    tokenPath = join(tokenDir, `${deps.pid}.token`);
    try {
      // The per-user temporary directory itself must be the user's own and closed to others before anything is put below it.
      if (darwin) ensureRuntimeDir(runtime as string, { uid, create: false, forbidden: 0o077 });
      ensureRuntimeDir(tokenDir, { uid, create: true, forbidden: 0o077 });
      cleanStaleTokenFiles(tokenDir, /^([0-9]+)\.token$/, uid, deps.pid, deps.alive ?? processAlive);
      createTokenFile(tokenPath, token.value);
    } catch (error) {
      await monitor.close();
      return { ok: false, code: tokenFailure(error, io) };
    }
  }
  const url = `http://127.0.0.1:${port}/`;
  io.out(`tollgate-monitor (user view) listening on ${url}\n`);
  if (tokenPath !== null) io.out(`token file: ${tokenPath}\n`);
  else io.err(`Access token (valid until ${new Date(token.expiresAtMs).toISOString()}): ${token.value}\n`);
  const path = tokenPath;
  return {
    ok: true,
    started: {
      monitor,
      url,
      mode: "user",
      expiresAtMs: token.expiresAtMs,
      stop: async () => {
        if (path !== null) removeTokenFile(path);
        await monitor.close();
      },
      cleanupSync: () => {
        if (path !== null) removeTokenFile(path);
      },
    },
  };
}
