// Where the decision log lives. Stand-alone locations follow the platform; the
// enterprise locations are fixed paths that never come from environment variables.
import { isAbsolute, join, win32 } from "node:path";

export type LayoutKind = "standalone" | "enterprise-per-user" | "enterprise-shared";

export interface Layout {
  kind: LayoutKind;
  /** Directory of the event files `u<uid>-<YYYYMMDD>[-<n>].jsonl`. */
  eventsDir: string;
  /** Directory of the lock, the state file and the session files; only the user can write there. */
  lockDir: string;
  /** Numeric uid in the file names (0 where the platform has no uid). */
  fileUid: number;
  fileMode: number;
  /** The file group must equal the group of the event directory. */
  checkGroup: boolean;
  createLockDir: boolean;
  createEventsDir: boolean;
  /** An unusable file name leads to an alternate file `-<n>` (stand-alone and layout S) instead of an error. */
  alternateFiles: boolean;
}

export interface LocationEnv {
  XDG_STATE_HOME?: string | undefined;
  XDG_CONFIG_HOME?: string | undefined;
  LOCALAPPDATA?: string | undefined;
  APPDATA?: string | undefined;
}

/** `/var/log/tollgate` on Linux. */
export const ENTERPRISE_LOG_ROOT = "/var/log/tollgate";
/** macOS: under `/Library`, never under `/var` or `/etc` (symbolic links there). */
export const ENTERPRISE_LOG_ROOT_DARWIN = "/Library/Logs/TollGate";

/** Fixed enterprise log root of a platform; Linux for every platform that has no root of its own. */
export function enterpriseLogRoot(platform: NodeJS.Platform): string {
  return platform === "darwin" ? ENTERPRISE_LOG_ROOT_DARWIN : ENTERPRISE_LOG_ROOT;
}

function absoluteOr(value: string | undefined, fallback: string): string {
  return value !== undefined && isAbsolute(value) ? value : fallback;
}

/** Stand-alone locations: `<state>/tollgate/events` (Linux), `~/Library/Logs/TollGate` (macOS), `%LOCALAPPDATA%\TollGate\events`. */
export function standaloneLayout(env: LocationEnv, platform: NodeJS.Platform, home: string, uid: number | undefined): Layout {
  let privateDir: string;
  let eventsDir: string;
  if (platform === "darwin") {
    privateDir = join(home, "Library", "Logs", "TollGate");
    eventsDir = privateDir;
  } else if (platform === "win32") {
    privateDir = win32.join(absoluteOr(env.LOCALAPPDATA, win32.join(home, "AppData", "Local")), "TollGate");
    eventsDir = win32.join(privateDir, "events");
  } else {
    privateDir = join(absoluteOr(env.XDG_STATE_HOME, join(home, ".local", "state")), "tollgate");
    eventsDir = join(privateDir, "events");
  }
  return {
    kind: "standalone",
    eventsDir,
    lockDir: privateDir,
    fileUid: uid !== undefined && uid >= 0 ? uid : 0,
    fileMode: 0o600,
    checkGroup: false,
    createLockDir: true,
    createEventsDir: true,
    alternateFiles: true,
  };
}

/** Enterprise layout P (per user, default) or S (shared directory; Linux only, not on macOS). Paths are fixed per platform. */
export function enterpriseLayout(variant: "per_user" | "shared", uid: number, home: string, platform: NodeJS.Platform = "linux"): Layout {
  const root = enterpriseLogRoot(platform);
  if (variant === "per_user") {
    const dir = `${root}/events/${uid}`;
    return {
      kind: "enterprise-per-user",
      eventsDir: dir,
      lockDir: dir,
      fileUid: uid,
      fileMode: 0o640,
      checkGroup: true,
      createLockDir: false,
      createEventsDir: false,
      alternateFiles: false,
    };
  }
  return {
    kind: "enterprise-shared",
    eventsDir: `${root}/events`,
    lockDir: join(home, ".local", "state", "tollgate"),
    fileUid: uid,
    fileMode: 0o640,
    checkGroup: true,
    createLockDir: true,
    createEventsDir: false,
    alternateFiles: true,
  };
}

/** User configuration file: `<XDG_CONFIG_HOME or ~/.config>/tollgate/config.json` (Windows: `%APPDATA%\tollgate\config.json`). */
export function userConfigFile(env: LocationEnv, platform: NodeJS.Platform, home: string): string {
  if (platform === "win32") return win32.join(absoluteOr(env.APPDATA, win32.join(home, "AppData", "Roaming")), "tollgate", "config.json");
  return join(absoluteOr(env.XDG_CONFIG_HOME, join(home, ".config")), "tollgate", "config.json");
}

/** Directories that agents must never write: the user configuration and the stand-alone log (with trailing slash). */
export function userProtectedDirs(env: LocationEnv, platform: NodeJS.Platform, home: string, uid: number | undefined): string[] {
  const standalone = standaloneLayout(env, platform, home, uid);
  const config = userConfigFile(env, platform, home);
  const configDir = config.slice(0, Math.max(config.lastIndexOf("/"), config.lastIndexOf("\\")));
  return [...new Set([standalone.lockDir, standalone.eventsDir, configDir])].map((d) => `${d}/`);
}

export const EVENT_FILE = /^u([0-9]+)-([0-9]{8})(?:-([0-9]+))?\.jsonl$/;

export function eventFileName(uid: number, day: string, n: number): string {
  return `u${uid}-${day}${n > 0 ? `-${n}` : ""}.jsonl`;
}
