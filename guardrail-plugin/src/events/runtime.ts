// Facts about the running process that go into every event (host, user, version) and the platform locations.
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, sha256Hex } from "../vendor/hashchain.js";
import type { LocationEnv } from "./layout.js";
import type { ProcessFacts } from "./lock.js";
import type { Meta } from "./store.js";
import { COMPONENT } from "./types.js";

export interface Runtime {
  platform: NodeJS.Platform;
  uid: number | undefined;
  username: string;
  /** Home directory from the user database (`getpwuid`), not from `HOME`. */
  home: string;
  hostname: string;
  version: string;
  /** Package root (contains `dist/` when installed). */
  pluginRoot: string;
  clock: () => Date;
  uuid: () => string;
  facts?: ProcessFacts;
}

const PACKAGE_ROOT = fileURLToPath(new URL("../..", import.meta.url));

export function packageVersion(root: string): string {
  try {
    const parsed = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version.slice(0, 64) : "unknown";
  } catch {
    return "unknown";
  }
}

export function systemRuntime(): Runtime {
  let username = "unknown";
  let home = "/";
  let uid: number | undefined;
  try {
    const info = userInfo();
    username = info.username;
    home = info.homedir;
    uid = info.uid >= 0 ? info.uid : undefined;
  } catch {
    try {
      home = homedir();
    } catch {
      // keep "/"
    }
    uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  }
  let host = "unknown";
  try {
    host = hostname();
  } catch {
    // keep "unknown"
  }
  return {
    platform: process.platform,
    uid,
    username,
    home,
    hostname: host,
    version: packageVersion(PACKAGE_ROOT),
    pluginRoot: PACKAGE_ROOT,
    clock: () => new Date(),
    uuid: () => randomUUID(),
  };
}

export function osName(platform: NodeJS.Platform): string {
  return platform === "darwin" ? "macos" : platform === "win32" ? "windows" : platform;
}

export function metaOf(rt: Runtime): Meta {
  return {
    host: { name: rt.hostname.slice(0, 255), os: osName(rt.platform) },
    user: { name: rt.username.slice(0, 256), id: String(rt.uid ?? -1) },
    source: { component: COMPONENT, version: rt.version },
  };
}

/** Only the named location variables are read from the environment. */
export function locationEnv(env: NodeJS.ProcessEnv): LocationEnv {
  return { XDG_STATE_HOME: env.XDG_STATE_HOME, XDG_CONFIG_HOME: env.XDG_CONFIG_HOME, LOCALAPPDATA: env.LOCALAPPDATA, APPDATA: env.APPDATA };
}

const MAX_HASHED_FILES = 500;
const MAX_HASHED_FILE_BYTES = 4 * 1024 * 1024;

/** SHA-256 over the hashes of all files in `<root>/dist` (self-report for the comparison with a reference list); null if none. */
export function pluginFilesHash(root: string): string | null {
  const hashes: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      if (Object.keys(hashes).length >= MAX_HASHED_FILES) return;
      const path = join(dir, name);
      const info = lstatSync(path);
      if (info.isDirectory()) walk(path);
      else if (info.isFile() && info.size <= MAX_HASHED_FILE_BYTES) hashes[relative(root, path).split("\\").join("/")] = sha256Hex(readFileSync(path));
    }
  };
  try {
    walk(join(root, "dist"));
  } catch {
    return null;
  }
  return Object.keys(hashes).length === 0 ? null : sha256Hex(canonicalJson(hashes));
}

/** Managed-settings file of Claude Code per platform (read only to hash it). */
export function managedSettingsPath(platform: NodeJS.Platform): string {
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode/managed-settings.json";
  if (platform === "win32") return "C:\\Program Files\\ClaudeCode\\managed-settings.json";
  return "/etc/claude-code/managed-settings.json";
}

export function fileHash(path: string, maxBytes = 1024 * 1024): string | null {
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.size > maxBytes) return null;
    return sha256Hex(readFileSync(path));
  } catch {
    return null;
  }
}
