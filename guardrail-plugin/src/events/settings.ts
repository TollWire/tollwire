// Log settings: the user file for the stand-alone log (the only switch) and the defaults.
import { z } from "zod";
import { sha256Hex } from "../vendor/hashchain.js";
import { readSmallFile } from "./fsutil.js";
import type { CommandDetail } from "./types.js";

export const MAX_CONFIG_BYTES = 64 * 1024;

export interface LogSettings {
  enabled: boolean;
  tools: "all" | "checked";
  commandDetail: CommandDetail;
  commandHash: boolean;
  projectDir: boolean;
  onWriteError: "warn" | "block";
  rateLimit: number;
  layout: "per_user" | "shared";
}

/** Stand-alone defaults: on, no command text, warn on write errors. */
export const STANDALONE_DEFAULTS: LogSettings = {
  enabled: true,
  tools: "checked",
  commandDetail: "none",
  commandHash: false,
  projectDir: false,
  onWriteError: "warn",
  rateLimit: 600,
  layout: "per_user",
};

/** Enterprise defaults when the policy omits a field. */
export const ENTERPRISE_DEFAULTS: LogSettings = {
  enabled: true,
  tools: "all",
  commandDetail: "redacted",
  commandHash: false,
  projectDir: true,
  onWriteError: "block",
  rateLimit: 600,
  layout: "per_user",
};

/** The part of the user file that is evaluated; everything else is ignored. */
export interface UserConfig {
  enabled: boolean;
  commandDetail: "none" | "redacted";
  projectDir: boolean;
}

export const DEFAULT_USER_CONFIG: UserConfig = { enabled: true, commandDetail: "none", projectDir: false };

const UserFileSchema = z.object({
  logging: z
    .object({
      enabled: z.boolean().optional(),
      commandDetail: z.enum(["none", "redacted"]).optional(),
      projectDir: z.boolean().optional(),
    })
    .optional(),
});

export interface UserConfigRead {
  config: UserConfig;
  /** SHA-256 of the file content; null if there is no readable file. */
  sha256: string | null;
  /** False if a file exists but is unreadable or invalid (the log then stays on). */
  valid: boolean;
}

/**
 * Reads the user file. A missing file means the defaults. An unreadable or invalid file also means the defaults, so the
 * log stays on: a broken file never switches the log off.
 */
export function readUserConfig(path: string): UserConfigRead {
  let file;
  try {
    file = readSmallFile(path, MAX_CONFIG_BYTES, true);
  } catch {
    return { config: DEFAULT_USER_CONFIG, sha256: null, valid: false };
  }
  if (file === null) return { config: DEFAULT_USER_CONFIG, sha256: null, valid: true };
  const sha256 = sha256Hex(file.bytes);
  try {
    const parsed = UserFileSchema.safeParse(JSON.parse(file.text));
    if (!parsed.success) return { config: DEFAULT_USER_CONFIG, sha256, valid: false };
    const logging = parsed.data.logging ?? {};
    return {
      config: {
        enabled: logging.enabled ?? DEFAULT_USER_CONFIG.enabled,
        commandDetail: logging.commandDetail ?? DEFAULT_USER_CONFIG.commandDetail,
        projectDir: logging.projectDir ?? DEFAULT_USER_CONFIG.projectDir,
      },
      sha256,
      valid: true,
    };
  } catch {
    return { config: DEFAULT_USER_CONFIG, sha256, valid: false };
  }
}

export function standaloneSettings(config: UserConfig): LogSettings {
  return { ...STANDALONE_DEFAULTS, enabled: config.enabled, commandDetail: config.commandDetail, projectDir: config.projectDir };
}
