import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";

const MAX_LINK_DEPTH = 40;

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === "ENOENT" || (error as NodeJS.ErrnoException)?.code === "ENOTDIR";
}

/**
 * Resolves all symlinks in a path, including dangling links whose target does not exist yet.
 * Missing trailing components are kept as-is. Throws on link cycles or unexpected filesystem errors,
 * so callers can fail closed.
 */
export function canonicalPath(path: string, depth = 0): string {
  if (depth > MAX_LINK_DEPTH) throw new Error(`Too many symlink levels: ${path}`);
  const absolute = resolve(path);
  try {
    return realpathSync(absolute);
  } catch (error) {
    if (!isMissing(error) && (error as NodeJS.ErrnoException)?.code !== "ELOOP") throw error;
  }
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch (error) {
    if (!isMissing(error)) throw error;
    const parent = dirname(absolute);
    if (parent === absolute) return absolute;
    return resolve(canonicalPath(parent, depth), basename(absolute));
  }
  if (stat.isSymbolicLink()) {
    const target = readlinkSync(absolute);
    const parent = canonicalPath(dirname(absolute), depth);
    return canonicalPath(isAbsolute(target) ? target : resolve(parent, target), depth + 1);
  }
  // Exists but realpath failed (ENOTDIR inside path or ELOOP below): resolve parent and keep the name.
  return resolve(canonicalPath(dirname(absolute), depth), basename(absolute));
}

function toRelative(from: string, to: string): string | null {
  const rel = relative(from, to).split("\\").join("/");
  if (rel === "" || rel === ".." || rel.startsWith("../") || isAbsolute(rel)) return null;
  return rel;
}

export interface ResolvedPath {
  /** Project-relative path as requested (lexically normalized), or null if outside. */
  requested: string | null;
  /** Project-relative path after resolving symlinks, or null if outside. */
  canonical: string | null;
}

export function resolveProjectPath(filePath: string, projectDir: string): ResolvedPath {
  const root = canonicalPath(projectDir);
  const absolute = isAbsolute(filePath) ? resolve(filePath) : resolve(projectDir, filePath);
  return {
    requested: toRelative(resolve(projectDir), absolute) ?? toRelative(root, absolute),
    canonical: toRelative(root, canonicalPath(absolute)),
  };
}

// Characters that HFS+ and some tools ignore in names (zero-width, bidi controls, BOM).
const IGNORABLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;

/** Case folding that does not depend on `toLowerCase` alone: compatibility forms first (Kelvin sign, long s, full-width letters), then upper and lower case (dotless i). */
function foldText(text: string): string {
  return text.normalize("NFKC").replace(IGNORABLE, "").toUpperCase().toLowerCase().normalize("NFKC");
}

function foldSegments(path: string, streams: boolean): string {
  const segments = text(path)
    .split("/")
    .flatMap((segment) => {
      if (segment === "" || segment === "." || segment === "..") return [segment];
      const colon = streams && !segment.includes("[") ? segment.indexOf(":") : -1;
      const bare = (colon > 0 ? segment.slice(0, colon) : segment).replace(/[. ]+$/, "");
      return bare === "" ? [] : [bare];
    });
  return foldText(segments.join("/"));
}

function text(path: string): string {
  return path.normalize("NFKC").replace(IGNORABLE, "");
}

/**
 * Comparison key for protected-path checks. APFS (default) and NTFS do not distinguish case, APFS and HFS+ treat
 * canonically equivalent Unicode names (NFC/NFD) as one name, and Windows drops trailing dots and spaces and ignores
 * NTFS stream suffixes (`name::$DATA`). The key therefore: normalizes to NFKC (this also maps the Kelvin sign, the long s and
 * full-width letters to their plain forms), removes ignorable code points, drops trailing dots/spaces and a `:stream` suffix per
 * segment, and folds case through upper and lower case (so that the dotless i and similar letters meet their counterparts). It is
 * applied on every platform (Linux included), so a false positive on a case-sensitive file system is accepted in exchange for one
 * rule everywhere. 8.3 short names (`CLAUDE~1`) cannot be resolved from the name and stay out of scope. A trailing "/" is kept.
 * The Python port in the repository hook uses the same steps.
 */
export function foldPath(path: string): string {
  return foldSegments(path, true);
}

/** Key for glob patterns: the same segment rules, except that a segment with a bracket expression keeps its colons (`[[:alpha:]]`). */
export function foldGlob(pattern: string): string {
  return foldSegments(pattern, true);
}
