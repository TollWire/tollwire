// Access tokens for local services (first consumer: tollgate-monitor).
// Node built-ins only (`node:crypto`). A token is random, lives in memory of the service and is handed over out of band.
// It is no credential store and no session system: one token per service start, with an expiry.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Smallest accepted entropy: 128 bit. The default is 256 bit. */
export const MIN_TOKEN_BYTES = 16;
export const DEFAULT_TOKEN_BYTES = 32;
/** A presented token longer than this is refused without comparing (bounds the work for hostile input). */
export const MAX_PRESENTED_LENGTH = 512;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export interface IssuedToken {
  /** The secret value (base64url, no padding). Never log it. */
  readonly value: string;
  readonly issuedAtMs: number;
  /** Absolute expiry; the token is invalid at and after this instant. */
  readonly expiresAtMs: number;
}

export type TokenCheck = "ok" | "invalid" | "expired";

/** Random token from the operating system's CSPRNG, as base64url. */
export function generateToken(bytes: number = DEFAULT_TOKEN_BYTES): string {
  if (!Number.isInteger(bytes) || bytes < MIN_TOKEN_BYTES || bytes > 128) {
    throw new RangeError(`token size must be an integer from ${MIN_TOKEN_BYTES} to 128 bytes`);
  }
  return randomBytes(bytes).toString("base64url");
}

/**
 * Comparison in constant time with respect to the content and the length: both values are hashed to the same size
 * first, so neither a prefix nor the length of the secret leaks through timing.
 */
export function tokensEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb);
}

/** Issues a token that expires `ttlMs` after `nowMs`. */
export function issueToken(nowMs: number, ttlMs: number, bytes: number = DEFAULT_TOKEN_BYTES): IssuedToken {
  if (!Number.isFinite(nowMs)) throw new RangeError("now must be a finite number");
  if (!Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 30 * 24 * 3_600_000) throw new RangeError("ttl must be from 1 ms to 30 days");
  return { value: generateToken(bytes), issuedAtMs: nowMs, expiresAtMs: nowMs + ttlMs };
}

/**
 * Checks a presented value against an issued token. The comparison always runs (also for expired tokens and for values
 * of the wrong shape) so that the time does not tell which condition failed.
 */
export function checkToken(presented: string | undefined | null, issued: IssuedToken, nowMs: number): TokenCheck {
  const candidate = typeof presented === "string" && presented.length <= MAX_PRESENTED_LENGTH && BASE64URL.test(presented) ? presented : "";
  const equal = tokensEqual(candidate, issued.value);
  if (!equal || candidate === "") return "invalid";
  return nowMs >= issued.expiresAtMs || nowMs < issued.issuedAtMs ? "expired" : "ok";
}

/** Value of an `Authorization: Bearer <token>` header; null for any other shape (one space, no extra parts). */
export function parseBearer(header: string | undefined | null): string | null {
  if (typeof header !== "string" || header.length > MAX_PRESENTED_LENGTH + 7) return null;
  const m = /^Bearer ([A-Za-z0-9_-]+)$/.exec(header);
  return m === null ? null : (m[1] as string);
}
