// Resource limits of the monitor. The values are proposals of this implementation; tests inject smaller values.
export interface Limits {
  defaultLimit: number;
  maxLimit: number;
  /** Largest `since` (age of the oldest event that may be asked for). */
  maxSinceMs: number;
  defaultSinceMs: number;
  /** Largest JSON body of one list answer. */
  responseBytes: number;
  /** File bytes read for one list or session request. */
  scanBytes: number;
  /** File bytes read by one chain verification. */
  verifyBytes: number;
  maxSessions: number;
  sseSeats: number;
  sseMaxMs: number;
  ssePollMs: number;
  sseKeepAliveMs: number;
  sseDrainMs: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  keepAliveTimeoutMs: number;
  maxConnections: number;
  maxHeaderBytes: number;
  maxUrlLength: number;
  /** Authenticated requests per second (all routes). */
  requestsPerSecond: number;
  /** Failed authentications per minute before answers turn into 429. */
  authFailuresPerMinute: number;
  /** Lifetime of the token of one start. */
  tokenTtlMs: number;
  /** Age after which a verification result is computed again. */
  verifyCacheMs: number;
}

export const DEFAULT_LIMITS: Limits = {
  defaultLimit: 100,
  maxLimit: 1000,
  maxSinceMs: 7 * 86_400_000,
  defaultSinceMs: 86_400_000,
  responseBytes: 1024 * 1024,
  scanBytes: 16 * 1024 * 1024,
  verifyBytes: 128 * 1024 * 1024,
  maxSessions: 500,
  sseSeats: 8,
  sseMaxMs: 30 * 60_000,
  ssePollMs: 2000,
  sseKeepAliveMs: 15_000,
  sseDrainMs: 10_000,
  headersTimeoutMs: 5000,
  requestTimeoutMs: 10_000,
  keepAliveTimeoutMs: 5000,
  maxConnections: 64,
  maxHeaderBytes: 8192,
  maxUrlLength: 2048,
  requestsPerSecond: 50,
  authFailuresPerMinute: 30,
  tokenTtlMs: 8 * 3_600_000,
  verifyCacheMs: 10_000,
};
