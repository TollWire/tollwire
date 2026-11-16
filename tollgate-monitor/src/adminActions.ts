// Extension point for the admin view. The public monitor is read-only and knows nothing about how actions are carried out:
// it only knows this interface. The commercial admin entry point may hand an implementation to `Monitor` (option `actions`);
// the public entry point never does, so every POST stays refused. Nothing in this file talks to another process.

/** Fixed error codes of an action. They map to HTTP statuses and fixed messages in the server; never to free text. */
export type ActionErrorCode = "invalid_action" | "confirm_invalid" | "control_unavailable" | "control_failed";

export class ActionError extends Error {
  constructor(
    readonly code: ActionErrorCode,
    /** Fixed code of the helper for `control_failed` (never text). */
    readonly detail: string | null = null,
  ) {
    super(code);
  }
}

/** Writes one entry to the access log of the admin view. */
export type ActionAudit = (action: string, details: Record<string, unknown>) => void;

/**
 * What the server needs from an implementation of admin actions. Results are plain JSON values that the server sends as they
 * are, apart from `prepare().summary`, whose kind and target go to the access log.
 */
export interface AdminActions {
  /** Name of the host, shown in the lock view. */
  readonly hostName: string;
  /** Current state of the locks. Throws if it cannot be read. */
  locks(): object;
  /** Checks an action and hands out a one-time confirmation. Throws `ActionError` for an invalid action. */
  prepare(raw: unknown, nowMs: number): { summary: { kind: string; target: unknown } };
  /** Carries out a prepared action. Throws `ActionError`. */
  commit(confirmId: unknown, raw: unknown, nowMs: number, audit: ActionAudit): Promise<object>;
}

// TODO(remove after monitor-control-private.patch is applied): deprecated way to hand over admin actions. Until that
// patch changes src/admin/run.ts, it still passes the old option `control` (the options of the action service). The server cannot
// import the private implementation, so the implementation registers a factory here when its module is loaded (src/control/
// actions.ts; run.ts imports it before it builds the Monitor). Once run.ts passes `actions`, delete this block, the option
// `control` of `MonitorOptions`, the registration at the end of src/control/actions.ts and the tests marked "deprecated".
type LegacyControlFactory = (options: object) => AdminActions;
let legacyControlFactory: LegacyControlFactory | null = null;

/** @deprecated Registration of the adapter for the old option `control`. */
export function registerLegacyControl(factory: LegacyControlFactory): void {
  legacyControlFactory = factory;
}

/** @deprecated Wraps the old option `control` into `AdminActions`; throws if no implementation has registered itself. */
export function wrapLegacyControl(options: object): AdminActions {
  if (legacyControlFactory === null) throw new Error("admin actions: no implementation registered for the option control");
  return legacyControlFactory(options);
}
