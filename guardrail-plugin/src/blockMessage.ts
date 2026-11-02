// Structured block message for the agent (#52). One format for every kind of block:
//
//   TollGate guardrail: blocked.
//   rule_id: <id or ->
//   rule_kind: <kind>
//   target (untrusted, verbatim): "<shortened path, command or tool name>"      (only if there is a target; quoted, data not instruction)
//   detail: <what was found>
//   fix: <what to do instead>
//
// Delivery: the hook ends a block with exit code 2 and writes this text to stderr, which Claude Code hands to the model. The text is
// plain lines without markup, so it reads the same if a host passes it as the reason of a JSON decision instead.
// The message is for the agent and goes to the host's stderr; it never goes into the decision log (the log keeps its own
// redacted fields). It must not help to get around the rule: no regular expressions, no allowlist contents, no administrator text,
// no paths in `detail` or `fix` (a path appears only as the quoted target). The one text of a policy author that is shown is the
// `reason` of a blocked command rule (`detail` of `blocked_command`); policy errors show the message of the policy loader.
import { redactCommand, redactText } from "./events/redact.js";
import type { RuleKind } from "./events/types.js";

export const MAX_TARGET_LENGTH = 80;
export const MAX_DETAIL_LENGTH = 400;

/** What the agent should do instead, per kind of rule. Fixed texts: nothing from the policy or the input. */
const FIX: Readonly<Record<RuleKind, string>> = {
  none: "no action needed.",
  protected_path: "protected path - deliver the change as a patch file (for example in the repository's patches directory) for human review; do not retry or work around it.",
  active_policy: "the active guardrail policy is protected - propose the change as a patch for human review.",
  path_unresolvable: "the path cannot be resolved safely - use a plain path without symlink loops.",
  outside_project: "outside the project directory - use a path inside the project.",
  hardlink_alias: "the file has several hard links - ask a human to review it.",
  parse_error: "the command cannot be parsed - simplify it or fix the quoting.",
  blocked_command: "command blocked by policy - use a permitted alternative, or ask a human if the action is required.",
  write_target: "the command writes to a protected or outside location - write inside the project, or deliver the change as a patch.",
  dependency_unverifiable: "dependencies cannot be verified - write the complete manifest with the Write tool.",
  dependency: "dependency not approved - approval is a policy change (R2) by a human; do not add it.",
  invalid_input: "malformed tool call - correct the tool input.",
  size_limit: "the command is too long - split it or use a script file.",
  policy_error: "the guardrail policy is unusable - ask your administrator.",
  internal_error: "the guardrail failed unexpectedly - retry once; if it persists, ask your administrator.",
  log_write_error: "the decision log cannot be written - ask your administrator.",
  enterprise_unsupported_platform: "enterprise mode is not supported on this platform - ask your administrator.",
  unchecked_tool: "tool not approved in enterprise mode - approval is a policy change (R2); ask your administrator.",
  admin_lock: "locked by the administrator - contact your administrator.",
  lock_error: "the administrator lock state is unusable - contact your administrator.",
  taint: "this session read untrusted content, so network, push and secret access are reduced - a human lifts this with 'tollgate-taint release' in their own terminal (enterprise: the administrator); do not try to work around it.",
};

export function fixHint(kind: RuleKind): string {
  return FIX[kind];
}

// Terminal escape sequences (CSI, OSC, two-character escapes and the 8-bit CSI), removed whole so that no "[31m" is left behind.
const ANSI = /(?:\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?|\u001b[@-Z\\-_]|\u009b[0-?]*[ -/]*[@-~])/g;

/** One line without escape sequences, control, format (bidi, zero width) or separator characters. */
function oneLine(text: string): string {
  return text.replace(ANSI, "").replace(/[\p{C}\p{Z}]+/gu, " ").trim();
}

/** Longest input that the shortening looks at: bounds the run time of every regular expression below (a hook timeout is no block). */
export const MAX_SCAN_INPUT = 2048;

function head(text: string, max = MAX_SCAN_INPUT): string {
  return text.length <= max ? text : text.slice(0, max);
}

/** Shortens by code points (no split surrogate pair). */
function cut(text: string, max: number): string {
  const points = Array.from(text);
  return points.length <= max ? text : `${points.slice(0, max - 3).join("")}...`;
}

/** Long opaque words (tokens, keys, digests, also path segments) are replaced; the pattern masks what the redactor does not know. */
function maskOpaque(text: string): string {
  return text.replace(/[A-Za-z0-9_+=.-]{24,}/g, (word) => (/\d/.test(word) && /[A-Za-z]/.test(word) ? "[token]" : word));
}

/** URLs are reduced to scheme and host: user info, port, path and query can carry credentials. */
function hostOnly(text: string): string {
  if (!text.includes("://")) return text;
  // The look-behind and the bounded scheme keep every start position O(1): no quadratic run on long dotted words.
  return text.replace(/(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/)(?:[^\s/@]*@)?([^\s/?#:]+)(?::\d+)?[^\s]*/g, "$1$2");
}

/** A file path or tool name for the message: one line, secret formats redacted, URLs and opaque tokens reduced, shortened. */
export function shortPath(path: string): string {
  return cut(maskOpaque(hostOnly(oneLine(redactText(head(path)).text))), MAX_TARGET_LENGTH);
}

/** A command for the message: redacted and normalized like the log, opaque tokens masked, shortened. `null` if it cannot be tokenized. */
export function shortCommand(command: string): string | null {
  const redacted = redactCommand(head(command));
  if (redacted === null) return null;
  return cut(maskOpaque(hostOnly(oneLine(redactText(redacted.text).text))), MAX_TARGET_LENGTH);
}

export interface BlockMessage {
  kind: RuleKind;
  ruleId: string | null;
  /** Already shortened target, or undefined. Use `shortPath` / `shortCommand`. */
  target?: string | undefined;
  /** What was found; one line. */
  detail: string;
}

/**
 * Rule id for the message: the id as logged, except a protected-path entry that is an absolute host path; that one is not shown
 * (it would name the layout of the machine).
 */
function shownRuleId(kind: RuleKind, ruleId: string | null): string {
  if (ruleId === null || ruleId === "") return "-";
  if (kind === "protected_path" && ruleId.startsWith("/")) return "host-protected";
  return cut(oneLine(redactText(head(ruleId)).text), MAX_TARGET_LENGTH);
}

export function formatBlock(block: BlockMessage): string {
  const lines = [
    "TollGate guardrail: blocked.",
    `rule_id: ${shownRuleId(block.kind, block.ruleId)}`,
    `rule_kind: ${block.kind}`,
    ...(block.target === undefined || block.target === "" ? [] : [`target (untrusted, verbatim): ${JSON.stringify(cut(oneLine(head(block.target)), MAX_TARGET_LENGTH))}`]),
    `detail: ${cut(oneLine(redactText(head(block.detail, 4 * MAX_DETAIL_LENGTH)).text), MAX_DETAIL_LENGTH)}`,
    `fix: ${FIX[block.kind]}`,
  ];
  return lines.join("\n");
}

/** Fixed details of the kinds that concern a path: the path is the target only, never part of a sentence. */
const PATH_DETAIL: Readonly<Partial<Record<RuleKind, string>>> = {
  protected_path: "the target is a protected path; changes need human review.",
  active_policy: "the target is the active guardrail policy; changes need human review.",
  outside_project: "the target is outside the project directory.",
  path_unresolvable: "the target cannot be resolved safely (symlink loop or filesystem error).",
  hardlink_alias: "the target has more than one hard link (possible alias of a protected file).",
  write_target: "the command writes to a protected, unresolvable or outside location.",
  dependency_unverifiable: "the dependencies of this manifest cannot be verified.",
  parse_error: "the command cannot be parsed unambiguously (fail closed).",
  size_limit: "the command is longer than the permitted size.",
  unchecked_tool: "the tool is not on the enterprise tool allowlist.",
};

const DEPENDENCY_ITEM = /^(?:npm|pypi):[A-Za-z0-9@._~/-]{1,80}$/;

/**
 * The detail for the agent from the reason that goes into the log. Kinds that concern a path or tool get a fixed text (the log
 * keeps the full reason). For a dependency only well-formed `ecosystem:name` items are listed (names come from the agent's own
 * input and are untrusted).
 */
export function detailFor(kind: RuleKind, reason: string): string {
  const fixed = PATH_DETAIL[kind];
  if (fixed !== undefined) return fixed;
  if (kind === "dependency") {
    const list = reason.replace(/^[^:]*:\s*/, "").replace(/\.$/, "").split(", ");
    const shown = list.slice(0, 10).map((item) => (DEPENDENCY_ITEM.test(item) ? item : "(invalid name)"));
    return `Dependencies not on the allowlist: ${shown.join(", ")}${list.length > 10 ? ", ..." : ""}.`;
  }
  return reason;
}
