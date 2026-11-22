// Mapping of Guardrail decision `rule_kind` values (schema `tollgate.event.v1`, type `decision`)
// to control references, and helpers to read deny decisions from the Guardrail log as evidence of
// enforced controls (SOC 2 Operating Effectiveness, ISO/IEC 27001 Annex A).
//
// Draft mapping like `controls.ts` — not auditor-confirmed. Only deny decisions on the rule_kinds
// below demonstrate a security control. Operational/error rule_kinds (none, parse_error,
// invalid_input, size_limit, policy_error, internal_error, log_write_error, path_unresolvable,
// enterprise_unsupported_platform, unchecked_tool, lock_error, active_policy) are intentionally
// unmapped: a parser error or a size limit is not evidence of a control working.
import type { ControlRef } from "./controls.js";

const iso = (id: string, title: string): ControlRef => ({ framework: "ISO/IEC 27001:2022 Annex A", id, title });
const soc2 = (id: string, title: string): ControlRef => ({ framework: "SOC 2 (AICPA TSC 2017)", id, title });

export const RULE_KIND_CONTROL_MAP: Record<string, ControlRef[]> = {
  protected_path: [soc2("CC6.1", "Logical access security"), iso("A.5.15", "Access control"), iso("A.8.3", "Information access restriction")],
  outside_project: [soc2("CC6.1", "Logical access security"), iso("A.8.3", "Information access restriction")],
  write_target: [soc2("CC6.1", "Logical access security"), iso("A.8.3", "Information access restriction")],
  hardlink_alias: [soc2("CC6.1", "Logical access security"), iso("A.8.3", "Information access restriction")],
  admin_lock: [soc2("CC6.1", "Logical access security"), iso("A.5.15", "Access control")],
  blocked_command: [soc2("CC6.1", "Logical access security"), soc2("CC7.2", "Security monitoring and anomaly detection"), iso("A.8.19", "Installation of software on operational systems")],
  dependency: [soc2("CC6.8", "Prevention of unauthorized or malicious software"), iso("A.8.19", "Installation of software on operational systems")],
  dependency_unverifiable: [soc2("CC6.8", "Prevention of unauthorized or malicious software"), iso("A.8.19", "Installation of software on operational systems")],
  taint: [soc2("CC7.2", "Security monitoring and anomaly detection"), iso("A.8.16", "Monitoring activities")],
};

// A blocked command that would have reached the network (tool effect "network", e.g. curl/wget)
// additionally demonstrates boundary protection against exfiltration.
const NETWORK_EXFIL_CONTROLS: ControlRef[] = [
  soc2("CC6.6", "Boundary protection against external threats"),
  iso("A.8.20", "Networks security"),
];

/** Minimal shape read from a Guardrail `decision` event; a superset is ignored. */
export interface GuardrailDecision {
  ts: string;
  tool?: { name?: string; effects?: string[] };
  decision: { outcome: string; rule_kind: string; rule_id: string | null };
}

export interface DenySample {
  ts: string;
  tool: string;
  rule_kind: string;
  rule_id: string | null;
}

export interface DenyControlRow {
  framework: string;
  id: string;
  title: string;
  blocked_count: number;
  samples: DenySample[];
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : undefined;
}

/** Parse NDJSON Guardrail events; unwrap relay_record; keep well-formed `decision` events. Tolerant. */
export function parseGuardrailDecisions(content: string): GuardrailDecision[] {
  const out: GuardrailDecision[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let raw: unknown;
    try {
      raw = JSON.parse(trimmed);
    } catch {
      continue;
    }
    let obj = asRecord(raw);
    if (!obj) continue;
    if (obj.type === "relay_record") {
      const inner = asRecord(asRecord(obj.data)?.event);
      if (inner) obj = inner;
    }
    if (obj.type !== "decision") continue;
    const decision = asRecord(obj.decision);
    const tool = asRecord(obj.tool);
    if (!decision) continue;
    if (typeof obj.ts !== "string" || typeof decision.outcome !== "string" || typeof decision.rule_kind !== "string") continue;
    const effects = Array.isArray(tool?.effects) ? (tool!.effects as unknown[]).filter((e): e is string => typeof e === "string") : undefined;
    let parsedTool: GuardrailDecision["tool"];
    if (tool) {
      parsedTool = {};
      if (typeof tool.name === "string") parsedTool.name = tool.name;
      if (effects && effects.length > 0) parsedTool.effects = effects;
    }
    out.push({
      ts: obj.ts,
      ...(parsedTool ? { tool: parsedTool } : {}),
      decision: {
        outcome: decision.outcome,
        rule_kind: decision.rule_kind,
        rule_id: typeof decision.rule_id === "string" ? decision.rule_id : null,
      },
    });
  }
  return out;
}

function controlsForDeny(dec: GuardrailDecision): ControlRef[] {
  const controls = [...(RULE_KIND_CONTROL_MAP[dec.decision.rule_kind] ?? [])];
  if (dec.decision.rule_kind === "blocked_command" && dec.tool?.effects?.includes("network")) controls.push(...NETWORK_EXFIL_CONTROLS);
  return controls;
}

/** Aggregate deny decisions into per-control blocked counts and up to 5 samples each. */
export function summarizeDenyControls(decisions: GuardrailDecision[], bounds?: { start: number; end: number }): DenyControlRow[] {
  const rows = new Map<string, DenyControlRow>();
  for (const dec of decisions) {
    if (dec.decision.outcome !== "deny") continue;
    if (bounds) {
      const ts = Date.parse(dec.ts);
      if (!(ts >= bounds.start && ts <= bounds.end)) continue;
    }
    for (const c of controlsForDeny(dec)) {
      const key = `${c.framework} ${c.id}`;
      let row = rows.get(key);
      if (!row) {
        row = { framework: c.framework, id: c.id, title: c.title, blocked_count: 0, samples: [] };
        rows.set(key, row);
      }
      row.blocked_count += 1;
      if (row.samples.length < 5) {
        row.samples.push({ ts: dec.ts, tool: dec.tool?.name ?? "unknown", rule_kind: dec.decision.rule_kind, rule_id: dec.decision.rule_id });
      }
    }
  }
  return [...rows.values()];
}
