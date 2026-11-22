// Mapping of evidence event types to control references.
// Draft mapping for orientation (not auditor-confirmed); must be confirmed by an auditor before it is used in reports to customers.
// SOC 2 entries reference the AICPA Trust Services Criteria (2017, revised 2022 points of focus) and support SOC 2 Type I/II
// evidence collection only; final control attestation remains with the certified CPA auditor.
export const EVENT_TYPES = ["change", "review", "scan", "approval", "deployment", "incident", "access_change", "agent_action", "anchor"] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export interface ControlRef {
  framework: "ISO/IEC 27001:2022 Annex A" | "NIS2 Art. 21(2)" | "SOC 2 (AICPA TSC 2017)";
  id: string;
  title: string;
}

const iso = (id: string, title: string): ControlRef => ({ framework: "ISO/IEC 27001:2022 Annex A", id, title });
const nis2 = (id: string, title: string): ControlRef => ({ framework: "NIS2 Art. 21(2)", id, title });
const soc2 = (id: string, title: string): ControlRef => ({ framework: "SOC 2 (AICPA TSC 2017)", id, title });

export const CONTROL_MAP: Record<EventType, ControlRef[]> = {
  change: [iso("A.8.32", "Change management"), iso("A.8.25", "Secure development life cycle"), nis2("(e)", "Security in acquisition, development and maintenance"), soc2("CC8.1", "Change management")],
  review: [iso("A.8.28", "Secure coding"), iso("A.8.29", "Security testing in development and acceptance"), nis2("(e)", "Security in acquisition, development and maintenance"), soc2("CC8.1", "Change management")],
  scan: [iso("A.8.8", "Management of technical vulnerabilities"), iso("A.8.29", "Security testing in development and acceptance"), nis2("(e)", "Vulnerability handling and disclosure"), soc2("CC7.1", "Detection of configuration changes and new vulnerabilities"), soc2("CC8.1", "Change management")],
  approval: [iso("A.8.32", "Change management"), iso("A.5.3", "Segregation of duties"), soc2("CC8.1", "Change management")],
  deployment: [iso("A.8.32", "Change management"), iso("A.8.31", "Separation of development, test and production environments"), soc2("CC8.1", "Change management")],
  incident: [iso("A.5.24", "Information security incident management planning and preparation"), iso("A.5.26", "Response to information security incidents"), nis2("(b)", "Incident handling"), soc2("CC7.3", "Evaluation of security events"), soc2("CC7.4", "Incident response")],
  access_change: [iso("A.5.15", "Access control"), iso("A.5.18", "Access rights"), nis2("(i)", "Access control policies"), soc2("CC6.1", "Logical access security"), soc2("CC6.3", "Role-based access rights")],
  agent_action: [iso("A.8.15", "Logging"), iso("A.8.16", "Monitoring activities"), soc2("CC7.2", "Security monitoring and anomaly detection")],
  // External storage of an evidence anchor (signed tag, digest comment), recorded by the human AFTER storing it.
  // Draft like all entries above (not auditor-confirmed).
  anchor: [
    iso("A.8.15", "Logging"),
    iso("A.5.33", "Protection of records"),
    iso("A.5.28", "Collection of evidence"),
    nis2("(f)", "Policies and procedures to assess the effectiveness of cybersecurity risk-management measures"),
  ],
};

export function controlsFor(type: EventType): ControlRef[] {
  return CONTROL_MAP[type];
}
