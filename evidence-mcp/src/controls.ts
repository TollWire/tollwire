// Mapping of evidence event types to control references.
// Draft mapping for orientation (not auditor-confirmed); must be confirmed by an auditor before it is used in reports to customers.
export const EVENT_TYPES = ["change", "review", "scan", "approval", "deployment", "incident", "access_change", "agent_action", "anchor"] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export interface ControlRef {
  framework: "ISO/IEC 27001:2022 Annex A" | "NIS2 Art. 21(2)";
  id: string;
  title: string;
}

const iso = (id: string, title: string): ControlRef => ({ framework: "ISO/IEC 27001:2022 Annex A", id, title });
const nis2 = (id: string, title: string): ControlRef => ({ framework: "NIS2 Art. 21(2)", id, title });

export const CONTROL_MAP: Record<EventType, ControlRef[]> = {
  change: [iso("A.8.32", "Change management"), iso("A.8.25", "Secure development life cycle"), nis2("(e)", "Security in acquisition, development and maintenance")],
  review: [iso("A.8.28", "Secure coding"), iso("A.8.29", "Security testing in development and acceptance"), nis2("(e)", "Security in acquisition, development and maintenance")],
  scan: [iso("A.8.8", "Management of technical vulnerabilities"), iso("A.8.29", "Security testing in development and acceptance"), nis2("(e)", "Vulnerability handling and disclosure")],
  approval: [iso("A.8.32", "Change management"), iso("A.5.3", "Segregation of duties")],
  deployment: [iso("A.8.32", "Change management"), iso("A.8.31", "Separation of development, test and production environments")],
  incident: [iso("A.5.24", "Information security incident management planning and preparation"), iso("A.5.26", "Response to information security incidents"), nis2("(b)", "Incident handling")],
  access_change: [iso("A.5.15", "Access control"), iso("A.5.18", "Access rights"), nis2("(i)", "Access control policies")],
  agent_action: [iso("A.8.15", "Logging"), iso("A.8.16", "Monitoring activities")],
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
