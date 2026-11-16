import { CONTROL_MAP, EVENT_TYPES, type EventType } from "./controls.js";
import { verifyEntries, type EvidenceEntry, type Verification } from "./log.js";

export interface ReportOptions {
  from?: string;
  to?: string;
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/** Bounds in epoch ms; a date-only upper bound includes the whole UTC day. */
export function rangeBounds({ from, to }: ReportOptions): { start: number; end: number } {
  const start = from ? Date.parse(DATE_ONLY.test(from) ? `${from}T00:00:00.000Z` : from) : -Infinity;
  const end = to ? Date.parse(DATE_ONLY.test(to) ? `${to}T23:59:59.999Z` : to) : Infinity;
  return { start, end };
}

function inRange(entry: EvidenceEntry, bounds: { start: number; end: number }): boolean {
  const ts = Date.parse(entry.ts);
  return ts >= bounds.start && ts <= bounds.end;
}

function cell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** Markdown evidence report: integrity status, coverage per control, event list. */
export function renderReport(entries: EvidenceEntry[], options: ReportOptions = {}, verification: Verification = verifyEntries(entries)): string {
  const bounds = rangeBounds(options);
  const selected = entries.filter((e) => inRange(e, bounds));
  const coverage = new Map<string, { title: string; framework: string; count: number }>();
  for (const type of EVENT_TYPES) {
    for (const control of CONTROL_MAP[type]) {
      const key = `${control.framework} ${control.id}`;
      if (!coverage.has(key)) coverage.set(key, { title: control.title, framework: control.framework, count: 0 });
    }
  }
  for (const entry of selected) {
    for (const control of CONTROL_MAP[entry.type as EventType] ?? []) {
      const item = coverage.get(`${control.framework} ${control.id}`);
      if (item) item.count += 1;
    }
  }
  const lines = [
    "# Evidenzbericht",
    "",
    `Zeitraum: ${options.from ?? "Beginn"} bis ${options.to ?? "heute"}. Einträge: ${selected.length} von ${entries.length}.`,
    `Integrität der Hash-Kette: ${verification.valid ? "gültig" : `VERLETZT bei seq ${verification.brokenAt} (${verification.reason})`}.`,
    "",
    "> Zuordnung zu Controls ist ein Entwurf (nicht von einem Auditor bestätigt) und vor Verwendung gegenüber Dritten von einem Auditor zu bestätigen.",
    "> Der Bericht belegt Aktivitäten; er bescheinigt keine Konformität.",
    "",
    "## Abdeckung je Control",
    "",
    "| Rahmenwerk | Control | Titel | Nachweise |",
    "|---|---|---|---|",
    ...[...coverage.entries()].map(([key, c]) => `| ${c.framework} | ${key.slice(c.framework.length + 1)} | ${c.title} | ${c.count} |`),
    "",
    "## Ereignisse",
    "",
    "| seq | Zeit (UTC) | Typ | Akteur | Zusammenfassung | Referenz |",
    "|---|---|---|---|---|---|",
    ...selected.map((e) => `| ${e.seq} | ${e.ts} | ${e.type} | ${cell(e.actor)} | ${cell(e.summary)} | ${cell(e.ref ?? "")} |`),
    "",
  ];
  return lines.join("\n");
}
