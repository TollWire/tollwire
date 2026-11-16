import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { anchorTagName, createAnchor, recordEvent, signedTagCommand, verifyLogWithAnchors } from "../src/anchor.js";
import { CONTROL_MAP, controlsFor } from "../src/controls.js";
import { appendEntry, readEntries } from "../src/log.js";
import { renderReport } from "../src/report.js";

const tmpLog = () => join(mkdtempSync(join(tmpdir(), "ev-anchor-event-")), "nested", "log.jsonl");
const event = { type: "change" as const, summary: "PR #7 merged", actor: "engineer" };

function seed(log: string, n: number): void {
  for (let i = 0; i < n; i++) appendEntry(log, { ...event, summary: `event ${i}` }, new Date(Date.UTC(2026, 9, 3, 10, i)));
}

function anchorEvent(anchor: unknown, overrides: Record<string, unknown> = {}) {
  return {
    type: "anchor" as const,
    summary: "Evidenz-Anker extern abgelegt",
    actor: "owner",
    ref: "evidence-anchor-2026-10-04-seq2",
    details: { anchor, storage: "signed_tag" },
    ...overrides,
  };
}

describe("anchor event type", () => {
  it("maps anchor events to logging, protection of records and collection of evidence (draft)", () => {
    expect(controlsFor("anchor").map((c) => `${c.framework} ${c.id}`)).toEqual([
      "ISO/IEC 27001:2022 Annex A A.8.15",
      "ISO/IEC 27001:2022 Annex A A.5.33",
      "ISO/IEC 27001:2022 Annex A A.5.28",
      "NIS2 Art. 21(2) (f)",
    ]);
    // A.8.15 is shared with agent_action; the report lists each control once and counts both.
    const report = renderReport([]);
    expect(report.match(/\| A\.8\.15 \|/g)).toHaveLength(1);
    expect(report).toContain("| A.5.33 | Protection of records | 0 |");
    expect(report).toContain("| A.5.28 | Collection of evidence | 0 |");
    expect(CONTROL_MAP.agent_action.map((c) => c.id)).toContain("A.8.15");
  });

  it("create_anchor never records an evidence event itself (head stays on the anchored entry)", () => {
    const log = tmpLog();
    seed(log, 2);
    const first = createAnchor(log);
    const entries = readEntries(log);
    expect(entries).toHaveLength(2);
    expect(entries.some((e) => e.type === "anchor")).toBe(false);
    expect(first.anchor.seq).toBe(entries.at(-1)!.seq);
    expect(createAnchor(log).created).toBe(false); // still idempotent
  });

  it("records the external storage AFTER the anchor; the next anchor covers the event", () => {
    const log = tmpLog();
    seed(log, 2);
    const first = createAnchor(log, { now: new Date("2026-10-04T08:00:00Z") });
    const ref = anchorTagName(first.anchor, first.record.created_at);
    expect(signedTagCommand(first.anchor, first.record.created_at)).toContain(` ${ref} `);

    const recorded = recordEvent(log, anchorEvent({ ...first.anchor, note: "dropped" }, { ref }), new Date("2026-10-04T08:05:00Z"));
    expect(recorded).toMatchObject({ seq: 3, type: "anchor", ref, details: { anchor: first.anchor, storage: "signed_tag" } });

    // The first (external) anchor still verifies: the event only extends the log.
    expect(verifyLogWithAnchors(log, [first.anchor])).toMatchObject({ valid: true, anchored: true, count: 3 });
    const second = createAnchor(log);
    expect(second).toMatchObject({ created: true, anchor: { seq: 3, hash: recorded.hash } });
    expect(verifyLogWithAnchors(log, [first.anchor, second.anchor])).toMatchObject({ valid: true, externalAnchorsChecked: 2 });
  });

  it("refuses anchor events without a matching anchor, storage or ref and writes nothing", () => {
    const log = tmpLog();
    seed(log, 2);
    const { anchor } = createAnchor(log);
    const cases: [ReturnType<typeof anchorEvent>, RegExp][] = [
      [anchorEvent(undefined), /needs details\.anchor/],
      [anchorEvent(anchor, { details: { anchor } }), /details\.storage/],
      [anchorEvent(anchor, { details: { anchor, storage: "email" } }), /details\.storage/],
      [anchorEvent(anchor, { ref: undefined }), /needs ref/],
      [anchorEvent({ ...anchor, hash: "a".repeat(64) }), /does not match the evidence log \(hash at seq 2 differs/],
      [anchorEvent({ ...anchor, seq: 9, count: 9 }), /does not match the evidence log \(anchored entry seq 9 missing/],
      [anchorEvent({ ...anchor, ts: "2020-01-01T00:00:00.000Z" }), /does not match the evidence log \(timestamp/],
    ];
    for (const [input, error] of cases) expect(() => recordEvent(log, input)).toThrow(error);
    expect(readEntries(log)).toHaveLength(2);
  });

  it("passes other event types through unchanged", () => {
    const log = tmpLog();
    const entry = recordEvent(log, { ...event, details: { anchor: "not checked for other types" } });
    expect(entry).toMatchObject({ seq: 1, type: "change", details: { anchor: "not checked for other types" } });
  });
});
