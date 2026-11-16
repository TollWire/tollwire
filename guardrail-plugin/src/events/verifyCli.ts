// `tollgate-events verify [--strict] [--json] [path...]`: checks the hash chain of the decision log.
import { expandPaths, verifyGroups, type PathFinding, type VerifyReport } from "./verify.js";
import { sanitize } from "./sanitize.js";

const USAGE =
  "Usage: tollgate-events verify [--strict] [--json] [path...]\n" +
  "  path: an event file or a directory with event files (u<uid>-*, control-*, monitor-*, relay-*, host-*, send-*,\n" +
  "        sendcfg-*.jsonl; default: the local decision log). A given directory without events fails; for the\n" +
  "        default log an empty directory is a warning. --strict also fails on warnings and metadata findings.\n";

export interface CliIo {
  out: (text: string) => void;
  err: (text: string) => void;
}

function line(f: PathFinding): string {
  return `${f.kind}: ${sanitize(f.file)}${f.line === undefined ? "" : `:${f.line}`} (${sanitize(f.detail)})`;
}

function render(report: VerifyReport, warnings: readonly PathFinding[], ok: boolean): string[] {
  const lines: string[] = [];
  for (const f of warnings) lines.push(`WARN: ${line(f)}`);
  for (const f of report.readFindings) lines.push(line(f));
  for (const f of report.chainFindings) lines.push(`${f.kind}: ${sanitize(f.file)}:${f.line} (${sanitize(f.detail)})`);
  lines.push(`${ok ? "OK" : "FAIL"}: ${report.events} events in ${report.files} files, ${report.chains.length} chains`);
  return lines;
}

/** Runs the CLI; returns the exit code (0 valid, 1 findings, 2 usage error). */
export function runVerifyCli(argv: readonly string[], io: CliIo, defaults: { dir: string }): number {
  const [command, ...rest] = argv;
  if (command !== "verify") {
    io.err(USAGE);
    return 2;
  }
  let strict = false;
  let json = false;
  const paths: string[] = [];
  for (const arg of rest) {
    if (arg === "--strict") strict = true;
    else if (arg === "--json") json = true;
    else if (arg.startsWith("-")) {
      io.err(USAGE);
      return 2;
    } else paths.push(arg);
  }
  const explicit = paths.length > 0;
  const expanded = expandPaths(explicit ? paths : [defaults.dir]);
  const { report, noEvents } = verifyGroups(expanded.groups);
  // Which path findings fail:
  // - a directory that cannot be listed, a link or a missing path: always (fail closed);
  // - no event files / no events: for a given path always (nothing was verified, Abnahme-Befund 8); for the default log
  //   only with --strict, because it is legitimately empty with logging switched off or after retention. A missing
  //   default directory stays a failure (`unreadable`): the log writer creates it with its first event, so its absence
  //   is not the normal state of a used installation and is not softened here;
  // - scan limit and unknown *.jsonl names: with --strict, or when a given path verified no file at all.
  const nothingVerified = explicit && report.files === 0;
  const fails = (f: PathFinding): boolean => {
    if (f.kind === "no_event_files" || f.kind === "no_events") return strict || explicit;
    if (f.kind === "directory_limit" || f.kind === "unknown_file") return strict || nothingVerified;
    return true;
  };
  const pathFindings = [...expanded.findings, ...noEvents];
  const warnings = pathFindings.filter((f) => !fails(f));
  report.readFindings.push(...pathFindings.filter(fails));
  const ok = report.chainOk && pathFindings.every((f) => !fails(f)) && (!strict || report.metaOk);
  if (json) io.out(`${JSON.stringify({ ok, ...report, warnings })}\n`);
  else for (const text of render(report, warnings, ok)) io.out(`${text}\n`);
  return ok ? 0 : 1;
}
