# TollWire Evidence MCP (`tollwire-evidence`, MVP)

MCP server that records agent changes, reviews, scans, approvals, deployments, incidents and permission changes as a tamper-evident hash chain. It maps event types to ISO/IEC 27001:2022 Annex A and NIS2 Article 21(2) controls (draft).

Status: version 0.x (MVP). Interfaces can change incompatibly before 1.0.
Installation, the marketplace and npm options, and the project-wide security notes are in the [top-level README](https://github.com/TollWire/tollwire#readme).
Issues are welcome; pull requests from third parties are not accepted, see [CONTRIBUTING.md](https://github.com/TollWire/tollwire/blob/main/CONTRIBUTING.md).

## Tools

| Tool | Purpose |
|---|---|
| `record_event` | Append an event. Events that contain a recognized secret format are refused. Type `anchor` is accepted only with a matching anchor (see below). |
| `list_events` | Read events, optionally filtered by type. |
| `verify_log` | Check the hash chain. Also checks the local anchor file (if present) and any external anchors passed in `anchors`. |
| `create_anchor` | Write the last entry as an anchor `{seq, hash, ts, count}` to the anchor file. Returns the anchor line, a tag name and a suggested signed Git tag command. Writes no event. |
| `map_controls` | Map event types to controls (draft, not confirmed by an auditor). |
| `export_report` | Markdown evidence report with integrity and coverage. |

## Storage

- **Log:** `TOLLGATE_EVIDENCE_LOG` if set; otherwise `.tollgate/evidence/log.jsonl` in the project directory (`CLAUDE_PROJECT_DIR`, or the current directory).
- **Anchor file:** `<log>.anchors.jsonl` in the same directory. Append-only. Each line carries `prev_anchor_hash` and `anchor_hash`, so the anchor file is itself tamper-evident.
- **Lock:** a lock file next to the log.
- **Permissions:** files are created with mode 0600.
- **Path:** every path component between the root and the log must be a real directory, not a symbolic link. Otherwise all tools that access files refuse to work. The root itself may be reached through a link.
- **Files:** log and anchor file must be regular files with exactly one directory entry. Symbolic links and hard links are refused. Checks are repeated on the opened file descriptor.
- **Errors:** tool error responses contain no stack trace and no file paths. Unexpected errors are reported generically.

## External anchors

An anchor records the sequence number, hash, timestamp and count of the last entry in canonical JSON, for example `{"count":42,"hash":"…","seq":42,"ts":"2026-10-04T08:00:00.000Z"}`.

`verify_log` checks, besides the chain, that for each anchor an entry with that `seq` exists and carries exactly that hash and timestamp. A log that was rewritten after the anchor (a new, internally valid chain) or truncated is then detected.

- `valid` means only "internally consistent".
- `anchored` is `true` only if the result is valid and at least one external anchor was confirmed. `valid: true` with `anchored: false` is not proof that the log is unchanged.
- A local anchor file does not protect against someone who rewrites or deletes the log and the anchor file together. An anchor is effective only when it is stored outside the machine.

Recommended procedure, performed by a person with their own signing key:

1. `create_anchor` (or `node scripts/anchor.mjs create` in the package directory).
2. Store the anchor outside the machine, for example as a signed Git tag. The tools never sign anything.
3. Record an `anchor` event with `node scripts/anchor.mjs record '<anchor-json>' signed_tag <tag-name> <actor>`. Exit code 0: recorded. Exit code 2: refused.

Verification: `git tag -v <tag>` checks the signature. Then pass the anchor line from the tag message to `verify_log` (`anchors`), or run `node scripts/anchor.mjs verify '<anchor-json>'` (exit 0 valid, 1 finding, 2 usage error).

## `anchor` events

An `anchor` event documents that a person stored an anchor outside the machine. The control mapping is a draft (ISO/IEC 27001:2022 A.8.15, A.5.33, A.5.28; NIS2 Article 21(2)(f)).

- Order: `create_anchor`, then the external storage, then the `anchor` event. Recording the event before storage would document a storage that has not happened yet.
- The event carries `ref` (tag name or comment URL), `details.anchor` (the stored anchor) and `details.storage` (`signed_tag` or `digest_comment`).
- The anchor must match the log: the entry at `seq` must have the same hash and timestamp. This is checked under the lock. Otherwise nothing is written.
- The tool checks that the anchor matches the log. It does not check that the external storage happened, who stored it, or that `ref` points to a real storage location. Only the signed tag or comment itself is evidence of that.

## Self-declared fields

The hash chain shows that the log is internally consistent. It does not show who wrote an entry.

- `actor` is free text supplied by the caller. The server does not check identity. Any process that may write the log can record any actor, including the name of a person.
- An `anchor` event is also self-declared. Only the external storage itself is evidence.
- For reviewers, anchors in signed tags count, not `anchor` events in the log.

## Secret filter

`record_event` refuses events whose content matches a known credential format: private keys (PEM, OpenSSH, PGP), GitHub, GitLab and npm tokens, AWS access keys, Anthropic and OpenAI keys (`sk-…`), Stripe keys (`sk_live_`, `sk_test_`, `rk_…`), Google API keys (`AIza…`), signed JWTs, Slack tokens and Slack webhook URLs. Only formats with a fixed prefix are recognized, which keeps false positives low. Unknown formats and freely chosen passwords are not detected. Do not put secrets into events.

## Package contents

The `files` field of `package.json` includes `dist/`, `.claude-plugin/`, `.mcp.json`, `scripts/anchor.mjs`, `LICENSE` and `README.md`. Source code, tests, coverage and the smoke test are not shipped. Run `npm run build` before packing, so that no stale files are included.

## Limits

- The hash chain detects changes; it does not prevent them. Whoever rewrites the whole file can create a new valid chain.
- External anchors detect this only for entries up to the last externally stored anchor, and only when the anchors are passed to `verify_log`. Entries after the last anchor are not protected.
- Signing each entry and automated external storage are not implemented.
- The control mapping has not been confirmed by an auditor and is not evidence of conformity with ISO/IEC 27001 or NIS2.
- The server makes no network requests.

## Development

```bash
npm ci --ignore-scripts
npm run check   # typecheck, lint, tests with coverage, build, smoke test
```

Node.js 22.12.0 or later is required (`engines`). Runtime dependencies: `@modelcontextprotocol/sdk` and `zod`, both pinned to exact versions.

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE) (SPDX: `PolyForm-Noncommercial-1.0.0`), see also [NOTICE](NOTICE). Noncommercial use only; commercial use requires prior written permission. Details: [LEGAL.md](https://github.com/TollWire/tollwire/blob/main/LEGAL.md).
