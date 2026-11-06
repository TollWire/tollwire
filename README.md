# TollWire

TollWire adds a policy enforcement layer to AI coding agents: it checks file writes, shell commands and new dependencies before they run, blocks recognized detected violations, and keeps a tamper-evident log of reported changes, scans and approvals as evidence supporting audits. TollWire itself runs locally and sends no data anywhere.

German version: [README.de.md](README.de.md)

> **Release status: version 0.1.2.** Interfaces can change incompatibly before 1.0.

## Quick start

Guardrail and evidence log as Claude Code plugins, three commands in Claude Code:

```text
/plugin marketplace add TollWire/tollwire
/plugin install tollwire-guardrail@tollwire
/plugin install tollwire-evidence@tollwire
```

Each plugin is installed on its own; you can install only the guardrail. There is no single bundle install yet.

Only the evidence MCP server (instead of the `tollwire-evidence` plugin), one command in a shell:

```bash
claude mcp add tollwire-evidence -- npx -y @tollwire/evidence-mcp
```

You need Node.js 22.12 or later and npm on your `PATH` ([Requirements](#requirements)). Read the
[Security notes](#security-notes) before you install, and see [Uninstall](#uninstall) to remove everything again.
For administrator-managed Linux machines there is a separate [enterprise edition](#enterprise-edition-linux).

## What it is

TollWire contains two local, source-available plugins (PolyForm Noncommercial License 1.0.0, noncommercial use only, see [License](#license)):

| Plugin | Package | What it does |
|---|---|---|
| `tollwire-guardrail` | [`guardrail-plugin/`](guardrail-plugin/README.md) | Blocks writes to protected paths, dangerous shell commands and dependencies that are not on the allowlist, before the tool call runs (PreToolUse hook). The same checks are available as MCP tools. |
| `tollwire-evidence` | [`evidence-mcp/`](evidence-mcp/README.md) | MCP server that records agent changes, reviews, scans, approvals, deployments, incidents and permission changes in a hash-chained log. It verifies the chain, creates external anchors, maps event types to ISO/IEC 27001:2022 Annex A and NIS2 Article 21(2) controls (draft), and exports a Markdown report. |

Both plugins run as local processes on your machine. The project does not operate a hosted service.
The plugin code makes no network requests.
Apart from what your own tools do (for example Claude Code or npm when they install packages), no data leaves your machine through TollWire. The evidence log is a file in your project directory; see the evidence package for details.

## Install via the Claude Code plugin marketplace

In Claude Code:

```text
/plugin marketplace add TollWire/tollwire
/plugin install tollwire-guardrail@tollwire
/plugin install tollwire-evidence@tollwire
```

To pin the marketplace to a release tag:

```text
/plugin marketplace add TollWire/tollwire#<tag>
```

From the command line:

```bash
claude plugin marketplace add TollWire/tollwire
claude plugin install tollwire-guardrail@tollwire --scope user
claude plugin install tollwire-evidence@tollwire --scope user
```

`--scope` accepts `user`, `project` or `local`. See the install documentation for what each scope means.

Auto-update is off by default for marketplaces from third parties. The marketplace entries use exact package versions.

## Install via npm

Choose **one** path: the marketplace install above or the npm install below. Running both can register the same MCP servers twice.

The npm path is for the evidence MCP server only. The guardrail needs its PreToolUse hook, which only the plugin install registers, so install the guardrail through the marketplace.

Register the evidence server for your user account:

```bash
claude mcp add --scope user --transport stdio tollwire-evidence -- npx -y @tollwire/evidence-mcp
```

Or add it to the `.mcp.json` of your project:

```json
{
  "mcpServers": {
    "tollwire-evidence": {
      "command": "npx",
      "args": ["-y", "@tollwire/evidence-mcp"]
    }
  }
}
```

To run a version you have reviewed, pin it: `npx -y @tollwire/evidence-mcp@<exact-version>`.

The evidence server is also listed in the official MCP Registry as `io.github.TollWire/evidence-mcp` (from the first release on).

The packages declare no install scripts. If you install a package with npm yourself, `--ignore-scripts` prevents npm from running lifecycle scripts.

## Requirements

- Node.js 22, version 22.12.0 or later (the `engines` field of both packages).
- Claude Code with plugin support; tested with Claude Code 2.1.302 (guardrail plugin, 2026-10-30).
- npm on your `PATH`. After a marketplace install, Claude Code installs the package dependencies with npm. If the runtime dependencies are missing, the guardrail hook blocks Bash, Edit, Write, MultiEdit and NotebookEdit calls (see [Security notes](#security-notes)).

## Security notes

A Claude Code plugin you install can execute arbitrary code on your machine with your user privileges. Hooks and MCP servers run outside Claude Code's sandbox. Source: [Claude Code plugin security](https://code.claude.com/docs/en/plugins/security) (wording checked against the source on 2026-10-24).

### What `tollwire-guardrail` executes

- **Hook:** PreToolUse for `Bash`, `Edit`, `Write`, `MultiEdit` and `NotebookEdit`. It runs `node dist/hookCli.js` and reads the tool call from stdin. Exit code 2 blocks the call; the reason is written to stderr.
- **Fail closed:** for the checked tools (`Bash`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`), if `node` or `dist/hookCli.js` is missing or does not load, or the hook exits with any code other than 0 or 2, the wrapper exits with 2 and the call is blocked. Observed tools (log only) and session events never block. The message starts with `TollGate guardrail: hook did not run or timed out`. Check that `node` is on your `PATH` and that the plugin dependencies are installed, or disable the plugin.
- **Timeout:** `hooks/hooks.json` sets 30 seconds. When GNU `timeout` is installed, the wrapper stops the hook after 25 seconds. Without `timeout` (for example with the default macOS setup) the wrapper starts the hook with a built-in watchdog (`dist/hookCliPosix.js`) that ends the process after 25 seconds; for the checked tools that is a block (exit code 2). What Claude Code itself does when its own 30-second limit passes has not been verified.
- **macOS:** path comparisons for protected paths ignore case and Unicode normalization form, because APFS does so by default (`.CLAUDE/settings.json` is the same file as `.claude/settings.json`). `Library/LaunchAgents/` and `Library/Application Support/Claude/` in the home directory are protected paths. The enterprise mode for macOS (managed by an administrator, with a root-owned policy) belongs to a separate commercial package and is not active in this plugin build: where an administrator directory is present, the checked tools are blocked (`enterprise_unsupported_platform`) until the mode has been accepted on real hardware. Without the administrator directory the plugin behaves as described in this document.
- **MCP server:** stdio, started with `node dist/mcp/server.js`. Tools: `check_command`, `check_path`, `check_dependencies`, `describe_policy`. The server does not write files.
- **Logs:** the plugin writes a local log of its decisions (redacted); you can turn it off in your user configuration. By default it contains no command text and nothing is sent anywhere. Location, retention and the switch are described in the plugin README ("Decision log"). Hook messages go to stderr.

### What `tollwire-evidence` executes

- **MCP server:** stdio, started with `node dist/server.js`. Tools: `record_event`, `list_events`, `verify_log`, `create_anchor`, `map_controls`, `export_report`.
- **Writes:** a JSON Lines log. The path is `TOLLGATE_EVIDENCE_LOG` if set; otherwise `.tollgate/evidence/log.jsonl` in the project directory (`CLAUDE_PROJECT_DIR`, or the current directory). Files are created with mode 0600. A lock file and an anchor file (`log.jsonl.anchors.jsonl`) are created next to the log. Symbolic links in the path are refused.
- **Content:** the log contains what is recorded, including the `actor` you name. Do not record secrets. The server refuses only some known secret formats, not all of them.

### Before you install

- Read `hooks/hooks.json` and `.mcp.json` in the package. They show exactly what Claude Code will run.
- Verify the release: download the `.tgz` and the `SHA256SUMS` file from the GitHub release of the version you install, then run `sha256sum --check --strict SHA256SUMS` in that directory. The marketplace entry has no integrity digest. This check covers the file you downloaded, not the copy that npm serves.
- Compare with the copy npm serves: `npm view @tollwire/<package>@<version> dist.integrity` must be equal to
  `sha512-` followed by `openssl dgst -sha512 -binary <file>.tgz | openssl base64 -A` for the file you checked.
- Pin the version: use `#<tag>` for the marketplace, and an exact version for `npx`.
- Auto-update of third-party marketplaces is off by default. Keep it off unless you have reviewed the release.

### Uninstall

Disable a plugin in `/plugin`, or uninstall it:

```bash
claude plugin uninstall tollwire-guardrail@tollwire --scope user
claude plugin uninstall tollwire-evidence@tollwire --scope user
claude plugin marketplace remove tollwire
```

Use the scope you installed with. For the npm install, remove the server with `claude mcp remove tollwire-evidence` or delete its entry from `.mcp.json`.

Uninstalling does not delete your data: the evidence log stays in the project (`.tollgate/evidence/`), the guardrail's decision log and user configuration stay in your user directories (locations in the plugin README, "Decision log"). Delete them yourself if you no longer need them.

## Limits

- TollWire is defense in depth, not a security boundary. The guardrail is not a sandbox.
- The guardrail checks shell commands heuristically. It does not analyze script files (`bash x.sh`, `./x.sh`, `source x.sh`), modules (`python -m`), `make`, `npm run`, or other programs that write files themselves. Such calls are allowed.
- The hook takes effect only if Claude Code loads the plugin or the project settings. The project directory is the directory from which Claude Code was started.
- The evidence log detects changes; it does not prevent them. Whoever rewrites the whole file can create a new, internally valid chain. External anchors detect this only up to the last anchor. Entries after the last anchor are not protected.
- The `actor` value and `anchor` events are self-declared. The tools do not verify who made an entry.
- The control mapping (ISO/IEC 27001:2022 Annex A, NIS2 Article 21(2)) is a draft. It has not been audited and is not evidence of conformity with either standard.
- Before 1.0, interfaces may change incompatibly.

## Enterprise edition (Linux)

For machines managed by an administrator there is a separate, commercial enterprise edition: a root-owned policy that
users and agents cannot change, a fixed system Node, forwarding of the decision log to your SIEM and an admin view.
It is not part of this repository; to ask for it, use the request route in [LEGAL.md](LEGAL.md). Linux comes first;
macOS and Windows are planned.

The enterprise package installs with one command, first as a dry run (run as a normal user; it asks for `sudo`
where root is needed):

```bash
sh install/linux/setup.sh --dry-run    # prints every step, changes nothing
sh install/linux/setup.sh              # Node check, build, root-owned copy, install, provisioning, system check
```

If you receive the package as an archive, check it before you unpack it: `sha256sum --check --strict SHA256SUMS` in
the download directory. The installer does not download anything and there is no `curl | sh` variant. Install it only
on a dedicated test or managed machine: once installed, the guardrail on that machine runs in enterprise mode (fail
closed).

## Naming

Some technical identifiers still carry the former name TollGate: environment variables (`TOLLGATE_*`), directories
(`.tollgate/`, `/etc/tollgate/`), the event schema `tollgate.event.v1`, the MCP server names inside the plugins and the
hook messages (`TollGate guardrail: …`). They keep working as documented. A later release may rename them; the release
notes will say so.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md): issues and bug reports are welcome; pull requests from third parties are not accepted.
- [SECURITY.md](SECURITY.md): report vulnerabilities privately, not as public issues.

## License

Source-available, not open source: [PolyForm Noncommercial License 1.0.0](LICENSE) (SPDX: `PolyForm-Noncommercial-1.0.0`). Noncommercial use only; commercial use requires prior written permission. Summary, request route and details: [LEGAL.md](LEGAL.md). See also [NOTICE](NOTICE).
