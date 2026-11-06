# TollWire Guardrail Plugin (`tollwire-guardrail`, MVP)

Claude Code plugin that stops a coding agent before an action runs: writes to protected paths, dangerous shell commands and dependencies that are not on the allowlist. The same checks are available as MCP tools.

Status: version 0.x (MVP). Interfaces can change incompatibly before 1.0.
Installation, the marketplace and npm options, and the project-wide security notes are in the [top-level README](https://github.com/TollWire/tollwire#readme).
Issues are welcome; pull requests from third parties are not accepted, see [CONTRIBUTING.md](https://github.com/TollWire/tollwire/blob/main/CONTRIBUTING.md).

**The plugin does not replace a sandbox.** It checks tool calls against a block list before they run; whatever no rule recognizes is allowed, and programs started by an allowed command are not checked. Run coding agents in a container or a virtual machine (no credentials they do not need, read-only mounts for what they must not change, restricted network) and use the plugin as an additional layer on top. See "Limits" below.

## What it checks

- **Protected paths:** writes to paths that the policy protects, including through Bash redirections and write commands (`sed -i`, `cp`, `mv`, `tee`, `rm` and others), downloaders (`curl -o`, `wget`) and Git subcommands (`--output`, `rebase --exec`).
- **Project boundary and temporary directories:** write tools and Bash write targets (redirections and the write commands the check recognizes, such as `cp`, `mv`, `tee`, `sed -i`, `touch`, `dd of=`, `tar -C`) may only write inside the project, `/tmp`, `/var/tmp` and an accepted `TMPDIR` (below). Both use the same rule and the same `rule_kind` (`outside_project`); the path is checked as written and with symlinks resolved, so `../x`, `cd .. && touch x`, `~/x` and a symlink that leads out of the project are outside. Allowed as Bash targets: `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/zero`, `/dev/full` (only if the path also resolves physically into `/dev`, so `link/../../dev/null` does not count) and descriptor duplications such as `2>&1`; the source of a link (`ln -s /usr/lib/x y`) is not a write target. A glob target counts as outside when one of its parts can expand to `..` (`.*/x`). For Bash the boundary applies to agent sessions; in a human-operated session (`TOLLGATE_HUMAN_SESSION=1`) the Bash write check is skipped as before, the write tools keep the boundary. `TMPDIR` (also for Bash targets of the form `"$TMPDIR/..."`) counts as a temporary directory only if it lies, as written and with symlinks resolved, below `/tmp`, `/var/tmp` or `/run/user/<uid>/tollgate-tmp` (on macOS also the per-user directory `/var/folders/<xx>/<id>/T`); any other value is ignored, and `/run/user/<uid>/tollgate-tmp` counts only if it is a real directory, not a symlink. If you use a temporary directory elsewhere (for example `/dev/shm`, `$XDG_RUNTIME_DIR`, `~/tmp` or `$RUNNER_TEMP`), set `TMPDIR` to `/tmp` or create `/run/user/<uid>/tollgate-tmp` yourself; the plugin does not create it. On macOS the check matches the shape `/var/folders/<xx>/<id>/T`, not the own user; the file permissions of `/var/folders` protect other users' directories.
- **Elevated privileges:** `sudo`, `sudoedit`, `doas` and `pkexec` are blocked as commands by two rules of the bundled policy (from version 0.1.2 on; 0.1.1 was not published). They recognize known forms: command position (also after `;`, `|`, `&&`, `(`, `{`, `!`, backticks and keywords), behind wrappers (`env`, `nohup`, `nice`, `timeout`, `xargs`, `flock`, `exec -a`, `watch`, `find -exec` and others, including the usual option values such as `env -u X`, `timeout -s KILL 5`, `xargs -I {}`) and inside `bash -c`, `su -c` or `env -S`. Other spellings (long options with a separate value such as `env --unset X`, a name built at run time such as `$(which sudo)`) are not recognized. Mentioning the names stays allowed (`man sudo`, `command -v sudo`, `grep sudo`). Known false positives: `sudo` right after `|` or `;` inside an argument (`grep -E 'a|sudo'`, `--body "a; sudo x"`) and a line of a here-document that starts with `sudo`. `su` and `runuser` are treated as wrappers: their command string is checked like any other command.
- **Shell commands:** nested shell strings (`bash -c`, `csh -c`, `trap`, `alias`, functions) are checked recursively. For `csh`/`tcsh` the forms `>!`, `>>!`, `>&!` and `>>&` are not analyzed and therefore blocked (fail closed). Commands are blocked when a target is only known at runtime (`$VAR`, `$(...)`, `xargs`), when a command name is dynamic, when code comes from a pipe or a file, or when the command is an editor.
- **Inline code:** a list-based heuristic looks for write or process APIs in inline code (`python -c`, `node -e`, here-documents).
- **Git configuration that runs commands** (`core.fsmonitor`, `alias.*`, `GIT_SSH_COMMAND`) and **home-directory configuration** (shell profiles, Git and SSH configuration) are blocked for writes.
- **Dependencies:** dependency changes are checked against the allowlist in the policy.
- **Size:** shell commands over 32 KiB are blocked, also in a human-operated session.
- `git apply`, `git am` and `patch` are allowed only with `--check` or `--dry-run`.

The following are always protected against agent writes: `.git/config`, `.git/config.worktree`, `.git/hooks/`, `.tollgate/` and the active policy file.

## Install commands in Bash: scope and limits

Bash install commands (`npm|pnpm|yarn|bun install|i|add`, `pip|pipx|python -m pip|uv pip|uv add|uv tool install`, `poetry add`, `pipenv install`) are checked against `allowedDependencies`, in addition to writes to `package.json`/`requirements*.txt`. `npm ci` and an install without package arguments stay allowed. The bundled policy has an empty allowlist, so every install with a package argument is blocked there.

The install check applies to every session, also to a human-operated one (`TOLLGATE_HUMAN_SESSION=1`); this includes the conda block below.

Commands that fetch and run a package without changing a manifest are checked the same way: `npx`, `npm exec`/`npm x`, `pnpm dlx`, `yarn dlx`, `bunx`/`bun x` (npm allowlist; the packages named with `--package`, otherwise the command itself; with `--no` and `--yes` the last one wins, as in npm), `npm init <name>`/`npm create <name>`, `pnpm|yarn|bun create <name>` (the initializer package `create-<name>`, `@scope` → `@scope/create`; `npm init` without a name stays allowed) and `uvx`, `uv tool run`, `pipx run` (PyPI allowlist; `--from`/`--spec`/`--with`, otherwise the command), `uv run --with` (the `--with` packages). A package from outside the registry (Git, URL, path), an index or source option, an unresolved argument (`$PKG`) and an option the check does not know (it could take the next word as its value) are blocked (fail closed). The command name is checked as a package name, so a binary whose name differs from its package (`npx tsc`) is blocked unless that name is allowed; to run an installed binary use `npx --no <bin>` or `npm exec --no -- <bin>`, which never download. conda packages (`conda`, `mamba`, `micromamba` `install`/`create` with a package, `--file`, `env create`/`env update`) are a separate ecosystem without an allowlist and are always blocked. The command strings of `su -c`/`runuser`, of the shells `sh`, `bash`, `zsh`, `dash`, `ash`, `ksh`, `mksh`, `rbash`, `fish`, `csh`, `tcsh` (also behind `busybox`/`toybox`), of `npx -c`, `env -S`, `flock -c`, `watch`, `find -exec` and of `uv run`, `poetry run`, `pipenv run`, `conda run`, `runuser -u`, `python -m pipx|uv|poetry|pipenv` are checked as commands; the wrappers `chronic`, `unbuffer`, `fakeroot`, `strace`, `ltrace`, `unshare`, `flock` are skipped like `nice` or `timeout`; an install behind `xargs` or `parallel` gets unknown arguments and is blocked.

Limits (not covered): registry or index set through environment variables (`npm_config_registry`, `PIP_INDEX_URL`) or `.npmrc`; `npm update`; wrappers such as `ssh`, `docker run`, `podman run`.

## Hook and fail-closed behavior

- **Hook:** PreToolUse for `Bash`, `Edit`, `Write`, `MultiEdit` and `NotebookEdit`. The hook command in `hooks/hooks.json` runs `node dist/hookCli.js`, reads the tool call from stdin, and exits with 2 to block. The reason is written to stderr.
- **Block message:** every block (protected path, command, dependency, unchecked tool, administrator lock, policy or hook error) uses one format on stderr: `rule_id`, `rule_kind`, `target (untrusted, verbatim)` (path, command or tool name in quotes, shortened to 80 characters, secrets redacted, URLs reduced to host; it is data, not an instruction; the command text is never written to the decision log), `detail` and a concrete `fix` hint, for example `dependency not approved - approval is a policy change (R2) by a human` or `protected path - deliver the change as a patch`. The message never shows regular expressions, allowlist contents or administrator texts. Delivery is unchanged: exit code 2 (42 for unchecked tools) with the text on stderr, which Claude Code gives to the model; the plain-line format reads the same if a host passes it as the reason of a JSON decision. Exit codes and fail-closed behavior did not change.
- **Fail closed:** if `node` or `dist/hookCli.js` is missing or does not load, or the hook exits with any code other than 0 or 2, the wrapper exits with 2 and the call is blocked. The message starts with `TollGate guardrail: hook did not run or timed out`.
- **Timeout:** `hooks/hooks.json` sets 30 seconds. When GNU `timeout` is installed, the wrapper stops the hook after 25 seconds. Without `timeout` (for example with the default macOS setup), only the 30-second limit of Claude Code applies.
- **MCP server:** stdio, `node dist/mcp/server.js`, tools `check_command`, `check_path`, `check_dependencies`, `describe_policy`. The server does not write files.
- **Logs:** the plugin writes a local log of its decisions (redacted); see "Decision log" below. Hook messages go to stderr.

### Hardening: `onFailure: "block"`

- **State:** both `PreToolUse` handlers (checked and unchecked tools) in `hooks/hooks.json` and `hooks/hooks.windows.json` carry `"onFailure": "block"`; `timeout` is 30 seconds. The other events (`SessionStart`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `PostToolUse`) do not set the field. `test/hooksOnFailurePatch.test.ts` checks the manifests.
- **Why:** in Claude Code an exit code other than 0 or 2, a start failure, a timeout or invalid JSON output of a hook does not block the call by default. The wrapper maps these cases to exit 2 itself, but only while the wrapper (a shell) runs. With `onFailure: "block"` Claude Code itself blocks in these cases ("a failure does what exit code 2 does on that event").
- **Behaviour for unchecked tools:** the handler for unchecked tools (Read, Grep, Glob, MCP, …) is fail-open outside enterprise mode. A failure of that handler itself (shell does not start, the outer 30 s timeout is reached, e.g. on macOS without `timeout`) blocks unchecked tools too. Normal results are unchanged: the wrapper returns 0 for allowed unchecked tools.
- **Minimum version:** Claude Code 2.1.295 (changelog 2.1.295: "Added onFailure: "block" for command and HTTP hooks"). Source: https://code.claude.com/docs/en/hooks. The field has no effect for `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` and async hooks; it is therefore set only for `PreToolUse`.
- **Second layer:** the wrapper stays. It covers the unchecked-tool exit code 42 mapping and older versions that ignore the field.
- **Open (security relevant, not proven):** the documentation does not say what Claude Code versions before 2.1.295 do with an unknown field in a hook object (ignore it, or reject the manifest so that the plugin does not load, which would fail open). Check before a rollout on such a version: run `claude plugin validate` on the plugin and check the Errors tab of `/plugin`; the plugin must load and the PreToolUse hook must still block (for example a write to a protected path). Until then, use Claude Code 2.1.295 or later, or record the result of this check.

## Decision log

Every evaluation of a tool call writes one event to a local, hash-chained log (`tollgate.event.v1`, JSON Lines; fields, size rule and test vectors in [docs/events-v1.md](docs/events-v1.md)). The log is **on by default**. Nothing is sent anywhere.

- **Content:** decision, tool, program names, affected paths and rule. By default **no command text** is logged. Prompts, file contents, tool responses and environment variables are never logged.
- **Location:** `$XDG_STATE_HOME/tollgate/events/` (default `~/.local/state/tollgate/events/`), `~/Library/Logs/TollGate/` on macOS, `%LOCALAPPDATA%\TollGate\events\` on Windows. Directory `0700`, files `0600`, one file per UTC day (`u<uid>-<YYYYMMDD>.jsonl`). Files older than 30 days are deleted at the start of a session.
- **Your switch:** `$XDG_CONFIG_HOME/tollgate/config.json` (default `~/.config/tollgate/config.json`):

  ```json
  { "logging": { "enabled": false, "commandDetail": "redacted", "projectDir": false } }
  ```

  `enabled: false` turns the log off; the last event is then `logging_disabled`. `commandDetail: "redacted"` additionally logs the command text with secrets redacted (a heuristic). The redaction recognizes known secret formats, credential-like names, headers, JSON members and the password options of common programs, but it cannot find a secret in free-form text or in the options of an unknown program, so treat the redacted command text as sensitive. An invalid file leaves the log on. The file is read at the start of a session and stays fixed for that session. No project policy, `TOLLGATE_POLICY` or environment variable can change these settings. The user configuration and the log directories are always protected against agent writes (a person in a `TOLLGATE_HUMAN_SESSION=1` session can still edit them); this is a rule of the hook, not a security boundary against scripts that run as your user.
- **Verification:** `tollgate-events verify [--strict] [--json] [path...]` checks the hash chain (default: the local log). A directory may hold user logs (`u<uid>-*.jsonl`) and the service chains of the enterprise package and the monitor (`control-`, `monitor-`, `relay-`, `host-`, `send-`, `sendcfg-*.jsonl`); each source is verified as its own chain. A given path without events fails (`no_event_files` for a directory without event files, `no_events` for files that hold no event, e.g. truncated to 0 bytes). For the default log both are a `WARN:` line (in `--json`: `warnings`) and fail only with `--strict` (logging switched off, retention); a missing default directory fails. `--strict` also fails on the scan limit (`directory_limit`), unknown `*.jsonl` names (`unknown_file`) and metadata findings. Windows event files (`s<SID>-*.jsonl`) are not verified yet; they are reported as `unknown_file`. Exit code 0 valid, 1 findings, 2 usage. The hash chain detects changes, gaps and reordering inside a chain; it is not authenticated: whoever can write the log can replace it with a newly computed chain or cut off its end. It is no protection against writers; that needs an anchor stored elsewhere (e.g. the forwarded copy at the relay/SIEM).
- **Errors:** if an event cannot be written, the hook warns on stderr and lets the call pass. A damaged file never stops the log: it continues in a new file with a new chain id and a `chain_start` event that points to the last valid event.
- **Hook events:** `session_start`, `session_end`, `subagent_start`, `subagent_stop` and read-only tools need the extended `hooks/hooks.json` (second PreToolUse entry and the session events). Backups or cloud sync of your home directory also copy the log.

### Enterprise mode

If the directory `/etc/tollgate/` exists or `TOLLGATE_ENTERPRISE=1` is set, the hook enforces an administrator-owned policy (`/etc/tollgate/policy.json`, version 2; owner root, not writable by group or others, also for all parent directories) and fails closed if it is missing or unsafe (`policy_error`). The project policy and `TOLLGATE_POLICY` can then only tighten: command rules as `literal`, `tokens` or `glob` (regular expressions there are ignored and reported), more protected paths, fewer dependencies. `TOLLGATE_HUMAN_SESSION`, `TMPDIR` and `HOME` from the environment have no effect, the log goes to a fixed location (`/var/log/tollgate/events/<uid>/`), with redacted commands, and a failed write blocks checked tools (`onWriteError: block`). On macOS the signal makes every checked tool fail with `enterprise_unsupported_platform`; on Windows the access rights cannot yet be verified and the hook fails closed. Tools that the hook does not check (MCP tools, WebFetch, subagents) are only recorded by default. In enterprise mode these tools are blocked by default, except the base list `Read`, `Glob`, `Grep`, `LS`, `TodoWrite`, `Task`, `Agent`; the enterprise policy releases more with `"tools": {"allow": ["WebSearch", "mcp__server__*"]}` (or sets `"unchecked": "observe"` to go back to recording only). Any other tool is blocked (rule kind `unchecked_tool`, hook exit code 42, which the manifest entry for unchecked tools maps to a block). Entries are exact tool names or `mcp__<server>__*`; lower policy layers cannot set the section, and stand-alone mode is unchanged. The manifest also starts Node without `NODE_OPTIONS`, `NODE_PATH` and `LD_PRELOAD`, and in enterprise mode only from a system location (`/opt/tollgate/node/bin/node` or `/usr/bin/node`), never from `PATH`. Neither is a security boundary: an allowed MCP server or a script run through Bash stays outside the hook's view. The administrator's tooling (relay, SIEM forwarding, provisioning) is not part of this package.

## Session taint

A session that has read untrusted content is *tainted*: results of `WebFetch`, `WebSearch` and MCP tools, Bash commands with
network access (`curl`, `wget`, `gh`, `git fetch`/`pull`/`clone` ...) and files read outside the project. In a tainted session
the hook blocks network egress (also `WebFetch`, `WebSearch` and MCP tools; wrappers such as `xargs`, `find -exec`, `su -c`;
unknown git subcommands and aliases), `git push`, access to secrets and credential files (also printing the environment), nested
agent CLIs (`claude`, `codex`, ...) and the release command, and `TOLLGATE_HUMAN_SESSION` no longer opens protected paths for any
checked tool, Bash included (rule kind `taint`). Everything else goes on. Mode `observe` only records (`taint_would_block`).

- **Policy:** section `"taint": {"mode": "off" | "observe" | "enforce"}` with optional `sources` (`tools`, `bashNetwork`,
  `readOutsideProject`) and `restrictTools`. Absent means off. Merge: tightening only; in stand-alone mode the bundled default
  is the floor that a project policy cannot lower; in enterprise mode the enterprise policy decides, lower layers only tighten.
  A project policy (`<project>/.tollgate/policy.json`) replaces the bundled base, so it has to be a complete policy: a file with
  only `{"taint": {"mode": "enforce"}}` is invalid (`policy_error`; fail closed, every checked call is blocked). To switch to
  `enforce`, copy the bundled `policy/default.json` (with `version` and all other sections) and change only `taint.mode`, for
  example from the project directory:

  ```bash
  mkdir -p .tollgate
  node -e 'const fs = require("node:fs"); const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); p.taint.mode = "enforce"; fs.writeFileSync(".tollgate/policy.json", JSON.stringify(p, null, 2) + "\n")' <plugin>/policy/default.json
  ```

  The result keeps every rule of the base and has `"taint": {"mode": "enforce", "sources": {...}, "restrictTools": [...]}`.
- **State:** `tollgate.taint.v1`, one file per session in the private state directory (stand-alone `<state>/tollgate/taint/`,
  enterprise `~/.local/state/tollgate/taint/`), HMAC-SHA256 with a per-user key. Missing, unreadable or manipulated state counts
  as tainted. A new session (`startup`, `clear`) starts clean, a resumed session without state starts tainted.
- **Release (only a human):** `tollgate-taint status`, then `tollgate-taint release --session <id>` in a real terminal (not from
  inside Claude Code; a typed confirmation code, read from the controlling terminal `/dev/tty`; end of input, a read error or
  no answer within 10 minutes means not confirmed). The block message names the session and the full path
  (`node <plugin>/dist/taintCli.js`); `./install.sh` of the source repository places `~/.local/bin/tollgate-taint`. Enterprise: `sudo tollgate-taint admin-release --uid <uid> --session <id>`
  writes a root-owned release file that the hook consumes; an administrator cannot release their own account.
- **Events:** `taint_set`, `taint_release`, `taint_would_block` (observe) and `decision` with `rule_kind` `taint`, all in the
  hash chain (`docs/events-v1.md`).
- **Inheritance:** `TOLLGATE_TAINTED=1` in the hook's environment taints a session for its whole life (for launchers; the
  current hook manifest does not pass the variable through yet).
- **Limits:** the hook sees tool calls, not the model context: the taint is per session and coarse. A program run through Bash
  (an interpreter, a script, a package manager), globs or variables in paths and symbolic links are not analyzed; the boundary for
  that is the sandbox's network allowlist. The key lies in the user's own directory (also in enterprise mode, where only the
  release is root-owned): code that runs as you outside the hook can read it, forge a state or put back an older clean one (the
  hash chain still shows every `taint_set`). A new key (after the old one was deleted) makes every running session tainted.

## Policy

The base policy is resolved in this order:

1. `<project>/.tollgate/policy.json`;
2. the bundled `policy/default.json`.

`TOLLGATE_POLICY` names a further layer on top of the base. It can only tighten (same rules as the lower layers in enterprise mode): protected paths and command rules (`literal`, `tokens`, `glob`) are added, a dependency list can only shrink the allowlist. Regular expression rules, wider dependency lists, duplicate rule ids and enterprise-only sections are ignored and logged as `policy_override_ignored` (or `policy_error`). A missing or invalid file blocks (fail closed). The file is protected against agent writes.

The project directory is the directory from which Claude Code was started.

`TOLLGATE_HUMAN_SESSION=1` allows changes to protected paths. It is meant for sessions that a person operates. Do not set it for unattended or CI runs.

## Limits

- This is a guardrail, not a sandbox, and it does not replace one. The rules are a block list: a command that no rule recognizes is allowed. The security boundary is a review on the server (protected paths, code owners, branch rules) and isolation at the operating-system level (container or virtual machine, read-only mounts, minimal rights, restricted network).
- Not analyzed, and therefore allowed: script files (`bash x.sh`, `./x.sh`, `source x.sh`), modules (`python -m`), `make`, `npm run`, and other programs that write files themselves. Also not analyzed: unknown APIs or interpreters, `cd` behind unknown wrappers, and Git plumbing commands.
- The project boundary for Bash covers only the write targets the check recognizes (redirections and known write commands). Programs that write on their own (scripts, build tools, `npm install -g`, package managers, unknown programs) can still write outside the project. Running as another user is caught only where the name is visible: `$(which sudo)`, a variable or an alias that holds the name is not recognized; `ssh`, `docker`/`podman` and `run0` are not modeled.
- The hook takes effect only if Claude Code loads the plugin or the project settings.
- Without GNU `timeout`, the 25-second limit does not apply; only the 30-second limit of Claude Code does.

## Components

| Path | Content |
|---|---|
| `src/evaluate.ts` | Decision logic for paths, commands and dependencies |
| `src/shell.ts` | Shell tokenizer (quotes, substitutions, here-documents); fails closed |
| `src/writes.ts` | Write targets of Bash commands, checked against protected paths |
| `src/policy.ts`, `src/enterprise.ts`, `src/matchers.ts` | Policy schema (Zod), enterprise mode, merge of policy layers, safe rule matchers |
| `src/hook.ts`, `src/hookCli.ts` | Hook (PreToolUse and session events); `hookCli.ts` is the executable entry point |
| `src/taint.ts`, `src/taintPolicy.ts`, `src/taintHook.ts`, `src/taintCli.ts` | Session taint: classification, state with HMAC, hook integration, `tollgate-taint` |
| `src/events/` | Decision log: event assembly, redaction, writer, reader, `tollgate-events verify` |
| `src/vendor/hashchain.ts` | Copy of the shared hash-chain module (canonical JSON, SHA-256) |
| `src/vendor/mcpStdio.ts` | Copy of the shared MCP stdio server (JSON-RPC 2.0, one message per line) |
| `src/mcp/` | MCP server (stdio): tool registration and entry point |
| `policy/default.json` | Default policy |
| `.claude-plugin/plugin.json`, `hooks/hooks.json`, `.mcp.json` | Plugin manifest, hook configuration, MCP configuration |

## Development

```bash
npm ci --ignore-scripts
npm run check   # typecheck, lint, tests with coverage, build, smoke test
```

Node.js 22.12.0 or later is required (`engines`). Runtime dependency: `zod` only, pinned to an exact version.

**Dependencies and security:** the MCP server is a small built-in implementation (`src/vendor/mcpStdio.ts`): JSON-RPC 2.0 over stdin/stdout, one message per line, protocol versions as in the official SDK 1.32.0 (latest `2025-11-25`). It opens no network connection, rejects lines over 1 MiB (the session ends with exit code 1) and the key `__proto__`, and writes diagnostics to stderr only. The official `@modelcontextprotocol/sdk` is a development dependency only: `scripts/sdkCompat.mjs` (part of `npm run smoke`) connects its `Client` with `StdioClientTransport` to the built server and calls every tool. The SDK and its HTTP stack are not installed with the package.

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE) (SPDX: `PolyForm-Noncommercial-1.0.0`), see also [NOTICE](NOTICE). Noncommercial use only; commercial use requires prior written permission. Details: [LEGAL.md](https://github.com/TollWire/tollwire/blob/main/LEGAL.md).
