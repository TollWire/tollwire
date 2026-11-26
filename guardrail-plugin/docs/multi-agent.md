# Using the TollWire guardrail with other agents (Codex, Copilot)

The deterministic decision engine is agent-agnostic. The Claude Code integration is one adapter around it;
the same engine now has adapters for **OpenAI Codex CLI** and **GitHub Copilot CLI**. Both agents expose a
pre-execution hook (`PreToolUse`) that can deterministically deny a tool call before it runs, so TollWire makes
the *same* allow/deny decision there as in Claude Code.

> **Defense in depth, not a sandbox.** Every one of these hooks is, in each vendor's own words, a guardrail and
> not a complete enforcement boundary. Code run *indirectly* (a script written, then executed by an interpreter)
> is outside what any pre-execution hook sees. Pair the guardrail with OS-level isolation — see `SECURITY.md`.

## Executables

The package ships these binaries alongside `tollgate-guard` (Claude Code):

| Agent                | Binary                    | Entry                    |
| -------------------- | ------------------------- | ------------------------ |
| OpenAI Codex CLI     | `tollgate-guard-codex`    | `dist/codexHookCli.js`   |
| GitHub Copilot CLI   | `tollgate-guard-copilot`  | `dist/copilotHookCli.js` |
| xAI Grok Build (CLI) | `tollgate-guard-grok`     | `dist/grokHookCli.js`    |
| Cursor Agent         | `tollgate-guard-cursor`   | `dist/cursorHookCli.js`  |

Each reads the agent's `PreToolUse` payload on stdin and reuses the full engine (policy, protected paths,
blocked commands, dependency allowlist, credential-read lock, admin locks, session taint) with the same
fail-closed behaviour as the Claude Code hook.

## GitHub Copilot CLI

Register the hook with a **PascalCase `PreToolUse` matcher**. Copilot then delivers Claude-format input
(`tool_name` = `Bash`/`Write`/…, `tool_input` as an object), which is what the adapter needs to check **writes**
(the camelCase `preToolUse` form does not publish file-tool argument field names, so it can only check the shell
reliably — the adapter fails closed on anything it cannot map).

Repository hooks live in `.github/hooks/*.json`; personal hooks in `~/.copilot/hooks/*.json`. Example
(`examples/copilot/github-hooks.json` in this package):

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      { "type": "command", "bash": "node /absolute/path/to/guardrail-plugin/dist/copilotHookCli.js", "timeoutSec": 10 }
    ]
  }
}
```

Deny contract honoured by the adapter (from GitHub's official hooks reference):

- deny → exit code `2` **and** a single stdout JSON object `{"permissionDecision":"deny","permissionDecisionReason":"…"}`;
- allow → exit `0` with `{"permissionDecision":"allow"}`;
- a hook **timeout is fail-open** (the tool proceeds), so keep the hook fast — the engine is synchronous and returns in milliseconds;
- any other non-zero exit is treated by Copilot as a deny ("hook errored"), which keeps the fail-closed posture.

## OpenAI Codex CLI

Codex delivers Claude-compatible `PreToolUse` input. Register the adapter for `PreToolUse`; non-managed hooks
must be **reviewed and trusted** (`/hooks` in the CLI) before they run, and the trust is tied to the hook's hash.

Hook config locations (official docs): user `~/.codex/hooks.json` (or `$CODEX_HOME/hooks.json`), project
`.codex/hooks.json` (trusted project), system `/etc/codex/hooks.json`, or managed via `requirements.toml`
(`allow_managed_hooks_only = true` enforces managed-only). The adapter points at `tollgate-guard-codex`
(`dist/codexHookCli.js`). Example (`examples/codex/hooks.json` in this package):

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "node \"/absolute/path/to/guardrail-plugin/dist/codexHookCli.js\"", "timeout": 10, "statusMessage": "TollWire guardrail" } ] }
    ]
  }
}
```

Omitting `matcher` (or `"*"`/`""`) matches every tool, so Bash, `apply_patch`, reads and MCP calls are all checked;
the adapter passes non-write tools through. Keep the hook **synchronous** (do not set `async: true`): the Codex docs
say only synchronous hooks can make permission decisions.

Deny contract honoured by the adapter:

- deny → the preferred stdout JSON
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}`
  **and** exit code `2` with the reason on stderr (both channels say deny);
- allow → exit `0` with no output.

**apply_patch.** Codex reports `tool_name: "apply_patch"` for file edits. That name is not one of the engine's
checked write tools, so the adapter parses the patch envelope for its `*** Add/Update/Delete File:` and
`*** Move to:` target paths and evaluates **each as a write** — otherwise the write path would fail open. A patch
that touches a protected path or writes outside the project is denied; an unparseable patch fails closed.

> The `hooks.json` structure, the matcher semantics, the stdin fields and the deny contract above are taken
> **verbatim** from the official Codex hooks documentation (learn.chatgpt.com/docs/hooks) and are matched by the
> adapter's unit and smoke tests. What still requires a **live run** on an installed Codex CLI (the repo's
> bug-fix/validation rule) is only the end-to-end behaviour: that a trusted hook actually fires and that a real
> `apply_patch`/`Bash` deny is honoured on that machine.

## xAI Grok Build (Grok CLI)

Grok delivers a camelCase `PreToolUse` envelope (`toolName`, `toolInput`, `cwd`, `sessionId`) with its own runtime
tool names (`run_terminal_command`, `search_replace`, `read_file`, ...). The adapter maps them to Claude tool names
via Grok's documented alias table and checks each call; a write whose file path cannot be resolved is denied (fail
closed). Hook config lives in `~/.grok/hooks/*.json` (always trusted) or `<project>/.grok/hooks/*.json` (needs
`/hooks-trust`); Grok also reads a shared `~/.claude/settings.json`. Example (`examples/grok/hooks.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "run_terminal_command|search_replace|read_file|grep|Bash|Write|Edit|Read|Grep",
        "hooks": [ { "type": "command", "command": "node \"/absolute/path/to/guardrail-plugin/dist/grokHookCli.js\"", "timeout": 10 } ] }
    ]
  }
}
```

Deny contract honoured by the adapter: a `{"decision":"deny","reason":"…"}` object on stdout (honoured regardless of
exit) **and** exit code `2`; allow exits `0` with no output. **Important:** Grok is **fail-open** on crashes, timeouts
and malformed output — only an explicit `deny` blocks — so the adapter emits an explicit deny on any catchable error
and must stay fast; register the hook globally (`~/.grok/hooks/`, always trusted) or trust the project.

## Cursor Agent

Cursor delivers a snake_case `preToolUse` envelope (`tool_name`, `tool_input`, `cwd`) with its own tool names
(`Shell`, `Write`, `Read`, `Grep`, `Delete`, `MCP:<tool>`). The adapter maps them to Claude tool names; a `Delete` is
checked as a write to its target (deleting a protected path is denied). Hook config lives in `.cursor/hooks.json`
(project, trusted workspace) or `~/.cursor/hooks.json`. Example (`examples/cursor/hooks.json`):

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      { "command": "node \"/absolute/path/to/guardrail-plugin/dist/cursorHookCli.js\"", "matcher": "Shell|Write|Read|Grep|Delete", "failClosed": true, "timeout": 10 }
    ]
  }
}
```

Deny contract honoured by the adapter: a single stdout object `{"permission":"deny","agent_message":"…","user_message":"…"}`
**and** exit code `2`; allow emits `{"permission":"allow"}` and exit `0`. **Important:** Cursor is **fail-open** by
default, so the hook **must** be registered with `"failClosed": true` (a crash, timeout or no output then blocks) and
with a `matcher` scoped to the checked tools. The scoping keeps the explicit allow limited to tools the engine
actually evaluated, so the guardrail decides allow/deny for `Shell|Write|Read|Grep|Delete` and never auto-approves a
tool it did not check. (If you prefer Cursor's own permission prompt to remain for allowed calls, drop `failClosed`
and accept that a hook crash then fails open.)

## Gemini CLI — not shipped (deprecated)

No Gemini CLI adapter is shipped. Google's own docs state the Gemini CLI was **replaced by the Antigravity CLI on
2026-06-18**, and its edit/write tool argument field names are not documented, so a write-blocking adapter could not
be built safely. Targeting Antigravity instead is a separate decision (its hook contract needs its own research).

## Validation status

The adapters' decision logic is proven by unit tests (`test/codexAdapter.test.ts`, `test/copilotAdapter.test.ts`,
`test/grokAdapter.test.ts`, `test/cursorAdapter.test.ts`, `test/translate.test.ts`): safe calls allowed; force-push,
protected-path writes (PascalCase, apply_patch, and the runtime-named `search_replace`/`Write`/`Delete` tools) and
out-of-project writes denied; unverifiable writes and malformed input fail closed. The **built binaries** are
additionally exercised end-to-end by the package smoke test (`scripts/smoke.mjs`), which feeds each vendor's exact
`PreToolUse` payload to the real executable and asserts the exit code and the stdout decision JSON.

The one remaining step for each agent is a **live run on the installed CLI** (the repo's bug-fix/validation rule):
install the hook config, trust it where required, and confirm a real deny/allow on that machine. For Grok and Cursor
this also confirms the exact `tool_input` field names of their edit/write tools (the adapter already falls back across
the common field names and fails closed when a write path cannot be resolved). Gemini CLI is intentionally not
covered (see above).
