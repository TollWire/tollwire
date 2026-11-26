# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Report it privately through GitHub private vulnerability reporting for this repository (**Security** tab, then **Report a vulnerability**).

Helpful information:

- affected package and version;
- steps to reproduce;
- expected and actual behavior;
- your assessment of the impact.

## Supported versions

Only the latest published version of each package (`guardrail-plugin`, `evidence-mcp`) receives security fixes. Before version 1.0, fixes are not backported to older releases.

## Process

We confirm receipt, assess the report, and agree with you on the fix and the disclosure through the private report. A fix is released as a new version with a note in the changelog or release notes. On request, we credit you as the reporter.

## Scope

Known and documented limits are described in the package READMEs. Examples: "defense in depth, not a sandbox", shell command indirection, and rewriting the evidence log without an external anchor. Please still report new ways to bypass a check, even if they resemble a documented limit.

## Security model, boundaries and required deployment

TollWire is a **deterministic, pre-execution policy layer** plus a **tamper-evident audit layer** for AI coding agents. It is **defense-in-depth, not a sandbox** — it complements OS-level isolation, it does not replace it.

### What TollWire enforces (deterministically, before execution)

- Writes to protected paths, and writes outside the project directory — including symlink and shell-wrapper resolution and runtime-unknown targets.
- Privilege escalation (`sudo`/`doas`/`pkexec`) and other blocked commands.
- Reads of credential stores (`~/.ssh`, `~/.aws`, `~/.kube`, `.npmrc`, …).
- Non-allowlisted package installs (npm/pip/uv/npx).
- Every decision is written to a hash-chained, redacted evidence log.

### Known limitation — indirect execution

TollWire inspects the **tool call** (the command, the file write), not the **runtime behaviour** of a process it launches. An agent that writes a script and then runs it through an interpreter (`python`/`node`/`bash`, `make`, a compiled binary) executes code TollWire cannot see. We **deliberately do not** scan arbitrary code for intent: that would be probabilistic and trivially bypassable (base64, dynamic import, download-then-run) — the same weakness as LLM-based filters — and would trade away TollWire's core property, determinism. This limit is inherent to **every** pre-execution policy hook, not specific to TollWire.

*Partial mitigation:* **session taint** — when the agent uses its own tools to read secrets or perform risky actions, the session is marked tainted and subsequent risky tool calls are blocked. Taint does **not** cover reads or actions performed inside a subprocess.

### Required deployment for containment

To actually contain arbitrary code — including the indirect-execution path — run the agent inside OS-level isolation, with TollWire as the policy/evidence layer **inside** that boundary:

- **Filesystem confinement** (container / bubblewrap / mount namespace): do not mount `~/.ssh`, `~/.aws` or other secret stores; limit the writable scope to the project.
- **Network egress control** (no-network namespace or an allowlist proxy): blocks exfiltration regardless of what the code does.
- **seccomp / LSM** (AppArmor, SELinux): restrict syscalls (raw sockets, `execve`).
- **Least-privilege secrets**: the agent runs without long-lived credentials in its environment; secrets are injected only into the specific processes that need them.
- An **ephemeral** environment where possible.

Without this boundary, a subprocess can read any file the user can read and reach any host the network allows — TollWire cannot prevent that, by design.

### Reads vs. writes

Protected paths are protected against **writes** (changes require human review); reading project files is not blocked. Credential stores have a separate read rule. Read-prevention for other specific files requires a dedicated rule and/or filesystem confinement.

## Deutsch (Kurzfassung)

Bitte melden Sie Sicherheitslücken nicht als öffentliches Issue, sondern vertraulich über GitHub Private Vulnerability Reporting (Reiter **Security**, dann **Report a vulnerability**). Unterstützt wird nur die jeweils neueste veröffentlichte Version jedes Pakets. Neue Umgehungswege melden Sie bitte auch dann, wenn sie einer dokumentierten Grenze ähneln. TollWire ist eine deterministische Policy- und Audit-Schicht (Defense-in-Depth), **kein Sandbox-Ersatz**: Indirekt ausgeführter Code (z. B. ein vom Agenten geschriebenes und dann ausgeführtes Skript) wird erst durch OS-Containment (Dateisystem-Confinement, Egress-Kontrolle, seccomp) eingehegt – siehe Abschnitt „Security model, boundaries and required deployment".
