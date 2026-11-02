# Decision log: event schema `tollgate.event.v1`

Specification of the local decision log of the guardrail plugin. One JSON object per line (JSON Lines),
UTF-8, `\n` terminated. The schema is versioned through the field `schema`; readers must reject other values.

Scope of this version: the stand-alone (single user) log and the enterprise-mode writers (layouts P and S). Event types of
the relay, sender, heartbeat and monitor are reserved names only and are not produced by this package.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | always `tollgate.event.v1` |
| `event_id` | string | UUID v4 |
| `ts` | string | RFC 3339 UTC with milliseconds (`2026-10-11T08:15:02.113Z`) |
| `chain_id` | string | UUID of the hash chain |
| `seq` | integer | 1, 2, 3 ... per `chain_id`, no gaps, continues across files |
| `type` | string | see "Event types" |
| `host.name`, `host.os` | string | host name; `linux`, `macos`, `windows` or the raw platform name |
| `user.name`, `user.id` | string | operating-system user (`getpwuid`); `id` is the numeric uid (`"-1"` on Windows) |
| `claude.session_id` | string | `^[A-Za-z0-9_.:-]{1,128}$`, else `"<invalid>"` |
| `claude.tool_use_id` | string or null | same rule |
| `claude.agent_id`, `claude.agent_type` | string or null | at most 128 characters, else `"<invalid>"` |
| `claude.hook_event` | string | `PreToolUse`, `SessionStart`, ... (`^[A-Za-z]{1,64}$`) |
| `claude.permission_mode` | string or null | `^[A-Za-z0-9_-]{1,32}$` |
| `claude.project_dir` | string | only if configured (`logging.projectDir`), at most 4096 bytes |
| `claude.invalid_fields` | string[] | names of stdin fields that failed validation |
| `tool.name` | string | `^[A-Za-z0-9_.:-]{1,256}$`, else `"<invalid>"` |
| `tool.command` | string | only with `commandDetail = redacted`, see "Command text" |
| `tool.command_sha256` | string | SHA-256 (hex) of the raw command; only with `commandDetail = hash` or `commandHash: true` |
| `tool.programs` | string[] | program names of the simple commands of a Bash call, also without command text |
| `tool.paths` | string[] | affected paths (write targets, file arguments), at most 4096 bytes each |
| `tool.paths_omitted` | integer | number of paths dropped by truncation |
| `tool.effects` | string[] | subset of `write`, `network`, `package`, `exec`, `unknown`, fixed order |
| `tool.domain` | string | host name of a `WebFetch` URL (observed tools only) |
| `tool.truncated` | boolean | `true` after any truncation |
| `redactions` | integer | number of `[REDACTED:...]` replacements in the event |
| `decision.outcome` | string | `allow`, `deny`, `observe` (`ask` is reserved) |
| `decision.rule_kind` | string | see "rule_kind" |
| `decision.rule_id` | string or null | id of the matching rule or the matched protected path |
| `decision.reason` | string or null | reason text (null if allowed) |
| `decision.human_session` | boolean | `TOLLGATE_HUMAN_SESSION=1` was effective |
| `policy.revision` | string or null | `revision` of the enterprise policy |
| `policy.sha256` | string or null | SHA-256 over the hashes of all layers |
| `policy.layers` | object[] | `{level, sha256}`, level one of `default`, `enterprise`, `project`, `explicit`; with admin locks a last entry `{level: "locks", sha256, generation}`: SHA-256 of the lock file as read and its `generation` (no `generation` if the file was unreadable as JSON). The lock layer is not part of `policy.sha256`, so a new lock does not look like a policy change |
| `policy.enterprise_mode` | boolean | enterprise mode was active |
| `source.component`, `source.version` | string | `tollgate-guardrail`, package version |
| `data` | object | type-specific fields (below) |
| `prev_hash` | string | `hash` of the previous event, 64 zeros for the first event of a chain |
| `hash` | string | SHA-256 (hex) over the canonical JSON of all other fields |

Never logged: prompts, content fields of Edit/Write, the content of `tool_response` (only kind and size, see `tool_result`), `transcript_path`, environment variables. The Bash
command text is logged only redacted and truncated (`commandDetail = redacted`), as a hash (`hash`) or not at all (`none`).

## Event types

| Type | Written when | `data` |
|---|---|---|
| `decision` | once per evaluated tool call (`allow` or `deny`); `observe` for tools that are only observed | none |
| `session_start` | hook event `SessionStart` | `source`, `plugin_version`, `plugin_files_sha256`, `managed_settings_sha256`, `config_sha256`, `human_session` |
| `session_end` | hook event `SessionEnd` | `reason`, `human_session` |
| `subagent_start`, `subagent_stop` | hook events `SubagentStart`, `SubagentStop` | `human_session` |
| `chain_start` | first event of a new chain | `reason`: `new`, `retention`, `missing_previous`, `corruption`; for `corruption` also `broken_file`, `broken_chain_id`, `broken_seq` |
| `chain_continue` | first event in a new file of an existing chain (new UTC day, size rotation, alternate file) | `file` |
| `log_error` | after a corruption or a failed safety check; in enterprise mode also at the fallback location if the event directory is unusable | `reason`, `file` (fallback: `reason`, `code`) |
| `suppressed` | summary of left-out read-only events | `count`, `window_start`, `top_paths` (at most 10 objects `{path, count}`) |
| `policy_error` | invalid lower-layer rule (for example a regular expression in enterprise mode) | `findings`: `{level, id, detail}` |
| `policy_override_ignored` | a lower layer tried to loosen the policy | `findings`: `{level, id, detail}` |
| `logging_disabled`, `logging_enabled` | the user turned the stand-alone log off or on | `config_sha256` |
| `tool_result` | hook event `PostToolUse` (needs the `PostToolUse` entry in `hooks/hooks.json`); with `tools = checked` (stand-alone default) only for the checked tools | `response_kind` (`none`, `string`, `array`, `object`, `other`), `response_bytes` (UTF-8 size of the response, or null), `is_error` (the flag `is_error` or `isError` of the response if it has one, else null), `human_session`. `tool` holds `name`, `paths` and `effects` as for decisions, never a command text. The response itself is never logged. Read-only calls are subject to the flood limit like decisions. Never blocks. The event is bound to the hook entry by `--event PostToolUse` in the manifest command; see "Hook events" below |
| `taint_set` | session taint: the session became tainted (a source was allowed or finished, or the taint state was missing or invalid) | `source_kind` (`tool`, `bash_network`, `bash_wrapper` (a wrapper, `sh -c`, dynamic program or git command line whose command is not analyzed), `read_outside_project`, `state_missing`, `state_invalid`, `inherited`), `source_name` (tool or program name, or the state problem), `previous` (`clean`, `state_missing`, `state_invalid`, `key_missing`), `epoch`, `taint_seq`, `invalid_sha256` (SHA-256 of a manipulated state file, else absent or null), `mode`, `human_session`. Never a URL, path, argument or content |
| `taint_release` | a human lifted the taint | `via` (`user`: `tollgate-taint release` in a terminal; `admin`: root-owned release file consumed by the hook), `release_id`, `epoch`, `taint_seq`, `by_uid` (admin only: `SUDO_UID` of the administrator), `mode`, `human_session` |
| `taint_would_block` | mode `observe`: a call that `enforce` would have blocked | `rule_id`, `category` (`network`, `git_push`, `secrets`, `release_cli`, `nested_agent`), `tool`, `mode`, `human_session` |

All `taint_*` data fields are flat scalars (no arrays of objects), so that SIEM decoders that cannot read arrays of objects (Wazuh) match them directly. The block itself is a `decision` event with `rule_kind` `taint`.

### `admin_action` (admin locks; written by `tollgate-control`, not by the hook)

Own chain and own files `control/control-<YYYYMMDD>.jsonl` (directory `root:tollgate-spool 2750`, files `0640`); `source.component` is
`tollgate-control`, `user` is the root account. One event per lock, unlock, expiry, refusal or failure:

| Field | Meaning |
|---|---|
| `data.action.op` | `lock`, `unlock`, `expire`, `reject`, `failed` |
| `data.action.attempted` | the operation that was asked for (`lock`, `unlock`, `list`), also for `reject` and `failed`; null if the request could not be read |
| `data.action.kind`, `data.action.target` | `user` (`{uid}`), `session` (`{session_id}`), `tool` (`{tool}`), `global` (`{}`); an invalid target is not echoed (null) |
| `data.action.lock_id`, `data.action.expires` | id and expiry of the lock concerned |
| `data.action.reason` | the administrator's reason after the sanitizer, at most 500 characters |
| `data.action.request_id` | UUID from the monitor or the CLI (correlation with `monitor_access`) |
| `data.action.existing` | `true` if an equal active lock already existed that lasts at least as long (nothing was changed) |
| `data.action.extended` | `true` if an equal lock existed but the request lasts longer (unlimited beats any date): the lock keeps its id and gets the longer expiry, as a new generation |
| `data.actor.peer_uid`, `data.actor.peer_pid` | the kernel's peer (from the systemd instance name; 0 for the CLI) |
| `data.actor.claimed_uid`, `data.actor.claimed_name` | `SUDO_UID`/`SUDO_USER` of the administrator; for `via = monitor` this is the monitor's statement |
| `data.actor.via` | `monitor` or `cli` |
| `data.locks.generation_before/after`, `sha256_before/after` | chain of the lock file (`prev_sha256` of the next generation is `sha256_before`) |
| `data.result` | `applied`, `rejected`, `failed` |
| `data.reject_reason` | `forbidden`, `bad_request`, `locks_invalid`, `invalid_target`, `invalid_expiry`, `limit`, `not_found`, `replay`, or null |

A `failed` event follows an `applied` one if the lock file could not be written after the audit entry; the `sha256_after` of the
first then does not match the file (SIEM rule 19).

Reserved, not produced here: `heartbeat`, `forward_rejected`, `forward_status`, `relay_record`,
`relay_finding`, `file_anchor`, `relay_heartbeat`, `host_heartbeat`, `layout_violation`, `provision_missing`, `monitor_access`. `admin_action` is produced by `tollgate-control` (see above).

## Canonical JSON and hash

`hash = SHA-256(canonicalJson(event without "hash"))`, implemented in `src/vendor/hashchain.ts`. Keys sorted by UTF-16 code unit, `undefined` members omitted, no whitespace, scalars as
`JSON.stringify`. Only strings, safe integers, booleans, `null`, arrays and objects occur; in this range the output equals
RFC 8785. The line itself may use any key order; readers recompute the hash from the parsed object.

Test vectors (the hashes were computed independently with Python `hashlib`; the same pair is a unit test):

```json
{"schema":"tollgate.event.v1","event_id":"00000000-0000-4000-8000-000000000001","ts":"2026-10-11T08:15:02.113Z","chain_id":"00000000-0000-4000-8000-0000000000c1","seq":1,"type":"chain_start","host":{"name":"host-1","os":"linux"},"user":{"name":"alice","id":"1000"},"source":{"component":"tollgate-guardrail","version":"0.1.0"},"data":{"reason":"new"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"96584c854e9ebca3a68e1b7a1f559f3f9520b6e5f75df945d559428efbb2aeed"}
{"schema":"tollgate.event.v1","event_id":"00000000-0000-4000-8000-000000000002","ts":"2026-10-11T08:15:03.001Z","chain_id":"00000000-0000-4000-8000-0000000000c1","seq":2,"type":"decision","host":{"name":"host-1","os":"linux"},"user":{"name":"alice","id":"1000"},"claude":{"session_id":"s-1","tool_use_id":"tu-1","agent_id":null,"agent_type":null,"hook_event":"PreToolUse","permission_mode":"default"},"tool":{"name":"Bash","programs":["git"],"paths":[],"effects":["network"],"truncated":false},"redactions":0,"decision":{"outcome":"deny","rule_kind":"blocked_command","rule_id":"blockedCommands[0]","reason":"Force push is not allowed.","human_session":false},"policy":{"revision":null,"sha256":"1111111111111111111111111111111111111111111111111111111111111111","layers":[{"level":"default","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}],"enterprise_mode":false},"source":{"component":"tollgate-guardrail","version":"0.1.0"},"prev_hash":"96584c854e9ebca3a68e1b7a1f559f3f9520b6e5f75df945d559428efbb2aeed","hash":"cb7aa5ebc319e8f674dd9fcfe0a782b3f59bde4b0a2ac606221d0a9f2d412f82"}
```

## Size and truncation

A serialized event is at most 8192 bytes (UTF-8, without the newline). An event is never dropped. Order of truncation:

1. `tool.paths` to 8 entries (`tool.paths_omitted` counts the rest);
2. `tool.command` to 512 characters;
3. `decision.reason` to 128 characters;
4. `claude.project_dir` is left out;
5. only mandatory fields remain (base fields, `claude.session_id`, `tool.name`, `decision.outcome`, `decision.rule_kind`).

`tool.truncated` is `true` after any truncation, including the 2048-character limit of the command text. Cuts are made on
whole characters of the sanitized text (never inside a `\u{XXXX}` escape or between the two characters of `\\`).
`tool.programs` has at most 16 entries of at most 64 characters; `tool.paths` at most 64 entries before step 1.

## Command text

Processing order (`tool.command`), implemented in `src/events/`:

1. The raw text is cut to 16 KiB.
2. It is split into unquoted words with the shell tokenizer (`shell.ts`, decodes `$'...'`). If this fails, no command text
   is logged (tool, effects and the optional hash remain).
3. Redaction on the unquoted words. For comparing names, format characters (Cf) are removed and NFKC is applied. The
   replacement keeps the position of the word. Commands are written in a normalized form: simple commands, words
   separated by one space, commands separated by ` ; `; comments and here-document bodies are not part of the text.
4. The sanitizer runs over the result and over all other string fields.
5. The text is cut to 2048 characters.
6. The event is chained.

Redaction replaces by `[REDACTED:<kind>]` (`secret`, `credential`, `header`, `userinfo`, `password`, `heredoc`):

1. prefix-anchored secret formats (private key headers, GitHub, AWS, Slack, Stripe, Google, JWT, npm, GitLab tokens);
2. name-value pairs `NAME=value`, `--name value`, `--name=value`: the name is split at `_`, `-`, `.` and camel case;
   a hit is an exact part `token`, `secret`, `password`, `passwd`, `pwd`, `pass`, `passphrase`, `apikey`, `auth`,
   `authorization`, `credential`, `credentials`, `cookie`, or a last part `key`, or the name `PGPASSWORD`;
3. headers in `curl -H/--header` (also joined `-HAuthorization:`), `wget --header=`, `http`: `Authorization`,
   `Proxy-Authorization`, `Cookie`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `X-Amz-Security-Token`, `X-Goog-Api-Key`,
   `Private-Token`, `X-Vault-Token`;
4. user info in URLs (`scheme://user:pass@host`), `curl -u/--user`;
5. password options of known programs: `mysql -p<pw>`, `sshpass -p`, `aws configure set ...secret...`, `docker login -p`,
   `htpasswd -b`, `openssl ... pass:<pw>`.

Redaction is a heuristic. Counter-examples without a hit: `--author`, `GIT_AUTHOR_NAME`, `--bypass`, `compass`,
`passthrough`, `keyboard`, `--tokenizer`.

Examples (input, logged text):

| Input | Logged |
|---|---|
| `curl --pass''word=hunter2 https://x` | `curl --password=[REDACTED:credential] https://x` |
| `curl --$'pass'word=hunter2 https://x` | `curl --password=[REDACTED:credential] https://x` |
| `curl -HAuthorization:Bearer\ abc https://x` | `curl -HAuthorization:[REDACTED:header] https://x` |
| `export MY_API_KEY=abc` | `export MY_API_KEY=[REDACTED:credential]` |
| `git clone https://u:p@h/r.git` | `git clone https://[REDACTED:userinfo]@h/r.git` |

## Sanitizer

Applied once, to every string value of the event, after redaction:

1. every backslash becomes `\\` (this keeps the mapping injective);
2. C0 controls, DEL, C1 controls, U+2028, U+2029, bidirectional controls, all other format characters (Cf) and lone
   surrogates become `\u{XXXX}` (at least 4 upper-case hex digits).

Vector: `a\b` + U+001B + U+202E becomes `a\\b\u{001B}\u{202E}`.

## `tool.programs` and `tool.effects`

`tool.programs`: the command word of every simple command, after variable assignments (`NAME=...`) and wrappers (`sudo`,
`doas`, `env`, `nohup`, `nice`, `timeout`, `stdbuf`, `command`, `exec`, `time`, `setsid`, `ionice`, `unbuffer`, `chronic`)
including their options; never an assignment; paths reduced to the file name (`/opt/x/bin/tool` becomes `tool`, the full
path is only in `tool.paths` if it is a write target); a command name that expands at run time becomes `<dynamic>`.

`tool.effects` for Bash is derived from the programs and redirections: `write` (redirections, `rm`, `mv`, `cp`, `tee`, ...),
`network` (`curl`, `wget`, `ssh`, `git push|pull|fetch|clone`, ...), `package` (`npm`, `pip`, `apt`, ...), `exec`
(shells, interpreters, `xargs`, `eval`), `unknown` (any program not in a list; unparsable commands). Read-only allowlist
programs (below) have no effect. Edit, Write, MultiEdit and NotebookEdit have the effect `write`.

## Flood limit

Only read-only calls are subject to the limit: `observe` for `Read`, `Glob`, `Grep`, `LS`, and `allow` for Bash calls in
which every simple command is on the read-only allowlist and there is no redirection, substitution, expansion or opaque
part. Allowlist: `ls`, `pwd`, `wc`, `stat`, `head`, `cat` (all options); `tail` without `-f`, `-F`, `--follow`, `--retry`,
`--pid`; `grep`; `rg` without `--pre`, `--pre-glob`, `--hostname-bin`, `-z`, `--search-zip` (and not with
`RIPGREP_CONFIG_PATH` set); `find` without `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint*`, `-fls`. Long options
are matched as GNU abbreviations (`--fol` counts as `--follow`). Program names with a path (`./ls`) are `unknown`. Calls with
paths outside the project or sensitive paths (`~/.ssh`, `~/.aws`, `~/.config`, `.env`, `/proc/*/environ`, `/etc/shadow`, ...)
are never summarized. `git` is not on the list. `deny` events are never summarized.

After 600 such events per session and minute the following ones are not written but counted; the next event writes one
`suppressed` event (count, window start, ten most frequent paths).

## Settings

Stand-alone: on by default, no command text. The only switch is the user file `$XDG_CONFIG_HOME/tollgate/config.json`
(`logging.enabled`, `logging.commandDetail` = `none` or `redacted`, `logging.projectDir`; `%APPDATA%\tollgate\config.json` on
Windows). It is read at `SessionStart` and frozen for that session in `session-<session_id>.json` (mode `0600`, removed at
`SessionEnd`); without a `SessionStart` the current file counts. An invalid or unreadable file leaves the log on. Switching
off writes one `logging_disabled` event (hash of the file) and then nothing; switching on again writes `logging_enabled`.
Neither the project policy, `TOLLGATE_POLICY` nor any environment variable changes these settings, and the user file has no
effect in enterprise mode.

Enterprise mode: the settings come from `logging` in the administrator's policy (`enabled`, `layout` = `per_user` or
`shared`, `tools` = `all` or `checked`, `commandDetail` = `none`, `hash` or `redacted`, `commandHash`, `projectDir`,
`onWriteError` = `block` or `warn`, `rateLimit`); defaults: on, `per_user`, `all`, `redacted`, no hash, project directory
logged, `block`, 600. Paths are fixed: `/var/log/tollgate/events/<uid>/` (P) or `/var/log/tollgate/events/` with lock and
state in `~/.local/state/tollgate/` (S).

## Chain, files, rotation, corruption

- One chain per (host, user). File names: `u<uid>-<YYYYMMDD>[-<n>].jsonl` (UTC day), regular files, mode `0600` (stand-alone)
  or `0640` (enterprise).
- Rotation per UTC day or at 64 MiB: the first event of the new file is `chain_continue` (same `chain_id`, `seq` goes on,
  `prev_hash` is the last hash). The first event ever is `chain_start` with `reason: new`; if the previous file was removed
  by retention, `retention`; if it is gone otherwise, `missing_previous`.
- Appending happens under a lock, on a checked descriptor (`O_APPEND|O_NOFOLLOW|O_NONBLOCK`, `fstat`: regular file, one
  link, own uid, expected mode). Only the end of the file (at most 16 KiB) is read and its last line verified.
- Corruption (last line incomplete, invalid, wrong hash): logging goes on in a new file with `chain_start` (`reason:
  corruption`, `broken_file`, `broken_chain_id`, `broken_seq`), a new `chain_id`, `seq = 1` and `prev_hash` = hash of the
  last valid event of the broken chain, followed by `log_error`.
- An unusable file name (symlink, FIFO, foreign owner, hard link, wrong mode) leads to an alternate file `...-<n>.jsonl`
  (at most 8) with `chain_continue`; no `chain_start`.

## `rule_kind`

| Value | Origin |
|---|---|
| `none` | allowed (and observed) |
| `path_unresolvable`, `outside_project`, `protected_path`, `active_policy`, `hardlink_alias` | path checks of write tools |
| `parse_error`, `blocked_command` | command checks (`rule_id` is the rule `id`, or `blockedCommands[<index>]` for version 1 policies) |
| `write_target` | Bash write targets (`writes.ts`) |
| `dependency_unverifiable`, `dependency` | dependency checks |
| `invalid_input` | invalid hook input or invalid `CLAUDE_PROJECT_DIR` |
| `size_limit` | command longer than 32768 bytes |
| `policy_error` | policy cannot be loaded, enterprise policy unsafe |
| `internal_error` | unexpected error in the hook |
| `log_write_error` | event could not be written and `onWriteError` is `block` |
| `enterprise_unsupported_platform` | enterprise signal on macOS |
| `unchecked_tool` | a tool that is neither checked nor on the enterprise tool allowlist (`tools.unchecked = deny`); `rule_id` is `tools.unchecked` |
| `admin_lock` | an administrator lock applies: user, session, tool or emergency stop; `rule_id` is the id of the lock. Applies to every tool, checked or not; `TOLLGATE_HUMAN_SESSION` does not lift it. The reason of the administrator is never in the event |
| `taint` | session taint, mode `enforce`: the session read untrusted content and the call is network egress, `git push`, access to secrets or credential files, or the release command (`rule_id` `taint.network`, `taint.git_push`, `taint.secrets`, `taint.release_cli`, `taint.nested_agent`); or the taint state could not be evaluated or recorded (`taint.state`, fail closed). Applies only to calls that the policy and the tool allowlist allow; a policy deny keeps its own kind |
| `lock_error` | `control.enabled` is set and the lock file is missing, unsafe (link, owner other than root, group/world write, hard link, over 64 KiB) or invalid: every tool call is denied (fail closed). `rule_id` is null |

## Verification

`tollgate-events verify [--strict] [--json] [path...]` reads files with the hardened reader (symlink, FIFO, device, more than one
hard link refused; size limit 65 MiB; chunked reading; lines over 8 KiB and invalid UTF-8 reported) and checks schema,
`seq` continuity, `prev_hash` links, hashes and chain markers across the files of a directory. A directory is grouped by
chain source: user files `u<uid>-<YYYYMMDD>[-<n>].jsonl` per uid and service files `<prefix>-<YYYYMMDD>[-<n>].jsonl` per
prefix (`control`, `monitor`, `relay`, `host`, `send`, `sendcfg`), each oldest first; no chain is linked across groups. Files
given directly are verified as one stream in the given order; trailing separators are removed first, so `link/` is a link.
The directory is listed once; a listing error is the finding `unreadable`. Path findings and when they fail:

| Finding | Meaning | Given path | Default log | `--strict` |
|---|---|---|---|---|
| `no_event_files` | directory without event files | fail | warning | fail |
| `no_events` | a chain source whose files hold no event (e.g. 0 bytes) | fail | warning | fail |
| `unknown_file` | `*.jsonl` that matches no known name, not verified (this includes the Windows event files `s<SID>-*.jsonl`) | warning | warning | fail |
| `directory_limit` | more than 1000 entries, the rest was not scanned | warning | warning | fail |

A given path that verified no file at all fails in any case. A missing default directory fails (`unreadable`): the writer
creates it with its first event. Warnings are printed as `WARN:` lines and in `--json` as `warnings`. Exit code 0: valid;
1: findings; 2: usage error.

The chain is not authenticated (no key, no external anchor). It detects changed, missing or reordered events inside a
chain, but whoever can write the files can replace them with a newly computed chain from the genesis hash or cut off the
end of a chain, and verification stays green. It does not protect against writers of the log directory.

## Hook events and spoofing

The manifest binds each entry to its event with `--event <name>` in the command (`PreToolUse`, `SessionStart`, `SessionEnd`,
`SubagentStart`, `SubagentStop`, `PostToolUse`). The name on stdin (`hook_event_name`) alone never selects the non-blocking
handling of a session, subagent or result event:

- declared event equals the event on stdin: handled as that event (the argument is part of the manifest command and cannot be forged by the caller);
- declared event differs from stdin: evaluated as a tool call (a checked tool is checked and can be blocked); the event is logged with the declared name in `claude.hook_event` and `hook_event_name_mismatch` in `claude.invalid_fields`; a call without tool name is rejected as invalid input;
- nothing declared (manifest from before `--event`): a call that names a checked tool (Bash, Edit, Write, MultiEdit, NotebookEdit) is evaluated whatever the stdin name says; other calls keep the previous handling by stdin name (they cannot block anyway).
