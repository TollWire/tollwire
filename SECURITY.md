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

## Deutsch (Kurzfassung)

Bitte melden Sie Sicherheitslücken nicht als öffentliches Issue, sondern vertraulich über GitHub Private Vulnerability Reporting (Reiter **Security**, dann **Report a vulnerability**). Unterstützt wird nur die jeweils neueste veröffentlichte Version jedes Pakets. Neue Umgehungswege melden Sie bitte auch dann, wenn sie einer dokumentierten Grenze ähneln.
