---
name: security-gate
description: Pre-PR security gate. Scans the pending diff for secrets, dangerous code patterns, AI/agent misconfiguration (OWASP LLM Top 10 2026, Agentic Top 10 2026) and vulnerable dependencies without executing project code, then does a focused diff review; returns PASS, WARN, BLOCK or INCOMPLETE. Use before opening or merging a PR, or when asked "run the security gate" / "is this safe to push".
---

# SSDLC Security Gate

A fast, mechanical gate. Not a substitute for `/ssdlc:security-review` or `/ssdlc:ai-security-review` on risky changes.

**Never execute the project's code to gate it** (OWASP ASI05). Every command below only reads files.
Run git with executable repository settings disabled, since `.git/config` belongs to the reviewed repo:
`GIT="git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c diff.external= -c core.pager=cat"`.

## Steps
1. **Collect the diff**: `$GIT diff --name-only --diff-filter=ACMR $($GIT merge-base HEAD origin/HEAD 2>/dev/null || echo HEAD~1)`, plus staged files and `$GIT ls-files --others --exclude-standard`.
2. **Pattern scan**:
   `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/gate_scan.py --json [--strict] <changed files>`
   - Use `--strict` unless the repository and every marker author are trusted: `ssdlc: allow <reason>` markers live in the reviewed code.
   - Output: `findings` (each with `rule`, `severity`, `file`, `line`, `refs`), `suppressed` (marker + reason), `skipped` (unscanned files). List suppressed and skipped entries in the report.
3. **Dependency audit** — only for manifests or lockfiles that changed, using tools that **parse** rather than install:
   - Any ecosystem: `osv-scanner scan source -L <lockfile>` (v2; v1: `osv-scanner --lockfile=<lockfile>`) — preferred: parses the lockfile, no resolution, no build.
   - Node: `npm audit --package-lock-only --omit=dev --audit-level=high` (reads the lockfile; never `npm install`).
   - Python: `pip-audit --disable-pip --no-deps -r requirements.txt` **only** for a fully pinned file; never plain `pip-audit -r`, which may build source distributions and run their code.
   - Record each tool's version (`--version`) in the report. A tool that is missing is a gap, not a pass.
4. **Diff review**: read the diff hunks for the 10 areas of `/ssdlc:security-review`, concentrating on new entry points, authz changes and new sinks. If the diff touches prompts, model calls, tools, MCP config, agent settings, RAG or memory, also apply `${CLAUDE_PLUGIN_ROOT}/references/ai-risk-checklist.md` and tag findings `LLMnn:2026` / `ASInn`.
5. **Verdict**
   - `BLOCK` — any secret; any High/Critical finding that is real on inspection; any High/Critical CVE in a changed dependency; `ai.agent-approval-bypass` or `ai.agent-wildcard-allowlist` in committed config.
   - `WARN` — Medium items; list them.
   - `INCOMPLETE` — a changed manifest could not be audited, files were skipped, or the scan could not run. Never report `PASS` in this state.
   - `PASS` — nothing left after verifying, and nothing skipped.
   Every High/Critical finding you dismiss as a false positive must appear in a **Dismissed** table with the reason and the evidence you read, so the user can overrule it. The gate is not allowed to turn a High into PASS silently (OWASP ASI09).

Never print a secret's full value in the report: show the first 4 characters and the location.
