---
name: security-gate
description: Pre-PR security gate. Scans the pending diff for secrets, dangerous code patterns and vulnerable dependencies, then does a focused diff review; returns PASS or BLOCK. Use before opening or merging a PR, or when asked "run the security gate" / "is this safe to push".
---

# SSDLC Security Gate

A fast, mechanical gate. Not a substitute for `/ssdlc:security-review` on risky changes.

## Steps
1. **Collect the diff**: changed files = `git diff --name-only --diff-filter=ACMR $(git merge-base HEAD origin/HEAD 2>/dev/null || echo HEAD~1)` plus staged and untracked files (`git ls-files --others --exclude-standard`).
2. **Pattern scan**:
   `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/gate_scan.py --json <changed files>`
   Exit 1 = findings. Each finding has `rule`, `severity`, `file`, `line`.
3. **Dependency audit** (only for manifests that changed; skip a tool that is not installed and say so):
   - Python: `pip-audit -r requirements.txt` (or `pip-audit` in the project env)
   - Node: `npm audit --omit=dev --audit-level=high`
   - Any: `osv-scanner --lockfile=<lockfile>`
4. **Diff review**: read the diff hunks for the 10 areas of `/ssdlc:security-review`, concentrating on new entry points, authz changes and new sinks.
5. **Verdict**
   - `BLOCK` — any secret, any High/Critical pattern that is real on inspection, any High/Critical CVE in a changed dependency.
   - `WARN` — Medium items; list them.
   - `PASS` — nothing left after verifying.
   Report false positives you dismissed and why, so the user can check.

Never print a secret's full value in the report: show the first 4 characters and the location.
