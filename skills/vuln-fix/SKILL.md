---
name: vuln-fix
description: Vulnerability remediation workflow — triage, reproduce, fix the root cause, add a regression test, and hunt for variants. Use when given a CVE, scanner finding, pentest result, bug-bounty report, or a security-review finding to fix.
---

# SSDLC Vulnerability Fix

## 1. Triage
- Restate the issue: component, CWE, attacker preconditions, impact. For AI/agent issues add the OWASP 2026 id (`LLMnn:2026`, `ASInn`) and fix with a control that **bounds** blast radius (least privilege, sandbox, egress deny, approval in code) rather than only a filter that reduces success — see `${CLAUDE_PLUGIN_ROOT}/references/ai-risk-checklist.md` §0.
- Score it (CVSS v3.1/v4 vector if possible) and confirm it is reachable in *this* codebase (call path from an entry point). Unreachable → document and downgrade, do not silently close.
- Dependency CVE: check whether the vulnerable function is used; prefer upgrading to the minimum fixed version.

## 2. Reproduce
- **Untrusted code runs only where it cannot hurt** (OWASP ASI05): run a PoC or the test suite of a repository you do not trust inside a disposable sandbox or container without credentials or network, or ask the user first. Never run it in the session that holds their credentials.
- Write a failing test (or a minimal PoC script kept out of production paths) that demonstrates the vulnerability. No reproduction → say so and state what evidence you rely on.

## 3. Fix the root cause
- Fix at the sink or the boundary, not by blocklisting one payload: parameterized queries, argument arrays instead of shells, safe loaders, allowlists, canonicalize-then-check for paths, authz checks on the object.
- Keep the change minimal and behaviour-preserving for legitimate input.

## 4. Verify
- The reproduction test now passes; the full test suite passes.
- Re-run `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/gate_scan.py` on the touched files.

## 5. Variant hunt
- Grep the codebase for the same pattern (same API, same idiom, copy-pasted code). Fix or list each variant.

## 6. Record
Write a short fix note: ID, root cause, fix, test, variants found, residual risk, and whether disclosure/advisory is needed (for Taiwan-regulated entities consider `vulnerability-disclosure-tw` and incident-notification duties).
