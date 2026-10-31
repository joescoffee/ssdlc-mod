---
name: security-review
description: Security-standard code review in 10 sections (scope, trust boundaries, STRIDE, authn/authz, dangerous input, secrets, crypto, dependencies, AI/agent risks, logging). Use when asked to "security review", "is this code safe", "review for vulnerabilities", or before merging security-sensitive changes. Delegates reading to the read-only ssdlc:security-reviewer agent.
---

# SSDLC Security Review

Run a structured security review of a diff, a directory, or a whole repo.

## 0. Set the target
- Diff: `git diff --merge-base origin/HEAD` (or the branch/PR given). Whole repo if nothing is pending.
- Run the mechanical scan first, it is cheap and catches the obvious:
  `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/gate_scan.py <paths…>`
- Then spawn the **`ssdlc:security-reviewer`** agent (read-only) with the target and the scan output. Large targets: split by component, one reviewer each, in parallel.

## Checklist (the reviewer walks all 10)

1. **Scope & assets** — what changed, what data/privileges it touches, who calls it.
2. **Trust boundaries** — every point where untrusted data enters: HTTP params/headers/body, files, env, CLI args, IPC, DB rows written by others, LLM output, webhooks.
3. **STRIDE** — for each boundary: spoofing, tampering, repudiation, info disclosure, DoS, elevation of privilege.
4. **Authentication & authorization** — every entry point checks identity *and* object-level permission (IDOR); deny by default; no authz decided client-side; session/token expiry and revocation.
5. **Dangerous input sinks** — SQL/NoSQL/LDAP injection (CWE-89/943), OS command (CWE-78: `shell=True`, `os.system`, backticks), code eval (CWE-95: `eval`, `exec`, `new Function`), deserialization (CWE-502: `pickle`, `yaml.load` without SafeLoader, Java `ObjectInputStream`), path traversal (CWE-22), SSRF (CWE-918), XSS/template injection (CWE-79/1336), XXE, regex DoS.
6. **Secrets** — no keys, tokens, passwords, private keys in code, tests, fixtures, logs or history; secrets from a vault/env; nothing secret in error messages.
7. **Cryptography & transport** — no MD5/SHA1 for security, no ECB, no hand-rolled crypto, CSPRNG for tokens, TLS verification never disabled (`verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify`).
8. **Dependencies & supply chain** — new/changed deps pinned, from the expected registry, no known CVEs (`pip-audit`, `npm audit`, `osv-scanner` when available), no install scripts fetching remote code, lockfile updated.
9. **AI / agent risks** — prompt injection via any text the model reads (docs, issues, web, tool output); tools granted wider than the task (excessive agency); model output used in a sink without validation (insecure output handling); secrets or PII placed in prompts; agents that auto-follow links or execute formatters/scripts from the repo.
10. **Logging, errors & resilience** — security events logged without secrets/PII; errors fail closed; rate limits/size limits on expensive operations.

## Output
Findings table most-severe first (ID, severity, `path:line`, CWE, evidence, exploit scenario, fix), then "Not reviewed", then verdict `BLOCK` / `FIX-BEFORE-MERGE` / `PASS`. Verify every High/Critical by re-reading the code yourself before reporting it; drop what does not hold.
