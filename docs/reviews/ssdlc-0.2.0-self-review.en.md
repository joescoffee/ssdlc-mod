**English** | [繁體中文](ssdlc-0.2.0-self-review.md)

# ssdlc v0.2.0 self-review and treatment (2026-11-01)

The mod was reviewed with its own `/ssdlc:ai-security-review` workflow: goldfish (`ssdlc:security-reviewer`, code only) reported 22 items (verdict BLOCK), and elephant (`ssdlc:design-reviewer`, threat modeling + MIT causal grid) reported 22 threats (T1–T22). After merging the two, the items were treated as in the table below and fixed in v0.2.1.

| Merged item | Source | Severity | Treatment (v0.2.1) |
|---|---|---|---|
| git commands execute the reviewed repo's `.git/config` (fsmonitor, filter, diff.external…), and the skills are inconsistent | SR-2/3/11, T8 | High | ✅ Added a single rule in `references/untrusted-repo.md`: run git only in repos you cloned yourself, with the full set of flags; do not run git on a `.git` that came from an archive or shared folder; referenced by all skills |
| security-review's dependency audit uses plain `pip-audit` | SR-12 | High | ✅ Now references the parse-only command |
| Guard bypass via letter case, `//`, `/./` | SR-4, SR-13 | High | ✅ Case-insensitive matching, path normalization |
| Grep recursively reads credentials from a parent directory | SR-1, T5 | High | ✅ (v0.4.0) Allowlist: working directory, plugin directory, paths named in the dispatch prompt; recursive searches of the root, home and system directories are denied; the denylist is kept as a second layer |
| Main session meets all three conditions (Rule of Two) | T1, T21, T22 | High | ⚠️ Not fixed: listed as a known limitation; skills now fail closed (stop if there is no ssdlc review agent) and forbid weakening checks to get a pass |
| Command injection via file names passed through the shell | T2 | High | ✅ Scanner uses `--files-from` (NUL-separated) and supports `--`; the gate now uses `git diff -z` to write a list file |
| Incomplete denylist (k8s token, .envrc, .claude.json, history…) | SR-5, T5b | Medium | ✅ Expanded |
| ReDoS | SR-6, T13 | Medium | ✅ 4 KB per-line limit, upper bounds on quantifiers; tests complete within 5 seconds |
| Excerpts leak secrets and control characters | SR-7, T3, T4 | Medium | ✅ Every excerpt masks all secrets, escapes control and invisible characters, JSON `ensure_ascii` |
| Allow marker scope too broad, honored by default | SR-8, T12 | Medium | ✅ Ignored by default (honored only with `--honor-markers`); never hides secrets or invisible characters; reason is sanitized |
| Incomplete detection of executable git config keys | SR-9 | Medium | ✅ New rule `repo.git-config-exec` (case-insensitive; filter/sshCommand/pager/alias `!`…, `config.worktree`) |
| Unreadable / nonexistent / FIFO files silently skipped | SR-10, T13, T14 | Medium | ✅ Reads regular files only (`lstat` + `O_NOFOLLOW` + `O_NONBLOCK`), lists all in skipped, exit code 3 = INCOMPLETE, exit code 2 for unknown flags |
| vuln-fix runs tests without restating the sandbox and can be triggered by injection | SR-20, T11 | Medium | ✅ Verification step restates the sandbox; `disable-model-invocation: true`; forbids markers or deleting tests to get a pass |
| Guard fails on timing and after reload; hard-coded name | T6, SR-13 | Medium | ✅ On cache miss, look up the type with `$.agent.list()`; prefix now uses `$.plugin.name` |
| Dependency audit tools read in-repo configuration (osv-scanner.toml, .npmrc) | T10 | Medium | ✅ Gate checks for these and runs in a temporary directory containing only the lockfile, against a specified registry |
| Persisted reports can exfiltrate via markdown images | T15 | Medium | ✅ safe-bootstrap neutralizes images, HTML and external links before writing files |
| Documentation claims more than is actually enforced; reports written as permanent conclusions | T7 | Low | ✅ README wording corrected; EGM report gains a point-in-time statement |
| Remaining symlink gaps (`.git` as a symlink, etc.) | SR-15 | Low | ✅ `.git` symlink reported; read only, not followed |
| Glob bypass via character classes / braces | SR-14 | Low | ✅ `[]{}?` flattened before matching |
| PLUGIN path falls back to a Glob search | SR-18, T17 | Low | ✅ Removed; now judged INCOMPLETE |
| MCP detection gaps (JSONC, npx.cmd, `pkg@1`, X-API-Key) | SR-19 | Low | ✅ |
| Global mutable state | SR-21 | Info | ✅ Reset on every scan |
| Evidence not mechanically checked; PASS treated as merge authorization | T16 | Medium | ✅ claim-check-act: cited evidence confirmed with Grep; PASS ≠ merge approval |
| Unbounded parallelism | T13, F11 | Low | ✅ security-review capped at 4 reviewers |
| TOCTOU, hard links | SR-16 | Low | ⚠️ Not fixed: requires an OS-level sandbox; listed as a known limitation |
| Marketplace does not pin versions, no integrity check | T17, F9 | Low | ⚠️ Partial: released as git tag `v0.2.1`; the manual explains how to pin a version |
| No persistent log of denials | T19 | Low | ✅ (v0.5.0) Stored in `$.state` within a session, cross-session history in `$.store` (500 entries), viewable via `guard_log` |
| Host API drift silently disables the guard | T18, SR-22 | Info | ✅ (v0.5.0) Liveness check: skills call `guard_log` before dispatching reviewers; if the tool is absent or the rule self-check fails, they fail closed (INCOMPLETE) |

Tests: Python unit tests 40 → 53, guard hook tests 9 → 13, all passing.
