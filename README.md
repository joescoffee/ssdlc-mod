**English** | [繁體中文](README.zh-TW.md)

<img src=".claude-plugin/icon.png" width="96" align="right">

# ssdlc — Secure SDLC mod for Claude Code

[![Release](https://img.shields.io/github/v/release/joescoffee/ssdlc-mod?sort=semver)](https://github.com/joescoffee/ssdlc-mod/releases/latest)

Security skills and truly read-only reviewer agents for Claude Code.

ssdlc brings the secure software development lifecycle into Claude Code: security review, a pre-PR gate, a vulnerability-fix workflow, and **a truly read-only variant of the Elephant-Goldfish Model (EGM) review**. Reviewers have only Read/Grep/Glob (tool limits enforced by frontmatter and a hook); the hook also blocks credential paths and recursive searches from the filesystem root or home directory. "Read only inside the repo, never open out-of-repo links" is a prompt-level rule. No workflow ever executes the reviewed repository's code.

## Install
```
claude plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```
In a conversation: `/plugin install ssdlc --marketplace joescoffee/ssdlc-mod`.

📦 **[Latest release](https://github.com/joescoffee/ssdlc-mod/releases/latest)** — release notes and earlier versions on the [Releases page](https://github.com/joescoffee/ssdlc-mod/releases).

📘 **New here? Start with the [Beginner's Guide](docs/manual/README.en.md)**: installation, a five-minute quick start, step-by-step use of every skill, the full procedure for reviewing an untrusted repository, the scanner CLI and CI, and troubleshooting.

## Demo
![ssdlc live demo (v0.5.0)](docs/demo.en.png)

Panels ①–③ are real output: the scanner ran with `--json` and the result is shown as a table; ② is a live verification in the Claude app (2026-11-01), whose interface was in Chinese, so the labels and the user's messages are translated. The original Chinese screenshot is `docs/demo.png`.

## Case study: reviewing EGM itself
`/ssdlc:safe-bootstrap` reviewed upstream [google/elephant-goldfish-model](https://github.com/google/elephant-goldfish-model) @ `403d888`: Elephant (design threat model) and Goldfish (zero-context code review) ran in parallel, then were merged and cross-checked.

| Result | Detail |
|---|---|
| Verdict | **FIX-BEFORE-MERGE**: no Critical, nothing malicious; safe on Claude Code for repositories you trust |
| Medium ×5 | bootstrap runs a formatter the repo configures (possible RCE); the orchestrator holds Bash while reading untrusted content; "read-only" is prompt-only on non-Claude hosts; unhashed dependencies installed in the same job as OIDC/attestation permissions; `Agent` spawn types unrestricted |
| Low ×7, Info ×1 | auto-reading linked paths, unscoped synthesizer writes, artifact-directory hijack, unpinned marketplace, and more |
| Prior conclusion overturned | EGM reviewers on Claude Code **really are** limited to Read/Grep/Glob |
| Recommendation | Do not run `/egm-bootstrap` on untrusted repositories; use `/ssdlc:safe-bootstrap` |

Full report (13 findings with file:line evidence): [`docs/reviews/egm-403d888.en.md`](docs/reviews/egm-403d888.en.md)

Reported upstream: [google/elephant-goldfish-model#261](https://github.com/google/elephant-goldfish-model/issues/261) (F1–F5), [#262](https://github.com/google/elephant-goldfish-model/issues/262) (F6–F13).

## How it works
![ssdlc mind map](docs/ssdlc-mindmap.en.png)

Interactive version: `docs/ssdlc-mindmap.en.html` (zoom, pan, edit; the toolbar text is Chinese); state file `docs/mindmaps/ssdlc.en.mindmap.json`. Chinese version: `docs/ssdlc-mindmap.png`.

## Skills
| Command | Purpose |
|---|---|
| `/ssdlc:security-review` | Ten-area security review: scope, trust boundaries, STRIDE, authn/authz, dangerous input, secrets, cryptography, dependencies, AI/agent risks, logging |
| `/ssdlc:ai-security-review` | Review of LLM / RAG / agent code against OWASP LLM Top 10 2026 (`LLM01–10:2026`), OWASP Agentic Top 10 2026 (`ASI01–10`) and the MIT AI Risk Repository causal taxonomy: inventory → scan → Rule-of-Two design gate → two reviewers → coverage matrix |
| `/ssdlc:security-gate` | Pre-PR gate: scans for secrets, dangerous patterns and AI/agent misconfiguration, audits dependencies (parse only — never installs or runs project code), reviews the diff → PASS / WARN / BLOCK / INCOMPLETE |
| `/ssdlc:vuln-fix` | Vulnerability fix workflow: triage → reproduce → root-cause fix → regression test → variant hunt → record |
| `ssdlc review-mode on\|off\|status` | Review mode (a plain message, or `/ssdlc-review-mode` in a terminal): the main session may run only exact, non-executing command forms; no network; writes only to report files; only ssdlc reviewers may be spawned; only the user can switch it off |
| `/ssdlc:rule-from-finding` | Turns a confirmed finding into a rule + planted defect + safe counterpart + tests (the improvement flywheel) |
| `/ssdlc:safe-bootstrap` | A truly read-only variant of the EGM (Elephant-Goldfish Model) bootstrap |

## Agents
- `ssdlc:security-reviewer` — security review of code or a diff
- `ssdlc:design-reviewer` — threat modelling of design documents (STRIDE + AI risks)

Both have only `Read, Grep, Glob` in their frontmatter; the guard hook in `hooks/register.ts` adds defense in depth (OWASP ASI02/ASI03, LLM02:2026):
- any tool other than Read/Grep/Glob and the reporting tool `SubagentHandback` is refused;
- credential stores (`~/.ssh`, `~/.aws`, `.env*`, key files, `~/.claude/.credentials.json`, `/proc`, …) may not be read, including through Grep/Glob glob arguments;
- **allow-list**: each reviewer may read only the absolute paths named in the prompt that dispatched it (the working directory when none are named) plus this plugin's folder; the filesystem root, home directories and credential locations are never admitted;
- symlinks are resolved with `$.fs.stat` before judging, so a link inside the repo that points at a credential is blocked too;
- **tripwire**: a reviewer trying to read a credential or use a forbidden tool is a sign of prompt injection; the alert is attached to the main session's next tool result and the skills turn it into a BLOCK;
- **liveness check and log**: `mcp__ssdlc__guard_log` reports the guard's version, load time and a rule self-test; every skill calls it before spawning reviewers and stops (INCOMPLETE) if the guard is missing or the self-test fails. Refusals are kept locally across sessions (up to 500).

## Scanner
`scripts/gate_scan.py` uses only the standard library, makes no network calls and never follows symlinks. Each finding carries `refs` (CWE, `LLMnn:2026`, `ASInn`).

| Category | Rules |
|---|---|
| Secrets | AWS / GitHub / Anthropic / OpenAI / Slack keys, private keys, hard-coded credentials (only the first 4 characters are shown) |
| General code | shell injection, eval, unsafe deserialization, SQL string building, disabled TLS verification, weak hashes, weak randomness |
| Prompt carriers (LLM01:2026) | Unicode tag smuggling (**the hidden text is decoded and shown**; raw characters are never echoed), zero-width/bidi characters, injection phrases |
| Model supply chain (LLM04:2026) | `trust_remote_code`, `allow_dangerous_deserialization`, unsafe model loading, unpinned models, LangChain `loads`, exposed Ray / Weaviate |
| Agent permissions (LLM03:2026, ASI02/05) | approval bypass (`bypassPermissions`, `--dangerously-skip-permissions`, `autoApprove`, `--yolo`), wildcard allow-lists, open-ended REPL/shell tools, unsandboxed execution, unbounded loops, run-on-open settings (`.git/config` fsmonitor, `runOn: folderOpen`), model output into HTML sinks |
| MCP config (parsed JSON) | unpinned `npx` / `uvx` / `@latest`, secrets inlined in `env` / `headers`, plaintext HTTP to non-local hosts |
| Repository | symlinks pointing outside the repository |

`# ssdlc: allow <reason>` markers are **ignored by default** (the reviewed code can write markers too); they apply only with `--honor-markers`, and never hide secret or invisible-character findings. Unreadable, non-regular or oversized files are listed as skipped, and exit code 3 (INCOMPLETE) signals an incomplete scan.

## References
`references/ai-risk-checklist.md` (OWASP 2026 item-by-item checks, tests and rule mapping), `references/mit-ai-risk-triage.md` (MIT 24-subdomain SSDLC triage and causal scenario grid), `references/untrusted-repo.md` (rules for handling an untrusted repository). The first two are adapted from Creative Commons works and are **CC BY-SA 4.0**; everything else is MIT.

## Strategy
How threat modelling, game theory and the flywheel shaped this version: [`docs/strategy/README.en.md`](docs/strategy/README.en.md); threat model report: [`docs/threat-model/report.en.md`](docs/threat-model/report.en.md).

## Known limitations
Disclosed items still open after the v0.2.0 self-review ([`docs/reviews/ssdlc-0.2.0-self-review.en.md`](docs/reviews/ssdlc-0.2.0-self-review.en.md)):

1. **Main-session restrictions must be switched on** (T1): `ssdlc review-mode on` bounds the main session in code; without it, only the procedures and Claude Code's per-call approval apply. **Turn review mode on before reviewing an untrusted repository.**
2. **The reviewer allow-list comes from the dispatching prompt** (SR-1, T5, since v0.4.0): the scope is the paths named in the prompt (or the working directory) plus the plugin folder; if the main session is injected into naming a directory it should not, the allow-list admits it (the credential deny-list still blocks).
3. **TOCTOU and hard links** (SR-16): there is a gap between the guard's check and the actual read, and hard links cannot be detected through realpath. An OS-level sandbox is needed.
4. **Unverified host behaviour**: whether Claude Code's Grep searches hidden files, and whether a subdirectory's `CLAUDE.md` is loaded lazily, has not been tested.
5. **The scanner is a code-hygiene check**, not a runtime injection or DLP filter (OWASP 2026 states plainly that regexes cannot stop encoded content).

## Tests
```
python3 -I -m unittest discover -s tests -v   # 53 tests: planted defects for every rule, safe counterparts, review regressions
claude plugin test .                           # 28 hook tests (guard, allow-list, review mode, tripwire, liveness, history)
```
`tests/fixtures/` contains **deliberately vulnerable** sample files — do not import or run them.

## License
MIT, except `references/ai-risk-checklist.md` and `references/mit-ai-risk-triage.md` (CC BY-SA 4.0; attribution at the end of each file).
