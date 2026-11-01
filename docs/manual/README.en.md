**English** | [繁體中文](README.md)

# ssdlc Beginner's Guide

[![Release](https://img.shields.io/github/v/release/joescoffee/ssdlc-mod?sort=semver)](https://github.com/joescoffee/ssdlc-mod/releases/latest)

> Applies to: **ssdlc v0.5.0** (2026-11-01, [release notes](https://github.com/joescoffee/ssdlc-mod/releases/tag/v0.5.0)). Every command in this guide was actually run on that version; the screenshots are real output.
> Read the first three chapters (about 15 minutes) and you can start using it; look up the other chapters when you need them.

## Contents

1. [What is ssdlc](#1-what-is-ssdlc)
2. [Glossary](#2-glossary)
3. [Before you install](#3-before-you-install)
4. [Install, verify, update and remove](#4-install-verify-update-and-remove)
5. [Five-minute start: your first security gate run](#5-five-minute-start-your-first-security-gate-run)
6. [Scenarios: the six skills step by step](#6-scenarios-the-six-skills-step-by-step)
7. [Reviewing an untrusted repo: the full safe workflow](#7-reviewing-an-untrusted-repo-the-full-safe-workflow)
8. [Using the scanner on its own (command line and CI)](#8-using-the-scanner-on-its-own-command-line-and-ci)
9. [Reading the reports](#9-reading-the-reports)
10. [Guard hook and review mode](#10-guard-hook-and-review-mode)
11. [Troubleshooting](#11-troubleshooting)
12. [Known limitations](#12-known-limitations)
13. [Advanced: development, testing and contributing](#13-advanced-development-testing-and-contributing)

---

## 1. What is ssdlc

ssdlc is a **Claude Code plugin** that turns the key steps of the Secure Software Development Life Cycle (Secure SDLC) into commands you can call directly:

| What you want to do | Use this |
|---|---|
| Quickly check, before opening a PR, for leaked keys, dangerous code and AI agent misconfiguration | `/ssdlc:security-gate` |
| Do a full security review of a piece of code | `/ssdlc:security-review` |
| Review code that calls an LLM or uses agents, MCP or RAG | `/ssdlc:ai-security-review` |
| Review a repo someone else gave you that you cannot trust (e.g. an external PR, vendor code) | `ssdlc review-mode on` + `/ssdlc:safe-bootstrap` |
| Fix a known vulnerability | `/ssdlc:vuln-fix` |
| Turn a confirmed finding into a rule that is checked automatically from then on | `/ssdlc:rule-from-finding` |

How it differs from an ordinary linter:

- **The reviewers really can only read**: review work is handed to two subagents (`ssdlc:security-reviewer`, `ssdlc:design-reviewer`) that have only the Read / Grep / Glob tools, and a guard hook additionally blocks other tools and credential-file reads in code.
- **Covers AI risk**: the checks are designed around the OWASP LLM Top 10 2026, the OWASP Agentic Top 10 2026 and the MIT AI Risk Repository.
- **Never runs the code under review**: no workflow runs the reviewed repo's tests, build, formatter or install commands.

**What it cannot do**: it is not a runtime firewall or DLP, and it cannot guarantee it finds every vulnerability. The scanner is a "code hygiene check", and the reviewers' conclusions need human judgment. See [Chapter 12](#12-known-limitations).

**The whole picture in one diagram** (v0.5.0): the seven main branches are skills, reviewers (agents), guard hook, scanner, tests, installation and reference standards; dashed lines show how they relate.

![Mind map of how ssdlc works (v0.5.0)](../ssdlc-mindmap.en.png)

**The interactive version** (open `docs/ssdlc-mindmap.en.html` in a browser) lets you drag to pan, zoom with the scroll wheel or toolbar, click to select a node, double-click or press F2 to edit text, drag a node to move a branch, and press Tab to add a child node. When you are done, click "Export JSON (paste back to Claude)" and paste the result back into the conversation to sync it to the mind map's state file. (The English page's interface text is translated by `docs/mindmaps/localize_en.py`; run it again after re-rendering.) The image below shows the view zoomed to 120% with the "Install → Releases → v0.5.0" node selected:

![Interactive mind map: zoomed in with a node selected](img/mindmap-interactive.en.png)

(Node notes currently live only in the `note` field of the state file `docs/mindmaps/ssdlc.en.mindmap.json`; the interactive view does not show them.)

---

## 2. Glossary

| Term | Meaning |
|---|---|
| **Skill** | A set of step-by-step instructions called as `/ssdlc:<name>`, which Claude follows. |
| **`ssdlc review-mode on／off／status`** | The review mode switch. Just type it as an ordinary message (no slash); the guard intercepts and handles it, and it is not sent to the model. Works in the Claude app, on the web and in the terminal. In the terminal you can also use the slash command `/ssdlc-review-mode on` (with a hyphen and no `ssdlc:` prefix, because it is not a skill). |
| **Agent (subagent)** | A helper that Claude dispatches separately. Both ssdlc reviewers are read-only subagents. |
| **Hook (guard)** | Code built into the plugin that checks every tool call before it runs and refuses it if it breaks the rules. Active automatically once installed. |
| **Goldfish / Elephant** | Two reviewer perspectives. The Goldfish gets no background and looks only at the code itself; the Elephant gets the full background and does design-level threat modeling. The two results are cross-checked. |
| **`LLM01:2026`** | Item 1 (prompt injection) of the **2026 edition** of the OWASP LLM Top 10. The 2026 numbering differs from the 2025 edition, so the year is always written. |
| **`ASI01`** | Item 1 (agent goal hijack) of the OWASP Agentic Top 10 (2026). |
| **`CWE-78`** | A Common Weakness Enumeration id (in this example, command injection). |
| **BLOCK / WARN / INCOMPLETE / PASS** | Verdicts: must fix / should look at / not fully checked (does not mean safe) / no problems found after checking (does not mean OK to merge). |
| **Tripwire** | Triggered when a reviewer tries to read credentials or use a tool it should not have; it means the reviewed content may be attempting prompt injection, and the verdict is BLOCK. |
| **Review mode** | When on, the main conversation can run only a few safe command forms, cannot go online, and can write only report files. |
| **allow marker** | A `# ssdlc: allow <reason>` at the end of a line of code. **Not honored** by default; see [Chapter 8](#8-using-the-scanner-on-its-own-command-line-and-ci). |

---

## 3. Before you install

| Item | Requirement | How to check |
|---|---|---|
| Claude Code | A version that supports plugins (terminal, desktop app or web all work) | `claude --version` |
| Python | 3.9 or later (the scanner uses only the standard library; no `pip install` needed) | `python3 --version` |
| git | Any recent version | `git --version` |
| GitHub access | Able to read `joescoffee/ssdlc-mod` (currently a **private** repo, so you need to be granted access; once it is public anyone can install it) | Open the repo page in a browser |
| Dependency audit tool (optional) | Any of `osv-scanner`, `npm`, `pip-audit`, used by security-gate to check packages for vulnerabilities; without one, the verdict is INCOMPLETE rather than PASS | `osv-scanner --version` |

---

## 4. Install, verify, update and remove

### 4.1 Install (pick one)

**A. One line in the terminal** (recommended)

```bash
claude plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

**B. Two steps** (add the marketplace first, then install)

```bash
claude plugin marketplace add joescoffee/ssdlc-mod
claude plugin install ssdlc@ssdlc-mod
```

**C. In a Claude Code conversation**

```
/plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

When `Add marketplace?` appears, press `y`, then choose the install scope (default user; press Enter).

**D. Desktop app**: **+** next to the prompt box → **Plugins** → **Add marketplace**, enter `joescoffee/ssdlc-mod` → **Add plugin**.

> Install scope: `user` (available in all projects, the default), `project` (written into the project settings, shared by the team), `local` (only this project, only you). In the terminal, specify it with `-s project`.

### 4.2 Verify the installation

```bash
claude plugin details ssdlc
```

![Install and verify](img/step1.en.png)

(The screenshot was taken installing with the local repo folder as the marketplace source; when installing from GitHub, the steps and component list on screen are the same.)

You should see **Skills (6)** and **Agents (2)**. `Hooks (0)` is normal: that number counts only old-style settings-file hooks, while the ssdlc guard is a hook module that is active as soon as it is installed.

Then confirm in a Claude Code conversation that the guard has loaded:

```
ssdlc review-mode status
```

A reply of `ssdlc ✓ Review mode is OFF; guard events this session: 0 …` means the hook is working (in the app it appears inside a "Hook 已封鎖您的提示" ("Prompt blocked by a hook") box, which is normal).

### 4.3 Update, disable, remove

| Action | Command |
|---|---|
| Update to the latest version | `claude plugin marketplace update ssdlc-mod`, then `claude plugin update ssdlc@ssdlc-mod`; run `/reload-plugins` in the conversation |
| See what changed in a new version | [Releases page](https://github.com/joescoffee/ssdlc-mod/releases): release notes for every version (English and Chinese); [latest release](https://github.com/joescoffee/ssdlc-mod/releases/latest) |
| See the installed version | `claude plugin list` (look at `Version:`) |
| Disable temporarily | `claude plugin disable ssdlc@ssdlc-mod` (to restore: `enable`) |
| Remove | `claude plugin uninstall ssdlc@ssdlc-mod`, then `claude plugin marketplace remove ssdlc-mod` |

---

## 5. Five-minute start: your first security gate run

In **your own** project (code you trust):

1. In the terminal, go to the project folder and start Claude Code: `claude`
2. Type:
   ```
   /ssdlc:security-gate
   ```
3. Claude will, in order: list the changed files → run the scanner → audit changed dependencies → read the diff → give a verdict.
4. Look at the final verdict:
   - **BLOCK**: there is a problem you must fix (e.g. a leaked key). Fix it at the `file:line` given in the report.
   - **WARN**: a medium-level problem worth a look.
   - **INCOMPLETE**: some files or dependencies were not checked (e.g. osv-scanner is not installed). The report says what was not checked.
   - **PASS**: no problems found after checking. This is a "gate result", not permission to merge.
5. After fixing, run it again until there is no BLOCK.

> Tip: keys in the report show only their first 4 characters, e.g. `tok_…`.

---

## 6. Scenarios: the six skills step by step

### 6.1 `/ssdlc:security-gate` — pre-PR gate

**When to use**: every time before you open a PR or merge.

**What it does**
1. Lists the changed files with `git diff -z` (file names never pass through a shell, so malicious file names cannot inject commands).
2. The scanner checks for secrets, dangerous code patterns and AI / agent configuration (allow markers are ignored by default).
3. Audits dependencies only by "parsing the lockfile", never with `npm install` or `pip install`; it also checks whether the PR changed settings such as `.npmrc` or `osv-scanner.toml` that affect the audit result.
4. Reads the diff and applies the AI checklist when needed.
5. Gives a verdict; any High / Critical judged to be a false positive is always listed in the **Dismissed** table, which you can overrule.

**You can say**: "Run the security gate with main as the base", "Can I push this PR?"

### 6.2 `/ssdlc:security-review` — full security review

**When to use**: security-related changes (login, permissions, file upload, external input), and before going live.

**What it does**: mechanical scan → dispatches `ssdlc:security-reviewer` to review along 10 aspects (trust boundaries, STRIDE, authentication and authorization, dangerous sinks, secrets, cryptography, dependencies, AI risk, logging) → goes back to the code with Grep to confirm the evidence for every High → report.

**Output**: a findings table (severity, `file:line`, CWE, evidence, attack scenario, fix) + a "not reviewed" list + a verdict.

**You can say**: "Do a security review of src/auth/".

### 6.3 `/ssdlc:ai-security-review` — AI / agent code review

**When to use**: the code calls a model, builds prompts, runs agents or tools, configures MCP, or uses RAG or agent memory.

**What it does**
1. **Inventory**: models, prompt sources, all untrusted text that reaches a prompt, tools and MCP, memory and vector stores, subagents, where model output flows.
2. **Scan**: includes the AI rules (hidden Unicode, `trust_remote_code`, approval bypass, unpinned MCP versions, etc.).
3. **Rule of Two design gate**: if a single agent at the same time "reads untrusted input" + "can reach sensitive data" + "can change state or send things out", without per-action human approval → High.
4. **Two reviewers**: code review (goldfish) and design threat modeling (elephant, including the MIT causal scenario grid) run in parallel.
5. **Report**: every finding is tagged `LLMnn:2026` / `ASInn` / CWE, with a **coverage matrix** attached — each of LLM01–10 and ASI01–10 must say "finding / checked, no finding / not applicable + reason / not reviewed + reason"; an item left blank counts as not checked.

### 6.4 `/ssdlc:safe-bootstrap` — read-only Elephant-Goldfish review

**When to use**: you need to review someone else's repo or design documents, and the review must not change anything. For the full steps, see [Chapter 7](#7-reviewing-an-untrusted-repo-the-full-safe-workflow).

### 6.5 `/ssdlc:vuln-fix` — vulnerability fix

**When to use**: you have a CVE, scan result, penetration test report or review finding to fix.

> This skill can **only be triggered by you typing it** (Claude will not call it automatically), so that malicious content cannot lure it into changing code or running tests.

**Flow**: classify (including the OWASP 2026 id) → reproduce (untrusted code runs only in a sandbox, or it asks you first) → fix the root cause → verify (it must not "pass" by adding allow markers or deleting tests) → search for variants of the same kind → fix record.

### 6.6 `/ssdlc:rule-from-finding` — turn a finding into a rule

**When to use**: a finding has been **confirmed as real**, and it can be detected by a pattern (a particular API, flag or settings key).

**Flow**: write the scan rule (with CWE and OWASP ids) → planted-defect example (must be caught) → safe counterpart (must not be flagged) → unit tests → add to the checklist. The tests check that the checklist and the rules agree, so skipping a step makes them fail.

> Manual trigger only. Unconfirmed findings must not be turned into rules, or the false positive would be locked in.

---

## 7. Reviewing an untrusted repo: the full safe workflow

An untrusted repo may hide: instructions that lead the AI astray, a `.git/config` that runs code as soon as you run `git`, a `CLAUDE.md` that Claude Code loads automatically. Follow these steps:

**Step 1: Determine where the repo came from**

| How you got it | Can you run git? |
|---|---|
| You ran `git clone <url>` yourself | Yes (a clone does not bring the other party's settings with it) |
| An archive, shared folder or someone else's working directory | **No**. Clone it again from the original URL, or review it only as plain files |

**Step 2: Make a review copy without agent settings**

```bash
rsync -a --exclude .git --exclude CLAUDE.md --exclude AGENTS.md --exclude .claude their-repo/ review-copy/
```

**Step 3: Start Claude Code in the review copy and turn on review mode**

```bash
cd review-copy && claude
```
```
ssdlc review-mode on
```

The status line shows `ssdlc: review mode ON`. From now on, the main conversation can only run the scanner, hardened read-only git, parse-only audit tools, directory listing and rsync; it cannot go online; it can write only report files; it can dispatch only ssdlc reviewers.

**Step 4: Run the review**

```
/ssdlc:safe-bootstrap review this folder
```

(If the code involves AI / agents, use `/ssdlc:ai-security-review` instead.)

**Step 5: Check the tripwire**

When the reviewers return, Claude checks `guard_log`. If any reviewer tried to read your credential files or use a tool it should not have, the report shows **BLOCK: `ai.injection-attempt-observed`** — meaning this repo is attempting prompt injection; treat it as malicious. You can also check yourself:

```
ssdlc review-mode status
```

**Step 6: Turn review mode off when done**

```
ssdlc review-mode off
```

> Only you typing it yourself can turn it off; the same text sent by Claude, other plugins or background notifications is refused. The guard replies to this message directly, and it is not sent to the model.
>
> In the Claude app / on the web, the reply appears in a box titled "**Hook 已封鎖您的提示**" ("Prompt blocked by a hook"), and its content starts with `ssdlc ✓` — this is normal: the guard intercepted the message (so it is not sent to the model), and the text in the box is the guard's reply.

---

## 8. Using the scanner on its own (command line and CI)

The scanner is a standalone Python script and works without Claude Code. After the plugin is installed it is at `scripts/gate_scan.py` in the plugin folder; you can also get it straight from the repo.

```bash
python3 -I scripts/gate_scan.py [--json] [--honor-markers] [--files-from <list-file>] [--] <path>…
```

| Option | Effect |
|---|---|
| `--json` | Outputs JSON: `findings`, `suppressed`, `skipped`, `incomplete`, `honor_markers` |
| `--files-from <file>` | Reads a list of paths from a file (NUL- or newline-separated); combine with `git diff -z --name-only > <list-file>` so file names never pass through a shell |
| `--honor-markers` | Honors `# ssdlc: allow <reason>` markers. **Not honored by default**, because the code under review can write markers itself; even when honored, secrets and invisible characters are never hidden |
| `--` | Every argument after this is treated as a path (for file names that start with `-`) |
| `--strict` | Kept for backward compatibility, has no effect (strict is now the default) |

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Everything scanned, no findings |
| 1 | Findings |
| 2 | Argument error (e.g. the mistyped option `--stict`) |
| 3 | No findings, but the **scan is incomplete** (path missing, unreadable, special file, too large) — not a PASS |

![Scanning AI and agent configuration](img/step2.en.png)

![Incomplete scan](img/step3.en.png)

**Using it in CI (GitHub Actions example)**

```yaml
- name: ssdlc gate scan
  run: |
    git diff -z --name-only --diff-filter=ACMR origin/${{ github.base_ref }}...HEAD > changed.lst
    python3 -I scripts/gate_scan.py --json --files-from changed.lst > gate.json || code=$?
    cat gate.json
    # 1 = findings, 3 = incomplete: both fail the job
    if [ "${code:-0}" -ne 0 ]; then exit 1; fi
```

> This example runs on **your own** repo. If you want to review PRs from external forks in CI, do not give that job any secrets or write permission.

---

## 9. Reading the reports

**Each line of scanner output**

```
HIGH     ai.mcp-inline-secret   .mcp.json:0  server 'issues': ISSUES_API_TOKEN=tok_…  [LLM02:2026, ASI03, CWE-798]
└severity └rule                  └file:line    └evidence (a secret shows only its first 4 chars)  └mapped ids
```

- Line number `0`: the finding comes from parsing the whole settings file (e.g. an MCP config) and has no single line number.
- `<tag-chars>`, `<U+200B>`: invisible characters are shown as codes; `hidden='…'` is the decoded hidden text.

**How to handle each severity**

| Severity | Recommendation |
|---|---|
| CRITICAL / HIGH | Fix before merging; if judged a false positive, write down the reason and put it in the Dismissed table |
| MEDIUM | Handle in this iteration or the next |
| LOW / INFO | Leads, left to the reviewers' judgment |

**The coverage matrix in review reports**: an AI review report always ends with a coverage matrix for LLM01–10 and ASI01–10. "Not reviewed" means that item is still a blind spot.

**Saved reports**: reports saved in `docs/reviews/` are stamped with a date and commit; they represent only "the state of that commit at that time", and later versions need a fresh review.

---

## 10. Guard hook and review mode

### 10.1 What the guard hook blocks (ssdlc reviewers only)

| Situation | Result | Level |
|---|---|---|
| A reviewer tries to use a non-read tool such as Bash, Write or WebFetch | Refused | tripwire |
| Reading credential locations: `~/.ssh`, `~/.aws`, `.env*` (templates excepted), key files, `~/.claude/.credentials.json`, `/proc`, k8s tokens, shell history, etc. (case-insensitive; symlink targets are checked too) | Refused | tripwire |
| Recursive search from `/`, the home directory, `/etc` or similar | Refused; pass the repo path instead | warn |
| Reading files outside the review scope. Scope = absolute paths written in the dispatch prompt (the working directory if none is written) + the ssdlc plugin directory (where the checklists are) | Refused; write that path in the prompt | warn |

Every refusal shows a notice; a tripwire also shows in the status line, and an alert is attached to the main conversation's next tool result.

### 10.2 Command forms allowed in review mode

| Category | Allowed forms |
|---|---|
| Scanner | `python3 -I …/gate_scan.py …` |
| git (read-only subcommands) | `env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c diff.external= …` plus `diff` / `log` / `show` / `ls-files` / `merge-base` / `rev-parse` / `status`; `diff` / `log` / `show` also require `--no-ext-diff --no-textconv` |
| Dependency audit | `osv-scanner …`, `npm audit --package-lock-only …`, `pip-audit --disable-pip --no-deps …` |
| Other | `rsync -a` (must exclude `.git`, `CLAUDE.md`, `AGENTS.md`, `.claude`), `ls`, `wc`, `file`, `stat`, `pwd`, `mktemp`, `mkdir -p`, `--version` |

Not allowed: pipes `|`, `;`, `&&`, `$(...)`, variables `$VAR`, multi-line commands; a single `> file` redirect is allowed at the end.

| Tool | In review mode |
|---|---|
| WebFetch, WebSearch | Off |
| Write, Edit | Can write only report files such as `docs/reviews/*.md`, `*-review.md`, `*-report.md` |
| Agent | Can dispatch only `ssdlc:*reviewer` |
| Other plugins' MCP tools | Off (except `mcp__ssdlc__guard_log`) |
| Read, Grep, Glob | Normal |

### 10.3 Guard liveness check and history

If the hook fails to load because of a Claude Code update, it cannot report the error itself. So ssdlc works the other way round: every skill calls the `guard_log` tool **before** dispatching reviewers, to confirm the guard is still there.

- The tool is missing, errors, or `selfTest.pass` is false (the rules themselves are broken) → the skill stops and reports **INCOMPLETE — ssdlc guard not active**; it never dispatches reviewers without protection.
- You can also ask Claude at any time to "call guard_log"; the `guard` block in the reply lists the version, load time and self-test result.
- Every refusal is written to a local history (across sessions, up to 500 entries); the `history` block of `guard_log` shows the total and the most recent 20.

Results verified on a real Claude app (review mode blocking `curl`, the reviewer allowlist, the `guard_log` liveness check). The app's interface was in Chinese, so the labels and the user's messages in this image are translated; the original is `img/step5.png`:

![Verified on a real Claude app](img/step5.en.png)

(The first line is raw output captured before the `ssdlc ✓` prefix was added; v0.5.0 replies start with `ssdlc ✓`.)

### 10.4 Local metrics

`ssdlc review-mode status` shows, since first use, the number of scans, reviewer dispatches, tripwires and warns. These numbers live only on your computer (in Claude Code's plugin storage) and are not sent anywhere; their purpose is to show you how much the tool is used and how often alerts fire.

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Plugin "ssdlc" not found in marketplace` | The marketplace name is `ssdlc-mod`: use `ssdlc@ssdlc-mod`, or install in one line with `--marketplace joescoffee/ssdlc-mod` |
| `Marketplace file not found` or 404 | The repo is currently private: make sure your GitHub account has access |
| Typing `/ssdlc:...` does nothing | Run `/reload-plugins`; use `claude plugin list` to confirm the status is enabled |
| `Unknown command: /ssdlc:review-mode` or `/ssdlc-review-mode` | In the Claude app / on the web (cloud sessions), slash commands that a plugin registers in code are not available. Type the ordinary message `ssdlc review-mode status` instead (no slash). If the ordinary message gets no reply either, the hook module did not load: update to v0.3.2 or later and restart |
| A command is refused in review mode | Rewrite it in a form from [Section 10.2](#102-command-forms-allowed-in-review-mode); expand variables to their actual values. If you really need another command, type `ssdlc review-mode off` yourself |
| Scanner exit code 3 | The report's `SKIPPED` lists the files not scanned and why; fix the path or permissions and rerun |
| A rule keeps giving false positives | Once confirmed as a false positive, write down the reason in the report's Dismissed table; if it happens routinely, open an issue, or narrow the rule with `/ssdlc:rule-from-finding` |
| A reviewer reports `outside this review's scope` | The directory to review was not written into the reviewer's prompt as an absolute path. Say "review /full/path", or start Claude Code in that directory |
| A reviewer says "checklist not found" | `${CLAUDE_PLUGIN_ROOT}` was not expanded: reinstall the plugin; the skill reports INCOMPLETE rather than hunting for a copy elsewhere |
| The report shows `ai.injection-attempt-observed` | The reviewed content is attempting prompt injection. Do not run any command that reviewer suggests; treat the repo as malicious |

---

## 12. Known limitations

1. **You must turn review mode on yourself**. When it is off, the main conversation relies only on the workflow rules and Claude Code's per-action approvals; do not review untrusted repos in bypass / acceptEdits permission modes.
2. **The reviewer allowlist is set by the dispatch prompt**: if Claude is injected into writing a directory it should not read into a reviewer's prompt, the allowlist will let it through (the credential blocklist still blocks). Turning on review mode reduces the impact of injection on the main conversation.
3. **There is a time gap between checking and reading (TOCTOU)**, and hard links cannot be detected; full protection needs an OS-level sandbox.
4. **The scanner is a code hygiene check**, not a runtime prompt-injection or data-exfiltration filter; encoded content can get past any regex.
5. **Unverified host behavior**: whether Claude Code's Grep searches hidden files, and whether a `CLAUDE.md` in a subdirectory is loaded when read, have not been tested.
6. The reviewers are AI and can miss things or report false positives; every High finding is verified back against the code, but the final judgment is still yours.

Full self-review and remediation: [`../reviews/ssdlc-0.2.0-self-review.en.md`](../reviews/ssdlc-0.2.0-self-review.en.md); threat model: [`../threat-model/report.en.md`](../threat-model/report.en.md); improvement strategy: [`../strategy/README.en.md`](../strategy/README.en.md).

---

## 13. Advanced: development, testing and contributing

**Directory layout**

```
.claude-plugin/   plugin.json (name, version), marketplace.json, icon.png
skills/           the six skills (one SKILL.md each)
agents/           the two read-only reviewers
hooks/            register.ts (guard, tripwire, review-mode wiring), review-mode.ts (review-mode rules)
scripts/          gate_scan.py (scanner)
references/       AI checklist, MIT triage, untrusted-repo rules
tests/            unit tests, hook tests, deliberately vulnerable examples (fixtures, do not run)
types/            type contracts for the plugin state
docs/             manual, review reports, threat model, strategy, mind map
```

**Running the tests**

```bash
python3 -I -m unittest discover -s tests   # 53: planted defect + safe counterpart per rule, review regressions
claude plugin test .                       # 28: guard, allow-list, review mode, tripwire, liveness, history
claude plugin validate .                   # plugin structure check
```

![Tests](img/step4.en.png)

**Adding a rule**: follow the steps of `/ssdlc:rule-from-finding`. The consistency tests make sure rules, examples, tests and checklists stay in sync.

**How it all works**: see [the mind map in Chapter 1](#1-what-is-ssdlc) (interactive version: `../ssdlc-mindmap.en.html`).

**License**: the code is MIT; `references/ai-risk-checklist.md` and `references/mit-ai-risk-triage.md` are adapted from OWASP (CC BY-SA 4.0) and the MIT AI Risk Repository (CC BY 4.0) and are licensed CC BY-SA 4.0; sources are at the end of each file.
