<!--
Channel: PUBLIC issue on google/elephant-goldfish-model, template "Task".
Can be filed now: the findings are public (joescoffee/ssdlc-mod, public since 2026-11-01). Draft A was filed as #261; the body already ends with "Related: #261".
-->

**Title:** Hardening: constrain file paths, write targets, and parallelism; align safety claims in docs

## Objective

These are low-severity hardening items from a read-only security review of `403d888`. Individually none is exploitable without other conditions, but together they narrow what untrusted repository content can influence when EGM reviews it.

## Scope

1. **Linked-file auto-reads.** `skills/egm-review/SKILL.md:75-76, 97-98` and `skills/egm-review-loop/SKILL.md:56-57, 71-72` automatically read any path or URL a design doc references, and accept arbitrary persona/standard paths. This conflicts with the adapters' "only explicitly supplied review context" (`.claude-plugin/agents/structural.md:14-15`). Proposal: resolve links only to relative paths inside the workspace, and ask the user before following absolute paths, `..`, or URLs. Load personas and standards only from the plugin root.
2. **Unscoped synthesizer writes.** `.claude-plugin/agents/synthesizer.md:5` grants `Write` with no path limit. Proposal: restrict writes to the fixed report filenames in the artifact directory.
3. **Artifact directory from project instructions.** `docs/claude.md:32-35` lets a repository's `CLAUDE.md`/`AGENTS.md` set `EGM artifact directory:` to any path and create it. Proposal: require the path to resolve under the working directory, or ask the user.
4. **Temp files outside the workspace.** `resources/execution_instructions.md:7-9` and `skills/egm-bootstrap/SKILL.md:57-59` use predictable `/tmp/` locations outside the project, which contradicts "keep write access limited to the project" (`docs/claude.md:59-60`). Proposal: use the host scratch directory or `mktemp -d`.
5. **Unbounded bootstrap parallelism.** `skills/egm-bootstrap/SKILL.md:194-196` has no cap on workers or scouts. Proposal: add a cap and show an estimated cost at the existing >15-directory gate.
6. **Marketplace tracks `main` and ships the whole repo.** `.claude-plugin/marketplace.json:9` uses `source: "./"`, which bypasses the runtime allowlist used for `distributions/claude`. Proposal: point it at `distributions/claude` or a pinned release.
7. **Dev dependencies.** `requirements-dev.txt:16-17` uses open lower bounds, and `.github/dependabot.yml` does not cover `pip`. Proposal: pin with hashes and add a `pip` ecosystem entry.
8. **Docs accuracy.** `docs/designs/synthesizer.md:116` says the persona file defines tool permissions, but the adapter does. `agents/*.md:11` asserts "You have NO tools to modify the workspace" regardless of host. Proposal: say this is host-dependent and point to the per-harness table.

## Completion Criteria

- Each item is either changed or explicitly documented as accepted, with a rationale.
- Unit tests cover the new path and write constraints where they are expressed in manifests (for example, extend `tests/unit/test_harnesses.py`).
- `docs/harnesses.md` states, per host, whether reviewer read-only is host-enforced or prompt-only.

Related: #261 (the medium-severity findings from the same review).

---
*Prepared with AI assistance (Claude, via a read-only two-reviewer static review); I reviewed the findings and the citations before filing.*
