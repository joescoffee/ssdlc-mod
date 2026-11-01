---
name: rule-from-finding
description: Turn a confirmed security finding into a permanent check — a gate_scan rule with OWASP 2026/CWE refs, a planted-defect fixture, a safe counterpart, unit tests and a checklist mapping — so the same mistake is caught mechanically next time. Use after a review or vuln-fix confirms a finding that a pattern could detect, or when asked to "add a rule for this".
disable-model-invocation: true
---

# Rule from finding (the improvement flywheel)

Every confirmed finding that a pattern can detect should become a rule, so reviews get cheaper and the
next reviewer can spend its attention on design (see `docs/strategy/README.md`, flywheel node n2 → n3).
Only **confirmed** findings qualify: one that was re-verified at its `path:line` (claim-check-act). An
unverified finding turned into a rule freezes a false positive into every future gate.

## 1. Decide whether it is pattern-detectable
- Yes: a specific API, flag, config key, character class or file shape whose presence is the defect
  (`trust_remote_code=True`, `"autoApprove": [...]`, a `.git/config` key).
- No: it needs data-flow or design reasoning (missing authorization, Rule-of-Two violations). Then add
  a review question to `references/ai-risk-checklist.md` instead, and stop.

## 2. Write the rule (`scripts/gate_scan.py`, `RULES`)
- Id: `code.*` (general), `secret.*`, `ai.*` (LLM/agent), `repo.*` (repository structure).
- Severity by exploit impact; refs: at least one `CWE-n`; AI rules must also carry `LLMnn:2026` and/or `ASInn`.
- Bound every quantifier (`{0,400}`, never `.*` or `[^)]*`): lines come from hostile repositories.
- Comment the provenance: `DOC` (stated in the source standard) or `STD` (standard practice).

## 3. Prove it both ways (`tests/`)
- **Planted defect**: a line in a fixture under `tests/fixtures/` that the rule must flag. Add it to an
  existing vulnerable fixture or create one; never put a real secret in it (build values in Python).
- **Safe counterpart**: the corrected form in a safe fixture that must stay clean — this is what keeps
  the false-positive rate, and therefore the gate's adoption, healthy.
- A unit test in `tests/test_gate_scan.py` asserting both.

## 4. Map it
- Add the rule id to the matching entry's **Scanner** line in `references/ai-risk-checklist.md`
  (AI rules) — `ChecklistConsistency` fails until you do.
- Add a row to the README scanner table if it opens a new category.

## 5. Check and record
- `python3 -I -m unittest discover -s tests` and `claude plugin test .` both pass.
- Run the scanner over the repository the finding came from: the rule fires on the original line.
- Commit message: `rule(<id>): <finding id> — <one line>`; note the finding's source review.

## Expiry
A rule that fires mostly on safe code is a liability: users stop reading the gate. If a rule's
dismissal rate in gate reports is high, narrow it or downgrade it to `info`, and say so in the commit.
