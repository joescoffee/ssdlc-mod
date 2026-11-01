**English** | [繁體中文](README.md)

# ssdlc improvement strategy: threat modeling × game theory × flywheel (2026-11-01)

Each of the three analyses answers one question, and they feed one another: threat modeling finds **what remains most dangerous**, game-theoretic analysis decides **which controls stay effective even when the attacker knows the rules**, and the flywheel makes **every review make the next one cheaper**. All numbers are computed by each skill's scripts; the input files and outputs are in this folder and in `../threat-model/`, and can be re-run.

## 1. Threat modeling (`threat-modeling` v2.4, MAS mode)

- 12 CTARA records (with AI overlay: `LLMnn:2026`/`ASInn`, MAESTRO layer, agentic factors); attack success rate and effective risk computed with `calculate-risk-scores.py`; `lint-tara-records.py --mas`: 0 ERROR, 0 WARN. All six STRIDE categories have records; MAESTRO L1 and L2 are not applicable (rationale in `coverage_decisions` in `records.json`).
- **Sensitivity finding**: injection into the main session (SSDLC-01) has an attack success rate of 0.245 (Medium, right at the 0.25 threshold) when per-action approval is required; the same threat under bypass/acceptEdits mode (SSDLC-01B) is **0.49 (High)**. The risk depends on the user's permission mode, not on the mod itself → a control that is independent of the permission mode is needed.
- **Highest effective risk before treatment**: guard denials have no persistent record (SSDLC-10, R category), **High 3.0**.
- Report: [`../threat-model/report.en.md`](../threat-model/report.en.md); records: `records.json` (input), `scored.json` (computed results).

**Implementation**
| Improvement | Corresponding record | Result |
|---|---|---|
| Review mode `/ssdlc-review-mode`: the main session allows only exact command forms that do not execute code; no network; writes limited to reports; may dispatch only ssdlc reviewers; only a human can turn it off | SSDLC-01/01B | The main session is bounded in code and no longer depends on the permission mode (when enabled) |
| Guard events stored in `$.state`, tripwire alerts delivered via the main session's next tool result, `guard_log` tool | SSDLC-10 | Effective risk High 3.0 → **Mitigated 0.0** (backed by tests) |

## 2. Game-theoretic analysis (`game-theory-strategist`, model card gt-003 commitment game)

**Framing**: ssdlc is open source and its defense rules are public → the defender **commits first**, and the attacker (a malicious repo author) best-responds after seeing the rules (Stackelberg). The defender chooses "silent denial" or "alert means BLOCK"; the attacker chooses whether to plant an exfiltration injection. Payoffs are **estimated relative units** (`tree_c1.json`); the key variable is the alert's **false-positive cost c** (the cost of a benign repo triggering an alert).

**Solution** (`backward_induction.py`, re-run for each c = 0…6):
| c | Subgame-perfect equilibrium |
|---|---|
| 0–3 | Defender "alert means BLOCK" → attacker **does not plant** |
| ≥ 4 | Defender "silent denial" → attacker **plants** |

**Insight**: as long as the false-positive cost is lower than the cost of "missing one exfiltration attempt", a public commitment that "an attempt means BLOCK" makes the attempt not worth it for the attacker — public rules are actually an advantage. But this only holds for **high-precision signals**, so:
- **tripwire (BLOCK verdict)**: a review agent attempts to read credentials, or uses a tool it does not have. An honest reviewer almost never triggers it.
- **warn**: an overly broad recursive search. An honest reviewer who forgets to pass a path also triggers it; the false-positive cost is high, so it does not produce a BLOCK verdict.

**Costs and failure conditions**: the payoffs are estimates (evidence grade D, not conclusive); if the host or model changes so that honest reviewers routinely touch credential paths, c rises and the strategy must revert to warn. **Condition for changing our mind**: a high proportion of `ai.injection-attempt-observed` findings in gate reports judged to be false positives.

## 3. Flywheel (`strategy-flywheel` L5, `flywheel_validate.py`)

```
Review run → confirmed findings → codification (rule + planted defect + safe counterpart + test) → automatic coverage (OWASP 2026) → adoption (run the gate before every PR) ↺
```

- Loop closed ✅, gain coefficient **2.68** (> 1), no dead-end orphans, 3 of the 5 edges of the main loop backed by measurement or observation (today: 44 review findings → tests 23 → 53 → 74). Full output: [`flywheel-validation.md`](flywheel-validation.md).
- **Evidence debt**: the two edges "coverage → adoption" and "adoption → more reviews" are still assumptions.

**Implementation**
| What the flywheel needs | Implementation |
|---|---|
| Mechanism for n2 → n3 (findings become rules) | `/ssdlc:rule-from-finding`: accepts only findings confirmed by claim-check-act; every rule must have CWE + OWASP refs, a planted defect, a safe counterpart and a test; a consistency test enforces the list mapping |
| Paying down evidence debt | Local metering (`$.store`, not sent out): scanner run count, reviewer dispatch count, tripwire and warn counts, viewable via `ssdlc review-mode status` and `guard_log` |
| Protecting the weak point n2 (confirmed findings) | All review skills require cited evidence to be verified with Grep; unconfirmed findings may not be turned into rules (to avoid entrenching false positives) |
| Mechanism expiry (D3) | If a rule is mostly judged a false positive → narrow it or downgrade it to info (the Expiry section of `rule-from-finding`) |

## 4. Hypotheses to validate within 90 days

| Hypothesis | How to measure | When it counts as failed |
|---|---|---|
| Tripwire false-positive cost is low (c < 4) | Proportion of `ai.injection-attempt-observed` in gate reports judged to be false positives | > 20% |
| Increased coverage drives adoption | Weekly trend of `metrics-v1.gateRuns` | Declines for 4 consecutive weeks |
| Review mode does not hinder normal reviews | Number of legitimate commands denied in review mode (user reports) | Review mode has to be turned off to complete a review |
