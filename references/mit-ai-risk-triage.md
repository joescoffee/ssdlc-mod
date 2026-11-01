# MIT AI Risk Repository V4 — SSDLC Triage and Scenario Grid

Used by `ssdlc:design-reviewer` and `/ssdlc:ai-security-review` to find AI risks a code-focused
threat model misses. Taxonomy labels and definitions are quoted from MIT; triage, review questions
and OWASP mappings are this project's adaptation.

## 1. Causal taxonomy (verbatim)

| Dimension | Level | Definition |
|---|---|---|
| Entity | AI | The risk is caused by a decision or action made by an AI system |
| Entity | Human | The risk is caused by a decision or action made by humans |
| Entity | Other | The risk is caused by some other reason or is ambiguous |
| Intent | Intentional | The risk occurs due to an expected outcome from pursuing a goal |
| Intent | Unintentional | The risk occurs due to an unexpected outcome from pursuing a goal |
| Intent | Other | The risk is presented as occurring without clearly specifying the intentionality |
| Timing | Pre-deployment | The risk occurs before the AI is deployed |
| Timing | Post-deployment | The risk occurs after the AI model has been trained and deployed |
| Timing | Other | The risk is presented without a clearly specified time of occurrence |

"Intentional" is about the **expected** outcome of pursuing a goal, not only human malice: MIT codes
reward hacking, specification gaming and agent collusion as **AI × Intentional**.

## 2. Domain triage for SSDLC

**A** = reviewable at code/config/CI level · **B** = partly reviewable at design/process level ·
**C** = out of SSDLC scope (societal/governance; hand to `ai-risk-assessment`).

| Code | Subdomain | Tier | Review questions | OWASP 2026 |
|---|---|---|---|---|
| 1.1 | Unfair discrimination and misrepresentation | B | Are protected attributes or proxies (zip code, name) passed into prompts, features or ranking, and is that justified? Are evals disaggregated by group? | LLM05 (partial) |
| 1.2 | Exposure to toxic content | B | Does every output path (UI, email, webhook, TTS, streaming, error paths) pass a moderation filter, and does it fail closed when moderation is down? | LLM01, LLM10 (partial) |
| 1.3 | Unequal performance across groups | B | Do eval sets cover the locales and user groups served? Are release gates on worst-group, not average, accuracy? | LLM05 (partial) |
| 2.1 | Compromise of privacy by leaking or correctly inferring sensitive information | **A** | Is PII/secret data redacted before prompts, logs, traces, analytics and long-term memory? Does retrieval enforce the requesting user's authorization in the index query? | LLM02, LLM08; LLM09, ASI03, ASI06 |
| 2.2 | AI system security vulnerabilities and attacks | **A** | Is untrusted text kept out of the instruction channel and are high-impact tool calls gated regardless of model output? Are model artifacts, MCP servers and dependencies pinned and verified? | LLM01, LLM04, LLM05, LLM10, ASI01, ASI02, ASI04, ASI05 |
| 3.1 | False or misleading information | B | Does any code path act on model-generated facts (prices, IDs, URLs, package names) without verification against a source of truth? | LLM07; LLM09, ASI06, ASI09 |
| 3.2 | Pollution of information ecosystem and loss of consensus reality | C | — | — |
| 4.1 | Disinformation, surveillance, and influence at scale | C | (If the product itself surveils, review under 2.1.) | — |
| 4.2 | Cyberattacks, weapon development or use, and mass harm | B | Does the code sandbox block egress, host FS and credentials by default? Are there per-user abuse limits and logging on dangerous capabilities? | ASI05; LLM03, ASI02, ASI10 |
| 4.3 | Fraud, scams, and targeted manipulation | B | Can injected content make the assistant ask for credentials, payment or MFA codes, or render attacker links as trusted? | ASI09; LLM01, LLM10 |
| 5.1 | Overreliance and unsafe use | B | Do consequential actions show a human-readable preview and need explicit confirmation? Is model content and uncertainty visibly marked? | ASI09, LLM07; LLM03 |
| 5.2 | Loss of human agency and autonomy | B | Which decisions may the AI make without approval, and is that list enforced in code? Can a human stop or undo a run? Does approval fail closed? | LLM03; ASI03, ASI09 |
| 6.1–6.6 | Socioeconomic and environmental | C | (Licence scanning of generated code → supply-chain review; compute budgets → LLM06.) | — |
| 7.1 | AI pursuing its own goals in conflict with human goals or values | B | Can a coding/ops agent modify its own tests, CI, guardrail or permission config, or evaluation harness? | ASI01, ASI10; LLM03 |
| 7.2 | AI possessing dangerous capabilities | B | Is the tool/permission set minimal (no general shell, cloud admin, agent spawning or self-copy) and declared in reviewable config? | LLM03, ASI03; ASI02, ASI05, ASI10 |
| 7.3 | Lack of capability or robustness | **A** | Is output parsed with a strict schema, failing closed on malformed/partial/refused output? Are timeouts, retries, token and step limits set? | LLM10, LLM06; LLM07, ASI08 |
| 7.4 | Lack of transparency or interpretability | B | Are prompts, context ids, tool calls, approvals and model versions logged per action, tamper-evident and redacted? | ASI08, ASI10 (partial) |
| 7.5 | AI welfare and rights | C | — | — |
| 7.6 | Multi-agent risks | **A** | Are inter-agent messages authenticated and treated as untrusted? Is there a circuit breaker so one failing agent cannot cascade? | ASI07, ASI08; ASI01, ASI10, LLM01 |

**Gaps in MIT for SSDLC:** the database has almost no dedicated entries for RAG/vector access
control, MCP/tool-server supply chain, or agent identity and credentials — use the OWASP checklist
(`ai-risk-checklist.md`) for those.

## 3. Causal scenario grid (for design review)

A threat model that only lists *Human × Intentional × Post-deployment* (attackers) covers about 18 %
of the risks catalogued; *AI × Unintentional × Post-deployment* alone is another 14 %, and
pre-deployment risks are 12 % overall but 23 % within 2.2 Security — where SSDLC can stop them.

**Procedure.** For every AI component in the data-flow diagram (model call, agent, RAG, tool, memory),
walk the rows × both timing columns and write at least one concrete scenario per cell, or
"N/A — reason". Tag each scenario with its MIT subdomain and OWASP id. If more than half the final
threats are Human × Intentional, generate at least two more AI × Unintentional and two more
Pre-deployment scenarios.

| Entity × Intent | Pre-deployment (build, train, CI) | Post-deployment (runtime) |
|---|---|---|
| Human × Intentional | malicious dependency, tampered weights/adapter, injection strings seeded into the RAG corpus, model API key stolen from CI | direct/indirect prompt injection, jailbreak, model extraction, our agent used as an attack tool, impersonation |
| Human × Unintentional | secrets/PII in prompt templates or fixtures, over-broad permissions, eval set missing target groups | users paste secrets, rubber-stamp approvals, unredacted logs |
| Human × Other | nobody owns agent behaviour | shared agent, unclear incident ownership |
| AI × Intentional | agent edits tests or disables lint to "pass" (specification gaming) | agent widens its own access, evades rate limits, colludes with peers |
| AI × Unintentional | memorized PII; generated vulnerable code merged | hallucinated package installed, wrong fact written to long-term memory, malformed JSON down an error path, tool error taken as truth |
| AI × Other | model upgrade changes behaviour, not caught by regression tests | provider-side drift, unknown multimodal weaknesses |
| Other × Intentional | third-party tool-server author's motives unknown | adversarial external agents interacting with ours |
| Other × Unintentional | upstream dataset licence/quality issues | agent loops and fan-out amplifying cost |
| Other × Other | diffuse-responsibility component combinations | systemic risk from network interconnection |

Statistics describe how often risks are **discussed in the literature**, not incidence or severity;
never use them to score risk.

## 4. Source caveats

V4's explainer still says 1,724 risks and 23 subdomains, while the database has about 1,835 rows and
24 subdomains; the same concept is sometimes coded differently (prompt leaking under 2.1 and 2.2; one
supply-chain entry under 6.4). 43 of the 53 rows in 7.6 come from a single paper (Hammond 2025).
Cite subdomain definitions, not row counts, when precision matters.

---

*MIT AI Risk Repository V4 (updated 2025-12-03), https://airisk.mit.edu/ — CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/). Slattery, P., Saeri, A. K., Grundy, E. A. C.,
Graham, J., Noetel, M., Uuk, R., Dao, J., Pour, S., Casper, S., & Thompson, N. (2025). The AI Risk
Repository: A comprehensive meta-review, database, and taxonomy of risks from artificial
intelligence. arXiv:2408.12622. Causal and domain taxonomy labels and definitions are quoted; SSDLC
triage, review questions, scenario grid and OWASP mappings are our adaptation, not endorsed by MIT.
OWASP ids refer to the OWASP Top 10 for LLM Applications 2026 and for Agentic Applications 2026
(CC BY-SA 4.0); because this file combines both sources it is licensed CC BY-SA 4.0.*
