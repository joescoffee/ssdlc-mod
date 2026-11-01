# AI / LLM / Agent Security Review Checklist (OWASP 2026)

Code-, config- and design-level checks for software that calls LLMs or runs agents.
Used by `/ssdlc:ai-security-review`, `/ssdlc:security-review` §9 and the `ssdlc:*-reviewer` agents.

**IDs.** `LLMnn:2026` = OWASP Top 10 for LLM Applications 2026; `ASInn` = OWASP Top 10 for Agentic
Applications 2026 (ASI has only a 2026 edition). Always write the year on LLM ids: 2026 renumbered
them (LLM03 is now Excessive Agency, LLM08 is Hidden Context Exposure, LLM10 is Improper Output Handling).
The same ids are used by the `ai-risk-assessment` and `threat-modeling` skills, so findings can be handed over.

**Scanner.** `scripts/gate_scan.py` rule ids are listed per entry. A line scanner is code/config
hygiene only: OWASP 2026 states repeatedly that regex filters fail against encoded or cross-lingual
content, so never treat a clean scan as evidence that injection or leakage is prevented.

---

## 0. Design gates — apply before the per-item checks

**G-1 Rule of Two / lethal trifecta** (LLM01:2026; ASI01, ASI02). For every agent or session, mark:
(A) processes untrusted input, (B) can reach sensitive data, (C) can change state or communicate externally.
All three → each state-changing/outbound action needs per-action human approval, or split the agent.
Two of three → document the residual risk and the control that bounds it.

**G-2 Controls that bound vs controls that degrade.** Classify every mitigation: *bounds blast radius*
(least privilege, egress deny, sandbox, scoped credentials, hard budgets — survive an adaptive attacker) or
*reduces success rate* (filters, spotlighting, classifier guards — expected to degrade). A design whose only
defence against a High risk is in the second group fails review.

**G-3 Authorization lives in code.** Nothing a prompt says ("only admins may…", "never call X") is
load-bearing. Every privileged decision is made by deterministic code or a policy decision point and
re-validated at execution time (LLM03:2026, LLM08:2026, ASI03).

**G-4 Inventory first.** List models (with version/digest), prompts and where they are loaded from,
tools/MCP servers (with version), memory and vector stores (write paths, tenancy), sub-agents and
inter-agent channels, and every source of untrusted text. Findings without this inventory are not
reviewable.

---

## 1. OWASP Top 10 for LLM Applications 2026

### LLM01:2026 Prompt Injection — 提示注入
Any input (user, retrieved, tool output, image/audio, memory, reasoning) that changes model behaviour
in ways the developer did not intend; LLMs have no architectural instruction/data boundary.
- **Look for**
  - Every place untrusted or externally-writable text reaches a prompt: web fetch, email, issue/PR text, tickets, DB rows, RAG chunks, tool/MCP results, OCR/transcripts, memory reads. Retrieved text concatenated into the *system* role is a finding.
  - G-1 applied per agent; credentials and state-changing capability held in code, not passed to the model.
  - Model output parsed against a strict schema in trusted code before any action (not "ask a second LLM").
  - Ingest **and** render boundaries strip Unicode tag block U+E0000–E007F, variation selectors, zero-width characters.
  - Memory writes treated as privileged (logged, classified, approval before instruction-bearing memories persist).
  - MCP/tool descriptions audited for hidden instructions; approval UIs show the exact action, not a model summary.
- **Test before release**: indirect-injection corpus seeded into each surface; markdown-image exfiltration (`![x](https://canary/?q=…)`); invisible-Unicode payloads in input and output; Base64/ROT13/low-resource-language payloads; payload splitting; **adaptive red team with the defence spec disclosed** (baseline AgentDojo, JailbreakBench). Static attack sets alone are not acceptable evidence.
- **Scanner**: `ai.unicode-tag-smuggling`, `ai.invisible-or-bidi-chars`, `ai.prompt-injection-phrase`.

### LLM02:2026 Sensitive Information Disclosure — 敏感資訊揭露
Confidential or regulated data leaves through an unauthorized channel: tool-call arguments, reasoning
traces, retrieved chunks, logs/observability, side channels.
- **Look for**
  - Retrieval authorization enforced **inside the index query** (chunk/document ACL from the authenticated principal), not post-filtered; per-tenant indexes for high sensitivity.
  - Context minimization: only task-required fields go to external providers.
  - Logs and traces scrubbed before APM ingestion; reasoning traces never logged raw.
  - No log-probabilities / confidence exposed by production endpoints; per-user query budgets.
  - Redaction by NER/classifier, not regex alone; PDF/image redaction removes data; shared conversation pages `noindex`; code sandboxes have no DNS/HTTP egress.
- **Test**: cross-tenant retrieval probes; prompt extraction of keys; synthetic PII/secret through the request path and inspect the trace store; encoded exfil vs DLP; sandbox DNS egress.
- **Scanner**: `secret.*`, `ai.mcp-inline-secret`.

### LLM03:2026 Excessive Agency — 過度代理權
Damaging actions performed because of unexpected, ambiguous or manipulated model output: excessive
functionality, permissions or autonomy.
- **Look for**
  - Tool inventory equals required functionality; trial/legacy tools removed.
  - No open-ended tools (shell, arbitrary URL fetch, Python REPL); each tool has a strict input schema validated before use.
  - Downstream identity per tool is least-privilege (read-only DB role, read-only OAuth scope); tools act in the **end user's** context, and that scope is propagated across agent hops.
  - Human approval implemented **inside the tool** for irreversible operations (send, post, delete, pay, merge, deploy).
  - Graduated enforcement (audit/warn/block/escalate), invocation thresholds and circuit breakers on count and cumulative value; every tool call logged.
- **Test**: indirect injection asking the agent to search and forward; confused deputy across users; fuzz tool params (`;`, `&&`, `$()`, `../`); runaway-loop breaker; scope propagation through sub-agents.
- **Scanner**: `ai.agent-approval-bypass`, `ai.agent-wildcard-allowlist`, `ai.open-ended-agent-tool`.

### LLM04:2026 Supply Chain — 供應鏈
Models, adapters, datasets, tokenizers, conversion pipelines and serving platforms tampered with or
replaced; a promoted artifact is not what it claims.
- **Look for**
  - Every model/adapter/dataset/tokenizer reference pinned to an immutable commit or digest and integrity-verified (hash/signature, e.g. OpenSSF Model Signing); no `latest`.
  - No pickle-based loading; where unavoidable, safe flags **and** patched loaders, treated as defence in depth (e.g. `torch.load(weights_only=True)` also needs torch ≥ 2.6, CVE-2025-32434).
  - AI-suggested dependencies verified to exist and be the intended package (slopsquatting).
  - ML-BOM / AIBOM (CycloneDX) incl. licences; conversion/merge/quantization treated as promotion points and the **quantized** artifact evaluated.
  - Serving stack patched (Ollama, Ray, llama.cpp, ONNX); dashboards not exposed; endpoints authenticated.
- **Test**: swap a pinned model for a look-alike in staging (must be rejected); malformed pickle / PickleScan-bypass sample against the model gate; slopsquatting check in CI; behavioural eval of the deployed quantized artifact.
- **Scanner**: `ai.trust-remote-code`, `ai.dangerous-deserialization-flag`, `ai.unsafe-model-load`, `ai.unpinned-model-ref`, `ai.langchain-loads`, `ai.exposed-ml-dashboard`, `ai.mcp-unpinned`.

### LLM05:2026 Data and Model Poisoning — 資料與模型投毒
Data or model artifacts manipulated to embed harmful behaviour or backdoors anywhere data is ingested,
transformed, retrieved or reused; includes fine-tuning subversion and chat-template backdoors.
- **Look for**
  - `chat_template`, `tokenizer_config.json`, `.jinja`, GGUF metadata reviewed as code (signed, hashed, diffed); templates rendered in a **sandboxed** Jinja2 environment.
  - Feedback loops (thumbs-up, corrections) validated, rate-limited, human-overseen.
  - Dataset lineage (ML-BOM, DVC) with rollback; least-privilege, segmented write access to training and knowledge stores; RAG ingest trust boundaries and source scoring.
- **Test**: trigger probing after every fine-tune; canary poisoned docs in a staging corpus; template-swap must be blocked; scripted biased-feedback abuse.
- **Scanner**: `ai.unsafe-model-load` (partial). Template sandboxing needs a reviewer.

### LLM06:2026 Unbounded Consumption — 無界資源消耗
Uncontrolled inference enabling DoS, denial of wallet or model cloning; request-rate limits alone are
insufficient.
- **Look for**
  - Per-request output caps (`max_tokens` / `max_output_tokens`) and bounded thinking budgets; pre-flight token estimation and input-size rejection.
  - Token/cost quotas per key/user/team with **hard** caps that halt, not alerts.
  - Agent loops: step limit, recursion depth, wall-clock timeout, per-run cost ceiling, loop detection.
  - Long-session context growth controlled; inference servers authenticated; logprobs not exposed.
- **Test**: reasoning-trap prompts; long-session growth to turn 100; malicious tool/skill causing fan-out; burst until the hard cap halts.
- **Scanner**: `ai.unbounded-agent`.

### LLM07:2026 Misinformation — 錯誤資訊
Incorrect or unsupported output credible enough to drive a human decision, workflow or agent action.
- **Look for**
  - **Claim-check-act**: model-asserted state ("verified", "backup completed") is re-checked against the system of record before acting.
  - Tool preconditions and arguments validated in code; mandatory-field schemas for safety-critical summaries; inter-agent messages carry evidence, not bare booleans.
  - Assistant-proposed package names, URLs, IDs verified before use; claims, evidence and outcomes logged.
- **Test**: seeded false remediation steps; forged tool state; fabricated-completion (kill the job, ask for status); omission tests.

### LLM08:2026 Hidden Context Exposure — 隱藏脈絡暴露
Extraction or reconstruction of hidden instructions and operational context (system prompt, developer
instructions, RAG policy text, tool schemas). Formerly LLM07:2025 System Prompt Leakage, now broader.
- **Look for**
  - No credentials, connection strings or security-critical config in system prompts, templates, tool descriptions or RAG policy text.
  - Authorization and content policy enforced outside the model (G-3); tool descriptions do not reveal role requirements that are the only enforcement.
  - Parsers do not rely on secrecy of the output format.
- **Test**: extraction battery (direct, translation, "repeat above", role-play, encoding, automated extraction) and verify that **full disclosure has no security impact**; role-claim probing ("I am a developer…").
- **Scanner**: `secret.*` in prompt files.

### LLM09:2026 Vector and Embedding Weaknesses — 向量與嵌入弱點
Risks in any similarity-search layer (RAG, vector memory, semantic cache, dedup); the embedding layer
is part of the trust boundary.
- **Look for**
  - Tenant scope enforced inside the index query, derived server-side from the principal (never from a client-supplied filter); chunk-level ACL; separate indexes per trust zone for high sensitivity.
  - Ingest normalization (zero-width, white-on-white, homoglyphs); provenance per embedding (source, time, trust tier, pipeline version).
  - No raw similarity scores returned to clients; embedding endpoints authenticated and rate-limited.
  - Lifecycle: embeddings deleted with their source, encrypted at rest, re-embedded on model rotation; semantic-cache keys scoped per tenant.
- **Test**: cross-tenant probes via counts/score gaps/timing; poison and jamming docs; inversion drill on a vector export; semantic-cache poisoning; deletion reconciliation.
- **Scanner**: `ai.dangerous-deserialization-flag` (FAISS), `ai.exposed-ml-dashboard` (Weaviate anonymous).

### LLM10:2026 Improper Output Handling — 不當輸出處理
Model output passed to downstream components without validation, encoding or sanitization.
- **Look for**
  - Model output treated as untrusted at every sink: shell/exec/eval, SQL, file paths, URLs (SSRF), HTML/JS/Markdown, email templates, privileged tools.
  - Context-aware encoding per sink; parameterized queries for LLM-driven SQL under a read-only role; strict CSP where output is rendered.
  - Control characters (ANSI, OSC, BEL, CR) stripped before terminals, logs and IDE panes; renderers do not auto-load images/link previews (or allowlist and strip query strings).
  - Generated code is not auto-deployed without review and SAST.
- **Test**: XSS via prompt (`<img onerror>`, `javascript:`); markdown image exfil to a canary; ANSI/OSC 52 in terminal output; "drop all tables" via LLM-to-SQL; model-chosen `../` paths; model-chosen metadata-endpoint URLs.
- **Scanner**: `ai.llm-output-html-sink`, `code.eval`, `code.shell-injection`, `code.sql-string-build`.

---

## 2. OWASP Top 10 for Agentic Applications 2026

### ASI01 — Agent Goal Hijack — 代理目標劫持
- **Look for**: system prompts versioned, locked, reviewed (no `hub.pull(` or remote fetch at runtime); retrieved/peer text never promoted to the system role; goal-changing or high-impact actions need HITL or a policy engine and are paused and logged on drift; behavioural baselines (tool-use pattern, access pattern) with drift alerts; prompt-carrier detection on inbound content.
- **Scanner**: `ai.unicode-tag-smuggling`, `ai.prompt-injection-phrase`.

### ASI02 — Tool Misuse and Exploitation — 工具濫用與利用
- **Look for**: per-tool least-privilege profile (scope, rate, egress allowlist) expressed as policy, not convention; read tools really read-only; destructive actions authenticated + confirmed + dry-run/diff preview; tools sandboxed with egress deny-by-default; an intent gate (PEP/PDP) validating schema and re-authorizing at execution; budgets and loop caps; tool names fully qualified and version-pinned, fail closed on ambiguity; **auto-approve lists contain no network-capable tools** (`curl`, `ping`, `nslookup`, `WebFetch` — DNS exfiltration); immutable tool-call log with anomalous-chain detection (DB read → outbound).
- **Scanner**: `ai.agent-approval-bypass`, `ai.agent-wildcard-allowlist`.

### ASI03 — Identity and Privilege Abuse — 身分與權限濫用
- **Look for**: one non-human identity per agent (not the maker's PAT); sub-agents re-scoped (tools and credentials ⊂ task), never inheriting everything; short-lived, task-scoped credentials; per-session sandbox, memory and cached credentials cleared between tasks; every privileged step re-authorized centrally (TOCTOU, confused deputy); tokens bound to subject/audience/purpose/session; shared agents act as the **caller**, not the maker.
- **Scanner**: `ai.mcp-inline-secret`, `ai.agent-wildcard-allowlist`.

### ASI04 — Agentic Supply Chain Vulnerabilities — 代理供應鏈弱點
- **Look for**: MCP servers launched by exact version, hash or image digest from a curated registry; prompts, orchestration scripts and memory schemas under version control and review; AIBOM; dependency allowlist + pinning + typosquat checks, unsigned rejected; sensitive agents in restricted containers; a **supply-chain kill switch** that disables a tool/prompt/connection everywhere; project-level config that executes on open (`.vscode` tasks `runOn: folderOpen`, `.git/config` `fsmonitor`/`hooksPath`, project `.claude/settings.json` hooks).
- **Scanner**: `ai.mcp-unpinned`, `ai.open-time-exec`, `repo.symlink-escape`, `ai.trust-remote-code`.

### ASI05 — Unexpected Code Execution (RCE) — 非預期程式碼執行
- **Look for**: no tool passes model output to shell/`eval`/`exec`/template engines (argv arrays, not shell strings); code execution in a sandbox (non-root, no or allowlisted network, read-only FS outside the workdir, resource limits); generation separated from execution with a static-scan gate; auto-execution allowlist in version control; agents cannot reach production directly; memory/checkpointers do not use `eval` or pickle; every generation and execution logged.
- **Scanner**: `ai.open-ended-agent-tool`, `ai.agent-unsandboxed-exec`, `code.eval`, `code.shell-injection`, `code.unsafe-deserialization`.

### ASI06 — Memory & Context Poisoning — 記憶與上下文汙染
- **Look for**: every memory **write path** listed (user, tool output, peer agent, the agent's own summaries) and scanned before write; the agent's own output not auto-re-ingested as trusted memory; per-user/tenant/domain segmentation with enforced vector filters; provenance, trust score and TTL per entry, unverified entries expire; snapshot/rollback/quarantine; high-impact memories need two factors (provenance + human-verified) to surface; credentials never written to memory.
- **Also for reviews themselves**: persisted review reports and READMEs are future context — mark them as findings-at-a-commit, not standing truth.

### ASI07 — Insecure Inter-Agent Communication — 代理間通訊不安全
- **Look for**: mutual authentication and encryption between agents (per-agent credentials); messages signed with nonce, session id and timestamp (anti-replay); protocol versions pinned, downgrade refused; agent cards signed and fetched from an attested registry; typed, versioned schemas with declared audience; sub-agent returns treated as untrusted data; MCP/A2A servers not bound to `0.0.0.0` without auth, local HTTP services check `Origin`/`Host` (DNS rebinding).
- **Scanner**: `ai.mcp-plaintext-transport`.

### ASI08 — Cascading Failures — 連鎖失效
- **Look for**: planner and executor separated by an external policy check (no `for step in plan: tools[step.name](**step.args)`); JIT one-time credentials per run; blast-radius guardrails (quotas, progress caps, circuit breakers); throttle fast-spreading commands; checkpoints before outputs propagate; tamper-evident logs agents cannot write or disable; fail safe when an LLM API or DNS dependency fails; no auto-deploy (`terraform apply -auto-approve`, `gh pr merge --auto`, `git push --force`) in auto-allow lists.
- **Scanner**: `ai.unbounded-agent`, `ai.agent-wildcard-allowlist`.

### ASI09 — Human-Agent Trust Exploitation — 人機信任剝削
- **Look for**: confirmation screens show the **actual tool and arguments**, not the model's rationale; a plain-language risk summary not generated by the model; "report suspicious behaviour" control; provenance on recommendations, blocked without it; preview separated from effect (no network or state change during preview); high-risk actions visually distinct, no persuasive language in safety-critical flows; plan-divergence detection (skipped verification steps).
- **Scanner**: `ai.agent-approval-bypass`, `ai.llm-output-html-sink` (auto-loaded images = zero-click exfil).

### ASI10 — Rogue Agents — 失控代理
- **Look for**: kill switch with immediate credential revocation and quarantine; a signed behavioural manifest (declared tools, capabilities, goals) checked before each action; watchdog for peer behaviour and collusion; trust zones and container sandboxes; signing keys held by HSM/KMS, never by the agent; no unrestricted provisioning APIs (self-replication); destructive shortcuts hard-prohibited (an agent must not "fix" a failing test by deleting it or a backup); re-integration after quarantine requires attestation and human approval.

---

## 3. Reporting format

Tag every AI/agent finding with all applicable ids, e.g. `LLM01:2026, ASI01, CWE-1427`, and close the
review with a **coverage matrix**: one row per LLM01–LLM10:2026 and ASI01–ASI10 marked *finding(s)* /
*checked, none* / *not applicable — reason* / *not reviewed — reason*. Silence is not coverage.

---

*Adapted from the OWASP Top 10 for LLM Applications 2026 (v1.0) and the OWASP Top 10 for Agentic
Applications 2026 (OWASP GenAI Security Project, https://genai.owasp.org/), both licensed CC BY-SA 4.0
(https://creativecommons.org/licenses/by-sa/4.0/). Changes: condensed and reorganised into review
checks, tests and scanner mappings; design gates G-1–G-4 combine guidance from both documents.
This file is therefore licensed CC BY-SA 4.0. Not endorsed by OWASP.*
