<!--
【中文審閱版，送出時請用英文版 A-private-vulnerability-report.md】
管道：私下回報。請經由 https://g.co/vulnz（Google Bug Hunters／OSS VRP）送出；
若 google/elephant-goldfish-model 的 Security 分頁有「Report a vulnerability」，也可用它。
請勿開成公開 issue。
-->

**標題：** egm-bootstrap 可能執行被審查 repo 中由攻擊者控制的程式碼；數條路徑上的「唯讀」保證只靠提示文字；簽署 release 的 job 安裝未鎖 hash 的依賴

**產品：** google/elephant-goldfish-model（EGM plugin），commit `403d8881d62022490637d740657b33f01e321ea8`（v0.1.0）

## 摘要

我們以唯讀方式審查這個 repo，找到五項 Medium 等級的問題。沒有後門或惡意程式碼，Claude Code 的 reviewer adapter 也正確限制為 `Read, Grep, Glob`。但當 EGM 審查**不受信任的 repo** 時，這些問題讓該 repo 的內容有機會觸發程式執行或不受限的檔案寫入。另有一項問題影響 release 簽章（attestation）的完整性。

## 1. egm-bootstrap 會執行目標 repo 設定的 formatter（程式碼執行）

- `skills/egm-bootstrap/SKILL.md:60-64, 323-326` 告訴 orchestrator：「如果 repo 有設定」markdown formatter（例如 `npx prettier --write`），就「可以執行」。
- `docs/designs/bootstrap.md:512-515, 552-554` 更進一步，要求**每次**修改 README 後都透過 `run_command` 執行 formatter，與 SKILL 的寫法不一致。
- 觸發條件「repo 有設定」由 repo 的作者決定。`prettier.config.js`、本地 plugin，或預先放好的 `node_modules/.bin/prettier`，都能執行任意程式碼。本機沒裝 prettier 時，`npx` 還可能從 registry 下載套件。
- orchestrator 握有 `Bash`（`.claude-plugin/agents/bootstrap_orchestrator.md:5`），唯一的控制是 host 的 Bash 權限提示。在 acceptEdits／bypass 模式下，或已有允許 `npx` 的規則時，不會跳出任何提示。

**建議修正：** 預設不執行 formatter；要執行時須取得使用者明確同意，並顯示完整指令；不使用 `npx`；讓 `docs/designs/bootstrap.md` 與 SKILL 的寫法一致。

## 2. 擁有 Bash/Write/Edit 的 orchestrator 讀取不受信任的 repo 文字（prompt injection）

- `bootstrap_orchestrator.md:5` 授予 `Agent, Bash, Read, Grep, Glob, Write, Edit`。`SKILL.md:227-241, 280-281` 會把既有 README 的內容和 scout 摘要餵回這個 context。
- 寫在 README 或原始碼註解中的注入指令，會送到一個能執行 shell 的 agent 手上。
- 產生的 README 被定位為「給未來 AI 助理的契約」（`SKILL.md:16-19`），所以注入的文字還可能被寫進去並長期留存，影響之後的 agent session。
- 目錄探索本來就用 Glob/Read（skill 明文禁止 `find`/`ls -R`），看起來並不需要 Bash。

**建議修正：** 移除 orchestrator 的 `Bash`；明文規定 repo 內容一律是資料、不是指令；寫入只限目標 README 的路徑；合併 scout 的 JSON 前，先用 `worker-return.schema.json` 驗證。

## 3. 在 Claude adapter 以外，reviewer 的「唯讀」只靠提示文字

- Claude Code 只載入 `.claude-plugin/agents/*`（依 `.claude-plugin/plugin.json:18-28`），這些都正確受限。但有三個例外：
  - `skills/egm-review/SKILL.md:21-26`（egm-review-loop、egm-brainstorm、egm-bootstrap 也一樣）有 fallback：「spawn 一個 general-purpose subagent，叫它先讀 persona 檔」。general-purpose subagent 擁有完整工具。
  - 在 Codex、ChatGPT、Antigravity、omp 上，reviewer 是 general-purpose agent，或使用沒有 `tools` 限制的 `agents/*.md`。persona 寫的「You have NO tools to modify the workspace」（`agents/*.md:11`）在這些 host 上不成立。`tests/integration/test_codex.py:200-201` 本身就用 `--sandbox workspace-write` 執行。
  - bootstrap 的 `goldfish-explorer` scout 只在 harness 支援執行期定義 subagent 時才是唯讀（`SKILL.md:204-219`），Claude Code 不支援。

**建議修正：** 在 Claude Code 上，找不到 `egm:egm-*` 類型時直接停止，不要 fallback；在文件中逐一標明各 host 的唯讀並非由 host 強制；新增一個已註冊的唯讀 `egm-goldfish-explorer` adapter；加入負向測試，驗證 reviewer 嘗試 Write/Bash 時會被拒絕（`docs/designs/multi_harness_support.md:136-137` 本來就要求這類測試）。

## 4. spawn subagent 時未限制類型

`synthesizer.md:5` 與 `bootstrap_orchestrator.md:5` 都有 `Agent` 工具，但沒有限制能 spawn 哪些 agent 類型。被 prompt injection 的 synthesizer 可以 spawn 一個 general-purpose agent，藉此重新取得 Bash 或網路存取。adapter 只在說明文字中限制這件事（`synthesizer.md:12-13`）。

**建議修正：** host 支援的話，限制可 spawn 的類型；不支援的話，改由主 context 直接派送 reviewer。

## 5. 簽署 release 的 job 安裝未鎖 hash 的依賴

`.github/workflows/release.yml:23-26` 授予 `id-token: write` 與 `attestations: write`，同一個 job 的第 `:49` 行又執行 `pip install pytest==8.3.5 pyyaml==6.0.2`。直接依賴有鎖版本，但間接依賴（pluggy、iniconfig、packaging）既沒鎖版本也沒鎖 hash。只要其中一個間接套件被入侵（例如透過 `.pth` 檔），就能在 `actions/attest` 簽章前竄改 `release/*.zip`，而 `gh attestation verify` 照樣會通過。

**建議修正：** 把測試移到另一個沒有 OIDC／attestation 權限的 job，build＋attest 的 job 只用標準函式庫（`prepare_release.py` 本來就是）；或改用 `pip install --require-hashes`。

## 已確認沒有問題的項目

- 沒有 hooks、MCP server 或 commands，打包程式也會拒絕它們。
- 7 個 skill 都設了 `disable-model-invocation: true`。
- Actions 都釘選 SHA、設 `persist-credentials: false`、權限最小化；`pr-scope-advisory.yml` 使用 `pull_request_target` 的方式是安全的。
- `pack_plugin.py` 有檢查 symlink 與相對路徑，而且沒有解壓步驟（不會有 zip-slip）。

## 審查方法

這是靜態、唯讀的審查，由兩位互相隔離的審查員進行：一位做設計層的威脅建模，一位只看程式碼。每項發現都回到原始碼重新核對。我們沒有拿惡意 repo 實際執行 EGM；上述攻擊情境是依據引用的指示與工具授權推導出來的。

回報者：joescoffee（https://github.com/joescoffee）
