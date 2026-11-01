<img src=".claude-plugin/icon.png" width="96" align="right">

# ssdlc — Secure SDLC mod for Claude Code

Security skills and truly read-only reviewer agents for Claude Code.

在 Claude Code 中落實安全軟體開發生命週期（SSDLC）：安全審查、PR 前閘門、漏洞修復流程，以及 **Elephant-Goldfish Model（EGM）審查的真正唯讀版本**。審查員只有 Read/Grep/Glob（工具限制由 frontmatter 與 hook 強制），hook 另擋憑證路徑與從根目錄、家目錄的遞迴搜尋；「只讀 repo 內、不開 repo 外連結」則是提示層約束。所有流程都不執行被審 repo 的程式碼。

## 安裝 / Install
```
claude plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```
對話中：`/plugin install ssdlc --marketplace joescoffee/ssdlc-mod`。

📘 **新手請從 [新手操作手冊](docs/manual/README.md) 開始**：安裝、五分鐘上手、六個技能逐步教學、審查不受信任 repo 的完整流程、掃描器 CLI 與 CI、疑難排解。

## 示範 / Demo
![ssdlc 實機示範（v0.5.0）](docs/demo.png)

①～③ 皆為實際輸出：掃描器以 `--json` 執行後整理成表格；② 取自 Claude app 中的實機驗證（2026-11-01）。

## 實戰案例：審查 EGM 本身 / Case study
用 `/ssdlc:safe-bootstrap` 審查上游 [google/elephant-goldfish-model](https://github.com/google/elephant-goldfish-model) @ `403d888`：Elephant（設計威脅建模）與 Goldfish（零背景程式碼審查）平行執行，再合併、交叉驗證。

| 結果 | 內容 |
|---|---|
| 判定 | **FIX-BEFORE-MERGE**：無 Critical、無惡意內容；在 Claude Code 上用於可信任 repo 安全 |
| Medium ×5 | bootstrap 執行 repo 設定的 formatter（可 RCE）、orchestrator 握有 Bash 又讀不受信任內容、非 Claude host 的「只讀」只有文字約束、release job 的未鎖 hash 依賴與 OIDC 權限在同一 job、`Agent` 未限制 spawn 類型 |
| Low ×7、Info ×1 | 自動讀取連結路徑、synthesizer 寫入路徑未限制、artifact 目錄劫持、marketplace 未鎖版本等 |
| 推翻前次結論 | Claude Code 的 EGM reviewer **確實**只有 Read/Grep/Glob |
| 建議 | 不受信任的 repo 不要跑 `/egm-bootstrap`，改用 `/ssdlc:safe-bootstrap` |

完整報告（13 項，含 file:line 證據）：[`docs/reviews/egm-403d888.md`](docs/reviews/egm-403d888.md)

已回報上游：[google/elephant-goldfish-model#261](https://github.com/google/elephant-goldfish-model/issues/261)（F1–F5）、[#262](https://github.com/google/elephant-goldfish-model/issues/262)（F6–F13）。

## 運作方式 / How it works
![ssdlc 心智圖](docs/ssdlc-mindmap.png)

互動版：`docs/ssdlc-mindmap.html`（可縮放、拖曳、編輯）；狀態檔 `docs/mindmaps/ssdlc.mindmap.json`。

## Skills
| Command | 用途 |
|---|---|
| `/ssdlc:security-review` | 10 段安全標準審查：範圍、信任邊界、STRIDE、認證授權、危險輸入、secrets、密碼學、依賴、AI/代理風險、日誌 |
| `/ssdlc:ai-security-review` | LLM／RAG／代理程式審查：依 OWASP LLM Top 10 2026（`LLM01–10:2026`）、OWASP Agentic Top 10 2026（`ASI01–10`）與 MIT AI Risk Repository 因果分類；盤點 → 掃描 → Rule of Two 設計閘門 → 雙審查員 → 覆蓋矩陣 |
| `/ssdlc:security-gate` | PR 前閘門：secrets、危險模式與 AI／代理設定掃描、依賴稽核（只解析、不安裝、不執行專案程式）、diff 審查 → PASS / WARN / BLOCK / INCOMPLETE |
| `/ssdlc:vuln-fix` | 漏洞修復流程：分類 → 複現 → 根因修復 → 回歸測試 → 變體搜尋 → 紀錄 |
| `ssdlc review-mode on\|off\|status` | 審查模式：主 session 只允許精確、不執行程式的命令形式；無網路；寫檔限報告；只能派 ssdlc 審查員；只有使用者能關閉 |
| `/ssdlc:rule-from-finding` | 把確認的發現變成規則＋植入缺陷＋安全對照＋測試（持續改進飛輪） |
| `/ssdlc:safe-bootstrap` | EGM（Elephant-Goldfish Model）bootstrap 的真正唯讀版本 |

## Agents
- `ssdlc:security-reviewer` — 程式碼／diff 安全審查
- `ssdlc:design-reviewer` — 設計文件威脅建模（STRIDE + AI 風險）

兩者 frontmatter 只有 `Read, Grep, Glob`；`hooks/register.ts` 守門 hook 再加三層縱深防禦（OWASP ASI02／ASI03、LLM02:2026）：
- 審查代理呼叫 Read/Grep/Glob 與回報用的 `SubagentHandback` 以外的工具，一律拒絕；
- 不得讀取憑證儲存處（`~/.ssh`、`~/.aws`、`.env*`、金鑰檔、`~/.claude/.credentials.json`、`/proc` 等），含 Grep/Glob 的 glob 參數；
- **白名單**：每個審查員只能讀派它出去的 prompt 中明確寫出的絕對路徑（沒寫時改用工作目錄）與本 plugin 目錄；根目錄、家目錄、憑證位置不會被收進白名單；
- 先以 `$.fs.stat` 解析 symlink 實際落點再判斷，repo 內指向憑證的連結也會被擋；
- **tripwire**：審查代理嘗試讀憑證或使用禁用工具＝提示注入跡象，警報會附在主 session 的下一個工具結果，技能據此判 BLOCK；
- **存活檢查與紀錄**：`mcp__ssdlc__guard_log` 回報 guard 版本、載入時間與規則自我檢查；每個技能派審查員前都先呼叫它，guard 不在或自我檢查失敗就停止（INCOMPLETE）。拒絕紀錄跨 session 保存在本機（最多 500 筆）。

## Scanner
`scripts/gate_scan.py` 只用標準函式庫、不連網、不跟隨 symlink。每筆發現附 `refs`（CWE、`LLMnn:2026`、`ASInn`）。

| 類別 | 規則 |
|---|---|
| Secrets | AWS／GitHub／Anthropic／OpenAI／Slack 金鑰、私鑰、硬編碼帳密（只顯示前 4 字元） |
| 一般程式 | shell injection、eval、不安全反序列化、SQL 字串組合、關閉 TLS 驗證、弱雜湊、弱亂數 |
| 提示載體（LLM01:2026） | Unicode tag 隱寫（**解碼顯示隱藏文字**、不回顯原字元）、零寬／bidi 字元、注入片語 |
| 模型供應鏈（LLM04:2026） | `trust_remote_code`、`allow_dangerous_deserialization`、不安全模型載入、未鎖版本模型、LangChain `loads`、對外暴露的 Ray／Weaviate |
| 代理權限（LLM03:2026、ASI02／05） | 核准繞過（`bypassPermissions`、`--dangerously-skip-permissions`、`autoApprove`、`--yolo`）、萬用允許清單、開放式 REPL／shell 工具、未沙箱執行、無上限迴圈、開啟即執行的設定（`.git/config` fsmonitor、`runOn: folderOpen`）、模型輸出進 HTML sink |
| MCP 設定（JSON 解析） | 未鎖版本的 `npx`／`uvx`／`@latest`、`env`／`headers` 內嵌密鑰、非本機的明文 HTTP |
| Repo | 指向 repo 外的 symlink |

`# ssdlc: allow <理由>` 標記**預設不採用**（被審程式碼也能寫標記）；只有加 `--honor-markers` 才生效，且永遠不能隱藏 secret 與隱形字元發現。無法讀取、非一般檔案、過大的檔案會列為 skipped，並以結束碼 3（INCOMPLETE）表示掃描不完整。

## References
`references/ai-risk-checklist.md`（OWASP 2026 逐項審查、測試與規則對照）、`references/mit-ai-risk-triage.md`（MIT 24 子域 SSDLC 分流與因果情境格）。這兩份改編自 CC 授權文件，採 **CC BY-SA 4.0**；其餘程式碼為 MIT。

## 改善策略 / Strategy
威脅建模、賽局分析與飛輪如何決定這一版的改善：[`docs/strategy/README.md`](docs/strategy/README.md)；威脅模型報告：[`docs/threat-model/report.md`](docs/threat-model/report.md)。

## 已知限制 / Known limitations
經 v0.2.0 自我審查（[`docs/reviews/ssdlc-0.2.0-self-review.md`](docs/reviews/ssdlc-0.2.0-self-review.md)）後仍未解決、如實揭露的項目：

1. **主 session 的約束需要手動開啟**（T1）：`ssdlc review-mode on` 會在 code 中界定主 session；沒開啟時，只能靠流程與 Claude Code 的逐次核准。**審查不受信任的 repo 前請先開啟審查模式**。
2. **審查員白名單由派遣 prompt 決定**（SR-1、T5，v0.4.0 起）：範圍是工作目錄、plugin 目錄與 prompt 中的絕對路徑；主 session 若被注入而把不該讀的目錄寫進 prompt，白名單會放行（憑證黑名單仍擋）。
3. **TOCTOU 與 hard link**（SR-16）：guard 檢查與實際讀取之間有時間差；hard link 無法以 realpath 辨識。需 OS 層 sandbox。
4. **未驗證的宿主行為**：Claude Code 的 Grep 是否搜尋隱藏檔、子目錄 `CLAUDE.md` 是否延遲載入，未實測。
5. **掃描器是程式碼衛生檢查**，不是執行期的注入或 DLP 過濾器（OWASP 2026 明言 regex 擋不住編碼內容）。

## Tests
```
python3 -I -m unittest discover -s tests -v   # 53 tests: planted defects for every rule, safe counterparts, review regressions
claude plugin test .                           # 28 hook tests (guard, allow-list, review mode, tripwire, liveness, history)
```
`tests/fixtures/` 內是**刻意植入漏洞**的範例檔，請勿匯入或執行。
