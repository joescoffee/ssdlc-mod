<img src=".claude-plugin/icon.png" width="96" align="right">

# ssdlc — Secure SDLC mod for Claude Code

Security skills and truly read-only reviewer agents for Claude Code.

在 Claude Code 中落實安全軟體開發生命週期（SSDLC）：安全審查、PR 前閘門、漏洞修復流程，以及 **Elephant-Goldfish Model（EGM）審查的真正唯讀版本**。審查員只有 Read/Grep/Glob（工具限制由 frontmatter 與 hook 強制），hook 另擋憑證路徑與從根目錄、家目錄的遞迴搜尋；「只讀 repo 內、不開 repo 外連結」則是提示層約束。所有流程都不執行被審 repo 的程式碼。

## 安裝 / Install
```
/plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

## 示範 / Demo
![ssdlc 實機示範](docs/demo.png)

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
| `/ssdlc:safe-bootstrap` | EGM（Elephant-Goldfish Model）bootstrap 的真正唯讀版本 |

## Agents
- `ssdlc:security-reviewer` — 程式碼／diff 安全審查
- `ssdlc:design-reviewer` — 設計文件威脅建模（STRIDE + AI 風險）

兩者 frontmatter 只有 `Read, Grep, Glob`；`hooks/register.ts` 守門 hook 再加三層縱深防禦（OWASP ASI02／ASI03、LLM02:2026）：
- 審查代理呼叫 Read/Grep/Glob 與回報用的 `SubagentHandback` 以外的工具，一律拒絕；
- 不得讀取憑證儲存處（`~/.ssh`、`~/.aws`、`.env*`、金鑰檔、`~/.claude/.credentials.json`、`/proc` 等），含 Grep/Glob 的 glob 參數；
- 先以 `$.fs.stat` 解析 symlink 實際落點再判斷，repo 內指向憑證的連結也會被擋；每次拒絕都跳出提示。

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

## 已知限制 / Known limitations
經 v0.2.0 自我審查（[`docs/reviews/ssdlc-0.2.0-self-review.md`](docs/reviews/ssdlc-0.2.0-self-review.md)）後仍未解決、如實揭露的項目：

1. **主 session 不受 guard 約束**（T1）：它握有 Bash/Write 又讀取不受信任內容，依本 mod 自己的 Rule of Two 屬 High。緩解靠流程（不執行 repo 程式、報告是資料）與 Claude Code 的逐次核准；**請勿在 bypass／acceptEdits 模式下審查不受信任的 repo**。路線圖：主 session「審查模式」hook。
2. **審查代理的檔案限制是 denylist**（SR-1、T5）：已擋憑證路徑與從根目錄／家目錄的遞迴搜尋，但不是「只能讀 repo 內」的 allowlist。路線圖：repo 根目錄 allowlist。
3. **TOCTOU 與 hard link**（SR-16）：guard 檢查與實際讀取之間有時間差；hard link 無法以 realpath 辨識。需 OS 層 sandbox。
4. **未驗證的宿主行為**：Claude Code 的 Grep 是否搜尋隱藏檔、子目錄 `CLAUDE.md` 是否延遲載入，未實測。
5. **掃描器是程式碼衛生檢查**，不是執行期的注入或 DLP 過濾器（OWASP 2026 明言 regex 擋不住編碼內容）。

## Tests
```
python3 -I -m unittest discover -s tests -v   # 53 tests: planted defects for every rule, safe counterparts, review regressions
claude plugin test .                           # 13 guard hook tests
```
`tests/fixtures/` 內是**刻意植入漏洞**的範例檔，請勿匯入或執行。
