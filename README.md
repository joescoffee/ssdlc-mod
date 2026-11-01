<img src=".claude-plugin/icon.png" width="96" align="right">

# ssdlc — Secure SDLC mod for Claude Code

Security skills and truly read-only reviewer agents for Claude Code.

## 安裝 / Install
```
/plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

## 示範 / Demo
![ssdlc 實機示範](docs/demo.png)

## 運作方式 / How it works
![ssdlc 心智圖](docs/ssdlc-mindmap.png)

互動版：`docs/ssdlc-mindmap.html`（可縮放、拖曳、編輯）；狀態檔 `docs/mindmaps/ssdlc.mindmap.json`。

## Skills
| Command | 用途 |
|---|---|
| `/ssdlc:security-review` | 10 段安全標準審查：範圍、信任邊界、STRIDE、認證授權、危險輸入、secrets、密碼學、依賴、AI/代理風險、日誌 |
| `/ssdlc:security-gate` | PR 前閘門：secrets＋危險模式掃描、依賴漏洞稽核、diff 審查 → PASS / WARN / BLOCK |
| `/ssdlc:vuln-fix` | 漏洞修復流程：分類 → 複現 → 根因修復 → 回歸測試 → 變體搜尋 → 紀錄 |
| `/ssdlc:safe-bootstrap` | EGM（Elephant-Goldfish Model）bootstrap 的真正唯讀版本 |

## Agents
- `ssdlc:security-reviewer` — 程式碼／diff 安全審查
- `ssdlc:design-reviewer` — 設計文件威脅建模（STRIDE + AI 風險）

兩者 frontmatter 只有 `Read, Grep, Glob`；另有 `hooks/register.ts` 守門 hook，凡 `ssdlc:*reviewer` 子代理呼叫 Read/Grep/Glob 及回報用的 `SubagentHandback` 以外的工具一律拒絕（縱深防禦）。

## Scanner
`scripts/gate_scan.py` 只用標準函式庫、不連網，偵測 secrets 與危險程式模式（shell injection、eval、不安全反序列化、SQL 字串組合、關閉 TLS 驗證、弱雜湊）。行尾加 `# ssdlc: allow <理由>` 可抑制單行。

## Tests
```
python3 -I -m unittest discover -s tests -v   # 23 tests, 8 planted defects
claude plugin test .                           # guard hook tests
```
`tests/fixtures/` 內是**刻意植入漏洞**的範例檔，請勿匯入或執行。
