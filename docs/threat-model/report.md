# 威脅模型報告：ssdlc mod v0.3.0（MAS 模式，2026-11-01）

> 版本：1.0 | 作者：— | 產生日期：2026-11-01

## 安全態勢總覽

**安全態勢評級：🔴 CRITICAL**（扣分：130.0）

| 指標 | 值 |
|------|-----|
| 系統資產數 | 0 |
| 攻擊面數 | 0（Critical: 0）|
| 威脅/失效記錄數 | 12（高風險: 5，未處理: 0）|
| 控制措施數 | 0（未實施: 0）|
| 攻擊面控制覆蓋率（已規劃） | 0.0% |
| 攻擊面控制覆蓋率（已實施） | 0.0% |
| 架構決策數 | 0 |

> 覆蓋率定義與追溯矩陣相同：已規劃＝被任何 ComplianceControl 的 `entry_points_covered` 列入；已實施＝只計 `is_implemented: true` 者。態勢扣分的「(1 − 覆蓋率) × 30」使用**已實施**覆蓋率。

## 有效風險（處置後）

有效風險＝風險值（Low 1 … Critical 4）×（1 − 實作狀態）；實作狀態取 `mitigation_status`（none 0／partial 0.5／full 1），未填者依處置狀態推定（verified 1、implemented 0.5、其餘 0）。

| Critical | High | Medium | Low | Mitigated |
|---|---|---|---|---|
| 0 | 0 | 3 | 5 | 4 |

處置狀態：none 0、planned 8、implemented 4、verified 0

## STRIDE 覆蓋度

| 類別 | 記錄數 | 狀態 |
|------|--------|------|
| S — Spoofing | 1 | ✅ |
| T — Tampering | 3 | ✅ |
| R — Repudiation | 1 | ✅ |
| I — Information Disclosure | 3 | ✅ |
| D — Denial of Service | 1 | ✅ |
| E — Elevation of Privilege | 3 | ✅ |

## MAESTRO 覆蓋（代理式記錄）

代理式記錄 12 條：對抗（CTARA）12 條／非對抗（DFMEA）0 條。

| 層 | L1 | L2 | L3 | L4 | L5 | L6 | L7 | X |
|---|---|---|---|---|---|---|---|---|
| 記錄數 | 0 ⚠️ | 0 ⚠️ | 3 | 4 | 2 | 1 | 2 | 0 |

| 代理因子 | ND | AU | ID | A2A |
|---|---|---|---|---|
| 記錄數 | 6 | 6 | 3 | 1 |

ASI 已記錄：6/10。
> 盲區：MAESTRO L1, L2 無記錄。
> 未記錄且未說明不適用的 ASI：ASI01, ASI02, ASI06, ASI10（請補分析，或在 coverage_decisions 說明不適用理由）。
> 提示：無非對抗記錄，是否漏了模型不一致、嵌入漂移、工作流狀態不同步等失效？

## AI 威脅分類（OWASP 2026 正規代碼）

| 記錄 | 分類 | 等級 |
|------|------|------|
| CTARA-SSDLC-01 | LLM01:2026 提示注入 | Medium |
| CTARA-SSDLC-02 | ASI03 身分與權限濫用 | High |
| CTARA-SSDLC-03 | ASI05 非預期程式碼執行 | Medium |
| CTARA-SSDLC-04 | ASI05 非預期程式碼執行 | Medium |
| CTARA-SSDLC-05 | LLM10:2026 不當輸出處理 | Medium |
| CTARA-SSDLC-06 | ASI09 人機信任剝削 | Critical |
| CTARA-SSDLC-07 | ASI04 代理供應鏈弱點 | Medium |
| CTARA-SSDLC-08 | ASI03 身分與權限濫用 | Low |
| CTARA-SSDLC-01B | LLM01:2026 提示注入 | High |
| CTARA-SSDLC-09 | ASI07 代理間通訊不安全 | Low |
| CTARA-SSDLC-10 | ASI08 連鎖失效 | High |
| CTARA-SSDLC-11 | LLM06:2026 無界資源消耗 | Critical |

## 高風險威脅詳細分析

### 1. [Critical] CTARA-SSDLC-06: 以 allow 標記讓閘門忽略惡意程式

**記錄類型**：CTARA
**情境**：惡意 PR 在惡意行加 `# ssdlc: allow reviewed`。

- STRIDE：T
- AI 威脅分類：ASI09 人機信任剝削
- DREAD：—
- 攻擊成功率：1（AC=1.0, UI=1.0, EM=1.0）
- 衝擊調整風險值 risk_value：—（impact=—）
- CWE：CWE-693
- MITRE ATT&CK：—
- 威脅行為者：惡意 repo／PR 作者
- MAESTRO：L6；代理因子：ND
- 現行控制：標記預設忽略；--honor-markers 才採用且不能隱藏 secret/隱形字元；新標記判 WARN
- 建議控制：維持：標記預設忽略；新增標記判 WARN
- 處理狀態：已完成
- 處置狀態 treatment_status：implemented　有效風險：0.0（Mitigated）

### 2. [Critical] CTARA-SSDLC-11: 以超大檔案、超長行或特殊檔案拖垮掃描

**記錄類型**：CTARA
**情境**：受審 repo 放 200 KB 單行、FIFO 或巨量小檔，使掃描卡住或逾時，主 session 略過掃描。

- STRIDE：D
- AI 威脅分類：LLM06:2026 無界資源消耗
- DREAD：—
- 攻擊成功率：0.7（AC=1.0, UI=1.0, EM=0.7）
- 衝擊調整風險值 risk_value：—（impact=—）
- CWE：CWE-1333
- MITRE ATT&CK：—
- 威脅行為者：惡意 repo／PR 作者
- MAESTRO：L4；代理因子：ND
- 現行控制：每行 4 KB 上限、量詞上界、只讀一般檔案、O_NONBLOCK、結束碼 3＝INCOMPLETE
- 建議控制：維持：行長上限、量詞上界、特殊檔案不開啟、INCOMPLETE
- 處理狀態：已完成
- 處置狀態 treatment_status：implemented　有效風險：0.0（Mitigated）

### 3. [High] CTARA-SSDLC-01B: （敏感度）CTARA-SSDLC-01 於 bypass／acceptEdits 模式

**記錄類型**：CTARA
**情境**：同 SSDLC-01，但使用者以 bypassPermissions 或已白名單 Bash 執行審查，沒有逐次核准。

- STRIDE：E
- AI 威脅分類：LLM01:2026 提示注入
- DREAD：—
- 攻擊成功率：0.49（AC=0.7, UI=1.0, EM=0.7）
- 衝擊調整風險值 risk_value：—（impact=—）
- CWE：CWE-1427
- MITRE ATT&CK：—
- 威脅行為者：惡意 repo／PR 作者
- MAESTRO：L3；代理因子：AU, ND
- 現行控制：同 SSDLC-01；審查模式 /ssdlc-review-mode（hooks/review-mode.ts）：主 session 只允許精確命令形式、拒絕網路、寫檔限報告路徑、只能派 ssdlc 審查員；關閉須由人輸入（需使用者開啟）
- 建議控制：審查不受信任的 repo 時預設開啟審查模式；長期：repo 根目錄 allowlist 與 OS 層 sandbox
- 處理狀態：進行中
- 處置狀態 treatment_status：planned　有效風險：1.5（Medium）

### 4. [High] CTARA-SSDLC-10: guard 拒絕無持久紀錄，事後無法追查

**記錄類型**：CTARA
**情境**：被注入的審查員嘗試讀取憑證被拒，只有短暫 toast，報告不提，使用者錯過訊號。

- STRIDE：R
- AI 威脅分類：ASI08 連鎖失效
- DREAD：—
- 攻擊成功率：0.49（AC=0.7, UI=1.0, EM=0.7）
- 衝擊調整風險值 risk_value：—（impact=—）
- CWE：CWE-778
- MITRE ATT&CK：—
- 威脅行為者：惡意 repo／PR 作者
- MAESTRO：L5；代理因子：AU
- 現行控制：guard 事件存於 $.state（重新載入不遺失）；憑證或禁用工具嘗試＝tripwire，於主 session 下一個工具結果以 context 傳遞警報並要求判 BLOCK；guard_log 工具可查；狀態列顯示 tripwire 數
- 建議控制：跨 session 持久化紀錄（$.store）
- 處理狀態：已完成
- 處置狀態 treatment_status：implemented　有效風險：0.0（Mitigated）

### 5. [High] CTARA-SSDLC-02: 審查代理被注入後讀取憑證並寫入報告

**記錄類型**：CTARA
**情境**：受審 repo 文件誘導審查代理以祖先目錄 Grep 或讀取未列入 denylist 的憑證檔，內容出現在 handback 報告。

- STRIDE：I
- AI 威脅分類：ASI03 身分與權限濫用
- DREAD：—
- 攻擊成功率：0.35（AC=0.7, UI=1.0, EM=0.5）
- 衝擊調整風險值 risk_value：—（impact=—）
- CWE：CWE-200
- MITRE ATT&CK：—
- 威脅行為者：惡意 repo／PR 作者
- MAESTRO：L3；代理因子：ID, AU
- 現行控制：frontmatter 只給 Read/Grep/Glob；guard denylist（不分大小寫、symlink 解析）、拒絕從根目錄／家目錄遞迴搜尋；憑證嘗試列為 tripwire，警報傳到主 session
- 建議控制：repo 根目錄 allowlist；憑證存取嘗試列為 tripwire 判 BLOCK
- 處理狀態：進行中
- 處置狀態 treatment_status：planned　有效風險：1.5（Medium）

## 建議的下一步行動

1. 為 5 個高風險記錄制定緩解策略
2. 補充 MAESTRO 層／代理因子盲區分析：L1, L2

---
*本報告由威脅建模技能自動產生，產生時間：2026-11-01T06:08:19.240685*