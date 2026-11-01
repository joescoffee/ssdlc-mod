# ssdlc 改善策略：威脅建模 × 賽局 × 飛輪（2026-11-01）

三個分析各回答一個問題，彼此餵養：威脅建模找出**還剩什麼最危險**，賽局分析決定**怎樣的控制在攻擊者知道規則時仍然有效**，飛輪讓**每次審查都讓下一次更便宜**。所有數字都由各技能的腳本計算，輸入檔與輸出都在本資料夾及 `../threat-model/`，可重跑。

## 1. 威脅建模（`threat-modeling` v2.4，MAS 模式）

- 12 筆 CTARA 記錄（含 AI overlay：`LLMnn:2026`／`ASInn`、MAESTRO 層、代理因子），以 `calculate-risk-scores.py` 計算攻擊成功率與有效風險，`lint-tara-records.py --mas`：0 ERROR、0 WARN。STRIDE 六類皆有記錄；MAESTRO L1、L2 不適用（理由見 `records.json` 的 `coverage_decisions`）。
- **敏感度發現**：主 session 被注入（SSDLC-01）在需逐次核准時攻擊成功率 0.245（Medium，緊貼 0.25 門檻）；同一威脅在 bypass／acceptEdits 模式下（SSDLC-01B）為 **0.49（High）**。風險取決於使用者的權限模式，而不是 mod 本身 → 需要一個與權限模式無關的控制。
- **處置前最高有效風險**：guard 拒絕沒有持久紀錄（SSDLC-10，R 類）**High 3.0**。
- 報告：[`../threat-model/report.md`](../threat-model/report.md)；記錄：`records.json`（輸入）、`scored.json`（計算結果）。

**落實**
| 改善 | 對應記錄 | 結果 |
|---|---|---|
| 審查模式 `/ssdlc-review-mode`：主 session 只允許精確、不執行程式的命令形式；無網路；寫檔限報告；只能派 ssdlc 審查員；只有人能關閉 | SSDLC-01／01B | 在 code 中界定主 session，不再依賴權限模式（開啟時） |
| guard 事件存於 `$.state`、tripwire 警報經主 session 的下一個工具結果傳遞、`guard_log` 工具 | SSDLC-10 | 有效風險 High 3.0 → **Mitigated 0.0**（測試佐證） |

## 2. 賽局分析（`game-theory-strategist`，模型卡 gt-003 承諾賽局）

**框定**：ssdlc 是開源的，防禦規則公開 → 防禦方**先承諾**、攻擊方（惡意 repo 作者）看到規則後最佳回應（Stackelberg）。防禦方選擇「靜默拒絕」或「警報即 BLOCK」；攻擊方選擇是否植入外洩注入。報酬為**推估的相對單位**（`tree_c1.json`），關鍵變數是警報的**誤報成本 c**（良性 repo 觸發警報的代價）。

**求解**（`backward_induction.py`，c = 0…6 逐一重跑）：
| c | 子賽局完全均衡 |
|---|---|
| 0–3 | 防禦方「警報即 BLOCK」→ 攻擊方**不植入** |
| ≥ 4 | 防禦方「靜默拒絕」→ 攻擊方**植入** |

**洞見**：只要誤報成本低於「漏掉一次外洩嘗試」的代價，公開承諾「嘗試即判 BLOCK」就讓攻擊方不值得嘗試——規則公開反而是優勢。但這只在**高精確度訊號**上成立，所以：
- **tripwire（判 BLOCK）**：審查代理嘗試讀取憑證，或使用它沒有的工具。誠實的審查員幾乎不會觸發。
- **warn**：遞迴搜尋範圍過大。誠實審查員忘了帶 path 也會觸發，誤報成本高，不判 BLOCK。

**代價與失效條件**：報酬是推估值（證據等級 D，不是定論）；若宿主或模型改變，使誠實審查員常態性觸碰憑證路徑，c 上升，策略需改回 warn。**改變主意的條件**：gate 報告中 `ai.injection-attempt-observed` 被判為誤報的比例偏高。

## 3. 飛輪（`strategy-flywheel` L5，`flywheel_validate.py`）

```
審查執行 → 確認的發現 → 規則化（規則＋植入缺陷＋安全對照＋測試）→ 自動覆蓋（OWASP 2026）→ 採用（每個 PR 前跑閘門）↺
```

- 閉環 ✅、增益係數 **2.68**（> 1）、無死端孤兒、主環 5 條邊中 3 條有實測或觀察支撐（今天：44 項審查發現 → 測試 23 → 53 → 74）。完整輸出：[`flywheel-validation.md`](flywheel-validation.md)。
- **證據債**：「覆蓋 → 採用」「採用 → 更多審查」兩條邊仍是假設。

**落實**
| 飛輪需要 | 實作 |
|---|---|
| n2 → n3 的機制（發現變規則） | `/ssdlc:rule-from-finding`：只接受經 claim-check-act 確認的發現；規則必有 CWE＋OWASP refs、植入缺陷、安全對照與測試；一致性測試強制清單對應 |
| 償還證據債 | 本機計量（`$.store`，不外送）：scanner 執行次數、審查員派出次數、tripwire 與 warn 次數，`ssdlc review-mode status` 與 `guard_log` 可查 |
| 守住脆弱點 n2（確認的發現） | 所有審查技能要求以 Grep 驗證引用證據；未確認的發現不得規則化（避免把誤報固化） |
| 機制有效期（D3） | 規則若多數被判誤報 → 收窄或降為 info（`rule-from-finding` 的 Expiry 段） |

## 4. 90 天待驗證假設

| 假設 | 怎麼量 | 何時算失敗 |
|---|---|---|
| tripwire 誤報成本低（c < 4） | gate 報告中被判誤報的 `ai.injection-attempt-observed` 比例 | > 20% |
| 覆蓋提升帶來採用 | `metrics-v1.gateRuns` 每週趨勢 | 連續 4 週下降 |
| 審查模式不妨礙正常審查 | 審查模式下被拒的合法命令數（使用者回報） | 需要關閉審查模式才能完成審查 |
