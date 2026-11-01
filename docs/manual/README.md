[English](README.en.md) | **繁體中文**

# ssdlc 新手操作手冊

[![Release](https://img.shields.io/github/v/release/joescoffee/ssdlc-mod?sort=semver)](https://github.com/joescoffee/ssdlc-mod/releases/latest)

> 適用版本：**ssdlc v0.5.0**（2026-11-01，[發布說明](https://github.com/joescoffee/ssdlc-mod/releases/tag/v0.5.0)）。本手冊的每一條指令都在該版本實際執行過；截圖為實機輸出。
> 讀完前三章（約 15 分鐘）即可開始使用；其餘章節在需要時查閱。

## 目錄

1. [ssdlc 是什麼](#1-ssdlc-是什麼)
2. [名詞速查](#2-名詞速查)
3. [安裝前準備](#3-安裝前準備)
4. [安裝、確認、更新與移除](#4-安裝確認更新與移除)
5. [五分鐘上手：第一次跑安全閘門](#5-五分鐘上手第一次跑安全閘門)
6. [情境操作：六個技能逐步教學](#6-情境操作六個技能逐步教學)
7. [審查不受信任的 repo：完整安全流程](#7-審查不受信任的-repo完整安全流程)
8. [單獨使用掃描器（命令列與 CI）](#8-單獨使用掃描器命令列與-ci)
9. [讀懂報告](#9-讀懂報告)
10. [守門 hook 與審查模式](#10-守門-hook-與審查模式)
11. [疑難排解](#11-疑難排解)
12. [已知限制](#12-已知限制)
13. [進階：開發、測試與貢獻](#13-進階開發測試與貢獻)

---

## 1. ssdlc 是什麼

ssdlc 是一個 **Claude Code 外掛（plugin）**，把安全軟體開發生命週期（Secure SDLC）的關鍵步驟變成可以直接呼叫的指令：

| 你想做的事 | 用這個 |
|---|---|
| 開 PR 前快速檢查有沒有洩漏金鑰、危險程式、AI 代理設定錯誤 | `/ssdlc:security-gate` |
| 對一段程式碼做完整安全審查 | `/ssdlc:security-review` |
| 審查會呼叫 LLM、使用代理、MCP、RAG 的程式 | `/ssdlc:ai-security-review` |
| 審查別人給的、不能信任的 repo（例如外部 PR、供應商程式碼） | `ssdlc review-mode on` ＋ `/ssdlc:safe-bootstrap` |
| 修一個已知漏洞 | `/ssdlc:vuln-fix` |
| 把一次確認過的發現，變成以後自動檢查的規則 | `/ssdlc:rule-from-finding` |

它和一般 linter 的差別：

- **審查員真的只能讀**：審查工作交給兩個子代理（`ssdlc:security-reviewer`、`ssdlc:design-reviewer`），它們只有 Read／Grep／Glob 工具，另有守門 hook 在程式層擋下其他工具與憑證檔讀取。
- **涵蓋 AI 風險**：依 OWASP LLM Top 10 2026、OWASP Agentic Top 10 2026 與 MIT AI Risk Repository 設計檢查項目。
- **不執行被審的程式**：任何流程都不跑被審 repo 的測試、建置、formatter 或安裝指令。

**它不能做的事**：它不是執行期的防火牆或 DLP，也不能保證找出所有漏洞。掃描器是「程式碼衛生檢查」，審查員的結論需要人判斷。詳見[第 12 章](#12-已知限制)。

**全貌一張圖**（v0.5.0）：七條主幹分別是技能、審查員（代理）、守門 hook、掃描器、測試、安裝與參考標準；虛線是彼此的關聯。

![ssdlc 運作方式心智圖（v0.5.0）](../ssdlc-mindmap.png)

**互動版**（用瀏覽器開啟 `docs/ssdlc-mindmap.html`）可以拖曳平移、滾輪或工具列縮放、單擊選取節點、雙擊或 F2 編輯文字、拖拉節點搬移分支、Tab 新增子節點；改完按「匯出 JSON（貼回給 Claude）」，貼回對話即可同步到心智圖狀態檔。下圖為放大到 120%、選取「存活檢查」節點的畫面：

![互動版心智圖：放大並選取節點](img/mindmap-interactive.png)

（節點的補充說明目前只存在狀態檔 `docs/mindmaps/ssdlc.mindmap.json` 的 `note` 欄位，互動版畫面不會顯示。）

---

## 2. 名詞速查

| 名詞 | 意思 |
|---|---|
| **Skill（技能）** | 以 `/ssdlc:名稱` 呼叫的一套步驟說明，Claude 照著執行。 |
| **`ssdlc review-mode on／off／status`** | 審查模式開關。直接當一般訊息輸入（不加斜線）即可，由守門程式攔截處理，不會送給模型；Claude app、網頁、終端機都適用。終端機另可用 slash 指令 `/ssdlc-review-mode on`（連字號、沒有 `ssdlc:` 前綴，因為它不是技能）。 |
| **Agent（子代理）** | Claude 另外派出的助手。ssdlc 的兩個審查員都是唯讀子代理。 |
| **Hook（守門程式）** | 外掛內建的程式，在每次工具呼叫前檢查，違規就拒絕。安裝後自動生效。 |
| **Goldfish／Elephant** | 兩種審查員視角。Goldfish（金魚）不給背景、只看程式碼本身；Elephant（大象）拿到完整背景、做設計層威脅建模。兩份結果交叉比對。 |
| **`LLM01:2026`** | OWASP LLM Top 10 **2026 版**第 1 項（提示注入）。2026 版編號與 2025 版不同，一律寫年份。 |
| **`ASI01`** | OWASP Agentic Top 10（2026）第 1 項（代理目標劫持）。 |
| **`CWE-78`** | 通用弱點列舉編號（此例為命令注入）。 |
| **BLOCK／WARN／INCOMPLETE／PASS** | 判定結果：必須修／應該看／沒檢查完整（不等於安全）／檢查後沒發現問題（不等於可以合併）。 |
| **Tripwire（絆線）** | 審查員試圖讀憑證或用不該有的工具時觸發，代表被審內容可能在做提示注入，判 BLOCK。 |
| **審查模式（review mode）** | 開啟後，主對話只能執行少數安全的指令形式，不能上網，只能寫報告檔。 |
| **allow 標記** | 程式碼行尾的 `# ssdlc: allow <理由>`。預設**不採用**，見[第 8 章](#8-單獨使用掃描器命令列與-ci)。 |

---

## 3. 安裝前準備

| 項目 | 需求 | 檢查方式 |
|---|---|---|
| Claude Code | 支援外掛的版本（終端機、桌面 app 或網頁版皆可） | `claude --version` |
| Python | 3.9 以上（掃描器只用標準函式庫，不需 `pip install`） | `python3 --version` |
| git | 任一近期版本 | `git --version` |
| GitHub 存取 | 能讀取 `joescoffee/ssdlc-mod`（目前為**私有** repo，需被授權；公開後任何人皆可安裝） | 瀏覽器開啟 repo 頁面 |
| 依賴稽核工具（選用） | `osv-scanner`、`npm`、`pip-audit` 任一，供 security-gate 檢查套件漏洞；沒裝時判定為 INCOMPLETE 而不是 PASS | `osv-scanner --version` |

---

## 4. 安裝、確認、更新與移除

### 4.1 安裝（擇一）

**A. 終端機一行完成**（推薦）

```bash
claude plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

**B. 兩步驟**（先加入市集，再安裝）

```bash
claude plugin marketplace add joescoffee/ssdlc-mod
claude plugin install ssdlc@ssdlc-mod
```

**C. 在 Claude Code 對話中**

```
/plugin install ssdlc --marketplace joescoffee/ssdlc-mod
```

出現 `Add marketplace?` 時按 `y`，再選安裝範圍（預設 user，按 Enter）。

**D. 桌面 app**：提示框旁的 **+** → **Plugins** → **Add marketplace**，輸入 `joescoffee/ssdlc-mod` → **Add plugin**。

> 安裝範圍：`user`（所有專案都能用，預設）、`project`（寫進專案設定，團隊共用）、`local`（只有這個專案、只有你）。終端機以 `-s project` 指定。

### 4.2 確認安裝成功

```bash
claude plugin details ssdlc
```

![安裝與確認](img/step1.png)

（截圖是以本機的 repo 資料夾作為市集來源安裝所得；從 GitHub 安裝時，畫面上的步驟與元件清單相同。）

應看到 **Skills (6)** 與 **Agents (2)**。`Hooks (0)` 是正常的：這個數字只計算舊式設定檔 hook，ssdlc 的守門程式是 hook 模組，安裝後即生效。

在 Claude Code 對話中再確認守門程式已載入：

```
ssdlc review-mode status
```

回覆 `ssdlc ✓ Review mode is OFF; guard events this session: 0 …` 即表示 hook 正常運作（app 中會顯示在「Hook 已封鎖您的提示」框內，屬正常）。

### 4.3 更新、停用、移除

| 動作 | 指令 |
|---|---|
| 更新到最新版 | `claude plugin marketplace update ssdlc-mod` 然後 `claude plugin update ssdlc@ssdlc-mod`；在對話中執行 `/reload-plugins` |
| 看新版改了什麼 | [Releases 頁面](https://github.com/joescoffee/ssdlc-mod/releases)：每一版的發布說明（中英雙語）；[最新版本](https://github.com/joescoffee/ssdlc-mod/releases/latest) |
| 查看已安裝版本 | `claude plugin list`（看 `Version:`） |
| 暫時停用 | `claude plugin disable ssdlc@ssdlc-mod`（恢復：`enable`） |
| 移除 | `claude plugin uninstall ssdlc@ssdlc-mod`，再 `claude plugin marketplace remove ssdlc-mod` |

---

## 5. 五分鐘上手：第一次跑安全閘門

在你**自己的**專案（你信任的程式碼）裡：

1. 終端機進入專案資料夾，啟動 Claude Code：`claude`
2. 輸入：
   ```
   /ssdlc:security-gate
   ```
3. Claude 會依序：列出變更檔案 → 跑掃描器 → 稽核有變動的依賴 → 讀 diff → 給出判定。
4. 看最後的判定：
   - **BLOCK**：有必須修的問題（例如洩漏的金鑰）。照報告中的 `檔案:行號` 修正。
   - **WARN**：值得看一眼的中度問題。
   - **INCOMPLETE**：有檔案或依賴沒檢查到（例如沒裝 osv-scanner）。報告會說哪裡沒檢查。
   - **PASS**：檢查後沒發現問題。這是「閘門結果」，不是「可以合併」的許可。
5. 修完再跑一次，直到沒有 BLOCK。

> 小提醒：報告中的金鑰只會顯示前 4 個字元，例如 `tok_…`。

---

## 6. 情境操作：六個技能逐步教學

### 6.1 `/ssdlc:security-gate` — PR 前閘門

**何時用**：每次開 PR 或合併前。

**它會做**
1. 以 `git diff -z` 列出變更檔（檔名不經過 shell，避免惡意檔名注入）。
2. 掃描器檢查 secrets、危險程式模式、AI／代理設定（預設忽略 allow 標記）。
3. 只用「解析 lockfile」的方式稽核依賴，絕不 `npm install` 或 `pip install`；並檢查 PR 有沒有改動 `.npmrc`、`osv-scanner.toml` 這類會影響稽核結果的設定。
4. 讀 diff，必要時套用 AI 檢查清單。
5. 給出判定；被判為誤報的 High／Critical 一律列在 **Dismissed** 表，你可以推翻。

**你可以這樣說**：「跑安全閘門，base 用 main」、「這個 PR 可以推嗎？」

### 6.2 `/ssdlc:security-review` — 完整安全審查

**何時用**：安全相關的變更（登入、權限、檔案上傳、外部輸入）、上線前。

**它會做**：機械掃描 → 派 `ssdlc:security-reviewer` 依 10 個面向審查（信任邊界、STRIDE、認證授權、危險 sink、secrets、密碼學、依賴、AI 風險、日誌）→ 每個 High 都回到程式碼用 Grep 確認證據 → 報告。

**產出**：發現表（嚴重度、`檔案:行號`、CWE、證據、攻擊情境、修法）＋「未審查」清單＋判定。

**你可以這樣說**：「對 src/auth/ 做安全審查」。

### 6.3 `/ssdlc:ai-security-review` — AI／代理程式審查

**何時用**：程式會呼叫模型、組 prompt、跑代理或工具、設定 MCP、用 RAG 或代理記憶。

**它會做**
1. **盤點**：模型、prompt 來源、所有會進到 prompt 的不可信文字、工具與 MCP、記憶與向量庫、子代理、模型輸出流向。
2. **掃描**：含 AI 規則（隱藏 Unicode、`trust_remote_code`、核准繞過、MCP 未鎖版本等）。
3. **Rule of Two 設計閘門**：同一個代理若同時「讀不可信輸入」＋「碰得到機敏資料」＋「能改狀態或對外發送」，而沒有逐次人工核准 → High。
4. **雙審查員**：程式碼審查（goldfish）與設計威脅建模（elephant，含 MIT 因果情境格）平行進行。
5. **報告**：每個發現標 `LLMnn:2026`／`ASInn`／CWE，並附 **覆蓋矩陣**——LLM01–10 與 ASI01–10 每一項都要寫「有發現／已檢查無發現／不適用＋理由／未審查＋理由」，沒寫等於沒檢查。

### 6.4 `/ssdlc:safe-bootstrap` — 唯讀版 Elephant-Goldfish 審查

**何時用**：要審查別人的 repo 或設計文件，且審查過程不能改動任何東西。完整步驟見[第 7 章](#7-審查不受信任的-repo完整安全流程)。

### 6.5 `/ssdlc:vuln-fix` — 漏洞修復

**何時用**：你拿到一個 CVE、掃描結果、滲透測試報告或審查發現要修。

> 這個技能**只能由你手動輸入**觸發（不會被 Claude 自動呼叫），避免被惡意內容誘導去改程式、跑測試。

**流程**：分類（含 OWASP 2026 編號）→ 複現（不受信任的程式只在沙箱跑或先問你）→ 根因修正 → 驗證（不得用加 allow 標記、刪測試的方式「通過」）→ 搜尋同類變體 → 修復紀錄。

### 6.6 `/ssdlc:rule-from-finding` — 把發現變成規則

**何時用**：某個發現**已確認為真**，而且可以用模式偵測（某個 API、旗標、設定鍵）。

**流程**：寫掃描規則（附 CWE 與 OWASP 編號）→ 植入缺陷範例（必須抓到）→ 安全對照（必須不誤報）→ 單元測試 → 加進檢查清單。測試會檢查清單與規則一致，漏一步就會失敗。

> 只有手動觸發。未確認的發現不能規則化，否則會把誤報固定下來。

---

## 7. 審查不受信任的 repo：完整安全流程

不受信任的 repo 可能藏有：讓 AI 誤入歧途的隱藏指令、執行 `git` 時就會跑程式的 `.git/config`、會被 Claude Code 自動載入的 `CLAUDE.md`。請照下列步驟：

**步驟 1：判斷 repo 來源**

| 怎麼拿到的 | 可以跑 git 嗎 |
|---|---|
| 你自己 `git clone <網址>` | 可以（clone 不會帶來對方的設定） |
| 壓縮檔、共享資料夾、別人的工作目錄 | **不可以**。請重新從原始網址 clone，或只當成一般檔案審查 |

**步驟 2：建立不含代理設定的審查副本**

```bash
rsync -a --exclude .git --exclude CLAUDE.md --exclude AGENTS.md --exclude .claude 對方的repo/ review-copy/
```

**步驟 3：在審查副本中啟動 Claude Code，開啟審查模式**

```bash
cd review-copy && claude
```
```
ssdlc review-mode on
```

狀態列會顯示 `ssdlc: review mode ON`。從現在起，主對話只能跑掃描器、加固過的唯讀 git、只解析的稽核工具、列目錄與 rsync；不能上網；只能寫報告檔；只能派 ssdlc 審查員。

**步驟 4：執行審查**

```
/ssdlc:safe-bootstrap 審查這個資料夾
```

（程式涉及 AI／代理時改用 `/ssdlc:ai-security-review`。）

**步驟 5：看 tripwire**

審查員回來後，Claude 會查 `guard_log`。如果任何審查員嘗試讀你的憑證檔或用不該有的工具，報告會出現 **BLOCK：`ai.injection-attempt-observed`**——代表這個 repo 在嘗試提示注入，請把它視為惡意。你也可以自己查：

```
ssdlc review-mode status
```

**步驟 6：結束後關閉審查模式**

```
ssdlc review-mode off
```

> 只有你親自輸入才能關閉；Claude、其他外掛或背景通知送出的同樣文字都會被拒絕。這則訊息由守門程式直接回覆，不會送給模型。
>
> 在 Claude app／網頁版中，回覆會出現在標題為「**Hook 已封鎖您的提示**」的框裡，內容以 `ssdlc ✓` 開頭——這是正常的：守門程式攔下了這則訊息（所以不會送給模型），框裡的文字就是它的回覆。

---

## 8. 單獨使用掃描器（命令列與 CI）

掃描器是一支獨立的 Python 腳本，不需要 Claude Code 也能用。外掛安裝後位於外掛資料夾的 `scripts/gate_scan.py`；也可以直接從 repo 取得。

```bash
python3 -I scripts/gate_scan.py [--json] [--honor-markers] [--files-from 清單檔] [--] 路徑…
```

| 選項 | 作用 |
|---|---|
| `--json` | 輸出 JSON：`findings`、`suppressed`、`skipped`、`incomplete`、`honor_markers` |
| `--files-from 檔案` | 從檔案讀路徑清單（NUL 或換行分隔），搭配 `git diff -z --name-only > 清單檔`，檔名不經過 shell |
| `--honor-markers` | 採用 `# ssdlc: allow <理由>` 標記。**預設不採用**，因為被審的程式碼也能自己寫標記；即使採用，也永遠不會隱藏 secret 與隱形字元 |
| `--` | 之後的參數一律當路徑（處理以 `-` 開頭的檔名） |
| `--strict` | 舊版相容，無作用（現在預設就是嚴格） |

**結束碼**

| 碼 | 意思 |
|---|---|
| 0 | 全部掃完，沒有發現 |
| 1 | 有發現 |
| 2 | 參數錯誤（例如打錯選項 `--stict`） |
| 3 | 沒有發現，但**掃描不完整**（路徑不存在、讀不到、特殊檔案、過大）——不是 PASS |

![掃描 AI 與代理設定](img/step2.png)

![掃描不完整](img/step3.png)

**在 CI 中使用（GitHub Actions 範例）**

```yaml
- name: ssdlc gate scan
  run: |
    git diff -z --name-only --diff-filter=ACMR origin/${{ github.base_ref }}...HEAD > changed.lst
    python3 -I scripts/gate_scan.py --json --files-from changed.lst > gate.json || code=$?
    cat gate.json
    # 1 = 有發現，3 = 不完整：兩者都讓工作失敗
    if [ "${code:-0}" -ne 0 ]; then exit 1; fi
```

> 這段範例在**你自己的** repo 上執行。若要在 CI 中審查外部 fork 的 PR，不要給該工作任何密鑰與寫入權限。

---

## 9. 讀懂報告

**掃描器的每一行**

```
HIGH     ai.mcp-inline-secret   .mcp.json:0  server 'issues': ISSUES_API_TOKEN=tok_…  [LLM02:2026, ASI03, CWE-798]
└嚴重度   └規則                  └檔案:行號    └證據（secret 只顯示前 4 字元）                └對照編號
```

- 行號 `0`：發現來自整份設定檔的解析（例如 MCP 設定），沒有單一行號。
- `<tag-chars>`、`<U+200B>`：看不見的字元以代碼顯示；`hidden='…'` 是被藏起來的文字解碼結果。

**嚴重度怎麼處理**

| 嚴重度 | 建議 |
|---|---|
| CRITICAL／HIGH | 合併前修正；若判定為誤報，寫明理由放進 Dismissed 表 |
| MEDIUM | 本次或下次迭代處理 |
| LOW／INFO | 線索，交由審查員判斷 |

**審查報告的覆蓋矩陣**：AI 審查的報告最後一定有 LLM01–10 與 ASI01–10 的覆蓋矩陣。看到「未審查」時，代表那一項仍是盲點。

**報告存檔**：存進 `docs/reviews/` 的報告會標日期與 commit，它只代表「那個 commit 當時的狀態」，之後的版本要重新審查。

---

## 10. 守門 hook 與審查模式

### 10.1 守門 hook 會擋什麼（只針對 ssdlc 審查員）

| 情況 | 結果 | 等級 |
|---|---|---|
| 審查員想用 Bash、Write、WebFetch 等非讀取工具 | 拒絕 | tripwire |
| 讀取憑證位置：`~/.ssh`、`~/.aws`、`.env*`（範本除外）、金鑰檔、`~/.claude/.credentials.json`、`/proc`、k8s token、shell history 等（不分大小寫，連 symlink 指向也檢查） | 拒絕 | tripwire |
| 從 `/`、家目錄、`/etc` 等位置遞迴搜尋 | 拒絕，請改傳 repo 路徑 | warn |
| 讀取審查範圍以外的檔案。範圍＝派遣 prompt 中寫出的絕對路徑（沒寫時為工作目錄）＋ ssdlc 外掛目錄（檢查清單所在） | 拒絕，請在 prompt 中寫出該路徑 | warn |

每次拒絕都會跳出提示；tripwire 也會顯示在狀態列，並在主對話的下一個工具結果附上警報。

### 10.2 審查模式允許的指令形式

| 類別 | 允許的形式 |
|---|---|
| 掃描器 | `python3 -I …/gate_scan.py …` |
| git（只讀子指令） | `env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null -c diff.external= …` 加上 `diff`／`log`／`show`／`ls-files`／`merge-base`／`rev-parse`／`status`；`diff`／`log`／`show` 還須 `--no-ext-diff --no-textconv` |
| 依賴稽核 | `osv-scanner …`、`npm audit --package-lock-only …`、`pip-audit --disable-pip --no-deps …` |
| 其他 | `rsync -a`（必須排除 `.git`、`CLAUDE.md`、`AGENTS.md`、`.claude`）、`ls`、`wc`、`file`、`stat`、`pwd`、`mktemp`、`mkdir -p`、`--version` |

不允許：管線 `|`、`;`、`&&`、`$(...)`、變數 `$VAR`、多行指令；最後可以有一個 `> 檔案` 重導向。

| 工具 | 審查模式下 |
|---|---|
| WebFetch、WebSearch | 關閉 |
| Write、Edit | 只能寫 `docs/reviews/*.md`、`*-review.md`、`*-report.md` 等報告檔 |
| Agent | 只能派 `ssdlc:*reviewer` |
| 其他外掛的 MCP 工具 | 關閉（`mcp__ssdlc__guard_log` 除外） |
| Read、Grep、Glob | 正常 |

### 10.3 guard 存活檢查與歷史紀錄

hook 若因 Claude Code 更新而沒有載入，它無法自己報錯。所以 ssdlc 反過來做：每個技能在派審查員**之前**都會呼叫 `guard_log` 工具確認 guard 還在。

- 工具不存在、出錯，或 `selfTest.pass` 為 false（規則本身壞掉）→ 技能停止並回報 **INCOMPLETE — ssdlc guard not active**，不會在沒有保護的情況下派審查員。
- 你也可以隨時請 Claude「呼叫 guard_log」，回覆中的 `guard` 區塊會列出版本、載入時間與自我檢查結果。
- 每次拒絕都會寫進本機的歷史紀錄（跨 session、最多 500 筆），`guard_log` 的 `history` 區塊顯示總數與最近 20 筆。

在 Claude app 中實機驗證的結果（審查模式擋下 `curl`、審查員白名單、`guard_log` 存活檢查）：

![Claude app 實機驗證](img/step5.png)

（第一行是加入 `ssdlc ✓` 前綴之前擷取的原始輸出；v0.5.0 的回覆會以 `ssdlc ✓` 開頭。）

### 10.4 本機計量

`ssdlc review-mode status` 會顯示自首次使用以來的掃描次數、審查員派出次數、tripwire 與 warn 次數。這些數字只存在你的電腦（Claude Code 的外掛儲存區），不會傳到任何地方，用途是讓你知道工具被使用的程度與警報的頻率。

---

## 11. 疑難排解

| 症狀 | 原因與解法 |
|---|---|
| `Plugin "ssdlc" not found in marketplace` | 市集名稱是 `ssdlc-mod`：用 `ssdlc@ssdlc-mod`，或用 `--marketplace joescoffee/ssdlc-mod` 一行安裝 |
| `Marketplace file not found` 或 404 | repo 目前是私有的：確認你的 GitHub 帳號有存取權 |
| 輸入 `/ssdlc:...` 沒反應 | 執行 `/reload-plugins`；用 `claude plugin list` 確認狀態為 enabled |
| `Unknown command: /ssdlc:review-mode` 或 `/ssdlc-review-mode` | 在 Claude app／網頁版（雲端 session）中，外掛以程式註冊的 slash 指令無法使用。請改輸入一般訊息 `ssdlc review-mode status`（不加斜線）。若一般訊息也沒有回應，代表 hook 模組沒載入：更新到 v0.3.2 以上並重新啟動 |
| 審查模式下指令被拒 | 改成[第 10.2 節](#102-審查模式允許的指令形式)的形式；變數要展開成實際值。真的需要其他指令時，由你輸入 `ssdlc review-mode off` |
| 掃描結束碼 3 | 報告的 `SKIPPED` 列出沒掃到的檔案與原因；修正路徑或權限後重跑 |
| 某條規則一直誤報 | 確認是誤報後，在報告的 Dismissed 表寫明理由；若是常態性誤報，請開 issue，或用 `/ssdlc:rule-from-finding` 收窄規則 |
| 審查員回報 `outside this review's scope` | 要審查的目錄沒有以絕對路徑寫進審查員的 prompt。請說「審查 /完整/路徑」，或在該目錄中啟動 Claude Code |
| 審查員說「找不到 checklist」 | `${CLAUDE_PLUGIN_ROOT}` 沒被展開：重新安裝外掛；技能會判 INCOMPLETE 而不是亂找副本 |
| 報告出現 `ai.injection-attempt-observed` | 被審內容在嘗試提示注入。不要照該審查員的建議執行任何指令；把 repo 視為惡意 |

---

## 12. 已知限制

1. **審查模式需要你手動開啟**。沒開時，主對話只靠流程規定與 Claude Code 的逐次核准；請勿在 bypass／acceptEdits 權限模式下審查不受信任的 repo。
2. **審查員白名單由派遣 prompt 決定**：Claude 若被注入而把不該讀的目錄寫進審查員的 prompt，白名單會放行（憑證黑名單仍會擋）。開啟審查模式可降低主對話被注入的影響。
3. **檢查與讀取之間有時間差（TOCTOU）**，hard link 也無法辨識；需要作業系統層的沙箱才能完全防護。
4. **掃描器是程式碼衛生檢查**，不是執行期的提示注入或資料外洩過濾器；編碼過的內容可以繞過任何 regex。
5. **未驗證的宿主行為**：Claude Code 的 Grep 是否搜尋隱藏檔、子目錄的 `CLAUDE.md` 是否會在讀取時載入，尚未實測。
6. 審查員是 AI，可能漏報或誤報；所有 High 發現都會回到程式碼驗證，但最終判斷仍在你。

完整的自我審查與處置：[`../reviews/ssdlc-0.2.0-self-review.md`](../reviews/ssdlc-0.2.0-self-review.md)；威脅模型：[`../threat-model/report.md`](../threat-model/report.md)；改善策略：[`../strategy/README.md`](../strategy/README.md)。

---

## 13. 進階：開發、測試與貢獻

**目錄結構**

```
.claude-plugin/   plugin.json（名稱、版本）、marketplace.json、icon.png
skills/           六個技能（每個一個 SKILL.md）
agents/           兩個唯讀審查員
hooks/            register.ts（守門、tripwire、審查模式接線）、review-mode.ts（審查模式規則）
scripts/          gate_scan.py（掃描器）
references/       AI 檢查清單、MIT 分流、不受信任 repo 規則
tests/            單元測試、hook 測試、刻意含漏洞的範例（fixtures，請勿執行）
types/            外掛狀態的型別合約
docs/             手冊、審查報告、威脅模型、策略、心智圖
```

**跑測試**

```bash
python3 -I -m unittest discover -s tests   # 53 個：每條規則的植入缺陷與安全對照、審查回歸測試
claude plugin test .                       # 28 個：守門、白名單、審查模式、tripwire、存活檢查、歷史
claude plugin validate .                   # 外掛結構檢查
```

![測試](img/step4.png)

**新增規則**：照 `/ssdlc:rule-from-finding` 的步驟。一致性測試會確保規則、範例、測試與檢查清單同步。

**運作方式總覽**：見[第 1 章的心智圖](#1-ssdlc-是什麼)（互動版：`../ssdlc-mindmap.html`）。

**授權**：程式碼為 MIT；`references/ai-risk-checklist.md` 與 `references/mit-ai-risk-triage.md` 改編自 OWASP（CC BY-SA 4.0）與 MIT AI Risk Repository（CC BY 4.0），採 CC BY-SA 4.0，出處見各檔末。
