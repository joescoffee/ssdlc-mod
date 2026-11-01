<!--
【中文審閱版，送出時請用英文版 B-public-task-issue.md】
管道：在 google/elephant-goldfish-model 開公開 issue，使用「Task」模板。
可以直接送出：這些發現已經公開（joescoffee/ssdlc-mod 自 2026-11-01 起公開）。草稿 A 已送出為 #261，內文結尾已加上「Related: #261」。
-->

**標題：** 強化：限制檔案路徑、寫入目標與平行數；讓文件中的安全宣稱與實際一致

## 目標（Objective）

以下是對 `403d888` 唯讀安全審查得出的低嚴重度強化項目。單獨來看，每一項都需要其他條件配合才能被利用；但一起處理，能縮小 EGM 審查不受信任 repo 時，該 repo 內容所能影響的範圍。

## 範圍（Scope）

1. **自動讀取連結檔案。** `skills/egm-review/SKILL.md:75-76, 97-98` 與 `skills/egm-review-loop/SKILL.md:56-57, 71-72` 會自動讀取設計文件引用的任何路徑或 URL，也接受任意的 persona／standard 路徑。這與 adapter 的「只使用明確提供的審查脈絡」（`.claude-plugin/agents/structural.md:14-15`）互相矛盾。提議：連結只解析為 workspace 內的相對路徑；遇到絕對路徑、`..` 或 URL 時先詢問使用者；persona 與 standard 只從 plugin root 載入。
2. **synthesizer 的寫入範圍未受限。** `.claude-plugin/agents/synthesizer.md:5` 授予 `Write`，但沒有路徑限制。提議：寫入只限 artifact 目錄中固定的報告檔名。
3. **從專案指示讀取 artifact 目錄。** `docs/claude.md:32-35` 讓 repo 的 `CLAUDE.md`／`AGENTS.md` 能把 `EGM artifact directory:` 設成任意路徑並自動建立。提議：要求路徑位於工作目錄之下，否則詢問使用者。
4. **暫存檔寫在 workspace 外。** `resources/execution_instructions.md:7-9` 與 `skills/egm-bootstrap/SKILL.md:57-59` 使用專案外、可預測的 `/tmp/` 路徑，與「寫入權限只限專案」（`docs/claude.md:59-60`）矛盾。提議：使用 host 的 scratch 目錄或 `mktemp -d`。
5. **bootstrap 平行數無上限。** `skills/egm-bootstrap/SKILL.md:194-196` 沒有限制 worker 或 scout 的數量。提議：加上上限，並在既有的「超過 15 個目錄」確認關卡中顯示預估成本。
6. **marketplace 追蹤 `main` 並安裝整個 repo。** `.claude-plugin/marketplace.json:9` 使用 `source: "./"`，繞過了 `distributions/claude` 所用的 runtime allowlist。提議：改指向 `distributions/claude`，或指向固定版本的 release。
7. **開發依賴。** `requirements-dev.txt:16-17` 只設下限，`.github/dependabot.yml` 沒有涵蓋 `pip`。提議：鎖定版本並加上 hash，Dependabot 加入 `pip`。
8. **文件正確性。** `docs/designs/synthesizer.md:116` 說工具權限由 persona 檔定義，實際上是由 adapter 定義。`agents/*.md:11` 不分 host 一律宣稱「You have NO tools to modify the workspace」。提議：註明這取決於 host，並引用逐 host 的對照表。

## 完成條件（Completion Criteria）

- 每一項都已修改，或明確記錄為「接受此風險」並附理由。
- 能在 manifest 中表達的路徑／寫入限制，都有 unit test 涵蓋（例如擴充 `tests/unit/test_harnesses.py`）。
- `docs/harnesses.md` 逐一標明各 host 的 reviewer 唯讀，是由 host 強制還是只靠提示文字。

Related: #261（同一次審查中的 Medium 等級發現）。

---
*以 AI 協助撰寫（Claude，唯讀雙審查員靜態審查）；送出前已由我本人審閱發現與引用。*
