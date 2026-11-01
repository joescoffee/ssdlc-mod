# ssdlc v0.2.0 自我審查與處置（2026-11-01）

以本 mod 自己的 `/ssdlc:ai-security-review` 流程審查自己：goldfish（`ssdlc:security-reviewer`，只看程式碼）回報 22 項（判定 BLOCK），elephant（`ssdlc:design-reviewer`，威脅建模＋MIT 因果格）回報 22 項威脅（T1–T22）。兩份合併後依下表處置，v0.2.1 修正。

| 合併項 | 來源 | 嚴重度 | 處置（v0.2.1） |
|---|---|---|---|
| git 指令會執行受審 repo 的 `.git/config`（fsmonitor、filter、diff.external…），且各技能不一致 | SR-2/3/11、T8 | High | ✅ 新增 `references/untrusted-repo.md` 單一規則：只在自己 clone 的 repo 跑 git＋完整旗標；壓縮檔／共享資料夾帶來的 `.git` 不跑 git；所有技能引用 |
| security-review 的依賴稽核用 plain `pip-audit` | SR-12 | High | ✅ 改引用只解析的指令 |
| 大小寫、`//`、`/./` 繞過 guard | SR-4、SR-13 | High | ✅ 不分大小寫、路徑正規化 |
| Grep 從上層目錄遞迴讀進憑證 | SR-1、T5 | High | ⚠️ 部分：拒絕從根目錄、家目錄、系統目錄、`~/.config` 遞迴搜尋；無 path 時以 cwd 判斷。repo 根目錄 allowlist 列入路線圖 |
| 主 session 三項全中（Rule of Two） | T1、T21、T22 | High | ⚠️ 未修：列入已知限制；技能新增 fail-closed（無 ssdlc 審查代理就停止）、禁止以弱化檢查求通過 |
| 檔名經 shell 造成命令注入 | T2 | High | ✅ 掃描器 `--files-from`（NUL 分隔）、支援 `--`；gate 改用 `git diff -z` 寫入清單檔 |
| denylist 不完整（k8s token、.envrc、.claude.json、history…） | SR-5、T5b | Medium | ✅ 擴充 |
| ReDoS | SR-6、T13 | Medium | ✅ 每行上限 4 KB、量詞加上界；測試 5 秒內完成 |
| excerpt 洩漏 secret、控制字元 | SR-7、T3、T4 | Medium | ✅ 每筆 excerpt 遮蔽所有 secret、跳脫控制與隱形字元、JSON `ensure_ascii` |
| allow marker 範圍過大、預設採用 | SR-8、T12 | Medium | ✅ 預設忽略（`--honor-markers` 才採用）；永不隱藏 secret／隱形字元；reason 淨化 |
| git config 可執行 key 偵測不全 | SR-9 | Medium | ✅ 新規則 `repo.git-config-exec`（不分大小寫、filter/sshCommand/pager/alias `!`…、`config.worktree`） |
| 讀不到／不存在／FIFO 被默默略過 | SR-10、T13、T14 | Medium | ✅ 只讀一般檔案（`lstat`＋`O_NOFOLLOW`＋`O_NONBLOCK`）、全部列入 skipped、結束碼 3＝INCOMPLETE、未知旗標結束碼 2 |
| vuln-fix 跑測試未重申 sandbox、可被注入觸發 | SR-20、T11 | Medium | ✅ 驗證步驟重申 sandbox；`disable-model-invocation: true`；禁止以 marker／刪測試求通過 |
| guard 時序與重新載入後失效、名稱寫死 | T6、SR-13 | Medium | ✅ 快取未命中時以 `$.agent.list()` 查類型；前綴改用 `$.plugin.name` |
| 依賴稽核工具讀 repo 內設定（osv-scanner.toml、.npmrc） | T10 | Medium | ✅ gate 檢查並在僅含 lockfile 的暫存目錄、指定 registry 執行 |
| 持久化報告可帶 markdown 圖片外洩 | T15 | Medium | ✅ safe-bootstrap 寫檔前中和圖片、HTML、外部連結 |
| 文件宣稱多於實際強制、報告寫成永久結論 | T7 | Low | ✅ README 措辭修正；EGM 報告加時點聲明 |
| symlink 剩餘缺口（`.git` 為 symlink 等） | SR-15 | Low | ✅ `.git` symlink 回報；只讀不跟隨 |
| glob 以字元類別／大括號繞過 | SR-14 | Low | ✅ 比對前展平 `[]{}?` |
| PLUGIN 路徑以 Glob 回退搜尋 | SR-18、T17 | Low | ✅ 移除，改判 INCOMPLETE |
| MCP 偵測漏洞（JSONC、npx.cmd、`pkg@1`、X-API-Key） | SR-19 | Low | ✅ |
| 全域可變狀態 | SR-21 | Info | ✅ 每次掃描重置 |
| 證據未經機械比對、PASS 被當合併授權 | T16 | Medium | ✅ claim-check-act：Grep 確認引用證據；PASS ≠ 合併核准 |
| 平行數無上限 | T13、F11 | Low | ✅ security-review 上限 4 個審查員 |
| TOCTOU、hard link | SR-16 | Low | ⚠️ 未修：需 OS 層 sandbox，列入已知限制 |
| marketplace 未鎖版本、無完整性檢查 | T17、F9 | Low | ⚠️ 部分：以 git tag `v0.2.1` 發布，手冊說明如何鎖定版本 |
| denial 無持久 log | T19 | Low | ⚠️ 未修：目前只有 toast，列入路線圖 |
| host API 漂移使 guard 靜默失效 | T18、SR-22 | Info | ⚠️ 未修：列入路線圖（啟用訊號） |

測試：Python 單元測試 40 → 53、guard hook 測試 9 → 13，全數通過。
