"""Translate the interface text of the English interactive mind map.

The mindmap skill's render.py writes its toolbar, hint and messages in Chinese.
After re-rendering docs/ssdlc-mindmap.en.html, run:

    python3 -I docs/mindmaps/localize_en.py docs/ssdlc-mindmap.en.html

Node text comes from ssdlc.en.mindmap.json and is not touched. Code comments
are left as they are. The script fails if a string it expects is missing, and
lists any Chinese text left outside comments.
"""
import re
import sys

PAIRS = [
    ('<html lang="zh-Hant">', '<html lang="en">'),
    ("SSDLC mod · 心智圖</title>", "SSDLC mod · mind map</title>"),
    ("匯出 JSON（貼回給 Claude）", "Export JSON (paste back to Claude)"),
    ('title="縮小"', 'title="Zoom out"'),
    ('title="放大"', 'title="Zoom in"'),
    ('title="整張圖縮放至可視範圍">適應<', 'title="Zoom the whole map to fit the window">Fit<'),
    ("mind.toCenter()\">置中<", "mind.toCenter()\">Center<"),
    ('title="切換滾輪行為">滾輪：縮放<', 'title="Switch the scroll-wheel behaviour">Wheel: zoom<'),
    ("'滾輪：縮放' : '滾輪：平移'", "'Wheel: zoom' : 'Wheel: pan'"),
    ("拖曳空白處即可平移畫布（像瀏覽地圖）、滾輪縮放；單擊選取節點、雙擊或 F2 編輯、拖拉節點搬移分支、Tab 新增子節點、右鍵拖曳框選；改完按「匯出 JSON」貼回對話即可同步。",
     "Drag empty space to pan (like a map), scroll to zoom; click to select a node, double-click or F2 to edit, drag a node to move its branch, Tab to add a child node, right-drag to box-select. When done, click “Export JSON” and paste it back into the conversation to sync."),
    ("已下載並複製到剪貼簿——貼回對話，Claude 會用 mm.py adopt 同步",
     "Downloaded and copied to the clipboard — paste it back into the conversation and Claude will sync it with mm.py adopt"),
    ("已下載 JSON——請貼回對話給 Claude 同步",
     "JSON downloaded — paste it back into the conversation for Claude to sync"),
]

CJK = re.compile(r"[　-鿿＀-￯]")


def main(path):
    s = open(path, encoding="utf-8").read()
    for zh, en in PAIRS:
        if zh not in s:
            sys.exit(f"not found (re-rendered with a different render.py?): {zh[:40]}")
        s = s.replace(zh, en)
    open(path, "w", encoding="utf-8").write(s)
    left = [line.strip()[:80] for line in s.splitlines()
            if CJK.search(re.sub(r"//.*", "", line))]
    for line in left:
        print("Chinese text left:", line)
    print(f"localized {path}; {len(left)} line(s) with Chinese outside comments")


if __name__ == "__main__":
    main(sys.argv[1])
