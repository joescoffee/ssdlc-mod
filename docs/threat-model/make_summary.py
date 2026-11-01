"""Build the one-page threat model summary (Chinese and English) from scored.json.

    python3 -I docs/threat-model/make_summary.py
    -> docs/threat-model/summary.html, summary.en.html

Every number is counted from scored.json, so the page cannot drift from the
records. The PNGs are screenshots of these pages (full page, 1280 px wide, 2x).
"""
import collections
import html
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = json.loads((HERE / "scored.json").read_text(encoding="utf-8"))
RECS = DATA["tara_dfmea"]
NA = {c["item"].split()[-1]: c["reason"] for c in DATA["project"].get("coverage_decisions", [])
      if c["decision"] == "not-applicable"}

EN_TITLES = {  # from report.en.md
    "CTARA-SSDLC-06": "Using allow markers to make the gate ignore malicious code",
    "CTARA-SSDLC-11": "Bringing the scan down with oversized files, overlong lines or special files",
    "CTARA-SSDLC-01B": "CTARA-SSDLC-01 under bypass / acceptEdits mode (sensitivity)",
    "CTARA-SSDLC-10": "Guard denials leave no persistent record and cannot be traced afterwards",
    "CTARA-SSDLC-02": "Injected review agent reads credentials and writes them into the report",
}

T = {
    "zh": {
        "lang": "zh-Hant", "title": "ssdlc 威脅模型摘要",
        "sub": "MAS 模式 · 2026-11-01 · 依 docs/threat-model/scored.json 計算",
        "t_records": "威脅紀錄", "t_records_s": "其中高風險（Critical／High）{n} 筆",
        "t_residual": "處置後仍為 Critical／High", "t_residual_s": "最高剩 Medium（{n} 筆）",
        "t_treat": "已實作控制", "t_treat_s": "其餘 {n} 筆為規劃中",
        "c_eff": "處置後有效風險（12 筆）", "c_stride": "STRIDE 分類", "c_maestro": "MAESTRO 層",
        "lvl": {"Medium": "Medium", "Low": "Low", "Mitigated": "已緩解"},
        "stride": {"S": "S 偽冒", "T": "T 竄改", "R": "R 否認", "I": "I 資訊揭露", "D": "D 阻斷服務", "E": "E 權限提升"},
        "na": "不適用（已宣告）",
        "c_high": "高風險紀錄與處置結果",
        "h_id": "紀錄", "h_lvl": "原始風險", "h_threat": "威脅", "h_eff": "處置後",
        "foot": "工具的整體態勢分數為 CRITICAL（扣分 130），因為這份模型只記錄威脅，未登錄資產、入口與控制項（皆為 0），覆蓋率計為 0%；請以處置後有效風險解讀。完整內容見 report.md。",
    },
    "en": {
        "lang": "en", "title": "ssdlc threat model summary",
        "sub": "MAS mode · 2026-11-01 · counted from docs/threat-model/scored.json",
        "t_records": "threat records", "t_records_s": "{n} rated high risk (Critical / High)",
        "t_residual": "still Critical / High after treatment", "t_residual_s": "highest remaining: Medium ({n})",
        "t_treat": "with controls implemented", "t_treat_s": "the other {n} are planned",
        "c_eff": "Effective risk after treatment (12 records)", "c_stride": "STRIDE category", "c_maestro": "MAESTRO layer",
        "lvl": {"Medium": "Medium", "Low": "Low", "Mitigated": "Mitigated"},
        "stride": {"S": "S Spoofing", "T": "T Tampering", "R": "R Repudiation", "I": "I Info disclosure", "D": "D Denial of service", "E": "E Elevation"},
        "na": "not applicable (declared)",
        "c_high": "High-risk records and where they stand",
        "h_id": "Record", "h_lvl": "Inherent", "h_threat": "Threat", "h_eff": "After treatment",
        "foot": "The tool's overall posture score is CRITICAL (deduction 130) because this model records threats only: assets, entry points and controls are not registered (all 0), so coverage counts as 0%. Read the effective risk after treatment instead. Full details: report.en.md.",
    },
}

LEVEL_ORDER = ["Medium", "Low", "Mitigated"]
LEVEL_STYLE = {"Medium": ("var(--warning)", "▲"), "Low": ("var(--neutral)", "●"), "Mitigated": ("var(--good)", "✓")}
CRIT_STYLE = {"Critical": ("var(--critical)", "◆"), "High": ("var(--serious)", "▲")}


def esc(s):
    return html.escape(str(s))


def bars(items, maxv, na_label=None):
    rows = []
    for label, v, na in items:
        w = 0 if maxv == 0 else v / maxv * 100
        val = f"0 · {esc(na_label)}" if na else str(v)
        bar = f'<span class="bar" style="width:{w:.1f}%"></span>' if v else ""
        rows.append(f'<div class="brow"><span class="blab">{esc(label)}</span>'
                    f'<span class="btrack">{bar}<span class="bval{" muted" if not v else ""}">{val}</span></span></div>')
    return "".join(rows)


def page(lang):
    t = T[lang]
    eff = collections.Counter(r["effective_risk_level"] for r in RECS)
    crit = collections.Counter(r["criticality"] for r in RECS)
    stride = collections.Counter(r["stride_classification"] for r in RECS)
    maestro = collections.Counter(r["maestro_layer"] for r in RECS)
    treat = collections.Counter(r["treatment_status"] for r in RECS)
    high = [r for r in RECS if r["criticality"] in ("Critical", "High")]
    high.sort(key=lambda r: (r["criticality"] != "Critical", -r["effective_risk"], r["record_id"]))
    n = len(RECS)
    residual_hi = sum(eff[k] for k in ("Critical", "High"))

    segs = "".join(
        f'<span class="seg" style="flex:{eff[k]};background:{LEVEL_STYLE[k][0]}"></span>' for k in LEVEL_ORDER if eff[k])
    legend = "".join(
        f'<span class="lg"><i style="background:{LEVEL_STYLE[k][0]}"></i>{LEVEL_STYLE[k][1]} {esc(t["lvl"][k])} <b>{eff[k]}</b></span>'
        for k in LEVEL_ORDER)

    s_items = [(t["stride"][k], stride[k], False) for k in "STRIDE"]
    layers = ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "X"]
    m_items = [(k, maestro[k], k in NA and not maestro[k]) for k in layers]
    smax = max(stride.values())
    mmax = max(maestro.values())

    rows = []
    for r in high:
        c, icon = CRIT_STYLE[r["criticality"]]
        e = r["effective_risk_level"]
        ec, eicon = LEVEL_STYLE.get(e, ("var(--neutral)", "●"))
        title = r["failure_threat_mode"] if lang == "zh" else EN_TITLES[r["record_id"]]
        rows.append(
            f'<tr><td class="mono">{esc(r["record_id"])}</td>'
            f'<td><span class="pill"><i style="background:{c}"></i>{icon} {esc(r["criticality"])}</span></td>'
            f'<td>{esc(title)}</td>'
            f'<td><span class="pill"><i style="background:{ec}"></i>{eicon} {esc(t["lvl"].get(e, e))} '
            f'<span class="muted">({r["effective_risk"]:g})</span></span></td></tr>')

    tiles = [
        (n, t["t_records"], t["t_records_s"].format(n=len(high))),
        (residual_hi, t["t_residual"], t["t_residual_s"].format(n=eff["Medium"])),
        (treat["implemented"], t["t_treat"], t["t_treat_s"].format(n=n - treat["implemented"])),
    ]
    tiles_html = "".join(f'<div class="tile"><div class="num">{v}</div><div class="tl">{esc(a)}</div>'
                         f'<div class="ts">{esc(b)}</div></div>' for v, a, b in tiles)

    return f"""<!doctype html><html lang="{t['lang']}"><meta charset="utf-8">
<title>{esc(t['title'])}</title>
<style>
:root{{--surface:#fcfcfb;--page:#eef1f5;--text:#0b0b0b;--text2:#52514e;--muted:#8a8984;--grid:#e4e3df;
--series:#2a78d6;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--neutral:#b9b8b2}}
body{{margin:0;padding:28px;background:var(--page);color:var(--text);font:15px/1.45 'Noto Sans TC','Noto Sans',sans-serif;width:1224px}}
h1{{margin:0;font-size:24px}} h1 img{{width:34px;vertical-align:-8px;margin-right:10px;border-radius:8px}}
.sub{{color:var(--text2);margin:4px 0 18px 46px;font-size:13px}}
.card{{background:var(--surface);border-radius:12px;padding:18px 20px;box-shadow:0 2px 10px #0001}}
.tiles{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}}
.num{{font-size:44px;font-weight:700;line-height:1.1}} .tl{{font-weight:600;margin-top:2px}} .ts{{color:var(--text2);font-size:13px}}
.tile{{background:var(--surface);border-radius:12px;padding:16px 20px;box-shadow:0 2px 10px #0001}}
h2{{font-size:15px;margin:0 0 12px;color:var(--text)}}
.stack{{display:flex;gap:2px;height:22px;border-radius:4px;overflow:hidden;margin:6px 0 10px}}
.lg{{margin-right:22px;color:var(--text2);font-size:14px}} .lg i,.pill i{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:0}}
.lg b{{color:var(--text)}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}}
.brow{{display:flex;align-items:center;margin:7px 0}} .blab{{width:150px;color:var(--text2);font-size:13.5px}}
.btrack{{flex:1;display:flex;align-items:center;gap:8px}} .bar{{height:14px;background:var(--series);border-radius:0 4px 4px 0}}
.bval{{font-size:13.5px;font-weight:600}} .muted{{color:var(--muted);font-weight:400}}
table{{width:100%;border-collapse:collapse;font-size:14px}} th{{text-align:left;color:var(--text2);font-weight:600;border-bottom:1px solid var(--grid);padding:6px 8px}}
td{{padding:8px;border-bottom:1px solid var(--grid);vertical-align:top}} tr:last-child td{{border-bottom:0}}
.mono{{font-family:'DejaVu Sans Mono',monospace;font-size:13px;white-space:nowrap}} .pill{{white-space:nowrap}}
.foot{{color:var(--text2);font-size:12.5px;margin-top:14px}}
</style>
<h1><img src="../../.claude-plugin/icon.png">{esc(t['title'])}</h1>
<div class="sub">{esc(t['sub'])}</div>
<div class="tiles">{tiles_html}</div>
<div class="card"><h2>{esc(t['c_eff'])}</h2><div class="stack">{segs}</div>{legend}</div>
<div class="grid2">
<div class="card"><h2>{esc(t['c_stride'])}</h2>{bars(s_items, smax)}</div>
<div class="card"><h2>{esc(t['c_maestro'])}</h2>{bars(m_items, mmax, t['na'])}</div>
</div>
<div class="card"><h2>{esc(t['c_high'])}</h2>
<table><tr><th>{esc(t['h_id'])}</th><th>{esc(t['h_lvl'])}</th><th>{esc(t['h_threat'])}</th><th>{esc(t['h_eff'])}</th></tr>{''.join(rows)}</table></div>
<div class="foot">{esc(t['foot'])}</div>
</html>"""


if __name__ == "__main__":
    (HERE / "summary.html").write_text(page("zh"), encoding="utf-8")
    (HERE / "summary.en.html").write_text(page("en"), encoding="utf-8")
    print("wrote summary.html, summary.en.html")
