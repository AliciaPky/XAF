"""XAF PDF report — a print-friendly security snapshot of the whole console.

build_pdf_report() reads the live pipeline data via lib.py and renders a multi-page
PDF (reportlab / Platypus): summary KPIs, attack-type breakdown, recent attacks,
clusters, and the rule inventory (live / pending / rolled back). Returns raw PDF
bytes so the dashboard can hand them straight to st.download_button.

Kept ASCII-safe on purpose — reportlab's built-in fonts render emoji / fancy unicode
as black boxes, so text is sanitised to latin-1 before drawing.
"""

from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

import lib

# --palette (print-friendly)--
BLUE = colors.HexColor("#2563eb")
DARK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6b7280")
GREEN = colors.HexColor("#059669")
RED = colors.HexColor("#dc2626")
AMBER = colors.HexColor("#d97706")
LINE = colors.HexColor("#e5e7eb")
ALT = colors.HexColor("#f9fafb")

_FAM = {"sqli": "SQLi", "xss": "XSS", "ssti": "SSTI"}

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Title"], fontSize=20, textColor=DARK, spaceAfter=2)
SUB = ParagraphStyle("sub", parent=_ss["Normal"], fontSize=9, textColor=MUTED)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=13, textColor=BLUE,
                    spaceBefore=14, spaceAfter=6)
BODY = ParagraphStyle("body", parent=_ss["Normal"], fontSize=9, textColor=DARK, leading=12)
CELL = ParagraphStyle("cell", parent=_ss["Normal"], fontSize=8, textColor=DARK, leading=10)
MONO = ParagraphStyle("mono", parent=_ss["Normal"], fontName="Courier", fontSize=7.5,
                      textColor=DARK, leading=9)
KLBL = ParagraphStyle("klbl", parent=_ss["Normal"], fontSize=7.5, textColor=MUTED)
KVAL = ParagraphStyle("kval", parent=_ss["Normal"], fontSize=17, textColor=DARK, leading=18)


def _san(s, n: int = 0) -> str:
    s = str(s).replace("\n", " ").replace("\r", " ").strip()
    s = s.encode("latin-1", "replace").decode("latin-1")   # drop glyphs the font lacks
    if n and len(s) > n:
        s = s[:n - 3] + "..."
    return s


def _p(text, style=CELL, n: int = 0):
    return Paragraph(escape(_san(text, n)), style)


def _table(headers, rows, widths, aligns=None):
    data = [[Paragraph(f"<b>{escape(h)}</b>",
             ParagraphStyle("th", parent=CELL, textColor=colors.white, fontSize=8)) for h in headers]]
    data += rows
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for col, a in (aligns or {}).items():
        style.append(("ALIGN", (col, 0), (col, -1), a))
    t.setStyle(TableStyle(style))
    return t


def _colored(text, color):
    return Paragraph(f'<font color="#{color.hexval()[2:]}">{escape(_san(text))}</font>',
                     ParagraphStyle("c", parent=CELL))


def _kpi_band(items):
    # items: list of (label, value, color)
    # Each cell stacks label over value, laid out 4 per row
    cells = []
    for label, value, color in items:
        vstyle = ParagraphStyle("kv", parent=KVAL, textColor=color)
        cells.append([Paragraph(escape(label), KLBL), Spacer(1, 2),
                      Paragraph(escape(str(value)), vstyle)])
    while len(cells) % 4:                          # pad the last row
        cells.append("")
    rows = [cells[i:i + 4] for i in range(0, len(cells), 4)]
    t = Table(rows, colWidths=[43 * mm] * 4)
    t.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 2), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _verdict(valid):
    if valid is True:
        return _colored("PASS", GREEN)
    if valid is False:
        return _colored("FAIL", RED)
    return _colored("-", MUTED)


def build_pdf_report() -> bytes:
    # Assemble the report from live pipeline data and return PDF bytes
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="XAF Security Report",
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm)
    story = []

    # -- header --
    df = lib.load_attacks()
    docker = lib.docker_status()
    waf = "running" if docker.get("nginx-modsec") == "up" else "not reachable"
    sch = lib.get_scheduler_state()
    story.append(Paragraph("XAF Operator Console &mdash; Security Report", H1))
    story.append(Paragraph(
        f"Generated {datetime.now():%Y-%m-%d %H:%M:%S}",SUB))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=LINE))
    story.append(Spacer(1, 8))

    # -- KPI summary --
    m = lib.attack_metrics(df) if not df.empty else {"total": 0, "blocked": 0,
                                                     "bypassed": 0, "clusters": 0}
    total = m.get("total", 0)
    cov = round(m.get("blocked", 0) / total * 100, 1) if total else 0.0
    byp = round(m.get("bypassed", 0) / total * 100, 1) if total else 0.0
    live = [r for r in lib.load_finalized_rules() if not r["disabled"]]
    rolled = [r for r in lib.load_finalized_rules() if r["disabled"]]
    pending = lib.load_candidate_rules()

    story.append(Paragraph("Summary", H2))
    story.append(_kpi_band([
        ("Total attacks", total, DARK),
        ("Blocked by CRS", f"{m.get('blocked', 0)} ({cov}%)", GREEN),
        ("Uncaught by CRS", f"{m.get('bypassed', 0)} ({byp}%)", RED),
        ("Active clusters", m.get("clusters", 0), BLUE),
        ("Live rules", len(live), GREEN),
        ("Pending approval", len(pending), AMBER),
        ("Rolled back", len(rolled), MUTED),
        ("Auto-gen runs", sch.get("runs", 0), DARK),
    ]))

    # -- attack-type breakdown --
    if not df.empty and "family" in df.columns:
        story.append(Paragraph("Attack types", H2))
        vc = df["family"].astype(str).str.lower().value_counts()
        rows = [[_p(_FAM.get(f, f.upper())), _p(str(int(c))),
                 _p(f"{round(int(c) / total * 100, 1)}%" if total else "0%")]
                for f, c in vc.items()]
        story.append(_table(["Family", "Count", "Share"], rows,
                            [70 * mm, 40 * mm, 40 * mm], aligns={1: "CENTER", 2: "CENTER"}))

    # -- recent attacks --
    if not df.empty:
        story.append(Paragraph("Recent attacks", H2))
        disp = {"blocked": "BLOCKED", "bypassed": "UNCAUGHT"}
        recent = df.tail(15).iloc[::-1]
        rows = []
        for _, r in recent.iterrows():
            ts = pd.to_datetime(r.get("timestamp"), errors="coerce")
            tstr = ts.strftime("%Y-%m-%d<br/>%H:%M:%S") if pd.notna(ts) else "--"
            status = disp.get(str(r.get("status", "")).lower(), "UNKNOWN")
            scol = GREEN if status == "BLOCKED" else RED
            rid = pd.to_numeric(r.get("rule_id"), errors="coerce")
            rid = str(int(rid)) if pd.notna(rid) else "-"
            rows.append([Paragraph(tstr, CELL), _colored(status, scol), _p(r.get("uri", ""), n=32),
                         Paragraph(escape(_san(r.get("payload", ""), 58)), MONO), _p(rid)])
        story.append(_table(["Timestamp", "Verdict", "URI", "Payload", "Rule"], rows,
                            [22 * mm, 20 * mm, 34 * mm, 66 * mm, 18 * mm]))

    # -- clusters --
    payloads = lib.csv_cluster_payloads()
    if payloads:
        fams = lib.cluster_families()
        covered = {lib.cluster_key(r["cluster"], r["subgroup"]) for r in lib.load_deployed_rules()}
        story.append(Paragraph("Attack clusters", H2))
        rows = []
        for cid in sorted(payloads):
            ps = payloads[cid]
            try:
                sig = lib.cluster_signature_label(ps)
            except Exception:
                sig = "-"
            rows.append([_p(f"C{cid}"), _p(_FAM.get(str(fams.get(cid)).lower(), "-")),
                         _p(str(len(ps))), _p(sig, n=40),
                         _colored("yes" if str(cid) in covered else "no",
                                  GREEN if str(cid) in covered else MUTED)])
        story.append(_table(["Cluster", "Family", "Payloads", "Signature", "Covered"], rows,
                            [18 * mm, 18 * mm, 20 * mm, 74 * mm, 20 * mm],
                            aligns={2: "CENTER", 4: "CENTER"}))

    # -- rule inventory --
    story.append(Paragraph("Rule inventory", H2))

    def _rule_rows(items):
        out = []
        for r in items:
            cl = f"C{r['cluster']}" + (f"/{r['subgroup']}" if r.get("subgroup") else "") \
                if r["cluster"] is not None else "-"
            cov = f"{max(r['scope_size'] - len(r['missed'] or []), 0)}/{r['scope_size']}"
            out.append([_p(str(r["id"])), _p(cl),
                        _p(_FAM.get(str(r.get("family")).lower(), "-")),
                        _verdict(r["valid"]), _p(cov)])
        return out

    for label, items, note in (
            ("Live (enforced)", live, "currently protecting the app"),
            ("Pending approval", pending, "awaiting human sign-off"),
            ("Rolled back", rolled, "disabled by the operator")):
        story.append(Paragraph(f"<b>{escape(label)}</b> &nbsp;"
                               f'<font size="8" color="#6b7280">&mdash; {escape(note)} '
                               f"({len(items)})</font>", BODY))
        story.append(Spacer(1, 3))
        if items:
            story.append(_table(["Rule ID", "Cluster", "Family", "Validation", "Coverage"],
                                _rule_rows(items),
                                [30 * mm, 30 * mm, 25 * mm, 30 * mm, 25 * mm],
                                aligns={3: "CENTER", 4: "CENTER"}))
        else:
            story.append(Paragraph('<font size="8" color="#6b7280">none</font>', BODY))
        story.append(Spacer(1, 6))

    doc.build(story)
    return buf.getvalue()
