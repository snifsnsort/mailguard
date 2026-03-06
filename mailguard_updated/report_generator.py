"""
MailGuard PDF Report Generator — ReportLab-based professional export.

Layout:
  Page 1  — Cover: logo, tenant name, score gauge, grade, scan date
  Page 2  — Executive Summary: penalty breakdown table, domain list
  Page 3+ — Findings Detail: grouped Critical → Warning → Pass, remediation steps
  Last    — Footer with generation timestamp
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Circle, String, Wedge, Rect
from reportlab.graphics import renderPDF
from datetime import datetime
from typing import List, Dict, Any
import io
import math

# ── Palette ───────────────────────────────────────────────────────────────────
BG      = colors.HexColor("#0e1520")
SURFACE = colors.HexColor("#131c2b")
ACCENT  = colors.HexColor("#00e5ff")
RED     = colors.HexColor("#ff4f5e")
YELLOW  = colors.HexColor("#ffd740")
GREEN   = colors.HexColor("#00e676")
GREY    = colors.HexColor("#5a7290")
LIGHT   = colors.HexColor("#e2e8f0")
WHITE   = colors.white
DARK    = colors.HexColor("#0d1623")

STATUS_COLOR = {"fail": RED, "warn": YELLOW, "pass": GREEN}
SEVERITY_ORDER = {"fail": 0, "warn": 1, "pass": 2}

PAGE_W, PAGE_H = A4  # 595.28 x 841.89 pts


# ── Style helpers ─────────────────────────────────────────────────────────────
def _style(name, **kw) -> ParagraphStyle:
    defaults = dict(fontName="Helvetica", fontSize=10, textColor=DARK,
                    leading=14, spaceAfter=4)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

S_COVER_TITLE  = _style("ct",  fontSize=32, fontName="Helvetica-Bold", textColor=DARK, spaceAfter=6, alignment=TA_CENTER)
S_COVER_SUB    = _style("cs",  fontSize=13, textColor=GREY, spaceAfter=4, alignment=TA_CENTER)
S_COVER_TENANT = _style("ctn", fontSize=18, fontName="Helvetica-Bold", textColor=DARK, spaceAfter=2, alignment=TA_CENTER)
S_COVER_DOMAIN = _style("cd",  fontSize=11, textColor=GREY, alignment=TA_CENTER)
S_SECTION      = _style("sh",  fontSize=14, fontName="Helvetica-Bold", textColor=DARK, spaceBefore=12, spaceAfter=6)
S_BODY         = _style("b",   fontSize=9,  textColor=DARK, leading=13)
S_MONO         = _style("m",   fontSize=8,  fontName="Courier", textColor=colors.HexColor("#1e3a5f"), leading=12)
S_MUTED        = _style("mu",  fontSize=8,  textColor=GREY, leading=12)
S_LABEL        = _style("lb",  fontSize=7,  textColor=GREY, fontName="Helvetica-Bold",
                          letterSpacing=1, textTransform="uppercase")
S_FINDING_NAME = _style("fn",  fontSize=10, fontName="Helvetica-Bold", textColor=DARK)
S_REM          = _style("re",  fontSize=8,  textColor=colors.HexColor("#2d4a6b"), leading=12, leftIndent=10)
S_FOOTER       = _style("ft",  fontSize=7,  textColor=GREY, alignment=TA_CENTER)


# ── Score gauge (SVG-style drawn with ReportLab shapes) ───────────────────────
def _score_gauge(score: int, grade: str) -> Drawing:
    """Draw a semicircular gauge with the score and grade."""
    W, H = 220, 130
    d    = Drawing(W, H)
    cx, cy, r = W / 2, 30, 80

    grade_color = {
        "A": GREEN, "B": colors.HexColor("#69db7c"),
        "C": YELLOW, "D": colors.HexColor("#ff9f43"), "F": RED,
    }.get(grade, GREY)

    # Background arc (grey full semicircle)
    # Draw as thick arc using many thin wedges
    arc_steps = 60
    for i in range(arc_steps):
        angle_start = 180 + i * (180 / arc_steps)
        angle_end   = 180 + (i + 1) * (180 / arc_steps)
        w = Wedge(cx, cy, r + 12, angle_start, angle_end, radius1=r - 2)
        w.fillColor = colors.HexColor("#dde4ed")
        w.strokeColor = None
        d.add(w)

    # Score arc (colored portion)
    score_frac  = score / 100.0
    score_steps = max(1, int(arc_steps * score_frac))
    for i in range(score_steps):
        angle_start = 180 + i * (180 / arc_steps)
        angle_end   = 180 + (i + 1) * (180 / arc_steps)
        w = Wedge(cx, cy, r + 12, angle_start, angle_end, radius1=r - 2)
        w.fillColor = grade_color
        w.strokeColor = None
        d.add(w)

    # Centre score text
    score_txt = String(cx, cy + 28, str(score),
                       textAnchor="middle", fontSize=38,
                       fontName="Helvetica-Bold", fillColor=DARK)
    d.add(score_txt)
    d.add(String(cx, cy + 10, "/ 100", textAnchor="middle",
                 fontSize=10, fontName="Helvetica", fillColor=GREY))
    d.add(String(cx, cy - 8, f"Grade  {grade}", textAnchor="middle",
                 fontSize=13, fontName="Helvetica-Bold", fillColor=grade_color))
    return d


# ── Score breakdown table ─────────────────────────────────────────────────────
def _penalty_table(breakdown: List[Dict]) -> Table:
    if not breakdown:
        return Table([["All checks passed."]])

    header = ["Check", "Status", "Points"]
    rows   = [header]
    for b in sorted(breakdown, key=lambda x: -(x.get("max_points", x.get("max_penalty", 0)))):
        status    = b.get("status", "").upper()
        earned    = b.get("points_earned", b.get("max_points", b.get("max_penalty", 0)) if status == "PASS" else 0)
        max_pts   = b.get("max_points", b.get("max_penalty", 0))
        is_fail   = status == "FAIL"
        is_warn   = status == "WARN"
        rows.append([
            Paragraph(b.get("name", b.get("check_id", "")), S_BODY),
            Paragraph(status, _style("st", fontSize=8, fontName="Helvetica-Bold",
                                     textColor=RED if is_fail else (YELLOW if is_warn else GREEN))),
            Paragraph(f"{earned}/{max_pts}", _style("p", fontSize=8, fontName="Helvetica-Bold",
                                             textColor=RED if is_fail else (YELLOW if is_warn else GREEN))),
        ])

    t = Table(rows, colWidths=[10.5*cm, 2.5*cm, 2*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0),  8),
        ("TEXTCOLOR",     (0,0), (-1,0),  GREY),
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#f0f4f8")),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f8fafc")]),
        ("GRID",          (0,0), (-1,-1), 0.25, colors.HexColor("#dde4ed")),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (1,0), (-1,-1), "CENTER"),
    ]))
    return t


# ── Single finding block ──────────────────────────────────────────────────────
def _finding_block(f: Dict) -> List:
    status = f.get("status", "pass")
    col    = STATUS_COLOR.get(status, GREY)
    label  = status.upper()
    domain = f.get("domain")
    name   = f.get("name", f.get("check_id", ""))

    name_line = f"<b>{name}</b>"
    if domain:
        name_line += f'  <font color="#5a7290" size="8">[{domain}]</font>'

    header_row = Table(
        [[Paragraph(name_line, S_FINDING_NAME),
          Paragraph(label, _style("sl", fontSize=9, fontName="Helvetica-Bold",
                                  textColor=col, alignment=TA_CENTER))]],
        colWidths=[13*cm, 2*cm]
    )
    header_row.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f5f8fc")),
        ("LEFTPADDING",  (0,0), (0,-1), 10),
        ("LINEAFTER",    (0,0), (0,-1), 2, col),
        ("BOX",          (0,0), (-1,-1), 0.25, colors.HexColor("#dde4ed")),
        ("PADDING",      (0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))

    elements = [header_row]

    cat_bench = f"<i>{f.get('category','')}</i>"
    if f.get("benchmark"):
        cat_bench += f"  ·  {f['benchmark']}"
    elements.append(Paragraph(cat_bench, S_MUTED))

    if f.get("description"):
        elements.append(Paragraph(f.get("description", ""), S_BODY))

    if f.get("remediation"):
        rem_lines = "".join(
            f"{i+1}. {step}<br/>"
            for i, step in enumerate(f["remediation"])
        )
        elements.append(Paragraph(f"<b>Remediation:</b><br/>{rem_lines}", S_REM))

    elements.append(Spacer(1, 0.25*cm))
    return elements


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_report(tenant: Dict, scan: Dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=2*cm,
        title=f"MailGuard Report — {tenant.get('display_name','')}"
    )

    findings          = scan.get("findings", [])
    penalty_breakdown = scan.get("penalty_breakdown", [])
    domains_scanned   = scan.get("domains_scanned", [tenant.get("domain", "")])
    score             = scan.get("score", 0)
    grade             = scan.get("grade", "F")
    platform          = scan.get("platform", "Microsoft 365")

    story = []

    # ── PAGE 1: Cover ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph("MailGuard", S_COVER_TITLE))
    story.append(Paragraph("Email Security Posture Report", S_COVER_SUB))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT))
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph(tenant.get("display_name", "—"), S_COVER_TENANT))
    story.append(Paragraph(", ".join(domains_scanned) or tenant.get("domain", "—"), S_COVER_DOMAIN))
    story.append(Spacer(1, 0.5*cm))

    # Score gauge
    gauge_drawing = _score_gauge(score, grade)
    story.append(Table([[gauge_drawing]], colWidths=[PAGE_W - 4*cm]))
    story.append(Spacer(1, 0.5*cm))

    # Meta info table
    critical = sum(1 for f in findings if f.get("status") == "fail")
    warnings = sum(1 for f in findings if f.get("status") == "warn")
    passing  = sum(1 for f in findings if f.get("status") == "pass")
    deducted    = sum(b.get("points_earned", 0) for b in penalty_breakdown)
    total_possible = sum(b.get("max_points", b.get("max_penalty", 0)) for b in penalty_breakdown)

    meta = [
        ["Platform",      platform],
        ["Scan Date",     datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Domains Scanned", str(len(domains_scanned))],
        ["Checks Run",    str(len(findings))],
        ["Points Earned", f"{round(deducted)} / {total_possible} pts"],
    ]
    mt = Table(meta, colWidths=[4.5*cm, 10.5*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("TEXTCOLOR",      (0,0), (0,-1),  GREY),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f8fafc"), WHITE]),
        ("GRID",           (0,0), (-1,-1), 0.25, colors.HexColor("#dde4ed")),
        ("PADDING",        (0,0), (-1,-1), 7),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.6*cm))

    # Severity summary bar
    summary_data = [
        [Paragraph(f"<b>{critical}</b>", _style("sc", fontSize=20, fontName="Helvetica-Bold", textColor=RED, alignment=TA_CENTER)),
         Paragraph(f"<b>{warnings}</b>", _style("sw", fontSize=20, fontName="Helvetica-Bold", textColor=YELLOW, alignment=TA_CENTER)),
         Paragraph(f"<b>{passing}</b>",  _style("sp", fontSize=20, fontName="Helvetica-Bold", textColor=GREEN, alignment=TA_CENTER))],
        [Paragraph("CRITICAL", _style("lc", fontSize=8, textColor=RED,    alignment=TA_CENTER, fontName="Helvetica-Bold")),
         Paragraph("WARNINGS", _style("lw", fontSize=8, textColor=YELLOW, alignment=TA_CENTER, fontName="Helvetica-Bold")),
         Paragraph("PASSING",  _style("lp", fontSize=8, textColor=GREEN,  alignment=TA_CENTER, fontName="Helvetica-Bold"))],
    ]
    st = Table(summary_data, colWidths=[5*cm, 5*cm, 5*cm])
    st.setStyle(TableStyle([
        ("BOX",     (0,0), (-1,-1), 0.5, colors.HexColor("#dde4ed")),
        ("INNERGRID",(0,0),(-1,-1), 0.25, colors.HexColor("#dde4ed")),
        ("PADDING", (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor("#fafbfc"),WHITE]),
    ]))
    story.append(st)
    story.append(PageBreak())

    # ── PAGE 2: Executive Summary ─────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S_SECTION))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dde4ed")))
    story.append(Spacer(1, 0.3*cm))

    # Score interpretation
    interp = {
        "A": "Excellent posture — minor hardening opportunities remain.",
        "B": "Good posture — a few important gaps should be addressed.",
        "C": "Fair posture — several significant risks require attention.",
        "D": "Poor posture — critical vulnerabilities present, remediate urgently.",
        "F": "Critical risk — multiple high-severity controls are failing.",
    }.get(grade, "")
    story.append(Paragraph(f"<b>Score {score}/100 — Grade {grade}:</b> {interp}", S_BODY))
    story.append(Spacer(1, 0.3*cm))

    if domains_scanned and len(domains_scanned) > 1:
        story.append(Paragraph("<b>Domains scanned:</b>", S_BODY))
        for d in domains_scanned:
            story.append(Paragraph(f"• {d}", S_REM))
        story.append(Spacer(1, 0.2*cm))

    if penalty_breakdown:
        story.append(Paragraph("<b>Score Breakdown</b>", S_BODY))
        story.append(Paragraph(
            "The following checks reduced the score. FAIL = full penalty, WARN = half penalty.",
            S_MUTED))
        story.append(Spacer(1, 0.2*cm))
        story.append(_penalty_table(penalty_breakdown))
    else:
        story.append(Paragraph("✓ No score deductions — all checks passed.", S_BODY))

    story.append(PageBreak())

    # ── PAGE 3+: Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("Findings Detail", S_SECTION))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dde4ed")))
    story.append(Spacer(1, 0.2*cm))

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("status","pass"), 2))

    current_status = None
    for f in sorted_findings:
        status = f.get("status", "pass")
        if status != current_status:
            current_status = status
            section_label = {"fail": "🔴  Critical Findings", "warn": "🟡  Warnings", "pass": "🟢  Passing Checks"}.get(status, status)
            story.append(Spacer(1, 0.4*cm))
            story.append(Paragraph(section_label, _style("ss", fontSize=11, fontName="Helvetica-Bold",
                                                          textColor=STATUS_COLOR.get(status, GREY), spaceAfter=6)))

        block = _finding_block(f)
        story.append(KeepTogether(block))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dde4ed")))
    story.append(Paragraph(
        f"Generated by MailGuard on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · Confidential",
        S_FOOTER,
    ))

    doc.build(story)
    return buf.getvalue()
