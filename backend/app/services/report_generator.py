"""
MailGuard PDF Report Generator - ReportLab-based professional export.

Layout:
  Page 1  - Cover: branding header, tenant info, score gauge, meta, severity bar
  Page 2  - Executive Summary: score interpretation, score breakdown table
  Page 3+ - Findings Detail: grouped Critical → Warning → Pass, remediation steps
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
from reportlab.graphics.shapes import Drawing, Circle, String, Wedge, Rect, Line
from reportlab.graphics import renderPDF
from datetime import datetime, timezone, timedelta

ET_OFFSET = timedelta(hours=-5)  # EST (UTC-5); EDT is UTC-4

def _et_now():
    return datetime.now(timezone.utc).astimezone(timezone(ET_OFFSET))
from typing import List, Dict, Any
import io
import math

# ── Palette ───────────────────────────────────────────────────────────────────
ACCENT   = colors.HexColor("#00e5ff")
RED      = colors.HexColor("#e53935")
YELLOW   = colors.HexColor("#f9a825")
GREEN    = colors.HexColor("#2e7d32")
GREEN_LT = colors.HexColor("#43a047")
GREY     = colors.HexColor("#78909c")
GREY_LT  = colors.HexColor("#eceff1")
GREY_MD  = colors.HexColor("#cfd8dc")
INK      = colors.HexColor("#1a2332")
INK_LT   = colors.HexColor("#37474f")
WHITE    = colors.white
BLUE_HDR = colors.HexColor("#0d1f3c")
ROW_ALT  = colors.HexColor("#f5f7fa")

STATUS_COLOR   = {"fail": RED, "warn": YELLOW, "pass": GREEN_LT}
SEVERITY_ORDER = {"fail": 0, "warn": 1, "pass": 2}
PAGE_W, PAGE_H = A4


# ── Style factory ─────────────────────────────────────────────────────────────
def _style(name, **kw) -> ParagraphStyle:
    defaults = dict(fontName="Helvetica", fontSize=10, textColor=INK, leading=15, spaceAfter=4)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

# Cover styles
S_PRODUCT    = _style("prod", fontSize=11, fontName="Helvetica", textColor=ACCENT,
                       letterSpacing=3, alignment=TA_CENTER, spaceAfter=2)
S_COVER_TITLE= _style("ct",  fontSize=26, fontName="Helvetica-Bold", textColor=WHITE,
                       spaceAfter=4, alignment=TA_CENTER, leading=30)
S_COVER_SUB  = _style("cs",  fontSize=11, textColor=colors.HexColor("#90a4b7"),
                       spaceAfter=0, alignment=TA_CENTER)
S_COVER_TENANT=_style("ctn", fontSize=20, fontName="Helvetica-Bold", textColor=INK,
                       spaceAfter=2, alignment=TA_CENTER)
S_COVER_DOMAIN=_style("cd",  fontSize=11, textColor=GREY, alignment=TA_CENTER, spaceAfter=0)

# Body styles
S_SECTION    = _style("sh",  fontSize=13, fontName="Helvetica-Bold", textColor=INK,
                       spaceBefore=14, spaceAfter=6)
S_BODY       = _style("b",   fontSize=9,  textColor=INK_LT, leading=13)
S_MUTED      = _style("mu",  fontSize=8,  textColor=GREY, leading=12)
S_FINDING_NAME=_style("fn",  fontSize=10, fontName="Helvetica-Bold", textColor=INK)
S_REM        = _style("re",  fontSize=8,  textColor=INK_LT, leading=13, leftIndent=12)
S_FOOTER     = _style("ft",  fontSize=7,  textColor=GREY, alignment=TA_CENTER)


# ── Cover header band (dark background) ───────────────────────────────────────
def _cover_header_band(tenant_name: str, subtitle: str) -> Drawing:
    """Full-width dark header band with product name and report title."""
    W = PAGE_W - 4*cm  # matches doc margins
    H = 110
    d = Drawing(W, H)

    # Dark background
    bg = Rect(0, 0, W, H, fillColor=BLUE_HDR, strokeColor=None)
    d.add(bg)

    # Accent top bar
    bar = Rect(0, H - 4, W, 4, fillColor=ACCENT, strokeColor=None)
    d.add(bar)

    # "MAILGUARD" product label - small caps style
    d.add(String(W/2, H - 26, "MAILGUARD",
                 textAnchor="middle", fontSize=10, fontName="Helvetica",
                 fillColor=ACCENT))

    # Report title
    d.add(String(W/2, H - 54, "Email Security Posture Report",
                 textAnchor="middle", fontSize=20, fontName="Helvetica-Bold",
                 fillColor=WHITE))

    # Subtitle / tenant
    d.add(String(W/2, H - 76, tenant_name,
                 textAnchor="middle", fontSize=13, fontName="Helvetica",
                 fillColor=colors.HexColor("#90a4b7")))

    # Bottom divider
    d.add(Line(0, 0, W, 0, strokeColor=colors.HexColor("#1e3a5f"), strokeWidth=1))

    return d


# ── Score gauge ────────────────────────────────────────────────────────────────
def _score_gauge(score: int, grade: str) -> Drawing:
    W, H = 200, 120
    d    = Drawing(W, H)
    cx, cy, r = W / 2, 25, 72

    grade_color = {
        "A": GREEN_LT, "B": colors.HexColor("#66bb6a"),
        "C": YELLOW,   "D": colors.HexColor("#fb8c00"), "F": RED,
    }.get(grade, GREY)

    arc_steps = 80
    for i in range(arc_steps):
        a0 = 180 + i * (180 / arc_steps)
        a1 = 180 + (i + 1) * (180 / arc_steps)
        w  = Wedge(cx, cy, r + 10, a0, a1, radius1=r)
        w.fillColor   = GREY_LT
        w.strokeColor = None
        d.add(w)

    filled = max(1, int(arc_steps * score / 100))
    for i in range(filled):
        a0 = 180 + i * (180 / arc_steps)
        a1 = 180 + (i + 1) * (180 / arc_steps)
        w  = Wedge(cx, cy, r + 10, a0, a1, radius1=r)
        w.fillColor   = grade_color
        w.strokeColor = None
        d.add(w)

    # White centre circle for clean look
    c = Circle(cx, cy, r - 4, fillColor=WHITE, strokeColor=None)
    d.add(c)

    d.add(String(cx, cy + 30, str(score),
                 textAnchor="middle", fontSize=34, fontName="Helvetica-Bold",
                 fillColor=INK))
    d.add(String(cx, cy + 14, "/ 100",
                 textAnchor="middle", fontSize=9, fontName="Helvetica",
                 fillColor=GREY))
    d.add(String(cx, cy - 2, f"Grade  {grade}",
                 textAnchor="middle", fontSize=11, fontName="Helvetica-Bold",
                 fillColor=grade_color))
    return d


# ── Score breakdown table ──────────────────────────────────────────────────────
def _penalty_table(breakdown: List[Dict]) -> Table:
    if not breakdown:
        return Table([["All checks passed - full marks."]])

    header = [
        Paragraph("<b>Check</b>",   _style("th", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Status</b>",  _style("th", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Points</b>",  _style("th", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]
    rows = [header]

    for b in sorted(breakdown, key=lambda x: -(x.get("max_points", x.get("max_penalty", 0)))):
        status  = b.get("status", "").upper()
        earned  = b.get("points_earned", b.get("max_points", b.get("max_penalty", 0)) if status == "PASS" else 0)
        max_pts = b.get("max_points", b.get("max_penalty", 0))
        is_fail = status == "FAIL"
        is_warn = status == "WARN"
        sc      = RED if is_fail else (YELLOW if is_warn else GREEN_LT)
        rows.append([
            Paragraph(b.get("name", b.get("check_id", "")), S_BODY),
            Paragraph(status, _style("st", fontSize=8, fontName="Helvetica-Bold",
                                     textColor=sc, alignment=TA_CENTER)),
            Paragraph(f"{earned}/{max_pts}", _style("pt", fontSize=8, fontName="Helvetica-Bold",
                                                     textColor=sc, alignment=TA_CENTER)),
        ])

    t = Table(rows, colWidths=[10.5*cm, 2.5*cm, 2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),  (-1,0),  BLUE_HDR),
        ("ROWBACKGROUNDS",(0,1),  (-1,-1), [WHITE, ROW_ALT]),
        ("GRID",          (0,0),  (-1,-1), 0.3, GREY_MD),
        ("PADDING",       (0,0),  (-1,-1), 7),
        ("VALIGN",        (0,0),  (-1,-1), "MIDDLE"),
        ("ALIGN",         (1,0),  (-1,-1), "CENTER"),
        ("LINEBELOW",     (0,0),  (-1,0),  1, ACCENT),
    ]))
    return t


# ── Single finding block ───────────────────────────────────────────────────────
def _finding_block(f: Dict) -> List:
    status = f.get("status", "pass")
    col    = STATUS_COLOR.get(status, GREY)
    label  = status.upper()
    domain = f.get("domain")
    name   = f.get("name", f.get("check_id", ""))

    name_line = f"<b>{name}</b>"
    if domain:
        name_line += f'  <font color="#78909c" size="8">[{domain}]</font>'

    header_row = Table(
        [[Paragraph(name_line, S_FINDING_NAME),
          Paragraph(label, _style("sl", fontSize=8, fontName="Helvetica-Bold",
                                  textColor=WHITE, alignment=TA_CENTER))]],
        colWidths=[13*cm, 2*cm]
    )
    label_bg = RED if status == "fail" else (YELLOW if status == "warn" else GREEN_LT)
    header_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), colors.HexColor("#f0f4f8")),
        ("BACKGROUND",   (1,0), (1,-1), label_bg),
        ("LEFTPADDING",  (0,0), (0,-1), 10),
        ("LINEAFTER",    (0,0), (0,-1), 3, col),
        ("BOX",          (0,0), (-1,-1), 0.3, GREY_MD),
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

    elements.append(Spacer(1, 0.3*cm))
    return elements


# ── Main entry point ───────────────────────────────────────────────────────────
def generate_report(tenant: Dict, scan: Dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.8*cm, bottomMargin=2*cm,
        title=f"MailGuard Report - {tenant.get('display_name','')}"
    )

    findings          = scan.get("findings", [])
    penalty_breakdown = scan.get("penalty_breakdown", [])
    domains_scanned   = scan.get("domains_scanned", [tenant.get("domain", "")])
    score             = scan.get("score", 0)
    grade             = scan.get("grade", "F")
    platform          = scan.get("platform", "Microsoft 365")
    scan_date         = _et_now().strftime("%Y-%m-%d %H:%M ET")

    story = []

    # ── PAGE 1: Cover ──────────────────────────────────────────────────────────

    # Header band
    header = _cover_header_band(tenant.get("display_name", "-"), "Email Security Posture Report")
    story.append(Table([[header]], colWidths=[PAGE_W - 4*cm]))
    story.append(Spacer(1, 0.5*cm))

    # Domain line
    story.append(Paragraph(
        ", ".join(domains_scanned) or tenant.get("domain", "-"),
        S_COVER_DOMAIN
    ))
    story.append(Spacer(1, 0.6*cm))

    # Score gauge centred
    story.append(Table([[_score_gauge(score, grade)]], colWidths=[PAGE_W - 4*cm]))
    story.append(Spacer(1, 0.5*cm))

    # Meta info - clean two-column table
    critical = sum(1 for f in findings if f.get("status") == "fail")
    warnings = sum(1 for f in findings if f.get("status") == "warn")
    passing  = sum(1 for f in findings if f.get("status") == "pass")
    earned   = sum(b.get("points_earned", 0) for b in penalty_breakdown)
    possible = sum(b.get("max_points", b.get("max_penalty", 0)) for b in penalty_breakdown)

    meta = [
        ["Platform",       platform],
        ["Scan Date",      scan_date],
        ["Domains Scanned",str(len(domains_scanned))],
        ["Checks Run",     str(len(findings))],
        ["Points Earned",  f"{round(earned)} / {possible} pts"],
    ]
    mt = Table(meta, colWidths=[4.5*cm, 10.5*cm])
    mt.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("TEXTCOLOR",      (0,0), (0,-1),  GREY),
        ("TEXTCOLOR",      (1,0), (1,-1),  INK_LT),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [ROW_ALT, WHITE]),
        ("GRID",           (0,0), (-1,-1), 0.3, GREY_MD),
        ("PADDING",        (0,0), (-1,-1), 8),
        ("LINEAFTER",      (0,0), (0,-1),  1, GREY_MD),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.7*cm))

    # Severity summary - 3 cards
    def _sev_cell(num, label, col):
        return [
            Paragraph(f"<b>{num}</b>", _style(f"s{label}", fontSize=22,
                      fontName="Helvetica-Bold", textColor=col, alignment=TA_CENTER)),
            Paragraph(label, _style(f"l{label}", fontSize=8, textColor=col,
                      alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=0)),
        ]

    sev_data = [
        [*_sev_cell(critical, "CRITICAL", RED)[:1],
         *_sev_cell(warnings, "WARNINGS", YELLOW)[:1],
         *_sev_cell(passing,  "PASSING",  GREEN_LT)[:1]],
        [*_sev_cell(critical, "CRITICAL", RED)[1:],
         *_sev_cell(warnings, "WARNINGS", YELLOW)[1:],
         *_sev_cell(passing,  "PASSING",  GREEN_LT)[1:]],
    ]
    st = Table(sev_data, colWidths=[5*cm, 5*cm, 5*cm])
    st.setStyle(TableStyle([
        ("BOX",          (0,0), (-1,-1), 0.5, GREY_MD),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, GREY_MD),
        ("PADDING",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [ROW_ALT, WHITE]),
        ("LINEABOVE",    (0,0), (-1,0),  3, GREY_MD),
        ("LINEABOVE",    (0,0), (0,0),   3, RED),
        ("LINEABOVE",    (1,0), (1,0),   3, YELLOW),
        ("LINEABOVE",    (2,0), (2,0),   3, GREEN_LT),
    ]))
    story.append(st)
    story.append(PageBreak())

    # ── PAGE 2: Executive Summary ──────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S_SECTION))
    story.append(HRFlowable(width="100%", thickness=1, color=GREY_MD))
    story.append(Spacer(1, 0.3*cm))

    interp = {
        "A": "Excellent posture - minor hardening opportunities remain.",
        "B": "Good posture - a few important gaps should be addressed.",
        "C": "Moderate risk - several significant controls need attention.",
        "D": "High risk - multiple critical controls are failing.",
        "F": "Critical risk - multiple high-severity controls are failing.",
    }.get(grade, "")
    story.append(Paragraph(
        f"<b>Score {score}/100 - Grade {grade}:</b> {interp}", S_BODY
    ))
    story.append(Spacer(1, 0.5*cm))

    if penalty_breakdown:
        story.append(Paragraph("<b>Score Breakdown</b>", S_SECTION))
        story.append(Paragraph(
            "Points earned per check. PASS = full points, WARN = half points, FAIL = 0 points.",
            S_MUTED
        ))
        story.append(Spacer(1, 0.25*cm))
        story.append(_penalty_table(penalty_breakdown))

    story.append(PageBreak())

    # ── PAGE 3+: Findings Detail ───────────────────────────────────────────────
    story.append(Paragraph("Findings Detail", S_SECTION))
    story.append(HRFlowable(width="100%", thickness=1, color=GREY_MD))
    story.append(Spacer(1, 0.3*cm))

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("status","pass"), 2))

    sections = [
        ("fail",  "■ Critical Findings", RED),
        ("warn",  "■ Warnings",          YELLOW),
        ("pass",  "■ Passing Checks",    GREEN_LT),
    ]
    for sev, heading, col in sections:
        group = [f for f in sorted_findings if f.get("status") == sev]
        if not group:
            continue
        story.append(Paragraph(
            f'<font color="#{col.hexval()[2:]}">{heading}</font>',
            _style(f"grp{sev}", fontSize=11, fontName="Helvetica-Bold",
                   textColor=col, spaceBefore=10, spaceAfter=6)
        ))
        for f in group:
            story.append(KeepTogether(_finding_block(f)))

    # Footer
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_MD))
    story.append(Paragraph(
        f"Generated by MailGuard on {scan_date}  ·  Confidential",
        S_FOOTER
    ))

    doc.build(story)
    return buf.getvalue()
