"""
report.py — Week 3
Generates a professional PDF security report from benchmark results.
Uses ReportLab for PDF creation.
"""

import json
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ─────────────────────────────────────────────
# COLOR PALETTE
# ─────────────────────────────────────────────

COLOR_RED       = colors.HexColor("#ff4b4b")
COLOR_ORANGE    = colors.HexColor("#ff8c42")
COLOR_YELLOW    = colors.HexColor("#ffaa00")
COLOR_GREEN     = colors.HexColor("#00cc44")
COLOR_DARK_GREEN= colors.HexColor("#00ff88")
COLOR_DARK      = colors.HexColor("#1a1a2e")
COLOR_GRAY      = colors.HexColor("#555555")
COLOR_LIGHT_GRAY= colors.HexColor("#f5f5f5")
COLOR_WHITE     = colors.white
COLOR_BLACK     = colors.black


def get_risk_color(risk_level: str):
    mapping = {
        "CRITICAL": COLOR_RED,
        "HIGH":     COLOR_ORANGE,
        "MEDIUM":   COLOR_YELLOW,
        "LOW":      COLOR_GREEN,
        "MINIMAL":  COLOR_DARK_GREEN,
    }
    return mapping.get(risk_level, COLOR_GRAY)


# ─────────────────────────────────────────────
# CUSTOM STYLES
# ─────────────────────────────────────────────

def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontSize=28,
        fontName="Helvetica-Bold",
        textColor=COLOR_DARK,
        alignment=TA_CENTER,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        fontSize=13,
        fontName="Helvetica",
        textColor=COLOR_GRAY,
        alignment=TA_CENTER,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontSize=16,
        fontName="Helvetica-Bold",
        textColor=COLOR_DARK,
        spaceBefore=18,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SubHeader",
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=COLOR_DARK,
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontSize=10,
        fontName="Helvetica",
        textColor=COLOR_GRAY,
        spaceAfter=4,
        leading=16,
    ))
    styles.add(ParagraphStyle(
        name="SmallText",
        fontSize=8,
        fontName="Helvetica",
        textColor=COLOR_GRAY,
    ))
    styles.add(ParagraphStyle(
        name="RiskBadge",
        fontSize=14,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="FooterText",
        fontSize=8,
        fontName="Helvetica",
        textColor=COLOR_GRAY,
        alignment=TA_CENTER,
    ))

    return styles


# ─────────────────────────────────────────────
# HELPER — Score bar as a table row visual
# ─────────────────────────────────────────────

def score_bar_table(score: float, max_width: float = 300) -> Table:
    """Create a visual progress bar using a table."""
    filled = max(1, int(score / 100 * 10))
    empty = 10 - filled

    bar_color = COLOR_GREEN if score >= 75 else COLOR_YELLOW if score >= 40 else COLOR_RED

    cells = []
    for i in range(filled):
        cells.append("")
    for i in range(empty):
        cells.append("")

    col_widths = [max_width / 10] * 10
    bar = Table([cells], colWidths=col_widths, rowHeights=[14])

    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_LIGHT_GRAY]),
    ]
    for i in range(filled):
        style_cmds.append(("BACKGROUND", (i, 0), (i, 0), bar_color))

    bar.setStyle(TableStyle(style_cmds))
    return bar


# ─────────────────────────────────────────────
# MAIN REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_pdf_report(
    session_id: str,
    session_data: dict,
    results: list,
    scores: dict,
    policy_summary: dict,
    output_path: str = None
) -> str:
    """
    Generate a full PDF security report.

    Args:
        session_id: The benchmark session ID
        session_data: Session metadata (model, date, counts)
        results: List of all test results
        scores: Detailed scores from scorer.py
        policy_summary: Policy violations from policy_engine.py
        output_path: Where to save the PDF

    Returns:
        Path to the generated PDF file
    """

    if output_path is None:
        reports_dir = Path(__file__).parent.parent / "data" / "reports"
        reports_dir.mkdir(exist_ok=True)
        output_path = str(reports_dir / f"report_{session_id}.pdf")

    styles = build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch
    )

    story = []
    overall = scores.get("overall", {})
    categories = scores.get("categories", {})

    # ─────────────────────────────────────────────
    # PAGE 1 — COVER PAGE
    # ─────────────────────────────────────────────

    story.append(Spacer(1, 0.8 * inch))

    story.append(Paragraph("🔐 AI Red Teaming", styles["ReportTitle"]))
    story.append(Paragraph("Security Benchmark Report", styles["ReportTitle"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOR_DARK))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(f"Session ID: {session_id}", styles["ReportSubtitle"]))
    story.append(Paragraph(f"Model Tested: {session_data.get('model_name', 'Unknown')}", styles["ReportSubtitle"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", styles["ReportSubtitle"]))
    story.append(Spacer(1, 0.5 * inch))

    # Overall risk badge
    risk_level = overall.get("risk_level", "UNKNOWN")
    risk_color = get_risk_color(risk_level)
    safety_score = overall.get("safety_score", 0)

    cover_data = [
        ["OVERALL SAFETY SCORE", "RISK LEVEL", "TOTAL TESTS"],
        [f"{safety_score}%", risk_level, str(overall.get("total_tests", 0))]
    ]
    cover_table = Table(cover_data, colWidths=[2.2 * inch, 2.2 * inch, 2.2 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 10),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",     (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 1), (0, 1), 28),
        ("FONTSIZE",     (1, 1), (1, 1), 20),
        ("FONTSIZE",     (2, 1), (2, 1), 24),
        ("TEXTCOLOR",    (0, 1), (0, 1), COLOR_GREEN if safety_score >= 75 else COLOR_RED),
        ("TEXTCOLOR",    (1, 1), (1, 1), risk_color),
        ("TEXTCOLOR",    (2, 1), (2, 1), COLOR_DARK),
        ("ROWHEIGHTS",   (0, 0), (-1, -1), [30, 60]),
        ("GRID",         (0, 0), (-1, -1), 1, colors.HexColor("#dddddd")),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.4 * inch))

    # Safe / Unsafe / Ambiguous summary row
    summary_data = [
        ["✅ Safe Responses", "❌ Unsafe Responses", "🟡 Ambiguous"],
        [
            str(overall.get("safe", 0)),
            str(overall.get("unsafe", 0)),
            str(overall.get("ambiguous", 0))
        ]
    ]
    summary_table = Table(summary_data, colWidths=[2.2 * inch, 2.2 * inch, 2.2 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 9),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (-1, 1), 22),
        ("TEXTCOLOR",   (0, 1), (0, 1), COLOR_GREEN),
        ("TEXTCOLOR",   (1, 1), (1, 1), COLOR_RED),
        ("TEXTCOLOR",   (2, 1), (2, 1), COLOR_YELLOW),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHTS",  (0, 0), (-1, -1), [24, 50]),
        ("GRID",        (0, 0), (-1, -1), 1, colors.HexColor("#dddddd")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4 * inch))

    # Recommendation box
    rec_text = overall.get("recommendation", "")
    rec_data = [["RECOMMENDATION"], [rec_text]]
    rec_table = Table(rec_data, colWidths=[6.5 * inch])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), risk_color),
        ("TEXTCOLOR",   (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 10),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica"),
        ("FONTSIZE",    (0, 1), (-1, 1), 10),
        ("TEXTCOLOR",   (0, 1), (-1, 1), COLOR_DARK),
        ("BACKGROUND",  (0, 1), (-1, 1), colors.HexColor("#f9f9f9")),
        ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",     (0, 0), (-1, -1), 10),
        ("GRID",        (0, 0), (-1, -1), 1, colors.HexColor("#dddddd")),
    ]))
    story.append(rec_table)

    story.append(PageBreak())

    # ─────────────────────────────────────────────
    # PAGE 2 — CATEGORY BREAKDOWN
    # ─────────────────────────────────────────────

    story.append(Paragraph("Category Vulnerability Breakdown", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_LIGHT_GRAY))
    story.append(Spacer(1, 0.15 * inch))

    cat_display_names = {
        "jailbreak": "Jailbreak Attacks",
        "prompt_injection": "Prompt Injection",
        "role_manipulation": "Role Manipulation",
        "data_extraction": "Data Extraction"
    }

    for cat, data in categories.items():
        display_name = cat_display_names.get(cat, cat.replace("_", " ").title())
        vuln = data.get("vulnerability_score", 0)
        safety = data.get("safety_score", 0)
        cat_risk = data.get("risk_level", "UNKNOWN")
        cat_risk_color = get_risk_color(cat_risk)

        story.append(Paragraph(f"{display_name}", styles["SubHeader"]))

        # Category stats row
        cat_data = [
            ["Safety Score", "Vulnerability", "Risk Level", "Safe", "Unsafe", "Ambiguous"],
            [
                f"{safety}%",
                f"{vuln}%",
                cat_risk,
                str(data.get("safe", 0)),
                str(data.get("unsafe", 0)),
                str(data.get("ambiguous", 0))
            ]
        ]
        cat_table = Table(cat_data, colWidths=[1.1*inch]*6)
        cat_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0), 8),
            ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 1), (-1, 1), 13),
            ("TEXTCOLOR",   (0, 1), (0, 1), COLOR_GREEN if safety >= 75 else COLOR_RED),
            ("TEXTCOLOR",   (1, 1), (1, 1), COLOR_RED if vuln > 25 else COLOR_GREEN),
            ("TEXTCOLOR",   (2, 1), (2, 1), cat_risk_color),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("ROWHEIGHTS",  (0, 0), (-1, -1), [20, 35]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ]))
        story.append(cat_table)
        story.append(Spacer(1, 0.05 * inch))

        # Insight text
        insight = data.get("insight", "")
        story.append(Paragraph(f"<i>{insight}</i>", styles["BodyText2"]))
        story.append(Spacer(1, 0.15 * inch))

    story.append(PageBreak())

    # ─────────────────────────────────────────────
    # PAGE 3 — DETAILED RESULTS TABLE
    # ─────────────────────────────────────────────

    story.append(Paragraph("Detailed Test Results", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_LIGHT_GRAY))
    story.append(Spacer(1, 0.15 * inch))

    # Table header
    results_header = ["ID", "Category", "Attack Description", "Verdict", "Confidence"]
    results_rows = [results_header]

    verdict_colors = {"SAFE": COLOR_GREEN, "UNSAFE": COLOR_RED, "AMBIGUOUS": COLOR_YELLOW}

    for r in results:
        verdict = r.get("verdict", "")
        results_rows.append([
            r.get("attack_id", ""),
            r.get("attack_category", "").replace("_", " ").title(),
            r.get("attack_description", "")[:45] + ("..." if len(r.get("attack_description", "")) > 45 else ""),
            verdict,
            f"{int(r.get('confidence', 0) * 100)}%"
        ])

    results_table = Table(
        results_rows,
        colWidths=[0.7*inch, 1.3*inch, 2.8*inch, 0.9*inch, 0.8*inch]
    )

    table_style = [
        ("BACKGROUND",  (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",       (2, 0), (2, -1), "LEFT"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHTS",  (0, 0), (-1, -1), [18]),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GRAY]),
    ]

    # Color verdict cells
    for i, r in enumerate(results, start=1):
        verdict = r.get("verdict", "")
        color = verdict_colors.get(verdict, COLOR_GRAY)
        table_style.append(("TEXTCOLOR", (3, i), (3, i), color))
        table_style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

    results_table.setStyle(TableStyle(table_style))
    story.append(results_table)

    story.append(PageBreak())

    # ─────────────────────────────────────────────
    # PAGE 4 — POLICY & AUDIT SUMMARY
    # ─────────────────────────────────────────────

    story.append(Paragraph("Policy Engine Report", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_LIGHT_GRAY))
    story.append(Spacer(1, 0.15 * inch))

    total_violations = policy_summary.get("total_violations", 0)
    blocks = policy_summary.get("blocks", 0)
    flags = policy_summary.get("flags", 0)

    policy_data = [
        ["Total Violations", "BLOCK Actions", "FLAG Actions"],
        [str(total_violations), str(blocks), str(flags)]
    ]
    policy_table = Table(policy_data, colWidths=[2.2 * inch, 2.2 * inch, 2.2 * inch])
    policy_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 10),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (-1, 1), 26),
        ("TEXTCOLOR",   (1, 1), (1, 1), COLOR_RED),
        ("TEXTCOLOR",   (2, 1), (2, 1), COLOR_ORANGE),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHTS",  (0, 0), (-1, -1), [28, 55]),
        ("GRID",        (0, 0), (-1, -1), 1, colors.HexColor("#dddddd")),
    ]))
    story.append(policy_table)
    story.append(Spacer(1, 0.3 * inch))

    if total_violations == 0:
        story.append(Paragraph(
            "✅ No policy violations detected. The model handled all adversarial prompts "
            "without producing any content that triggered security policies. "
            "This is the ideal outcome for a production AI system.",
            styles["BodyText2"]
        ))
    else:
        story.append(Paragraph("Policy Violations Detected:", styles["SubHeader"]))
        audit_entries = policy_summary.get("audit_entries", [])
        for entry in audit_entries[:10]:
            policies = json.loads(entry.get("policies_triggered", "[]"))
            for p in policies:
                story.append(Paragraph(
                    f"• [{p['severity']}] {p['policy_name']} — {p['description']}",
                    styles["BodyText2"]
                ))

    story.append(Spacer(1, 0.4 * inch))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_LIGHT_GRAY))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        f"Generated by AI Red Teaming Benchmark Suite | {datetime.now().strftime('%Y-%m-%d %H:%M')} | Session: {session_id}",
        styles["FooterText"]
    ))

    # Build PDF
    doc.build(story)
    print(f"✅ PDF Report generated: {output_path}")
    return output_path