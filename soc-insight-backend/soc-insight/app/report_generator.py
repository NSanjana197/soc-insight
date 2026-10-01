"""
Automated Incident Report Generator.

Builds a structured PDF report for a single incident, matching the layout
in the proposal: header info, evidence, timeline table, recommended
actions.
"""

import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
)

from app.models import Incident


def generate_incident_report_pdf(incident: Incident) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal = styles["Normal"]
    label_style = ParagraphStyle(
        "Label", parent=normal, fontName="Helvetica-Bold"
    )

    story = []

    story.append(Paragraph("SOC Incident Report", title_style))
    story.append(Spacer(1, 12))

    severity_color = {
        "CRITICAL": colors.HexColor("#7a0000"),
        "HIGH": colors.HexColor("#b34700"),
        "MEDIUM": colors.HexColor("#b38f00"),
        "LOW": colors.HexColor("#2e7d32"),
    }.get(incident.severity, colors.black)

    header_data = [
        ["Incident ID:", incident.incident_code],
        ["Incident Type:", incident.incident_type.replace("_", " ").title()],
        ["Severity:", incident.severity],
        ["Status:", incident.status],
        ["Affected Account:", incident.affected_account or "N/A"],
        ["Source IP:", incident.source_ip or "N/A"],
        ["Detection Time:", incident.detection_time.strftime("%Y-%m-%d %H:%M:%S")],
    ]
    header_table = Table(header_data, colWidths=[1.8 * inch, 4.2 * inch])
    header_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (1, 2), (1, 2), severity_color),
        ("FONTNAME", (1, 2), (1, 2), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 18))

    story.append(Paragraph("Evidence", heading_style))
    if incident.evidence:
        story.append(ListFlowable(
            [ListItem(Paragraph(item, normal)) for item in incident.evidence],
            bulletType="bullet",
        ))
    else:
        story.append(Paragraph("No evidence recorded.", normal))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Timeline", heading_style))
    timeline_data = [["Time", "Event"]]
    for ev in incident.timeline_events:
        timeline_data.append([ev.timestamp.strftime("%H:%M:%S"), ev.description])
    timeline_table = Table(timeline_data, colWidths=[1.2 * inch, 4.8 * inch])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Recommended Actions", heading_style))
    if incident.recommended_actions:
        story.append(ListFlowable(
            [ListItem(Paragraph(a, normal)) for a in incident.recommended_actions],
            bulletType="bullet",
        ))
    else:
        story.append(Paragraph("None.", normal))

    doc.build(story)
    return buffer.getvalue()
