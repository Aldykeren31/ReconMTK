"""
Modul Report Generator (Output: Laporan Otomatis)
====================================================
Menyusun dokumen pelaporan teknis terstruktur dari hasil scan
(host discovery, port scan, banner grabbing, CVE matching) mengikuti
pedoman pelaporan audit keamanan ala PTES, sesuai tahap "Output:
Laporan Otomatis" pada flowchart BAB III.
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#FF5470"),
    "High": colors.HexColor("#F5761A"),
    "Medium": colors.HexColor("#F5A623"),
    "Low": colors.HexColor("#3ED6C5"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=20, leading=24, spaceAfter=6,
        textColor=colors.HexColor("#0B1220"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=11, leading=14, spaceAfter=18,
        textColor=colors.HexColor("#55607A"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontSize=13, leading=16, spaceBefore=16, spaceAfter=8,
        textColor=colors.HexColor("#0B1220"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="Body", fontSize=9.5, leading=13.5, textColor=colors.HexColor("#1B2338"),
    ))
    styles.add(ParagraphStyle(
        name="Small", fontSize=8, leading=11, textColor=colors.HexColor("#7A869E"),
    ))
    return styles


def generate_report(scan_result: dict, output_path: str) -> str:
    """Bangun laporan PDF dari struktur hasil scan lengkap.

    scan_result: dict berisi keys 'target', 'host_discovery',
    'port_scan', 'banner_grab', 'detected_version', 'cve_matches',
    'started_at', 'finished_at'.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=20 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )
    story = []

    # --- Halaman Judul ---
    story.append(Paragraph("Laporan Teknis Reconnaissance", styles["ReportTitle"]))
    story.append(Paragraph(
        "Fase Intelligence Gathering (Footprinting &amp; Enumeration) &mdash; Metodologi PTES",
        styles["ReportSubtitle"],
    ))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#E1E5EE"), thickness=1))
    story.append(Spacer(1, 10))

    meta_rows = [
        ["Target", scan_result.get("target", "-")],
        ["Waktu Mulai", scan_result.get("started_at", "-")],
        ["Waktu Selesai", scan_result.get("finished_at", "-")],
        ["Versi RouterOS Terdeteksi", scan_result.get("detected_version") or "Tidak dapat dipastikan"],
        ["Dibuat oleh", "ReconMTK - Reconnaissance Tool (Python) - Tugas Akhir"],
    ]
    meta_table = Table(meta_rows, colWidths=[130, 340])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#55607A")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#EDEFF5")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # --- Ringkasan Host Discovery ---
    story.append(Paragraph("1. Host Discovery", styles["SectionHeading"]))
    hd = scan_result.get("host_discovery", [])
    alive = [h for h in hd if h.get("alive")]
    story.append(Paragraph(
        f"Total {len(hd)} host diperiksa, {len(alive)} host terdeteksi aktif dan merespons.",
        styles["Body"],
    ))
    if hd:
        rows = [["IP", "Status", "Metode Deteksi", "Waktu Respons (ms)"]]
        for h in hd:
            rows.append([
                h.get("ip", "-"),
                "AKTIF" if h.get("alive") else "Tidak Aktif",
                h.get("method", "-"),
                str(h.get("response_time_ms", "-")),
            ])
        t = Table(rows, colWidths=[120, 90, 130, 130], repeatRows=1)
        t.setStyle(_default_table_style())
        story.append(Spacer(1, 6))
        story.append(t)

    # --- Fase 1: Footprinting (Port Scan) ---
    story.append(Paragraph("2. Fase 1 &mdash; Footprinting (Port Scanning)", styles["SectionHeading"]))
    ps = scan_result.get("port_scan", [])
    open_ports = [p for p in ps if p.get("status") == "open"]
    story.append(Paragraph(
        f"Dari {len(ps)} port layanan manajemen MikroTik yang diperiksa, {len(open_ports)} "
        f"port ditemukan dalam status terbuka (open).",
        styles["Body"],
    ))
    if ps:
        rows = [["Port", "Layanan", "Status", "Latency (ms)"]]
        for p in ps:
            rows.append([str(p.get("port")), p.get("service", "-"), p.get("status", "-").upper(), str(p.get("latency_ms", "-"))])
        t = Table(rows, colWidths=[70, 200, 100, 100], repeatRows=1)
        t.setStyle(_default_table_style(highlight_col=2, highlight_value="OPEN"))
        story.append(Spacer(1, 6))
        story.append(t)

    # --- Fase 2: Enumeration (Banner Grabbing) ---
    story.append(Paragraph("3. Fase 2 &mdash; Enumeration (Banner Grabbing)", styles["SectionHeading"]))
    bg = scan_result.get("banner_grab", [])
    if bg:
        for b in bg:
            title = f"Port {b.get('port')} &mdash; {b.get('service', '-')}"
            story.append(Paragraph(f"<b>{title}</b>", styles["Body"]))
            banner_text = (b.get("banner") or "-").replace("<", "&lt;").replace(">", "&gt;")
            if len(banner_text) > 300:
                banner_text = banner_text[:300] + "..."
            story.append(Paragraph(f"Banner/response: <font face='Courier'>{banner_text}</font>", styles["Small"]))
            if b.get("routeros_version"):
                story.append(Paragraph(f"Indikasi versi/identitas: {b['routeros_version']}", styles["Small"]))
            if b.get("error"):
                story.append(Paragraph(f"Catatan: gagal mengambil banner ({b['error']})", styles["Small"]))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("Tidak ada port terbuka untuk dilakukan banner grabbing.", styles["Body"]))

    # --- Analisis CVE ---
    story.append(Paragraph("4. Analisis Hasil &mdash; Pencocokan Basis Data CVE", styles["SectionHeading"]))
    cves = scan_result.get("cve_matches", [])
    if cves:
        story.append(Paragraph(
            f"Ditemukan {len(cves)} referensi kerentanan publik yang berpotensi relevan dengan "
            f"kondisi target. Hasil ini bersifat indikatif berdasarkan versi/porta yang terdeteksi "
            f"dan tetap memerlukan verifikasi manual sebelum dijadikan dasar tindakan lebih lanjut.",
            styles["Body"],
        ))
        story.append(Spacer(1, 6))
        for c in cves:
            sev = c.get("severity_level", "Low")
            color = SEVERITY_COLORS.get(sev, colors.grey)
            header = Table([[f"{c.get('cve_id')}  |  {sev}  (CVSS {c.get('cvss', '-')})"]], colWidths=[470])
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(header)
            story.append(Paragraph(f"<b>{c.get('title')}</b>", styles["Body"]))
            story.append(Paragraph(f"Kategori: {c.get('vulnerability_type', '-')}", styles["Small"]))
            story.append(Paragraph(c.get("description", ""), styles["Body"]))
            story.append(Paragraph(f"Rekomendasi mitigasi: {c.get('mitigation_hint', '-')}", styles["Body"]))
            story.append(Paragraph(f"Alasan kecocokan: {c.get('match_reason', '-')}", styles["Small"]))
            story.append(Paragraph(f"Referensi: {c.get('reference', '-')}", styles["Small"]))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph(
            "Tidak ditemukan kecocokan CVE pada basis data referensi untuk versi/port yang "
            "terdeteksi saat ini. Tetap disarankan memperbarui RouterOS ke versi terbaru secara berkala.",
            styles["Body"],
        ))

    # --- CVE yang Dikecualikan (validasi banner produk) ---
    excluded = []
    try:
        from modules import cve_matcher
        open_ports_now = {p.get("port") for p in scan_result.get("port_scan", []) if p.get("status") == "open"}
        matched_ids = {c.get("cve_id") for c in cves}
        banner_map = {b.get("port"): b.get("banner", "") for b in bg}
        for cve in cve_matcher.load_database().get("cves", []):
            if cve.get("version_type") != "openssh":
                continue
            relevant_ports = set(cve.get("affected_ports", [])) & open_ports_now
            if not relevant_ports or cve.get("cve_id") in matched_ids:
                continue
            banner_text = " ".join(banner_map.get(p, "") or "" for p in relevant_ports)
            excluded.append((cve, sorted(relevant_ports), banner_text))
    except Exception:
        excluded = []
    if excluded:
        story.append(Paragraph("5. CVE yang Dikecualikan (Validasi Banner Produk)", styles["SectionHeading"]))
        story.append(Paragraph(
            "Port berikut terbuka dan secara nomor port cocok dengan referensi CVE pada basis data, "
            "namun TIDAK dilaporkan sebagai temuan karena banner layanan yang terdeteksi tidak "
            "menunjukkan produk yang dimaksud CVE tersebut (mis. CVE spesifik OpenSSH namun banner "
            "menunjukkan SSH proprietary MikroTik). Bagian ini disertakan agar proses eliminasi "
            "false positive dapat diverifikasi secara transparan.",
            styles["Body"],
        ))
        story.append(Spacer(1, 6))
        for cve, ports, banner_text in excluded:
            story.append(Paragraph(f"<b>{cve.get('cve_id')}</b> &mdash; {cve.get('title')}", styles["Body"]))
            story.append(Paragraph(f"Port terkait yang terbuka: {ports}", styles["Small"]))
            story.append(Paragraph(
                f"Banner terdeteksi: <font face='Courier'>{(banner_text or '-')[:200]}</font>",
                styles["Small"],
            ))
            story.append(Paragraph(
                "Alasan dikecualikan: banner tidak memuat identifikasi OpenSSH, sehingga CVE ini "
                "dinilai tidak relevan untuk implementasi SSH pada perangkat target.",
                styles["Small"],
            ))
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#E1E5EE"), thickness=1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Catatan: Laporan ini dihasilkan otomatis oleh ReconMTK - Reconnaissance Tool sebagai bagian "
        "dari Tugas Akhir (fase Intelligence Gathering pada PTES). Basis data CVE bersifat kuratif dan "
        "perlu diverifikasi/diperbarui dari sumber resmi (mikrotik.com/supportsec, nvd.nist.gov) sebelum "
        "digunakan sebagai dasar audit resmi.",
        styles["Small"],
    ))

    doc.build(story)
    return output_path


def _default_table_style(highlight_col=None, highlight_value=None):
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#E1E5EE")),
    ])
    return style


def default_filename(target: str = "") -> str:
    return "Report_ReconMTK.pdf"

