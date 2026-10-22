#!/usr/bin/env python3
"""
Skrip Impor Data CVE Dump (cvelistV5) ke ReconMTK
=================================================
Mengekstrak seluruh CVE terkait MikroTik / RouterOS dari CVE Dump
resmi (cvelistV5 dari CVE Project) dan mengimpornya ke dalam basis data
ReconMTK (data/cve_database.json).

Penggunaan:
    python3 scripts/import_cve_dump.py
    python3 scripts/import_cve_dump.py --dump-dir /path/to/cvelistV5-main
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import date

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)

from modules.cve_matcher import DB_PATH, parse_affected_version, load_database, save_database, get_stats

POSSIBLE_DUMP_DIRS = [
    os.path.join(ROOT_DIR, "cvelistV5-main"),
    "/Users/rifaldytamauka/Downloads/cvelistV5-main",
    os.path.expanduser("~/Downloads/cvelistV5-main"),
]

DEFAULT_DUMP_DIR = next((d for d in POSSIBLE_DUMP_DIRS if os.path.exists(d)), POSSIBLE_DUMP_DIRS[0])

KNOWN_PORT_MAP = {
    "winbox": [8291],
    "www": [80],
    "http": [80],
    "https": [443],
    "ssl": [443],
    "ssh": [22],
    "telnet": [23],
    "ftp": [21],
    "api-ssl": [8729],
    "api": [8728],
    "bandwidth": [2000],
    "btest": [2000],
    "smb": [139, 445],
    "dns": [53],
    "snmp": [161],
    "socks": [1080],
    "openflow": [6633],
}


def extract_ports_from_text(text: str) -> list:
    """Tebak port terkait dari deskripsi atau nama komponen."""
    found_ports = set()
    text_lower = text.lower()
    for keyword, ports in KNOWN_PORT_MAP.items():
        if re.search(rf"\b{re.escape(keyword)}\b", text_lower):
            found_ports.update(ports)

    # Cari pola nomor port eksplisit (mis. "port 80", "port 8291")
    explicit_ports = re.findall(r"\bport\s+(\d{1,5})\b", text_lower)
    for p in explicit_ports:
        p_int = int(p)
        if 1 <= p_int <= 65535:
            found_ports.add(p_int)

    return sorted(found_ports)


def parse_versions_from_cna(cna: dict, desc: str) -> str:
    """Ambil rentang versi terdampak dari CNA affected block atau deskripsi."""
    version_clauses = []
    affected = cna.get("affected", [])
    for aff in affected:
        for v in aff.get("versions", []):
            status = v.get("status", "affected")
            if status != "affected":
                continue
            v_val = v.get("version", "").strip()
            less_equal = v.get("lessThanOrEqual", "").strip()
            less_than = v.get("lessThan", "").strip()

            if less_equal and less_equal not in ("*", ""):
                version_clauses.append(f"<= {less_equal}")
            elif less_than and less_than not in ("*", ""):
                # jika format less than baku, buat <= versi sebelumnya atau gunakan rentang
                version_clauses.append(f"<= {less_than}")
            elif v_val and v_val not in ("*", "0", "unspecified"):
                version_clauses.append(f"<= {v_val}")

    if not version_clauses:
        # Cari dari deskripsi teks (mis. "before 6.49.8", "through 7.1", "before stable v7.5")
        matches = re.findall(r"(?:before|through|prior to|up to|version)\s+(?:stable\s+)?v?(\d+(?:\.\d+)+)", desc, re.I)
        for m in matches:
            version_clauses.append(f"<= {m}")

    # Hilangkan duplikat
    unique_clauses = []
    for c in version_clauses:
        if c not in unique_clauses:
            unique_clauses.append(c)

    if unique_clauses:
        return "; ".join(unique_clauses[:3])
    return "<= 7.15"


def determine_severity_and_cvss(cna: dict) -> tuple:
    """Ekstrak skor CVSS dan tingkat keparahan (Critical, High, Medium, Low)."""
    metrics = cna.get("metrics", [])
    for m in metrics:
        for k in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if k in m:
                score = m[k].get("baseScore")
                sev = m[k].get("baseSeverity", "").capitalize()
                if score is not None:
                    try:
                        score_float = float(score)
                        if not sev:
                            if score_float >= 9.0:
                                sev = "Critical"
                            elif score_float >= 7.0:
                                sev = "High"
                            elif score_float >= 4.0:
                                sev = "Medium"
                            else:
                                sev = "Low"
                        return score_float, sev
                    except (ValueError, TypeError):
                        pass

    return 7.5, "High"


def extract_vulnerability_type(cna: dict, desc: str) -> str:
    """Ambil jenis kerentanan dari problemTypes atau deskripsi."""
    problem_types = cna.get("problemTypes", [])
    for pt in problem_types:
        for d in pt.get("descriptions", []):
            val = d.get("description", "").strip()
            if val and val != "n/a":
                return val

    desc_lower = desc.lower()
    if "remote code execution" in desc_lower or "rce" in desc_lower:
        return "Remote Code Execution (RCE)"
    if "denial of service" in desc_lower or "dos" in desc_lower or "crash" in desc_lower:
        return "Denial of Service (DoS)"
    if "privilege escalation" in desc_lower:
        return "Privilege Escalation"
    if "memory corruption" in desc_lower or "out-of-bounds" in desc_lower or "buffer overflow" in desc_lower:
        return "Memory Corruption / Buffer Overflow"
    if "access control" in desc_lower or "authentication bypass" in desc_lower:
        return "Improper Access Control / Authentication Bypass"
    if "information disclosure" in desc_lower or "sensitive information" in desc_lower:
        return "Information Disclosure"

    return "Security Vulnerability"


def convert_cve_record(data: dict) -> dict:
    """Ubah format CVE JSON v5 menjadi format basis data ReconMTK."""
    cve_id = data.get("cveMetadata", {}).get("cveId", "")
    if not cve_id:
        return None

    cna = data.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") in ("en", "en-US", ""):
            desc_text = d.get("value", "")
            break
    if not desc_text and descriptions:
        desc_text = descriptions[0].get("value", "")

    # Cek apakah relevan MikroTik
    desc_lower = desc_text.lower()
    affected = cna.get("affected", [])
    is_mikrotik = False
    prod_name = "RouterOS"
    for aff in affected:
        vendor = str(aff.get("vendor", "")).lower()
        prod = str(aff.get("product", "")).lower()
        if "mikrotik" in vendor or "routeros" in prod or "mikrotik" in prod:
            is_mikrotik = True
            if aff.get("product"):
                prod_name = aff.get("product")
            break

    if not is_mikrotik and ("mikrotik" in desc_lower or "routeros" in desc_lower):
        is_mikrotik = True

    if not is_mikrotik:
        return None

    title = cna.get("title", "")
    if not title:
        first_sentence = desc_text.split(".")[0] if desc_text else "MikroTik RouterOS Vulnerability"
        title = first_sentence[:90]

    cvss_score, severity = determine_severity_and_cvss(cna)
    vuln_type = extract_vulnerability_type(cna, desc_text)
    affected_version = parse_versions_from_cna(cna, desc_text)
    ports = extract_ports_from_text(desc_text + " " + title + " " + prod_name)

    references = cna.get("references", [])
    ref_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    if references and references[0].get("url"):
        ref_url = references[0].get("url")

    return {
        "cve_id": cve_id,
        "title": title,
        "affected_component": f"MikroTik {prod_name}",
        "affected_ports": ports,
        "version_type": "routeros",
        "affected_version": affected_version,
        "severity_level": severity,
        "vulnerability_type": vuln_type,
        "cvss": cvss_score,
        "description": desc_text[:400] if desc_text else "Kerentanan pada MikroTik RouterOS.",
        "mitigation_hint": "Perbarui firmware MikroTik RouterOS ke versi terbaru resmi (mikrotik.com/download) dan terapkan aturan firewall ketat pada port manajemen.",
        "reference": ref_url,
    }


def import_cve_dump(dump_dir: str):
    print("=" * 65)
    print(" Import CVE Dump ke Basis Data ReconMTK")
    print(f" Direktori Sumber: {dump_dir}")
    print("=" * 65)

    if not os.path.exists(dump_dir):
        print(f"Error: Direktori '{dump_dir}' tidak ditemukan!")
        sys.exit(1)

    cves_path = os.path.join(dump_dir, "cves") if os.path.isdir(os.path.join(dump_dir, "cves")) else dump_dir

    print("\n[1/3] Memindai file CVE Dump untuk MikroTik / RouterOS...")
    scanned_files = 0
    mikrotik_records = []

    for root, dirs, files in os.walk(cves_path):
        for f in files:
            if f.endswith(".json") and f.startswith("CVE-"):
                scanned_files += 1
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8") as fp:
                        raw = json.load(fp)
                    rec = convert_cve_record(raw)
                    if rec:
                        mikrotik_records.append(rec)
                except Exception:
                    pass

    print(f"  -> Selesai memindai {scanned_files:,} file CVE.")
    print(f"  -> Ditemukan {len(mikrotik_records)} CVE terkait MikroTik / RouterOS.")

    print("\n[2/3] Menggabungkan ke basis data ReconMTK (data/cve_database.json)...")
    db = load_database(DB_PATH)
    existing_cves = db.get("cves", [])
    existing_ids = {c["cve_id"] for c in existing_cves}

    added_count = 0
    for rec in mikrotik_records:
        if rec["cve_id"] not in existing_ids:
            existing_cves.append(rec)
            existing_ids.add(rec["cve_id"])
            added_count += 1

    # Urutkan berdasarkan ID CVE terbaru
    def cve_sort_key(c):
        parts = c["cve_id"].split("-")
        try:
            return (int(parts[1]), int(parts[2]))
        except Exception:
            return (0, 0)

    existing_cves.sort(key=cve_sort_key, reverse=True)
    db["cves"] = existing_cves
    db.setdefault("_meta", {})["last_updated"] = date.today().isoformat()
    db["_meta"]["total_cves"] = len(existing_cves)

    # Simpan backup lalu simpan database baru
    shutil.copy2(DB_PATH, DB_PATH + ".bak")
    save_database(db, DB_PATH)

    print(f"  -> Berhasil menambahkan {added_count} entri CVE baru.")
    print(f"  -> Total CVE di database sekarang: {len(existing_cves)} entri.")

    print("\n[3/3] Statistik Basis Data Terkini:")
    stats = get_stats(db)
    print(f"  Total CVE: {stats['total']}")
    for sev, count in stats["by_severity"].items():
        print(f"   - {sev}: {count} CVE")
    print(f"  Terakhir diperbarui: {stats['last_updated']}")
    print("=" * 65)
    print("Impor selesai! Basis data siap digunakan di Web GUI & CLI.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Impor MikroTik CVE dari CVE Dump")
    parser.add_argument("--dump-dir", default=DEFAULT_DUMP_DIR, help="Path ke folder cvelistV5-main yang diekstrak")
    args = parser.parse_args()
    import_cve_dump(args.dump_dir)
