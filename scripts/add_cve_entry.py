#!/usr/bin/env python3
"""
Fitur Update Basis Data CVE
==============================
Script interaktif untuk menambahkan entri CVE baru ke dalam
data/cve_database.json TANPA perlu mengedit format JSON secara manual.

Latar belakang (hasil bimbingan): basis data CVE publik menerbitkan
ratusan-ribuan entri baru tiap tahun, sehingga operator (auditor) perlu
cara mudah untuk menambah entri baru yang relevan dengan MikroTik tanpa
harus memahami detail sintaks JSON. Script ini menangani seluruh proses
formatting -- operator cukup mengisi data yang diminta.

Cara pakai:
    python3 scripts/add_cve_entry.py

Alur:
    1. Operator mengisi setiap atribut CVE lewat prompt interaktif
       (cve_id, title, affected_component, affected_ports, version_type,
       affected_version, severity_level, vulnerability_type, cvss,
       description, mitigation_hint, reference).
    2. Script memvalidasi format `affected_version` memakai parser yang
       sama dengan cve_matcher.py (parse_affected_version), supaya entri
       baru dijamin bisa dicocokkan otomatis oleh mesin pencocokan CVE.
    3. Script mengecek cve_id belum ada di database (mencegah duplikat).
    4. Entri baru ditambahkan ke data/cve_database.json dan disimpan.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.cve_matcher import parse_affected_version, DB_PATH  # noqa: E402

VALID_SEVERITY = ["Critical", "High", "Medium", "Low"]
VALID_VERSION_TYPE = ["routeros", "openssh"]

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def ask(prompt, default=None, required=True):
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if not val and not required:
            return ""
        if val:
            return val
        print("  -> Wajib diisi, coba lagi.")


def ask_choice(prompt, choices):
    choices_str = "/".join(choices)
    while True:
        val = input(f"{prompt} ({choices_str}): ").strip()
        for c in choices:
            if val.lower() == c.lower():
                return c
        print(f"  -> Pilihan tidak valid, harus salah satu dari: {choices_str}")


def ask_float(prompt):
    while True:
        val = input(f"{prompt} (0.0 - 10.0): ").strip()
        try:
            f = float(val)
            if 0.0 <= f <= 10.0:
                return f
        except ValueError:
            pass
        print("  -> Masukkan angka desimal antara 0.0 dan 10.0, mis. 7.5")


def ask_ports(prompt):
    val = input(f"{prompt} (pisahkan koma, kosongkan jika tidak ada, mis. 80,443,8291): ").strip()
    if not val:
        return []
    ports = []
    for p in val.split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
        else:
            print(f"  -> '{p}' diabaikan (bukan angka valid)")
    return ports


def validate_affected_version(cve_id_hint):
    while True:
        print("\nContoh format affected_version yang didukung:")
        print('  "<= 6.49.7"')
        print('  ">= 7.0"')
        print('  "6.27 - 6.49.6"')
        print('  "stable: 6.27 - 6.49.6; long-term: <= 6.49.7"')
        val = ask("affected_version")
        parsed = parse_affected_version(val)
        if not parsed:
            print("  -> Format tidak dikenali oleh parser, coba lagi (lihat contoh di atas).")
            continue
        print(f"  -> Terbaca sebagai: {parsed}")
        confirm = input("  -> Sudah benar? (y/n): ").strip().lower()
        if confirm == "y":
            return val


def main():
    print("=" * 60)
    print(" Fitur Update Basis Data CVE - ReconMTK")
    print(" Tambah entri CVE baru tanpa perlu edit JSON manual")
    print("=" * 60)

    db_path = DB_PATH
    with open(db_path, "r", encoding="utf-8") as f:
        db = json.load(f)

    existing_ids = {c["cve_id"] for c in db.get("cves", [])}

    print("\n--- Data CVE Baru ---")
    while True:
        cve_id = ask("cve_id (format CVE-YYYY-NNNN)")
        if not CVE_ID_RE.match(cve_id):
            print("  -> Format cve_id tidak valid, contoh: CVE-2025-12345")
            continue
        if cve_id in existing_ids:
            print(f"  -> {cve_id} sudah ada di database! Batal ditambahkan.")
            continue
        break

    title = ask("title (nama singkat kerentanan)")
    affected_component = ask("affected_component (mis. Winbox service)")
    affected_ports = ask_ports("affected_ports")
    version_type = ask_choice("version_type", VALID_VERSION_TYPE)
    affected_version = validate_affected_version(cve_id)
    severity_level = ask_choice("severity_level", VALID_SEVERITY)
    vulnerability_type = ask("vulnerability_type (mis. Privilege Escalation (RCE))")
    cvss = ask_float("cvss")
    description = ask("description (penjelasan singkat)")
    mitigation_hint = ask("mitigation_hint (rekomendasi mitigasi)")
    reference = ask("reference (URL sumber resmi)")

    new_entry = {
        "cve_id": cve_id,
        "title": title,
        "affected_component": affected_component,
        "affected_ports": affected_ports,
        "version_type": version_type,
        "affected_version": affected_version,
        "severity_level": severity_level,
        "vulnerability_type": vulnerability_type,
        "cvss": cvss,
        "description": description,
        "mitigation_hint": mitigation_hint,
        "reference": reference,
    }

    print("\n--- Ringkasan Entri Baru ---")
    print(json.dumps(new_entry, indent=2, ensure_ascii=False))
    confirm = input("\nSimpan entri ini ke database? (y/n): ").strip().lower()
    if confirm != "y":
        print("Dibatalkan, tidak ada perubahan disimpan.")
        return

    db["cves"].append(new_entry)
    db["_meta"]["last_updated"] = __import__("datetime").date.today().isoformat()

    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nBerhasil! {cve_id} ditambahkan ke {db_path}")
    print(f"Total entri CVE sekarang: {len(db['cves'])}")


if __name__ == "__main__":
    main()
