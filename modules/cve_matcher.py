"""
Modul Analisis Hasil / Pencocokan Data (CVE Matching)
=======================================================
Membandingkan versi RouterOS (dan port terbuka) yang berhasil
diidentifikasi pada fase enumeration dengan basis data referensi CVE
publik (data/cve_database.json), sesuai tahap "Analisis Hasil
(Pencocokan Data)" pada flowchart BAB III.

Skema atribut basis data mengikuti Tabel 3.2 Perancangan Basis Data:
cve_id, affected_version, severity_level, vulnerability_type,
description, mitigation_hint (plus beberapa atribut fungsional
tambahan: title, affected_component, affected_ports, version_type,
cvss, reference).

Field `affected_version` disimpan sebagai satu string agar sesuai
rancangan skema, namun tetap bisa dibandingkan secara terprogram lewat
mini-parser `parse_affected_version()` di bawah ini. Format yang
didukung per segmen (segmen dipisah `;` untuk beberapa cabang versi):

    "<= 6.49.7"                      -> dari versi 0 s.d. 6.49.7
    ">= 7.0"                         -> dari versi 7.0 s.d. tak terhingga
    "6.27 - 6.49.6"                  -> rentang eksplisit
    "stable: 6.27 - 6.49.6"          -> rentang dengan label cabang
    "stable: 6.27 - 6.49.6; long-term: <= 6.49.7"  -> gabungan beberapa cabang

Teks tambahan dalam tanda kurung, mis. "(RouterOS v7 tidak terdampak)",
diabaikan saat parsing (murni catatan untuk pembaca laporan).
"""

import json
import os
import re
import shutil
import threading
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cve_database.json")

INFINITY_TUPLE = (99999,)

# Sesuai revisi pembimbing: CVE TIDAK boleh dicocokkan hanya dari port
# terbuka, untuk SEMUA tipe CVE (termasuk "routeros"), bukan cuma yang
# bertipe "openssh". Bila versi RouterOS tidak berhasil dipastikan, CVE
# berbasis versi tidak dilaporkan sebagai temuan -- auditor perlu
# verifikasi manual terpisah, bukan tool yang menebak dari port saja.
ALLOW_PORT_FALLBACK = False


def _version_tuple(v: str):
    """Ubah string versi menjadi tuple angka untuk dibandingkan.
    Versi non-numerik dikembalikan sebagai None.
    """
    if not v:
        return None
    match = re.match(r"^(\d+(?:\.\d+){0,3})", v.strip())
    if not match:
        return None
    return tuple(int(x) for x in match.group(1).split("."))


def parse_affected_version(affected_version: str) -> list:
    """Pecah string `affected_version` menjadi daftar rentang terstruktur:
    [{"branch": str, "from": str, "to": str|None}, ...]
    `to = None` berarti tidak terbatas ke atas (dari operator ">=").
    """
    if not affected_version:
        return []

    ranges = []
    for raw_segment in affected_version.split(";"):
        segment = raw_segment.strip()
        if not segment:
            continue

        # Buang catatan dalam tanda kurung, mis. "(cek changelog resmi ...)"
        segment = re.sub(r"\([^)]*\)", "", segment).strip()

        branch = "-"
        if ":" in segment:
            label, rest = segment.split(":", 1)
            branch = label.strip()
            segment = rest.strip()

        if segment.startswith("<="):
            ranges.append({"branch": branch, "from": "0", "to": segment[2:].strip()})
        elif segment.startswith(">="):
            ranges.append({"branch": branch, "from": segment[2:].strip(), "to": None})
        elif "-" in segment:
            parts = segment.split("-", 1)
            ranges.append({"branch": branch, "from": parts[0].strip(), "to": parts[1].strip()})
        else:
            # Versi tunggal (exact match)
            ranges.append({"branch": branch, "from": segment, "to": segment})

    return ranges


def _in_range(version_tuple, low: str, high) -> bool:
    low_t = _version_tuple(low) or (0,)
    high_t = INFINITY_TUPLE if high is None else _version_tuple(high)
    if high_t is None:
        # Batas atas tidak berformat versi baku -> jangan diloloskan otomatis
        return False
    length = max(len(version_tuple), len(low_t), len(high_t))
    v = version_tuple + (0,) * (length - len(version_tuple))
    lo = low_t + (0,) * (length - len(low_t))
    hi = high_t + (0,) * (length - len(high_t))
    return lo <= v <= hi


# Kunci agar dua permintaan hapus yang datang bersamaan tidak saling menimpa.
_DB_LOCK = threading.Lock()


def load_database(path: str = DB_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_database(db: dict, path: str = DB_PATH) -> None:
    """Simpan basis data secara atomik: tulis ke file sementara dulu, lalu
    ganti file asli. Scan yang sedang membaca database tidak akan pernah
    menemui file yang setengah tertulis."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, path)


def get_stats(db: dict = None) -> dict:
    """Ringkasan isi basis data: total entri, jumlah per severity, dan
    tanggal pembaruan terakhir."""
    db = db or load_database()
    cves = db.get("cves", [])
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for c in cves:
        sev = c.get("severity_level")
        if sev in by_severity:
            by_severity[sev] += 1
    return {
        "total": len(cves),
        "by_severity": by_severity,
        "last_updated": db.get("_meta", {}).get("last_updated"),
    }


def delete_cve(cve_id: str, path: str = DB_PATH):
    """Hapus satu entri CVE berdasarkan cve_id.
    Mengembalikan entri yang dihapus, atau None bila cve_id tidak ada.
    Sebelum menulis, salinan database lama disimpan ke `<path>.bak`
    (satu cadangan terakhir) sebagai pengaman bila ada salah hapus."""
    with _DB_LOCK:
        db = load_database(path)
        cves = db.get("cves", [])
        removed = next((c for c in cves if c.get("cve_id") == cve_id), None)
        if removed is None:
            return None
        shutil.copy2(path, path + ".bak")
        db["cves"] = [c for c in cves if c.get("cve_id") != cve_id]
        db.setdefault("_meta", {})["last_updated"] = date.today().isoformat()
        save_database(db, path)
        return removed


def _banner_text_for_ports(ports, banners: dict) -> str:
    """Gabungkan teks banner (raw, apa adanya dari banner_grabber) dari
    seluruh port yang diberikan, untuk dicek kata kunci produk di dalamnya."""
    if not banners:
        return ""
    return " ".join(str(banners.get(p, "") or "") for p in ports)


def _banner_indicates_openssh(banner_text: str) -> bool:
    """True hanya jika banner benar-benar memuat identifikasi OpenSSH,
    mis. 'SSH-2.0-OpenSSH_9.6p1'."""
    return "openssh" in banner_text.lower()


def _banner_indicates_proprietary_ssh(banner_text: str) -> bool:
    """True jika banner justru menunjukkan implementasi SSH proprietary
    MikroTik (bukan OpenSSH), mis. 'SSH-2.0-ROSSSH'."""
    lowered = banner_text.lower()
    return "rosssh" in lowered or ("mikrotik" in lowered and "openssh" not in lowered)


def match(detected_version: str, open_ports: list, db: dict = None, banners: dict = None) -> list:
    """Cocokkan versi RouterOS yang terdeteksi & daftar port terbuka
    terhadap basis data CVE. Mengembalikan daftar CVE yang relevan,
    diurutkan dari severity tertinggi.
    `banners`: dict opsional {port: raw_banner_text}, biasanya dibangun dari
    hasil banner_grabber.grab_all(). Dipakai untuk memvalidasi CVE dengan
    version_type == "openssh" -- CVE semacam ini hanya boleh cocok apabila
    banner pada port terkait benar-benar menunjukkan OpenSSH, bukan sekadar
    port yang kebetulan terbuka. Tanpa validasi ini, layanan SSH proprietary
    MikroTik (banner "ROSSSH") bisa salah dicocokkan dengan CVE yang
    sebenarnya spesifik untuk OpenSSH (mis. CVE-2024-6387 / regreSSHion),
    padahal RouterOS tidak menjalankan OpenSSH sama sekali.
    Untuk CVE bertipe "routeros", pencocokan HANYA lewat rentang versi yang
    telah tervalidasi (ALLOW_PORT_FALLBACK = False secara default) -- port
    yang kebetulan terbuka saat versi tidak terbaca TIDAK cukup untuk
    melaporkan sebuah CVE sebagai temuan, sesuai revisi pembimbing.
    """
    db = db or load_database()
    version_tuple = _version_tuple(detected_version)
    open_ports_set = set(open_ports)
    banners = banners or {}
    matches = []

    for cve in db.get("cves", []):
        reason = []
        matched = False
        version_type = cve.get("version_type")
        cve_ports = set(cve.get("affected_ports", []))
        relevant_open_ports = sorted(cve_ports & open_ports_set)
        banner_text = _banner_text_for_ports(relevant_open_ports, banners)
        # Guard khusus produk: CVE bertipe "openssh" butuh bukti banner
        # OpenSSH pada port yang relevan. Tanpa bukti itu, CVE ini dianggap
        # tidak relevan untuk perangkat MikroTik (SSH-nya proprietary),
        # sehingga langsung dilewati -- tidak dicocokkan lewat jalur port saja.
        if version_type == "openssh":
            if _banner_indicates_openssh(banner_text):
                matched = True
                reason.append(
                    f"Banner pada port {relevant_open_ports} mengindikasikan OpenSSH "
                    f"({banner_text.strip()[:80]!r}); CVE ini relevan untuk diverifikasi lebih lanjut."
                )
            else:
                # Tidak matched. Beri catatan eksplisit bila ternyata banner
                # justru proprietary MikroTik, supaya jelas ini exclusion
                # yang disengaja, bukan kegagalan sistem.
                if _banner_indicates_proprietary_ssh(banner_text):
                    reason.append(
                        "Dilewati: banner menunjukkan implementasi SSH proprietary MikroTik "
                        f"({banner_text.strip()[:80]!r}), bukan OpenSSH -- CVE ini secara produk "
                        "tidak berlaku untuk RouterOS."
                    )
                else:
                    reason.append(
                        "Dilewati: tidak ada bukti banner OpenSSH pada port terkait, "
                        "sehingga CVE bertipe openssh tidak dicocokkan hanya berdasarkan port."
                    )
            # CVE openssh tidak lagi lewat jalur pencocokan berbasis versi RouterOS
            # atau fallback port-saja di bawah -- lanjut ke entri berikutnya.
            if matched:
                entry = dict(cve)
                entry["match_reason"] = " ".join(reason)
                matches.append(entry)
            continue
        # Kecocokan berdasar rentang versi (jika versi berhasil dibaca)
        if version_tuple and version_type == "routeros":
            for rng in parse_affected_version(cve.get("affected_version", "")):
                if _in_range(version_tuple, rng.get("from", "0"), rng.get("to")):
                    matched = True
                    branch_label = rng.get("branch", "-")
                    to_label = rng.get("to") if rng.get("to") is not None else "tak terbatas"
                    reason.append(
                        f"Versi terdeteksi {detected_version} berada dalam rentang terdampak "
                        f"({branch_label}: {rng.get('from')} - {to_label})"
                    )
                    break
        # Kecocokan tambahan berdasar port terbuka yang relevan dengan CVE,
        # ditandai sebagai indikasi (bukan kepastian) bila versi tak terbaca.
        if cve_ports & open_ports_set:
            if ALLOW_PORT_FALLBACK and not matched and not version_tuple:
                matched = True
                reason.append(
                    f"Port terkait layanan rentan terbuka ({relevant_open_ports}), "
                    f"namun versi RouterOS tidak berhasil dipastikan -> perlu verifikasi manual."
                )
            elif matched:
                reason.append(f"Port layanan terkait juga ditemukan terbuka: {relevant_open_ports}")
        if matched:
            entry = dict(cve)
            entry["match_reason"] = " ".join(reason)
            matches.append(entry)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    matches.sort(key=lambda c: (severity_order.get(c.get("severity_level"), 9), -c.get("cvss", 0)))
    return matches
