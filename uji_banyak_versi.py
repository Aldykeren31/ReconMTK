#!/usr/bin/env python3
"""
Uji akurasi deteksi versi RouterOS pada banyak versi (dummy server).

Simpan di folder scripts/ project ReconMTK, lalu jalankan dari root project:

    sudo python3 scripts/uji_banyak_versi.py
    sudo python3 scripts/uji_banyak_versi.py --versi 6.40 6.45.9 6.48.6 6.49.18 7.15.3
    sudo python3 scripts/uji_banyak_versi.py --tanpa-port 23 80 443     # kasus "layanan versi dimatikan"

(sudo diperlukan karena dummy membuka port < 1024: 21, 22, 23, 80, 443.)

Skrip memulai dummy_mikrotik_target.py untuk tiap versi, menjalankan
banner grabbing + pencocokan CVE ReconMTK ke 127.0.0.1, lalu membandingkan
versi yang diharapkan dengan versi yang terdeteksi.

CATATAN: dummy hanya MENCETAK versi yang diberikan. Uji ini memvalidasi
parser dan logika pencocokan, bukan perilaku RouterOS asli.
"""
import argparse
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from modules import banner_grabber, cve_matcher  # noqa: E402

DUMMY = os.path.join(ROOT, "scripts", "dummy_mikrotik_target.py")
CORE_PORTS = [21, 22, 23, 80, 443, 2000, 8291, 8728, 8729]
DEFAULT_VERSIONS = ["6.40", "6.45.9", "6.48.6", "6.49.18", "7.15.3"]


def tunggu_siap(port=8291, batas=8.0):
    mulai = time.time()
    while time.time() - mulai < batas:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def uji_satu(versi, tanpa_port):
    proses = subprocess.Popen(
        [sys.executable, DUMMY, "--version", versi],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not tunggu_siap():
            return {"versi": versi, "error": "dummy gagal start (coba jalankan dengan sudo)"}
        ports = [p for p in CORE_PORTS if p not in tanpa_port]
        hasil = banner_grabber.grab_all("127.0.0.1", ports)
        terdeteksi = banner_grabber.summarize_version(hasil)
        cve = [c["cve_id"] for c in cve_matcher.match(terdeteksi, ports)]
        return {"versi": versi, "terdeteksi": terdeteksi, "cve": cve}
    finally:
        proses.terminate()
        try:
            proses.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proses.kill()
        time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--versi", nargs="+", default=DEFAULT_VERSIONS)
    ap.add_argument("--tanpa-port", nargs="*", type=int, default=[],
                    help="port yang dikeluarkan dari pemindaian (mis. 23 80 443 untuk kasus layanan versi dimatikan)")
    a = ap.parse_args()

    baris = [uji_satu(v, set(a.tanpa_port)) for v in a.versi]

    print(f"{'Versi diharapkan':<18}{'Versi terdeteksi':<34}{'Status':<20}{'Jml CVE':<9}CVE")
    print("-" * 110)
    benar = salah = tidak_pasti = 0
    for b in baris:
        if "error" in b:
            print(f"{b['versi']:<18}ERROR: {b['error']}")
            continue
        terdeteksi = str(b["terdeteksi"])
        if terdeteksi == b["versi"]:
            status, benar = "BENAR", benar + 1
        elif not terdeteksi[:1].isdigit():
            # Tool tidak menebak: melaporkan bahwa versi tidak dapat dipastikan.
            status, tidak_pasti = "TIDAK DIPASTIKAN", tidak_pasti + 1
        else:
            status, salah = "SALAH", salah + 1
        print(f"{b['versi']:<18}{terdeteksi:<34}{status:<20}{len(b['cve']):<9}{', '.join(b['cve']) or '-'}")
    print("-" * 110)
    total = benar + salah + tidak_pasti
    print(f"Total uji: {total} | benar: {benar} | salah: {salah} | tidak dipastikan: {tidak_pasti}")
    if total:
        print(f"Akurasi (benar / total): {100 * benar / total:.0f}%   |   Salah-tebak: {salah}")


if __name__ == "__main__":
    main()
