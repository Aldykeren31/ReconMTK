"""
Automated Reconnaissance Tool - Web GUI
==========================================
Tugas Akhir Skripsi - Pengembangan Automated Reconnaissance Tool
Berbasis Python untuk Pengujian Keamanan Router MikroTik Menggunakan
Metodologi PTES.

Jalankan:
    python3 app.py

Lalu buka browser ke http://127.0.0.1:5000

CATATAN ETIKA & LEGALITAS:
Tool ini HANYA untuk digunakan pada perangkat/jaringan yang Anda miliki
sendiri atau yang telah mendapat izin eksplisit untuk diuji (mis. lab
pengujian skripsi). Pemindaian tanpa izin terhadap perangkat milik
pihak lain adalah pelanggaran hukum.
"""

import os
import re
from flask import Flask, render_template, request, jsonify, send_file, abort

from modules import scanner_engine, cve_matcher

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    db = cve_matcher.load_database()
    return render_template("index.html", cve_count=len(db.get("cves", [])))


@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    profile = (data.get("profile") or "core").strip().lower()
    include_ip_protocol = bool(data.get("include_ip_protocol", False))
    if not target:
        return jsonify({"error": "Target IP / CIDR wajib diisi."}), 400
    if profile == "full":
        profile = "extended_udp"
    if profile not in ("core", "extended", "extended_udp"):
        profile = "core"
    job_id = scanner_engine.start_scan(target, profile=profile, include_ip_protocol=include_ip_protocol)
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>", methods=["GET"])
def api_scan_status(job_id):
    job = scanner_engine.get_job(job_id)
    if not job:
        return jsonify({"error": "Job tidak ditemukan."}), 404
    return jsonify(job)


@app.route("/api/report/<job_id>", methods=["GET"])
def api_download_report(job_id):
    job = scanner_engine.get_job(job_id)
    if not job or not job.get("report_path"):
        abort(404)
    path = job["report_path"]
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/api/cve-database", methods=["GET"])
def api_cve_database():
    return jsonify(cve_matcher.load_database())


@app.route("/api/cve-database/stats", methods=["GET"])
def api_cve_stats():
    """Jumlah CVE yang tercatat di database (total + per severity)."""
    return jsonify(cve_matcher.get_stats())


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@app.route("/api/cve-database/<cve_id>", methods=["DELETE"])
def api_delete_cve(cve_id):
    """Hapus satu entri CVE dari database."""
    if not CVE_ID_RE.match(cve_id):
        return jsonify({"error": "Format cve_id tidak valid."}), 400
    removed = cve_matcher.delete_cve(cve_id)
    if removed is None:
        return jsonify({"error": f"{cve_id} tidak ditemukan di database."}), 404
    return jsonify({"deleted": cve_id, "stats": cve_matcher.get_stats()})


if __name__ == "__main__":
    print("=" * 60)
    print(" Automated Reconnaissance Tool - Web GUI")
    print(" Buka browser: http://127.0.0.1:5000")
    print(" Tekan CTRL+C untuk berhenti.")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
