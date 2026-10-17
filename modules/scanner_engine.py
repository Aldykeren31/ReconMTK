"""
Scanner Engine
===============
Mengorkestrasi seluruh alur kerja sesuai flowchart BAB III:

  Mulai -> Input Target IP -> Host Discovery -> Kondisi Router Aktif?
        -> [tidak aktif] -> Peringatan "Target Tidak Aktif" -> Selesai
        -> [aktif] -> Fase 1: Footprinting (Port Scan)
                   -> Fase 2: Enumeration (Banner Grabbing)
                   -> Analisis Hasil (Pencocokan Data CVE)
                   -> Output: Laporan Otomatis -> Selesai

Dijalankan di background thread oleh app.py agar Web GUI tetap responsif
dan bisa menampilkan progres secara real-time (polling job store).

CATATAN INSTRUMENTASI WAKTU (ditambahkan untuk keperluan BAB IV,
subbab 4.2.3 -- pengujian pembanding dengan Nmap):
Setiap tahap pipeline diukur durasinya memakai `time.time()` dan
dikumpulkan ke dalam `stage_timings`, lalu disimpan ke job state (field
"timings") dan dicetak ke log proses ("Rincian waktu per tahap: ...")
setelah seluruh proses selesai. Ini memungkinkan operator membaca waktu
eksekusi per tahap (host discovery, footprinting, enumeration,
pencocokan CVE, pembuatan laporan, serta total) langsung dari log
proses di dashboard, tanpa perlu mengukur manual dengan stopwatch
eksternal.
"""

import os
import threading
import time
import uuid
from datetime import datetime

from modules import host_discovery, port_scanner, banner_grabber, cve_matcher, report_generator, ip_protocol_scanner

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

# Job store sederhana in-memory. Cukup untuk skala penggunaan skripsi
# (satu operator, satu/segelintir scan berjalan bersamaan).
JOBS = {}
JOBS_LOCK = threading.Lock()


def _new_job(target: str, profile: str = "core") -> str:
    job_id = str(uuid.uuid4())[:8]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "target": target,
            "profile": profile,
            "status": "queued",  # queued -> running -> done / failed / inactive
            "stage": "Mulai",
            "log": [],
            "host_discovery": [],
            "port_scan": [],
            "banner_grab": [],
            "detected_version": None,
            "cve_matches": [],
            "ip_protocol_scan": None,
            "report_path": None,
            "started_at": None,
            "finished_at": None,
            "timings": None,
            "error": None,
        }
    return job_id


def _log(job_id: str, message: str):
    with JOBS_LOCK:
        JOBS[job_id]["log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": message,
        })


def _set(job_id: str, **kwargs):
    with JOBS_LOCK:
        JOBS[job_id].update(kwargs)


def get_job(job_id: str) -> dict:
    with JOBS_LOCK:
        return dict(JOBS.get(job_id, {}))


def _run_pipeline(job_id: str, target: str, active_ip: str = None, profile: str = "core", include_ip_protocol: bool = False):
    stage_timings = {}
    _t0 = time.time()
    try:
        _set(job_id, status="running", started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # --- Tahap: Host Discovery ---
        _set(job_id, stage="Host Discovery (Cek Router Aktif)")
        _log(job_id, f"Memulai host discovery untuk target: {target}")

        def hd_progress(res):
            status_txt = "AKTIF" if res["alive"] else "tidak merespons"
            _log(job_id, f"  {res['ip']} -> {status_txt} ({res['method']})")

        hd_results = host_discovery.discover(target, progress_cb=hd_progress)
        _set(job_id, host_discovery=hd_results)
        stage_timings["host_discovery_s"] = round(time.time() - _t0, 2)

        alive_hosts = [h["ip"] for h in hd_results if h["alive"]]
        if not alive_hosts:
            _log(job_id, "Target Tidak Aktif -- proses dihentikan (sesuai flowchart).")
            stage_timings["total_s"] = round(time.time() - _t0, 2)
            _set(job_id, status="inactive", stage="Selesai (Target Tidak Aktif)",
                 finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 timings=stage_timings)
            return

        target_ip = active_ip if active_ip in alive_hosts else alive_hosts[0]
        _log(job_id, f"Router aktif terdeteksi pada {target_ip}. Melanjutkan ke fase Footprinting.")

        # --- Fase 1: Footprinting ---
        _t1 = time.time()
        profile_labels = {
            "core": "core (9 port TCP fokus penelitian)",
            "extended": "extended (+ port TCP tambahan simulasi BAB IV)",
            "extended_udp": "full scan (semua port TCP + UDP)",
        }
        _set(job_id, stage="Fase 1: Footprinting (Port Scanning)")
        _log(job_id, f"Profil port: {profile_labels.get(profile, profile)}")

        def ps_progress(res):
            if res["status"] in ("open", "open|filtered"):
                proto = res.get("protocol", "tcp").upper()
                _log(job_id, f"  [{proto}] Port {res['port']} ({res['service']}) -> {res['status'].upper()}")

        ps_results = port_scanner.scan_target(target_ip, progress_cb=ps_progress, profile=profile)
        _set(job_id, port_scan=ps_results)
        # Hanya port TCP "open" yang diteruskan ke fase banner grabbing --
        # UDP tidak punya banner grabber (di luar cakupan banner_grabber.py).
        open_tcp_ports = [p["port"] for p in ps_results if p["protocol"] == "tcp" and p["status"] == "open"]
        open_udp_ports = [p["port"] for p in ps_results if p["protocol"] == "udp" and p["status"] in ("open", "open|filtered")]
        # Untuk pencocokan CVE, gabungkan port TCP open + UDP open/open|filtered
        # (skema affected_ports pada cve_database.json tidak membedakan protokol).
        open_ports = sorted(set(open_tcp_ports) | set(open_udp_ports))
        _log(job_id, f"Footprinting selesai. TCP open: {open_tcp_ports or '-'} | UDP open/open|filtered: {open_udp_ports or '-'}")
        stage_timings["port_scan_s"] = round(time.time() - _t1, 2)

        # --- Fase 1.5: IP Protocol Scan (opsional, di luar TCP/UDP) ---
        if include_ip_protocol:
            _t_ipproto = time.time()
            _set(job_id, stage="Fase 1.5: IP Protocol Scan (nmap -sO)")
            _log(job_id, "Menjalankan IP protocol scan (/1 ICMP, /47 GRE, /89 OSPF, dst) via nmap -sO...")
            ip_proto_result = ip_protocol_scanner.scan_ip_protocols(target_ip)
            _set(job_id, ip_protocol_scan=ip_proto_result)
            if not ip_proto_result["supported"]:
                _log(job_id, f"  IP protocol scan dilewati: {ip_proto_result['error']}")
            else:
                for r in ip_proto_result["results"]:
                    _log(job_id, f"  [PROTO] /{r['protocol']} ({r['name']}) -> {r['status'].upper()}")
                _log(job_id, "IP protocol scan selesai.")
            stage_timings["ip_protocol_scan_s"] = round(time.time() - _t_ipproto, 2)
            _log(job_id, f"  Waktu IP protocol scan: {stage_timings['ip_protocol_scan_s']}s")

        # --- Fase 2: Enumeration ---
        _t2 = time.time()
        _set(job_id, stage="Fase 2: Enumeration (Banner Grabbing)")

        def bg_progress(res):
            note = res.get("routeros_version") or res.get("server_header") or "banner ditarik"
            _log(job_id, f"  Enumerasi port {res['port']} ({res['service']}) -> {note}")

        bg_results = banner_grabber.grab_all(target_ip, open_tcp_ports, progress_cb=bg_progress)
        _set(job_id, banner_grab=bg_results)
        detected_version = banner_grabber.summarize_version(bg_results)
        _set(job_id, detected_version=detected_version)
        _log(job_id, f"Versi/identitas RouterOS terindikasi: {detected_version or 'tidak dapat dipastikan'}")
        stage_timings["banner_grab_s"] = round(time.time() - _t2, 2)

        # --- Analisis Hasil (Pencocokan Data) ---
        _t3 = time.time()
        _set(job_id, stage="Analisis Hasil (Pencocokan Data CVE)")
        # Banner mentah per port diteruskan ke matcher agar CVE bertipe
        # "openssh" (mis. CVE-2024-6387) hanya dicocokkan bila banner benar-benar
        # menunjukkan OpenSSH -- bukan sekadar port 22 terbuka (yang pada
        # MikroTik justru dilayani SSH proprietary RouterOS, banner "ROSSSH").
        banner_map = {r["port"]: r.get("banner", "") for r in bg_results}
        cve_matches = cve_matcher.match(detected_version, open_ports, banners=banner_map)
        _set(job_id, cve_matches=cve_matches)
        _log(job_id, f"Pencocokan basis data CVE selesai. {len(cve_matches)} kerentanan relevan ditemukan.")
        excluded_openssh = [
            cve for cve in cve_matcher.load_database().get("cves", [])
            if cve.get("version_type") == "openssh"
            and set(cve.get("affected_ports", [])) & set(open_ports)
            and cve.get("cve_id") not in {m.get("cve_id") for m in cve_matches}
        ]
        for cve in excluded_openssh:
            _log(job_id, f"  {cve.get('cve_id')} dilewati: port terkait terbuka tetapi banner "
                          f"tidak menunjukkan OpenSSH (kemungkinan SSH proprietary MikroTik).")
        stage_timings["cve_matching_s"] = round(time.time() - _t3, 2)

        # --- Output: Laporan Otomatis ---
        _t4 = time.time()
        _set(job_id, stage="Output: Menyusun Laporan Otomatis")
        job_snapshot = get_job(job_id)
        job_snapshot["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = report_generator.default_filename(target_ip)
        output_path = os.path.join(REPORTS_DIR, filename)
        report_generator.generate_report(job_snapshot, output_path)
        stage_timings["report_generation_s"] = round(time.time() - _t4, 2)
        stage_timings["total_s"] = round(time.time() - _t0, 2)

        _set(job_id, report_path=output_path,
             finished_at=job_snapshot["finished_at"], timings=stage_timings)
        _log(job_id, f"Laporan berhasil dibuat: {filename}")
        _log(job_id, "  Rincian waktu per tahap: " + ", ".join(f"{k}={v}s" for k, v in stage_timings.items()))

        _set(job_id, status="done", stage="Selesai")
        _log(job_id, "Proses reconnaissance selesai (Selesai).")

    except Exception as exc:  # pragma: no cover - safety net untuk Web GUI
        stage_timings["total_s"] = round(time.time() - _t0, 2)
        _log(job_id, f"Terjadi kesalahan: {exc}")
        _set(job_id, status="failed", error=str(exc), timings=stage_timings,
             finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def start_scan(target: str, profile: str = "core", include_ip_protocol: bool = False) -> str:
    """Buat job baru dan jalankan pipeline di background thread.

    `profile`: "core" (default, 9 port TCP fokus penelitian BAB III),
    "extended" (+ port TCP tambahan simulasi BAB IV), atau
    "extended_udp" (+ port TCP tambahan + port UDP). Cocok dipasangkan
    dengan scripts/dummy_mikrotik_target.py --profile extended [--with-udp].

    `include_ip_protocol`: kalau True, tambahkan fase IP protocol scan
    (nmap -sO) setelah footprinting -- butuh nmap ter-install & app.py
    dijalankan dengan sudo (raw socket).
    """
    if profile not in ("core", "extended", "extended_udp"):
        profile = "core"
    job_id = _new_job(target, profile=profile)
    thread = threading.Thread(
        target=_run_pipeline,
        args=(job_id, target, None, profile, include_ip_protocol),
        daemon=True,
    )
    thread.start()
    return job_id
