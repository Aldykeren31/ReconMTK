"""
Modul Host Discovery
=====================
Bertugas memastikan apakah target (Router MikroTik) dalam keadaan aktif
sebelum tahap footprinting/enumeration dijalankan. Mendukung target IP
tunggal maupun rentang subnet (CIDR).

Sesuai flowchart BAB III: "Host Discovery (Cek Router Aktif)".
"""

import ipaddress
import platform
import subprocess
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def _ping_once(ip: str, timeout_s: float = 1.2) -> bool:
    """Kirim satu paket ICMP echo (via binary `ping` sistem) ke sebuah IP.

    Menggunakan subprocess ke `ping` bawaan OS agar tidak memerlukan
    hak akses raw-socket (root) yang biasanya dibutuhkan oleh ICMP
    murni di Python. Berjalan native di Kali Linux (UTM VM).
    """
    system = platform.system().lower()
    count_flag = "-n" if system == "windows" else "-c"
    timeout_flag = "-w" if system == "windows" else "-W"
    timeout_val = str(int(timeout_s * 1000)) if system == "windows" else str(int(timeout_s))

    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, ip]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 1.5
        )
        return result.returncode == 0
    except Exception:
        return False


def _tcp_fallback(ip: str, ports=(80, 443, 22, 8291), timeout_s: float = 0.8) -> bool:
    """Fallback: sebagian jaringan/VM memblokir ICMP. Jika ping gagal,
    coba TCP connect cepat ke beberapa port umum MikroTik sebagai bukti
    perangkat hidup dan menjawab di layer TCP.
    """
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_s)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            continue
    return False


def check_host(ip: str) -> dict:
    """Cek satu host. Mengembalikan status aktif/tidak beserta metode deteksi."""
    started = time.time()
    alive = _ping_once(ip)
    method = "icmp"
    if not alive:
        alive = _tcp_fallback(ip)
        method = "tcp-fallback" if alive else "none"
    return {
        "ip": ip,
        "alive": alive,
        "method": method,
        "response_time_ms": round((time.time() - started) * 1000, 1),
    }


def expand_targets(target: str) -> list:
    """Ubah input pengguna (IP tunggal atau CIDR) menjadi daftar IP."""
    target = target.strip()
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        # Batasi subnet besar agar scan tetap wajar untuk lingkup skripsi
        hosts = list(network.hosts())
        if len(hosts) > 254:
            hosts = hosts[:254]
        return [str(h) for h in hosts]
    return [target]


def discover(target: str, max_workers: int = 32, progress_cb=None) -> list:
    """Jalankan host discovery untuk satu IP atau seluruh rentang CIDR.

    progress_cb(dict) dipanggil setiap satu host selesai dicek, berguna
    untuk melaporkan progres real-time ke Web GUI.
    """
    ip_list = expand_targets(target)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            if progress_cb:
                progress_cb(res)
    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    return results
