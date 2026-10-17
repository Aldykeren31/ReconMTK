"""
Modul IP Protocol Scanner (opsional, BAB IV -- keterbatasan cakupan)
=====================================================================
Memindai nomor protokol IP (bukan port TCP/UDP) menggunakan Nmap mode
`-sO` (IP protocol scan). Ini KATEGORI SCAN YANG BERBEDA TOTAL dari
port scanning biasa:

- Port TCP/UDP ada di header TCP/UDP, di ATAS layer IP.
- Nomor protokol IP (mis. /1 ICMP, /47 GRE, /89 OSPF) ada di header IP
  itu sendiri (field "Protocol"), menandakan jenis payload yang dibawa
  paket IP -- bukan "port yang listen".

Untuk mengecek ini butuh mengirim paket IP mentah dan membaca balasannya
langsung, yang berarti perlu `socket.SOCK_RAW` + akses root. Alih-alih
menulis ulang raw-socket handling secara manual (kompleks dan rawan
bug), modul ini memanggil binary `nmap` yang sudah teruji di lapangan
dan mem-parsing outputnya. Ini sesuai praktik umum: Nmap sendiri
memperlakukan IP protocol scan sebagai mode terpisah (-sO), bukan
bagian dari -sT/-sU biasa.

SYARAT:
- Nmap harus ter-install di sistem (`sudo apt install nmap` di Kali,
  biasanya sudah ada bawaan).
- Proses yang menjalankan app.py harus punya izin membuat raw socket,
  artinya di Linux WAJIB dijalankan dengan `sudo`.

KETERBATASAN YANG PERLU DICATAT DI LAPORAN:
- Target dummy Python (scripts/dummy_mikrotik_target.py) TIDAK bisa
  merespons IP protocol scan ini secara berarti, karena dummy hanya
  listen di socket TCP/UDP biasa dan tidak punya handler untuk paket
  ICMP/GRE/OSPF mentah. Hasil scan ke dummy kemungkinan besar semua
  "open|filtered". Untuk melihat protokol yang benar-benar "open" (mis.
  /1 ICMP), scan harus diarahkan ke target sungguhan (MikroTik asli),
  karena router asli merespons protokol-protokol itu secara native.
- Proses ini bisa memakan waktu (Nmap default scan seluruh 256 nomor
  protokol IP), jadi timeout diberi lebih longgar dibanding port scan.
"""

import re
import shutil
import subprocess

# Nomor protokol IP yang relevan dengan cakupan MikroTik (referensi skripsi)
IP_PROTOCOLS = {
    1: "ICMP",
    2: "Multicast | IGMP",
    4: "IPIP encapsulation",
    41: "IPv6 (encapsulation)",
    46: "RSVP TE tunnels",
    47: "General Routing Encapsulation (GRE) - dipakai PPTP & EoIP",
    50: "Encapsulating Security Payload (ESP)",
    51: "Authentication Header (AH)",
    89: "OSPF routing protocol",
    103: "Multicast | PIM",
    112: "VRRP",
}

_LINE_RE = re.compile(r"^(\d+)\s+(open|closed|filtered|open\|filtered)\s+(\S+)")


def is_available() -> bool:
    """Cek apakah binary nmap ada di PATH."""
    return shutil.which("nmap") is not None


def scan_ip_protocols(ip: str, timeout_s: int = 90) -> dict:
    """Jalankan `nmap -sO` ke target dan kembalikan hasil terstruktur.

    Return dict:
      {
        "supported": bool,          # False kalau nmap tidak ada / gagal total
        "requires_root": bool,      # True kalau gagal karena bukan root
        "error": str | None,
        "results": [ {protocol, name, status}, ... ]  # hanya protokol di IP_PROTOCOLS
      }
    """
    if not is_available():
        return {
            "supported": False,
            "requires_root": False,
            "error": "Binary 'nmap' tidak ditemukan di sistem. Install dengan: sudo apt install nmap",
            "results": [],
        }

    proto_list = ",".join(str(p) for p in IP_PROTOCOLS)
    cmd = ["nmap", "-sO", "-p", proto_list, "--host-timeout", f"{timeout_s}s", ip]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 15,
        )
    except FileNotFoundError:
        return {
            "supported": False,
            "requires_root": False,
            "error": "Binary 'nmap' tidak ditemukan di sistem.",
            "results": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "supported": False,
            "requires_root": False,
            "error": f"Nmap IP protocol scan melebihi batas waktu ({timeout_s}s).",
            "results": [],
        }

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")

    if "requires root privileges" in output.lower() or "you requires root privileges" in output.lower():
        return {
            "supported": False,
            "requires_root": True,
            "error": "IP protocol scan (-sO) butuh raw socket, jalankan app.py dengan sudo.",
            "results": [],
        }

    parsed = {}
    for line in output.splitlines():
        m = _LINE_RE.match(line.strip())
        if m:
            proto_num = int(m.group(1))
            status = m.group(2)
            if proto_num in IP_PROTOCOLS:
                parsed[proto_num] = status

    if not parsed:
        return {
            "supported": True,
            "requires_root": False,
            "error": "Nmap berjalan tapi tidak ada baris hasil yang terbaca (lihat raw_output).",
            "results": [],
            "raw_output": output.strip()[-2000:],
        }

    results = [
        {"protocol": p, "name": IP_PROTOCOLS[p], "status": parsed.get(p, "unknown")}
        for p in sorted(IP_PROTOCOLS)
    ]
    return {"supported": True, "requires_root": False, "error": None, "results": results}
