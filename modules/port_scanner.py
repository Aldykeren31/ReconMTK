"""
Modul Port Scanner (Fase 1: Footprinting)
==========================================
Memindai port-port layanan manajemen bawaan MikroTik sesuai cakupan
skripsi: Winbox (8291), Webfig/HTTP (80), HTTPS (443), SSH (22),
Telnet (23), API (8728) dan API-SSL (8729).

Tiga profil port didukung:
- "core"     : 9 port TCP fokus utama penelitian (BAB III) -- default,
               perilaku sama seperti sebelumnya, tidak berubah.
- "extended" : core + port TCP tambahan (FTP-data, DNS-TCP, BGP, LDP,
               SOCKS, PPTP, uPnP, OpenFlow, HTTP-proxy, MME) untuk
               simulasi cakupan lebih luas di BAB IV.
- "extended_udp" : sama seperti "extended", ditambah pemindaian UDP
               (DNS, DHCP, NTP, SNMP, IKE, RIP, DHCPv6, LDP-hello,
               RSVP-TE, L2TP, SSDP, CAPsMAN, NAT-PMP, MNDP, MAC-Winbox).

Semua profil di atas cocok dipasangkan dengan
scripts/dummy_mikrotik_target.py (gunakan --profile extended --with-udp
untuk profil "extended_udp").

CATATAN KETERBATASAN (masih berlaku, lihat juga BAB IV):
Nomor protokol IP (mis. /1 ICMP, /47 GRE, /89 OSPF) TIDAK dicakup oleh
scanner ini. Itu bukan port TCP/UDP sama sekali, melainkan pemindaian
pada layer IP (setara Nmap -sO) yang butuh raw socket + akses root, dan
secara teknik sepenuhnya berbeda dari port scanning. Bisa didemonstrasikan
terpisah lewat `nmap -sO <target>` bila diperlukan untuk laporan.

Teknik UDP scan yang dipakai di sini mengikuti pendekatan standar Nmap:
- Kirim probe UDP kosong ke port target.
- Kalau ada balasan apa pun dalam batas waktu -> "open".
- Kalau OS mengirim balik ICMP "port unreachable" (muncul sebagai
  ConnectionRefusedError di Python saat socket "connected") -> "closed".
- Kalau tidak ada balasan sama sekali dalam batas waktu -> "open|filtered"
  (ambigu; ini keterbatasan UDP scanning pada umumnya, bukan bug -- MikroTik
  yang firewall-nya drop paket tanpa balasan akan selalu tampil begini).
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Port bawaan MikroTik yang menjadi fokus utama penelitian (BAB III)
MIKROTIK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "Webfig (HTTP)",
    443: "Webfig (HTTPS)",
    2000: "Bandwidth Test",
    8291: "Winbox",
    8728: "API",
    8729: "API-SSL",
}

# Port TCP tambahan untuk profil "extended" (simulasi cakupan luas BAB IV)
EXTENDED_PORTS = {
    20: "FTP data connection",
    53: "DNS (TCP)",
    179: "Border Gateway Protocol (BGP)",
    646: "LDP transport session",
    1080: "SOCKS proxy protocol",
    1723: "Point-To-Point Tunneling Protocol (PPTP)",
    1966: "MME gateway protocol",
    2828: "Universal Plug and Play (uPnP)",
    6343: "Default OpenFlow port",
    8080: "HTTP Web Proxy",
}

# Port UDP untuk profil "extended_udp"
EXTENDED_UDP_PORTS = {
    53: "DNS",
    67: "Bootstrap protocol / DHCP Server",
    68: "Bootstrap protocol / DHCP Client",
    123: "Network Time Protocol (NTP)",
    161: "Simple Network Management Protocol (SNMP)",
    500: "Internet Key Exchange (IKE) protocol",
    520: "RIP (unlabeled)",
    521: "RIP routing protocol",
    546: "DHCPv6 Client message",
    547: "DHCPv6 Server message",
    646: "LDP hello protocol",
    1698: "RSVP TE Tunnels",
    1699: "RSVP TE Tunnels",
    1701: "Layer 2 Tunnel Protocol (L2TP)",
    1900: "uPnP discovery (SSDP)",
    1966: "MME originator message traffic",
    5246: "CAPsMAN",
    5247: "CAPsMAN",
    5350: "NAT-PMP client",
    5351: "NAT-PMP server",
    5678: "Mikrotik Neighbor Discovery Protocol",
    20561: "MAC winbox",
}


def get_port_set(profile: str = "core") -> dict:
    """Kembalikan dict {port: nama_layanan} untuk port TCP sesuai profil."""
    if profile in ("extended", "extended_udp"):
        merged = dict(MIKROTIK_PORTS)
        merged.update(EXTENDED_PORTS)
        return merged
    return dict(MIKROTIK_PORTS)


def get_udp_port_set(profile: str = "core") -> dict:
    """Kembalikan dict {port: nama_layanan} untuk port UDP (kosong kecuali profil extended_udp)."""
    if profile == "extended_udp":
        return dict(EXTENDED_UDP_PORTS)
    return {}


def scan_port(ip: str, port: int, timeout_s: float = 1.0, port_labels: dict = None) -> dict:
    """Lakukan TCP connect scan pada satu port."""
    port_labels = port_labels or MIKROTIK_PORTS
    started = time.time()
    status = "closed"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_s)
            result = s.connect_ex((ip, port))
            status = "open" if result == 0 else "closed"
    except socket.gaierror:
        status = "error"
    except Exception:
        status = "error"
    return {
        "port": port,
        "protocol": "tcp",
        "service": port_labels.get(port, "Unknown"),
        "status": status,
        "latency_ms": round((time.time() - started) * 1000, 1),
    }


def scan_udp_port(ip: str, port: int, timeout_s: float = 1.2, port_labels: dict = None) -> dict:
    """Lakukan UDP scan pada satu port (pendekatan standar ala Nmap -sU).

    Batasan yang perlu dipahami: banyak layanan UDP tidak membalas probe
    kosong (mis. NTP/SNMP butuh payload valid), sehingga hasil "open|filtered"
    SANGAT umum dan bukan berarti scan gagal -- itu memang sifat UDP scanning.
    """
    port_labels = port_labels or {}
    started = time.time()
    status = "open|filtered"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout_s)
            s.connect((ip, port))
            try:
                s.send(b"")
            except OSError:
                pass
            try:
                s.recv(512)
                status = "open"
            except socket.timeout:
                status = "open|filtered"
            except ConnectionRefusedError:
                status = "closed"
    except socket.gaierror:
        status = "error"
    except Exception:
        status = "error"
    return {
        "port": port,
        "protocol": "udp",
        "service": port_labels.get(port, "Unknown"),
        "status": status,
        "latency_ms": round((time.time() - started) * 1000, 1),
    }


def scan_target(ip: str, ports=None, max_workers: int = 16, progress_cb=None, profile: str = "core") -> list:
    """Pindai seluruh port target pada satu IP secara paralel (threaded).

    `profile`: "core" (9 port fokus, default), "extended" (+ port TCP
    tambahan), atau "extended_udp" (+ port TCP tambahan + port UDP).
    """
    tcp_labels = get_port_set(profile)
    tcp_ports = ports or list(tcp_labels.keys())
    udp_labels = get_udp_port_set(profile)
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for p in tcp_ports:
            futures[executor.submit(scan_port, ip, p, 1.0, tcp_labels)] = ("tcp", p)
        for p in udp_labels:
            futures[executor.submit(scan_udp_port, ip, p, 1.2, udp_labels)] = ("udp", p)

        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            if progress_cb:
                progress_cb(res)

    results.sort(key=lambda r: (r["port"], r["protocol"]))
    return results
