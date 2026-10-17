#!/usr/bin/env python3
"""
Dummy MikroTik Target Server
===============================
Server tiruan yang membuka port-port layanan khas MikroTik dan mengirim
banner mirip RouterOS asli. Berguna untuk MENGUJI ReconMTK secara lokal
di satu mesin Kali Linux saja, tanpa perlu membuat VM MikroTik CHR
terpisah.

CATATAN PENTING:
- Ini BUKAN RouterOS asli, cuma tiruan banner untuk keperluan uji fungsi
  tool (memastikan port scanning, banner grabbing, dan pencocokan CVE
  berjalan benar). Untuk laporan resmi skripsi, tetap gunakan target
  MikroTik CHR atau RB951 asli sebagai real case.
- Secara default hanya mendengarkan di 127.0.0.1 (localhost) supaya
  tidak "menipu" perangkat lain di jaringan. Gunakan --bind 0.0.0.0
  hanya jika sengaja ingin diakses dari VM lain (mis. Kali & CHR
  terpisah) dalam jaringan privat yang sama.

DUA PROFIL PORT:
- --profile core (default): 9 port fokus penelitian yang sama persis
  dengan MIKROTIK_PORTS pada modules/port_scanner.py. Tool utama
  (app.py) tetap hanya memindai 9 port ini -- TIDAK berubah.
- --profile extended: menambahkan seluruh port TCP tambahan dari
  referensi port default MikroTik (FTP-data, DNS, BGP, LDP, SOCKS,
  PPTP, UPnP, OpenFlow, HTTP-proxy, dst). Profil ini dipakai KHUSUS
  untuk bagian simulasi cakupan-luas di BAB IV (di luar tool utama),
  bukan pengganti 9 port fokus penelitian.

CAKUPAN YANG SENGAJA TIDAK DISIMULASIKAN (dan alasannya, untuk BAB IV):
1. Port UDP (53,67,68,123,161,500,520,521,546,547,646,1698,1699,1701,
   1900,5246,5247,5350,5351,5678,20561, dst.) -- bisa diaktifkan lewat
   --with-udp, TAPI hanya sebagai listener pasif (server menjawab satu
   payload generik ketika menerima datagram). Ini BUKAN implementasi
   protokol asli (mis. bukan resolver DNS sungguhan, bukan DHCP server
   sungguhan) -- murni supaya socket UDP-nya "hidup" untuk keperluan
   demonstrasi scanning UDP dengan tool eksternal (mis. nmap -sU).
   port_scanner.py pada tool utama TIDAK melakukan UDP scan (connect()
   berbasis TCP), jadi hasil scan UDP harus didemonstrasikan terpisah
   (mis. via nmap) dan dituliskan sebagai temuan tambahan, bukan lewat
   dashboard ReconMTK.
2. Nomor protokol IP (/1 ICMP, /2 IGMP, /4 IPIP, /41 IPv6, /46 RSVP,
   /47 GRE, /50 ESP, /51 AH, /89 OSPF, /103 PIM, /112 VRRP) -- ini
   BUKAN port TCP/UDP sama sekali, melainkan nomor protokol pada layer
   IP. Simulasinya membutuhkan raw socket (SOCK_RAW) + hak akses root,
   dan termasuk kategori pemindaian yang berbeda total dari port
   scanning biasa (setara mode -sO pada Nmap / IP protocol scan).
   Server Python berbasis socket TCP/UDP standar seperti skrip ini
   tidak bisa dan tidak akan meniru layer ini. Jika bagian ini tetap
   ingin dimasukkan ke laporan, sebaiknya didekati sebagai keterbatasan
   penelitian (bukan sesuatu yang perlu dipaksakan disimulasikan).

Cara pakai:
    python3 dummy_mikrotik_target.py
    python3 dummy_mikrotik_target.py --profile extended
    python3 dummy_mikrotik_target.py --profile extended --with-udp
    python3 dummy_mikrotik_target.py --version 7.15.3
    python3 dummy_mikrotik_target.py --bind 0.0.0.0

Lalu di terminal lain / dashboard ReconMTK, scan ke 127.0.0.1
(atau IP bind yang dipilih). Untuk port di luar 9 port fokus (profil
extended) dan untuk UDP, gunakan nmap langsung sebagai pembanding,
mis.:
    nmap -sT -p 20,21,22,23,53,80,179,443,646,1080,1723,2000,2828,6343,8080,8291,8728,8729 127.0.0.1
    nmap -sU -p 53,67,123,161,500,1701,1900,5678 127.0.0.1
"""

import argparse
import socket
import threading
import time


# ---------------------------------------------------------------------------
# Handler TCP
# ---------------------------------------------------------------------------

def handle_ssh(conn, version):
    try:
        conn.sendall(b"SSH-2.0-ROSSSH\r\n")
        time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


def handle_telnet(conn, version):
    try:
        banner = f"\r\nMikroTik v{version} (stable)\r\n\r\nLogin: "
        conn.sendall(banner.encode())
        time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


def handle_http(conn, version, https=False, proxy=False):
    try:
        conn.recv(1024)  # baca request masuk (diabaikan isinya)
        title = "HTTP Web Proxy" if proxy else f"RouterOS {version}"
        body_label = "Web proxy aktif" if proxy else f"Webfig - MikroTik RouterOS {version} login"
        body = f"<html><head><title>{title}</title></head><body>{body_label}</body></html>"
        server_header = "mikrotik-httpproxy" if proxy else f"mikrotik-httpd/{version}"
        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {server_header}\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        conn.sendall(response.encode())
    except Exception:
        pass
    finally:
        conn.close()


def handle_winbox(conn, version):
    try:
        # Winbox pakai protokol biner tertutup; cukup kirim beberapa byte
        # acak sebagai indikasi "port aktif merespons".
        conn.sendall(bytes.fromhex("4d320001"))
        time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


def handle_api(conn, version):
    try:
        conn.sendall(b"\x05!trap\x03=message=invalid")
        time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


def handle_generic_ftp(conn, version):
    try:
        conn.sendall(b"220 dummy-ftp ready\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def handle_ftp_data(conn, version):
    # Port 20 (FTP data) pada koneksi pasif normal tidak mengirim banner
    # teks; server hanya membuka & menutup koneksi data. Kita tiru
    # perilaku itu (accept lalu close tanpa payload) supaya port terlihat
    # "terbuka" untuk keperluan port scanning, tanpa banner palsu yang
    # menyesatkan.
    try:
        time.sleep(0.05)
    finally:
        conn.close()


def handle_silent(conn, version):
    """Untuk layanan yang secara alami TIDAK mengirim banner otomatis saat
    TCP connect (mis. DNS-over-TCP, BGP, LDP, PPTP, OpenFlow) -- server
    asli menunggu pesan pertama dari klien. Kita tiru dengan menerima
    koneksi lalu menutupnya tanpa payload, supaya port tetap terdeteksi
    'open' oleh port scanner tanpa memalsukan protokol handshake yang
    kompleks."""
    try:
        conn.settimeout(0.3)
        try:
            conn.recv(64)
        except Exception:
            pass
    finally:
        conn.close()


def handle_socks(conn, version):
    try:
        conn.settimeout(0.5)
        data = conn.recv(64)
        # Balasan SOCKS5 generik: versi 5, metode auth 'no auth' (0x00)
        if data and data[0:1] == b"\x05":
            conn.sendall(b"\x05\x00")
        else:
            conn.sendall(b"\x00\x5b")  # penolakan SOCKS4-style generik
    except Exception:
        pass
    finally:
        conn.close()


def handle_bandwidth_test(conn, version):
    try:
        conn.sendall(b"\x00\x00\x00\x00")
        time.sleep(0.05)
    except Exception:
        pass
    finally:
        conn.close()


TCP_HANDLERS = {
    # --- profil "core": 9 port fokus penelitian (sama dgn port_scanner.py) ---
    21: ("FTP", handle_generic_ftp, "core"),
    22: ("SSH", handle_ssh, "core"),
    23: ("Telnet", handle_telnet, "core"),
    80: ("Webfig HTTP", lambda c, v: handle_http(c, v, https=False), "core"),
    443: ("Webfig HTTPS (banner only, tanpa TLS asli)", lambda c, v: handle_http(c, v, https=True), "core"),
    2000: ("Bandwidth Test", handle_bandwidth_test, "core"),
    8291: ("Winbox", handle_winbox, "core"),
    8728: ("API", handle_api, "core"),
    8729: ("API-SSL", handle_api, "core"),

    # --- profil "extended": port TCP tambahan dari daftar referensi ---
    20: ("FTP data connection", handle_ftp_data, "extended"),
    53: ("DNS (TCP)", handle_silent, "extended"),
    179: ("Border Gateway Protocol (BGP)", handle_silent, "extended"),
    646: ("LDP transport session", handle_silent, "extended"),
    1080: ("SOCKS proxy protocol", handle_socks, "extended"),
    1723: ("Point-To-Point Tunneling Protocol (PPTP)", handle_silent, "extended"),
    1966: ("MME gateway protocol", handle_silent, "extended"),
    2828: ("Universal Plug and Play (uPnP)", handle_silent, "extended"),
    6343: ("Default OpenFlow port", handle_silent, "extended"),
    8080: ("HTTP Web Proxy", lambda c, v: handle_http(c, v, proxy=True), "extended"),
}


# ---------------------------------------------------------------------------
# Handler UDP (opsional, --with-udp, hanya untuk profil extended)
# ---------------------------------------------------------------------------

UDP_SERVICES = {
    53: "DNS",
    67: "Bootstrap protocol atau DHCP Server",
    68: "Bootstrap protocol atau DHCP Client",
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


def serve_udp(bind_ip, port, name):
    """Listener UDP pasif generik -- BUKAN implementasi protokol asli.
    Hanya membalas datagram apa pun dengan payload penanda singkat,
    supaya port terdeteksi 'open' oleh UDP scanner eksternal (mis.
    nmap -sU). Lihat catatan keterbatasan di docstring atas file ini."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind((bind_ip, port))
        print(f"  [+] UDP {port:<5} ({name}) siap menerima datagram (listener pasif, bukan protokol asli)")
        while True:
            try:
                data, addr = srv.recvfrom(2048)
                print(f"      -> datagram UDP masuk dari {addr[0]}:{addr[1]} ke port {port}")
                srv.sendto(b"\x00", addr)
            except Exception:
                continue
    except PermissionError:
        print(f"  [!] Gagal bind UDP {port}: butuh izin root untuk port < 1024 (coba sudo, atau lewati port ini)")
    except OSError as exc:
        print(f"  [!] Gagal bind UDP {port}: {exc}")


# ---------------------------------------------------------------------------
# Server loop TCP
# ---------------------------------------------------------------------------

def serve_port(bind_ip, port, name, handler, version):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, port))
        srv.listen(5)
        print(f"  [+] Port {port:<5} ({name}) siap menerima koneksi")
        while True:
            conn, addr = srv.accept()
            print(f"      -> koneksi masuk dari {addr[0]}:{addr[1]} ke port {port}")
            threading.Thread(target=handler, args=(conn, version), daemon=True).start()
    except PermissionError:
        print(f"  [!] Gagal bind port {port}: butuh izin root untuk port < 1024 (coba sudo, atau lewati port ini)")
    except OSError as exc:
        print(f"  [!] Gagal bind port {port}: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Dummy MikroTik target server untuk uji coba ReconMTK")
    parser.add_argument("--bind", default="127.0.0.1", help="IP untuk mendengarkan (default: 127.0.0.1)")
    parser.add_argument("--version", default="6.48.6", help="Versi RouterOS palsu yang ditampilkan pada banner (default: 6.48.6)")
    parser.add_argument(
        "--profile",
        choices=["core", "extended"],
        default="core",
        help="'core' = 9 port fokus penelitian (default, sama dengan port_scanner.py). "
             "'extended' = tambahkan seluruh port TCP tambahan untuk simulasi cakupan-luas di BAB IV.",
    )
    parser.add_argument(
        "--with-udp",
        action="store_true",
        help="Sertakan listener UDP pasif untuk port UDP referensi (hanya berlaku efektif jika --profile extended). "
             "Listener ini BUKAN implementasi protokol asli, lihat catatan di docstring file.",
    )
    args = parser.parse_args()

    if args.profile == "core":
        active_ports = {p: v for p, v in TCP_HANDLERS.items() if v[2] == "core"}
    else:
        active_ports = dict(TCP_HANDLERS)

    print("=" * 60)
    print(" Dummy MikroTik Target Server")
    print(f" Bind address : {args.bind}")
    print(f" Versi palsu  : RouterOS {args.version}")
    print(f" Profil port  : {args.profile} ({len(active_ports)} port TCP)")
    if args.profile == "extended" and args.with_udp:
        print(f" UDP pasif    : aktif ({len(UDP_SERVICES)} port)")
    elif args.with_udp and args.profile != "extended":
        print(" UDP pasif    : diminta tapi diabaikan (--with-udp hanya berlaku di --profile extended)")
    print("=" * 60)
    print("Tekan CTRL+C untuk berhenti.\n")

    threads = []
    for port, (name, handler, _profile) in sorted(active_ports.items()):
        t = threading.Thread(target=serve_port, args=(args.bind, port, name, handler, args.version), daemon=True)
        t.start()
        threads.append(t)

    if args.profile == "extended" and args.with_udp:
        for port, name in sorted(UDP_SERVICES.items()):
            t = threading.Thread(target=serve_udp, args=(args.bind, port, name), daemon=True)
            t.start()
            threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDihentikan.")


if __name__ == "__main__":
    main()
