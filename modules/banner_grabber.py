"""
Modul Banner Grabbing & Service Enumeration (Fase 2: Enumeration)
===================================================================
Untuk setiap port yang terbukti terbuka, modul ini membangun koneksi
singkat guna menarik banner/response layanan dan, jika memungkinkan,
mengekstrak versi RouterOS yang berjalan pada target.

Teknik per-layanan:
- SSH (22)      : baca baris identifikasi protokol SSH yang otomatis
                  dikirim server saat handshake (mis. "SSH-2.0-ROSSSH").
- Telnet (23)   : baca banner awal yang biasanya memuat "RouterOS".
- HTTP/S (80/443): kirim GET, baca header Server & body login page.
- Winbox (8291) : baca beberapa byte awal (protokol biner MikroTik).
- API (8728/8729): baca respons awal handshake API.

CATATAN ARSITEKTUR (versi asynchronous):
Versi sebelumnya memproses port satu per satu (sekuensial) memakai
socket blocking. Layanan yang tidak mengirim banner otomatis saat
koneksi dibuka (mis. Winbox 8291, API 8728, API-SSL 8729) membuat
`recv()` menunggu sampai timeout habis (2 detik per port), sehingga
waktu total menumpuk menjadi jumlah seluruh timeout (sekitar 6 detik
pada RB951). Versi ini memakai `asyncio`: seluruh port diproses
bersamaan (non-blocking), sehingga waktu total mendekati timeout
terlama, bukan jumlah semua timeout.

Antarmuka publik `grab_all(ip, open_ports, progress_cb)` dan
`summarize_version(results)` TIDAK berubah, sehingga scanner_engine.py
tidak perlu dimodifikasi. Urutan hasil tetap sama dengan urutan
`open_ports`.
"""

import asyncio
import os
import re
import ssl
import threading
from contextlib import asynccontextmanager

ROUTEROS_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

def _versi_masuk_akal(v: str) -> bool:
    """Versi mayor RouterOS berada di rentang 2..7. Menolak angka lain,
    mis. '1.1' yang berasal dari teks 'HTTP/1.1'."""
    try:
        return 2 <= int(v.split(".")[0]) <= 7
    except ValueError:
        return False


# Batas jumlah koneksi banner grabbing yang berjalan bersamaan.
# Cukup besar untuk profil full scan (belasan port TCP); atur 1 untuk
# meniru perilaku sekuensial versi lama (berguna untuk pembandingan).
DEFAULT_MAX_CONCURRENCY = 50


# ---------------------------------------------------------------------------
# Utilitas koneksi async
# ---------------------------------------------------------------------------

def _err(exc: Exception) -> str:
    """Teks error yang konsisten dengan versi socket blocking."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out"
    if isinstance(exc, OSError) and exc.errno:
        return f"[Errno {exc.errno}] {os.strerror(exc.errno)}"
    return str(exc) or type(exc).__name__


@asynccontextmanager
async def _connect(ip: str, port: int, timeout_s: float, ssl_ctx=None):
    """Buka koneksi TCP (opsional TLS) dengan batas waktu, dan pastikan
    koneksi ditutup saat keluar dari blok `async with`."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout_s
    )
    try:
        yield reader, writer
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 0.5)
        except Exception:
            pass


async def _recv_banner(reader: asyncio.StreamReader, num_bytes: int = 256,
                       timeout_s: float = 2.0) -> bytes:
    """Baca maksimal `num_bytes`; kembalikan b"" jika timeout/error."""
    try:
        return await asyncio.wait_for(reader.read(num_bytes), timeout_s)
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Grabber per layanan (seluruhnya coroutine)
# ---------------------------------------------------------------------------

async def grab_ssh(ip: str, port: int = 22, timeout_s: float = 2.0) -> dict:
    info = {"port": port, "service": "SSH", "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, _writer):
            data = (await _recv_banner(reader, 256, timeout_s)).decode(errors="ignore").strip()
            info["banner"] = data
            if "ROSSSH" in data or "MikroTik" in data:
                info["routeros_version"] = "terindikasi RouterOS (ROSSSH)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_telnet(ip: str, port: int = 23, timeout_s: float = 2.0) -> dict:
    info = {"port": port, "service": "Telnet", "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, _writer):
            data = (await _recv_banner(reader, 512, timeout_s)).decode(errors="ignore").strip()
            info["banner"] = data
            if "RouterOS" in data or "MikroTik" in data:
                match = ROUTEROS_VERSION_RE.search(data)
                if match and _versi_masuk_akal(match.group(1)):
                    info["routeros_version"] = match.group(1)
                else:
                    info["routeros_version"] = "terdeteksi (versi tidak terbaca)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_http(ip: str, port: int = 80, use_ssl: bool = False, timeout_s: float = 2.5) -> dict:
    service_name = "Webfig (HTTPS)" if use_ssl else "Webfig (HTTP)"
    info = {"port": port, "service": service_name, "banner": "", "routeros_version": None, "server_header": None}
    try:
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        async with _connect(ip, port, timeout_s, ctx) as (reader, writer):
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\nUser-Agent: ReconTool/1.0\r\n\r\n"
            writer.write(request.encode())
            await asyncio.wait_for(writer.drain(), timeout_s)

            chunks = []
            total = 0
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(2048), timeout_s)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 8192:
                        break
            except asyncio.TimeoutError:
                pass  # server tidak menutup koneksi: pakai data yang sudah diterima

        raw = b"".join(chunks).decode(errors="ignore")
        info["banner"] = raw[:400]

        server_match = re.search(r"Server:\s*([^\r\n]+)", raw, re.IGNORECASE)
        if server_match:
            info["server_header"] = server_match.group(1).strip()

        if "MikroTik" in raw or "RouterOS" in raw or "webfig" in raw.lower():
            version_match = re.search(r"RouterOS\s*(?:v)?(\d+\.\d+(?:\.\d+)?)", raw, re.IGNORECASE)
            if not version_match:
                # Cadangan: cari pola versi di header & isi halaman, tetapi BUANG
                # baris status ("HTTP/1.1 200 OK") agar '1.1' tidak terbaca sebagai versi.
                sisa = raw.split("\r\n", 1)[1] if "\r\n" in raw else raw
                version_match = ROUTEROS_VERSION_RE.search(sisa)
            if version_match and _versi_masuk_akal(version_match.group(1)):
                info["routeros_version"] = version_match.group(1)
            else:
                info["routeros_version"] = "terdeteksi (versi tidak terbaca)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_winbox(ip: str, port: int = 8291, timeout_s: float = 2.0) -> dict:
    info = {"port": port, "service": "Winbox", "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, _writer):
            data = await _recv_banner(reader, 64, timeout_s)
            info["banner"] = data.hex()
            # Protokol Winbox bersifat biner tertutup; keberadaan respons
            # apapun pada port ini sudah menjadi indikator kuat perangkat
            # MikroTik (fingerprint berbasis port, bukan versi eksplisit).
            info["routeros_version"] = "port aktif (indikasi MikroTik, versi via Winbox tidak diekstrak)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_api(ip: str, port: int = 8728, timeout_s: float = 2.0) -> dict:
    service_name = "API-SSL" if port == 8729 else "API"
    info = {"port": port, "service": service_name, "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, _writer):
            data = await _recv_banner(reader, 32, timeout_s)
            info["banner"] = data.hex()
            info["routeros_version"] = "port API aktif (indikasi MikroTik)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_generic(ip: str, port: int, service: str, timeout_s: float = 1.5) -> dict:
    """Grabber generik untuk layanan yang tidak mengirim banner teks
    otomatis saat connect (mis. BGP, LDP, PPTP, uPnP, OpenFlow, DNS-TCP).
    Sekadar membuka koneksi & mencoba baca beberapa byte pasif -- kalau
    tidak ada apa-apa dalam batas waktu, itu normal untuk layanan ini
    (bukan berarti gagal), jadi cukup ditandai 'port aktif merespons'."""
    info = {"port": port, "service": service, "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, _writer):
            data = await _recv_banner(reader, 128, timeout_s)
            info["banner"] = data.hex() if data else "(tidak ada banner otomatis -- normal untuk layanan ini)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_socks(ip: str, port: int = 1080, timeout_s: float = 2.0) -> dict:
    info = {"port": port, "service": "SOCKS proxy", "banner": "", "routeros_version": None}
    try:
        async with _connect(ip, port, timeout_s) as (reader, writer):
            # Kirim SOCKS5 greeting: versi 5, 1 metode, "no auth"
            writer.write(b"\x05\x01\x00")
            await asyncio.wait_for(writer.drain(), timeout_s)
            data = await _recv_banner(reader, 8, timeout_s)
            info["banner"] = data.hex()
            if data[:1] == b"\x05":
                info["routeros_version"] = "port aktif, merespons handshake SOCKS5 (indikasi MikroTik)"
    except Exception as exc:
        info["error"] = _err(exc)
    return info


async def grab_ftp(ip: str, timeout_s: float = 2.0) -> dict:
    # FTP (21) sengaja tidak ditarik banner-nya (hanya penanda layanan).
    return {"port": 21, "service": "FTP", "banner": "", "routeros_version": None}


def _generic(port: int, service: str, default_timeout: float = 1.5):
    return lambda ip, timeout_s=default_timeout: grab_generic(ip, port, service, timeout_s)


def _http(port: int, use_ssl: bool, default_timeout: float = 2.5):
    return lambda ip, timeout_s=default_timeout: grab_http(ip, port, use_ssl=use_ssl, timeout_s=timeout_s)


def _api(port: int, default_timeout: float = 2.0):
    return lambda ip, timeout_s=default_timeout: grab_api(ip, port, timeout_s=timeout_s)


GRABBERS = {
    # --- profil "core" ---
    21: grab_ftp,
    22: grab_ssh,
    23: grab_telnet,
    80: _http(80, use_ssl=False),
    443: _http(443, use_ssl=True),
    2000: _generic(2000, "Bandwidth Test"),
    8291: grab_winbox,
    8728: _api(8728),
    8729: _api(8729),

    # --- profil "extended" ---
    20: _generic(20, "FTP data connection"),
    53: _generic(53, "DNS (TCP)"),
    179: _generic(179, "BGP"),
    646: _generic(646, "LDP"),
    1080: grab_socks,
    1723: _generic(1723, "PPTP"),
    1966: _generic(1966, "MME gateway protocol"),
    2828: _generic(2828, "uPnP"),
    6343: _generic(6343, "OpenFlow"),
    8080: _http(8080, use_ssl=False),
}


# ---------------------------------------------------------------------------
# Orkestrasi: seluruh port diproses bersamaan
# ---------------------------------------------------------------------------

async def grab_all_async(ip: str, open_ports: list, progress_cb=None,
                         max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> list:
    """Versi coroutine: jalankan banner grabbing seluruh port secara
    bersamaan. Urutan hasil sama dengan urutan `open_ports`."""
    sem = asyncio.Semaphore(max(1, int(max_concurrency)))

    async def _one(port: int) -> dict:
        grabber = GRABBERS.get(port)
        if grabber:
            async with sem:
                res = await grabber(ip)
        else:
            res = {"port": port, "service": "Unknown", "banner": "", "routeros_version": None}
        if progress_cb:
            progress_cb(res)
        return res

    return list(await asyncio.gather(*(_one(p) for p in open_ports)))


def grab_all(ip: str, open_ports: list, progress_cb=None,
             max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> list:
    """Jalankan banner grabbing untuk seluruh port yang berstatus open.

    Antarmuka sinkron (sama seperti versi lama) agar scanner_engine.py
    tidak perlu diubah. Di dalamnya, seluruh port diproses secara
    asynchronous. `progress_cb` dipanggil setiap satu port selesai
    (urutan pemanggilan = urutan selesai, bukan urutan `open_ports`).
    """
    coro = grab_all_async(ip, open_ports, progress_cb, max_concurrency)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # Thread ini sudah punya event loop aktif (mis. dipanggil dari
    # lingkungan async): jalankan di thread terpisah agar tidak bentrok.
    box = {}

    def _worker():
        try:
            box["result"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 - diteruskan ke pemanggil
            box["error"] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["result"]


def summarize_version(banner_results: list):
    """Ambil satu kandidat versi RouterOS paling meyakinkan dari seluruh
    hasil banner grabbing (mengutamakan hasil berformat angka versi)."""
    candidates = [r.get("routeros_version") for r in banner_results if r.get("routeros_version")]
    for c in candidates:
        if re.match(r"^\d+\.\d+", c or ""):
            return c
    return candidates[0] if candidates else None
