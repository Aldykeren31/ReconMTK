# ReconMTK &mdash; Automated Reconnaissance Tool untuk Router MikroTik

Implementasi program untuk Tugas Akhir Skripsi:
**"Pengembangan Automated Reconnaissance Tool Berbasis Python untuk
Pengujian Keamanan Router MikroTik Menggunakan Metodologi PTES"**

Tool ini mengotomasi fase **Intelligence Gathering** (PTES) yang terdiri dari
*Host Discovery* &rarr; *Footprinting* (port scanning) &rarr; *Enumeration*
(banner grabbing) &rarr; pencocokan hasil dengan basis data **CVE**
&rarr; pembuatan **laporan otomatis (PDF)**, sesuai flowchart pada BAB III
dokumen skripsi. Antarmuka berupa **Web GUI** (dashboard) sesuai rancangan
pada bagian 3.8 "Perancangan Antarmuka Pengguna".

> ⚠️ **Etika & Legalitas**: Gunakan tool ini **hanya** pada perangkat/jaringan
> yang Anda miliki sendiri atau yang telah memberi izin eksplisit untuk
> diuji (misalnya topologi lab pengujian skripsi Anda di Laboratorium D
> UKDW dengan Router MikroTik RB951). Memindai perangkat milik pihak lain
> tanpa izin adalah pelanggaran hukum (UU ITE).

---

## 1. Struktur Proyek

```
reconn_tool/
├── app.py                     # Aplikasi Flask (Web GUI + API)
├── run.sh                     # Script instalasi & menjalankan otomatis
├── requirements.txt           # Dependensi Python
├── modules/
│   ├── host_discovery.py      # Fase: Host Discovery (cek router aktif)
│   ├── port_scanner.py        # Fase 1: Footprinting (port scanning)
│   ├── banner_grabber.py      # Fase 2: Enumeration (banner grabbing, asynchronous/asyncio)
│   ├── cve_matcher.py         # Analisis: pencocokan versi vs basis data CVE
│   ├── report_generator.py    # Output: laporan otomatis (PDF)
│   └── scanner_engine.py      # Orkestrator seluruh alur (job/thread)
├── data/
│   └── cve_database.json      # Basis data referensi CVE MikroTik/RouterOS
├── templates/index.html       # Halaman dashboard
├── static/css/style.css       # Desain visual (dark, tema jaringan)
├── static/js/app.js           # Logika frontend (polling, render hasil)
└── reports/                   # Laporan PDF hasil scan akan tersimpan di sini
```

## 2. Instalasi di Kali Linux (via UTM)

Buka **Terminal** di Kali Linux (dalam UTM), lalu jalankan:

```bash
# 1. Ekstrak/salin folder reconn_tool ke home directory
cd ~
unzip ReconMTK.zip        # jika Anda mengunduh dalam bentuk .zip
cd reconn_tool

# 2. Pastikan Python 3 & pip tersedia (biasanya sudah ada di Kali)
python3 --version
sudo apt update && sudo apt install -y python3-pip python3-venv

# 3. Jalankan dengan script otomatis
./run.sh
```

`run.sh` akan otomatis membuat virtual environment, menginstal
`Flask` dan `reportlab`, lalu menjalankan server.

**Alternatif manual** (tanpa script):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Setelah server berjalan, buka browser (di dalam Kali Linux/UTM) ke:

```
http://127.0.0.1:5000
```

## 3. Cara Pakai

1. Pastikan **Attacker PC (Kali Linux)** terhubung dalam satu jaringan
   dengan **Router MikroTik RB951** target, sesuai topologi pengujian
   pada Gambar 3.2 skripsi (Attacker PC &rarr; Switch &rarr; Router).
2. Buka dashboard di browser, masukkan **IP target** pada panel kiri
   (contoh: `192.168.88.1`) atau rentang subnet CIDR (contoh:
   `192.168.88.0/29` untuk memindai beberapa host sekaligus).
3. Klik **"Mulai Reconnaissance"**. Dashboard akan menampilkan progres
   real-time untuk setiap tahap: Host Discovery &rarr; Footprinting
   &rarr; Enumeration &rarr; Analisis CVE &rarr; Laporan.
4. Setelah selesai, klik **"Unduh Laporan PDF"** di kanan atas untuk
   mengunduh laporan teknis otomatis (bisa dilampirkan sebagai bukti
   pengujian pada BAB IV skripsi).

## 4. Port yang Dipindai

Sesuai cakupan BAB III (Analisis Kebutuhan Sistem), tool ini berfokus
pada port layanan manajemen bawaan MikroTik:

| Port | Layanan |
|------|---------|
| 21   | FTP |
| 22   | SSH |
| 23   | Telnet |
| 80   | Webfig (HTTP) |
| 443  | Webfig (HTTPS) |
| 2000 | Bandwidth Test |
| 8291 | Winbox |
| 8728 | API |
| 8729 | API-SSL |

Daftar ini dapat diubah pada `modules/port_scanner.py` (`MIKROTIK_PORTS`).

## 5. Basis Data CVE

File `data/cve_database.json` berisi kurasi manual dari sumber publik
(NVD, VulnCheck, MikroTik Security Advisories) yang relevan dengan
RouterOS. **Sebelum digunakan untuk laporan akhir skripsi**, disarankan
memperbarui/memverifikasi entri ini dari:

- https://mikrotik.com/supportsec (advisori resmi MikroTik)
- https://nvd.nist.gov (National Vulnerability Database)
- https://cve.org

### Skema Atribut (Tabel 3.2)

| Atribut | Tipe Data | Keterangan |
|---|---|---|
| `cve_id` | String (PK) | Kode identifikasi resmi CVE, mis. `"CVE-2023-30799"`. |
| `title` | String | Nama umum/singkat kerentanan. |
| `affected_component` | String | Komponen/layanan MikroTik yang terdampak. |
| `affected_ports` | Array[Integer] | Port yang berkaitan dengan layanan rentan. |
| `version_type` | String | Basis pencocokan versi: `"routeros"` atau `"openssh"`. |
| `affected_version` | String | Rentang versi terdampak. Format: `"<= X"`, `">= X"`, `"X - Y"`, atau gabungan beberapa cabang dipisah `;` (mis. `"stable: 6.27 - 6.49.6; long-term: <= 6.49.7"`). |
| `severity_level` | String | Tingkat keparahan: `Low`, `Medium`, `High`, `Critical`. |
| `vulnerability_type` | String | Kategori serangan, mis. `Privilege Escalation`, `DoS`, `RCE`. |
| `cvss` | Float | Skor CVSS resmi (0.0 &ndash; 10.0). |
| `description` | Text | Penjelasan singkat mekanisme celah keamanan. |
| `mitigation_hint` | Text | Rekomendasi pencegahan/pembaruan versi. |
| `reference` | String (URL) | Tautan sumber referensi resmi. |

Menambah entri baru cukup dengan menambahkan objek baru pada array
`"cves"` mengikuti format di atas &mdash; tidak perlu mengubah kode Python,
selama `affected_version` ditulis sesuai format yang didukung
(`modules/cve_matcher.py`, fungsi `parse_affected_version()`).

### Melihat Jumlah & Menghapus CVE dari Web GUI

- Jumlah CVE yang tercatat tampil di sidebar (**Basis data CVE: N entri**)
  dan diperbarui otomatis setelah ada penghapusan.
- Buka tab **Basis Data CVE** pada panel hasil untuk melihat total entri,
  rincian per severity (Critical/High/Medium/Low), dan daftar
  seluruh CVE.
- Tombol **Hapus** pada tiap baris menghapus satu entri setelah
  konfirmasi. Penghapusan bersifat permanen, tetapi salinan database
  sebelum dihapus disimpan di `data/cve_database.json.bak` (hanya satu
  cadangan terakhir; untuk membatalkan, ganti nama file tersebut menjadi
  `cve_database.json`).
- Endpoint terkait: `GET /api/cve-database/stats` dan
  `DELETE /api/cve-database/<cve_id>`.

## 6. Catatan Teknis

- **Host discovery** mencoba ICMP ping terlebih dahulu, lalu fallback ke
  TCP connect pada beberapa port umum jika ICMP diblokir oleh
  firewall/jaringan target (umum terjadi pada banyak konfigurasi).
- **Deteksi versi RouterOS** diambil dari kombinasi banner SSH/Telnet,
  header/isi respons HTTP Webfig, serta indikasi dari port API/Winbox
  yang aktif. Akurasi versi bergantung pada seberapa banyak informasi
  yang bocor lewat layanan yang terbuka di target.
- **Pencocokan CVE** bersifat *indikatif* (berbasis rentang versi &
  port terbuka) dan **wajib diverifikasi manual** sebelum dijadikan
  simpulan akhir pada laporan skripsi &mdash; sebagaimana lazimnya
  pengujian penetrasi profesional.
- Aplikasi web berjalan secara lokal (`127.0.0.1:5000`) dan tidak
  mengekspos data ke internet.

## 7. Uji Coba Cepat Tanpa Perangkat/VM MikroTik (Dummy Target)

Kalau belum sempat ke lab kampus atau belum sempat setup MikroTik CHR,
kamu bisa uji seluruh alur ReconMTK **langsung di satu Kali Linux saja**
memakai server tiruan `scripts/dummy_mikrotik_target.py`. Script ini
membuka port-port khas MikroTik dan mengirim banner mirip RouterOS asli
(bukan RouterOS sungguhan &mdash; murni untuk uji fungsi tool).

```bash
# Terminal 1: jalankan target tiruan
cd reconn_tool
sudo python3 scripts/dummy_mikrotik_target.py --version 7.15.3
# (sudo diperlukan karena port FTP/Telnet/HTTP/HTTPS < 1024)

# Terminal 2: jalankan ReconMTK seperti biasa
./run.sh
```

Lalu di dashboard, scan target `127.0.0.1`. Hasilnya akan menunjukkan
seluruh 9 port terbuka, versi RouterOS terbaca (`7.15.3` pada contoh di
atas), dan kecocokan CVE yang relevan dengan versi tersebut &mdash; bagus
untuk memvalidasi tool bekerja benar sebelum diuji ke perangkat asli.

**Ini bukan pengganti pengujian resmi** &mdash; untuk BAB IV skripsi, hasil
akhir tetap harus dari MikroTik CHR (virtual) atau RB951 fisik di
Laboratorium D UKDW, karena dummy server ini cuma meniru banner teks,
bukan implementasi RouterOS sungguhan.

## 8. Troubleshooting

- **`ping: not found` / host selalu "tidak aktif"**: pastikan paket
  `iputils-ping` terpasang (`sudo apt install iputils-ping`, biasanya
  sudah default di Kali) dan Attacker PC benar-benar berada dalam
  jaringan yang sama dengan target.
- **Semua port "closed"**: cek firewall RouterOS (`/ip firewall filter`)
  tidak memblokir Attacker PC, dan Winbox/Webfig memang diaktifkan pada
  `/ip service`.
- **Port sudah dipakai (`Address already in use`)**: ubah port Flask di
  baris terakhir `app.py` (`app.run(..., port=5000)`) ke port lain.
