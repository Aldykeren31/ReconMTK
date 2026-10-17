#!/usr/bin/env bash
# ==========================================================
# Script pembantu instalasi & menjalankan ReconMTK
# di Kali Linux (termasuk Kali Linux yang berjalan via UTM)
# ==========================================================
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[*] Membuat virtual environment Python..."
    python3 -m venv venv
fi

echo "[*] Mengaktifkan virtual environment..."
source venv/bin/activate

echo "[*] Menginstal dependensi (Flask, reportlab)..."
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo ""
echo "[*] Menjalankan ReconMTK Web GUI..."
echo "[*] Buka browser ke: http://127.0.0.1:5000"
echo ""
python3 app.py
