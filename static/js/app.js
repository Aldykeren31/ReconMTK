/* =========================================================
   ReconMTK - app.js (versi sederhana)
   Alur kerjanya cuma 3 langkah:
     1. startScan()  -> kirim target ke server (POST /api/scan)
     2. poll()        -> tanya status tiap ~1 detik (GET /api/scan/<id>)
     3. render*()      -> tampilkan hasil ke HTML
   Tidak ada manipulasi SVG/animasi rumit -- semua elemen di sini
   cuma teks biasa (innerHTML), gampang ditelusuri kalau perlu diubah.
   ========================================================= */
(() => {
  // --- Ambil semua elemen HTML yang akan diubah isinya ---
  const targetInput = document.getElementById("target-input");
  const profileSelect = document.getElementById("profile-select");
  const ipProtocolCheckbox = document.getElementById("ip-protocol-checkbox");
  const scanBtn = document.getElementById("scan-btn");
  const scanError = document.getElementById("scan-error");
  const terminal = document.getElementById("terminal");
  const stagePill = document.getElementById("stage-pill");
  const pageTitle = document.getElementById("page-title");
  const pageSubtitle = document.getElementById("page-subtitle");
  const downloadBtn = document.getElementById("download-report");

  const statusTarget = document.getElementById("status-target");
  const statusHostBadge = document.getElementById("status-host-badge");
  const statusPorts = document.getElementById("status-ports");
  const statusVersion = document.getElementById("status-version");

  const stepperItems = Array.from(document.querySelectorAll("#stepper li"));
  const STAGE_ORDER = ["host", "footprint", "enum", "analysis", "report"];

  // Pemetaan teks "stage" dari server -> id langkah di sidebar
  const stageMap = {
    "Host Discovery (Cek Router Aktif)": "host",
    "Fase 1: Footprinting (Port Scanning)": "footprint",
    "Fase 1.5: IP Protocol Scan (nmap -sO)": "footprint",
    "Fase 2: Enumeration (Banner Grabbing)": "enum",
    "Analisis Hasil (Pencocokan Data CVE)": "analysis",
    "Output: Menyusun Laporan Otomatis": "report",
    "Selesai": "report",
  };

  let pollTimer = null;
  let lastLogCount = 0;

  // --- Toggle Tema Gelap / Terang ---
  const themeToggleBtn = document.getElementById("theme-toggle");
  const savedTheme = localStorage.getItem("reconmtk-theme");
  if (savedTheme === "light") {
    document.body.classList.add("light-mode");
    themeToggleBtn.textContent = "☀ Mode Gelap";
  }
  themeToggleBtn.addEventListener("click", () => {
    const isLight = document.body.classList.toggle("light-mode");
    themeToggleBtn.textContent = isLight ? "☀ Mode Gelap" : "☾ Mode Terang";
    localStorage.setItem("reconmtk-theme", isLight ? "light" : "dark");
  });

  // --- Update daftar langkah di sidebar (checklist 1-5) ---
  function setStage(stageKey, status) {
    const currentIdx = STAGE_ORDER.indexOf(stageKey);
    stepperItems.forEach((li) => {
      const idx = STAGE_ORDER.indexOf(li.dataset.stage);
      li.classList.remove("active", "done", "error");
      if (status === "failed" && idx === currentIdx) {
        li.classList.add("error");
      } else if (idx < currentIdx) {
        li.classList.add("done");
      } else if (idx === currentIdx) {
        li.classList.add("active");
      }
    });
  }

  // --- Tambahkan baris baru ke log terminal ---
  function appendLogLines(logs) {
    const placeholder = terminal.querySelector(".terminal-placeholder");
    if (placeholder && logs.length > 0) placeholder.remove();
    for (let i = lastLogCount; i < logs.length; i++) {
      const entry = logs[i];
      const line = document.createElement("div");
      line.className = "terminal-line";
      line.innerHTML = `<span class="t-time">[${entry.time}]</span>${escapeHtml(entry.message)}`;
      terminal.appendChild(line);
    }
    lastLogCount = logs.length;
    terminal.scrollTop = terminal.scrollHeight;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Render tabel port ---
  function renderPorts(portScan) {
    const tbody = document.querySelector("#ports-table tbody");
    if (!portScan || portScan.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-row">Belum ada data.</td></tr>`;
      return;
    }
    tbody.innerHTML = portScan.map((p) => {
      const isOpen = p.status === "open";
      const isFiltered = p.status === "open|filtered";
      const cls = isOpen ? "open" : isFiltered ? "filtered" : "closed";
      const label = isOpen ? "OPEN" : isFiltered ? "OPEN|FILTERED" : "CLOSED";
      return `
      <tr>
        <td>${p.port}</td>
        <td>${(p.protocol || "tcp").toUpperCase()}</td>
        <td>${escapeHtml(p.service)}</td>
        <td><span class="status-chip ${cls}">${label}</span></td>
      </tr>
    `;
    }).join("");
  }

  // --- Render tabel IP protocol scan (nmap -sO) ---
  function renderIpProtocol(ipProtoResult) {
    const note = document.getElementById("ipproto-note");
    const tbody = document.querySelector("#ipproto-table tbody");
    if (!ipProtoResult) {
      note.textContent = "";
      tbody.innerHTML = `<tr><td colspan="3" class="empty-row">Belum dipindai. Centang "Sertakan IP Protocol Scan" di panel kiri sebelum mulai.</td></tr>`;
      return;
    }
    if (!ipProtoResult.supported || !ipProtoResult.results || ipProtoResult.results.length === 0) {
      note.textContent = ipProtoResult.error || "Tidak ada hasil.";
      tbody.innerHTML = `<tr><td colspan="3" class="empty-row">Tidak ada data (lihat catatan di atas).</td></tr>`;
      return;
    }
    note.textContent = "Dipindai lewat nmap -sO. Status \"open|filtered\" umum terjadi pada UDP/IP-protocol scan bila target tidak membalas.";
    tbody.innerHTML = ipProtoResult.results.map((r) => {
      const cls = r.status === "open" ? "open" : r.status === "open|filtered" ? "filtered" : "closed";
      return `
      <tr>
        <td>/${r.protocol}</td>
        <td>${escapeHtml(r.name)}</td>
        <td><span class="status-chip ${cls}">${escapeHtml(r.status.toUpperCase())}</span></td>
      </tr>
    `;
    }).join("");
  }

  // --- Render daftar hasil enumerasi (banner grabbing) ---
  function renderEnum(bannerGrab) {
    const el = document.getElementById("enum-list");
    if (!bannerGrab || bannerGrab.length === 0) {
      el.innerHTML = `<p class="empty-row">Belum ada data.</p>`;
      return;
    }
    el.innerHTML = bannerGrab.map((b) => `
      <div class="enum-card">
        <div class="enum-card-head">
          <span class="enum-card-title">${escapeHtml(b.service || "Unknown")}</span>
          <span class="enum-card-port">port ${b.port}</span>
        </div>
        ${b.banner ? `<div class="enum-card-banner">${escapeHtml(b.banner).slice(0, 300)}</div>` : ""}
        ${b.routeros_version ? `<div class="enum-card-version">${escapeHtml(b.routeros_version)}</div>` : ""}
      </div>
    `).join("");
  }

  // --- Render daftar kerentanan CVE yang cocok ---
  function renderCve(cveMatches) {
    const el = document.getElementById("cve-list");
    if (!cveMatches || cveMatches.length === 0) {
      el.innerHTML = `<p class="empty-row">Belum ada kecocokan CVE.</p>`;
      return;
    }
    el.innerHTML = cveMatches.map((c) => {
      const sev = (c.severity_level || "low").toLowerCase();
      return `
      <div class="cve-card sev-${sev}">
        <div class="cve-card-head">
          <span class="cve-id">${escapeHtml(c.cve_id)}</span>
          <span class="severity-badge ${sev}">${escapeHtml(c.severity_level || "-")}</span>
        </div>
        <p class="cve-title">${escapeHtml(c.title)}</p>
        ${c.vulnerability_type ? `<p class="cve-type">${escapeHtml(c.vulnerability_type)}</p>` : ""}
        <p class="cve-desc">${escapeHtml(c.description)}</p>
        ${c.mitigation_hint ? `<div class="cve-mitigation"><strong>Mitigasi:</strong> ${escapeHtml(c.mitigation_hint)}</div>` : ""}
        <p class="cve-ref"><a href="${c.reference}" target="_blank" rel="noopener">Referensi &rarr;</a></p>
      </div>`;
    }).join("");
  }

  // --- Update kartu status ringkas di atas (target, host, port, versi) ---
  function updateStatusCard(job) {
    statusTarget.textContent = job.target || "\u2014";

    const aliveHost = (job.host_discovery || []).find((h) => h.alive);
    if (job.status === "running" || job.status === "queued") {
      statusHostBadge.textContent = "Memindai...";
      statusHostBadge.className = "badge running";
    } else if (aliveHost) {
      statusHostBadge.textContent = "Aktif";
      statusHostBadge.className = "badge alive";
    } else if (job.status === "inactive") {
      statusHostBadge.textContent = "Tidak Aktif";
      statusHostBadge.className = "badge dead";
    } else {
      statusHostBadge.textContent = "Standby";
      statusHostBadge.className = "badge";
    }

    const openPorts = (job.port_scan || []).filter((p) => p.status === "open");
    statusPorts.textContent = job.port_scan && job.port_scan.length > 0
      ? `${openPorts.length} / ${job.port_scan.length} terbuka`
      : "\u2014";

    statusVersion.textContent = job.detected_version || "\u2014";
  }

  function stagePillClass(status) {
    if (status === "running") return "running";
    if (status === "done") return "done";
    if (status === "failed" || status === "inactive") return "error";
    return "";
  }

  // --- Tanya status scan ke server tiap ~900ms selama masih berjalan ---
  async function poll(jobId) {
    try {
      const res = await fetch(`/api/scan/${jobId}`);
      if (!res.ok) throw new Error("Job tidak ditemukan");
      const job = await res.json();

      appendLogLines(job.log || []);
      renderPorts(job.port_scan);
      renderEnum(job.banner_grab);
      renderCve(job.cve_matches);
      renderIpProtocol(job.ip_protocol_scan);
      updateStatusCard(job);

      stagePill.textContent = job.stage || job.status;
      stagePill.className = `stage-pill ${stagePillClass(job.status)}`;
      setStage(stageMap[job.stage] || "host", job.status);

      pageTitle.textContent = `Target: ${job.target}`;
      if (job.status === "running") {
        pageSubtitle.textContent = job.stage;
      } else if (job.status === "inactive") {
        pageSubtitle.textContent = "Target tidak aktif / tidak merespons.";
      } else if (job.status === "done") {
        pageSubtitle.textContent = `Selesai. ${(job.cve_matches || []).length} kerentanan ditemukan.`;
      } else if (job.status === "failed") {
        pageSubtitle.textContent = `Terjadi kesalahan: ${job.error || "tidak diketahui"}`;
      }

      if (job.status === "done" && job.report_path) {
        downloadBtn.href = `/api/report/${jobId}`;
        downloadBtn.style.display = "inline-flex";
      }

      if (job.status === "running" || job.status === "queued") {
        pollTimer = setTimeout(() => poll(jobId), 900);
      } else {
        scanBtn.disabled = false;
      }
    } catch (err) {
      scanError.textContent = "Gagal memuat status scan.";
      scanBtn.disabled = false;
    }
  }

  // --- Klik tombol "Mulai Reconnaissance" ---
  async function startScan() {
    const target = targetInput.value.trim();
    const profile = profileSelect ? profileSelect.value : "core";
    const includeIpProtocol = ipProtocolCheckbox ? ipProtocolCheckbox.checked : false;
    scanError.textContent = "";
    if (!target) {
      scanError.textContent = "Isi target IP atau CIDR terlebih dahulu.";
      return;
    }

    scanBtn.disabled = true;
    lastLogCount = 0;
    terminal.innerHTML = `<div class="terminal-line terminal-placeholder">Menghubungkan ke target&hellip;</div>`;
    downloadBtn.style.display = "none";
    renderPorts([]);
    renderEnum([]);
    renderCve([]);
    renderIpProtocol(null);
    pageTitle.textContent = `Target: ${target}`;
    pageSubtitle.textContent = "Memulai host discovery\u2026";

    if (pollTimer) clearTimeout(pollTimer);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, profile, include_ip_protocol: includeIpProtocol }),
      });
      const data = await res.json();
      if (!res.ok) {
        scanError.textContent = data.error || "Gagal memulai scan.";
        scanBtn.disabled = false;
        return;
      }
      poll(data.job_id);
    } catch (err) {
      scanError.textContent = "Tidak dapat terhubung ke server backend.";
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener("click", startScan);
  targetInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") startScan();
  });

  // --- Ganti tab aktif (Port / Enumerasi / CVE) ---
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });

  // =========================================================
  // Basis Data CVE: ringkasan jumlah + hapus entri
  // =========================================================
  const dbSummary = document.getElementById("db-summary");
  const dbMessage = document.getElementById("db-message");
  const dbTbody = document.querySelector("#db-table tbody");
  const cveCountEl = document.getElementById("cve-count");
  const DB_HINT = dbMessage ? dbMessage.innerHTML : "";

  function setDbMessage(text, kind) {
    if (!dbMessage) return;
    dbMessage.className = "field-hint" + (kind ? ` db-msg-${kind}` : "");
    dbMessage.textContent = text;
  }

  // Ringkasan: total + jumlah per severity
  function renderDbSummary(stats) {
    cveCountEl.textContent = `${stats.total} entri`;
    const sev = stats.by_severity || {};
    dbSummary.innerHTML = `
      <div class="db-stat total"><strong>${stats.total}</strong>Total CVE</div>
      <div class="db-stat"><strong>${sev.Critical || 0}</strong>Critical</div>
      <div class="db-stat"><strong>${sev.High || 0}</strong>High</div>
      <div class="db-stat"><strong>${sev.Medium || 0}</strong>Medium</div>
      <div class="db-stat"><strong>${sev.Low || 0}</strong>Low</div>`;
  }

  function renderDbTable(cves) {
    if (!cves || cves.length === 0) {
      dbTbody.innerHTML = `<tr><td colspan="5" class="empty-row">Database CVE kosong.</td></tr>`;
      return;
    }
    dbTbody.innerHTML = cves.map((c) => {
      const sev = (c.severity_level || "low").toLowerCase();
      return `
      <tr>
        <td>${escapeHtml(c.cve_id)}</td>
        <td>${escapeHtml(c.title || "")}</td>
        <td><span class="severity-badge ${sev}">${escapeHtml(c.severity_level || "-")}</span></td>
        <td>${c.cvss ?? "-"}</td>
        <td><button class="btn-danger" data-cve-id="${escapeHtml(c.cve_id)}">Hapus</button></td>
      </tr>`;
    }).join("");
  }

  async function loadCveDb() {
    try {
      const res = await fetch("/api/cve-database");
      if (!res.ok) throw new Error();
      const db = await res.json();
      const cves = db.cves || [];
      const stats = await (await fetch("/api/cve-database/stats")).json();
      renderDbSummary(stats);
      renderDbTable(cves);
    } catch (err) {
      setDbMessage("Gagal memuat basis data CVE.", "err");
    }
  }

  async function deleteCve(cveId, btn) {
    if (!confirm(`Hapus ${cveId} dari basis data CVE?\n\nCVE ini tidak akan lagi dicocokkan pada scan berikutnya.`)) return;
    btn.disabled = true;
    try {
      const res = await fetch(`/api/cve-database/${encodeURIComponent(cveId)}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) {
        setDbMessage(data.error || "Gagal menghapus CVE.", "err");
        btn.disabled = false;
        return;
      }
      await loadCveDb();
      setDbMessage(`${cveId} berhasil dihapus. Sisa ${data.stats.total} entri.`, "ok");
    } catch (err) {
      setDbMessage("Tidak dapat terhubung ke server.", "err");
      btn.disabled = false;
    }
  }

  dbTbody.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-cve-id]");
    if (btn) deleteCve(btn.dataset.cveId, btn);
  });

  // Muat ulang daftar setiap kali tab "Basis Data CVE" dibuka
  document.querySelector('.tab-btn[data-tab="db"]').addEventListener("click", () => {
    if (dbMessage) { dbMessage.className = "field-hint"; dbMessage.innerHTML = DB_HINT; }
    loadCveDb();
  });
})();
