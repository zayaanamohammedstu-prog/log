/* ============================================================
   LogGuard – Dashboard JavaScript  v2
   ============================================================ */

"use strict";

// ============================================================
// THEME MANAGEMENT
// ============================================================
const THEME_KEY = "logguard-theme";

function getTheme() {
  return localStorage.getItem(THEME_KEY) || "dark";
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const isDark = theme === "dark";
  const icon   = isDark ? "🌙" : "☀️";
  const label  = isDark ? "Light Mode" : "Dark Mode";

  const btn = document.getElementById("themeToggle");
  if (btn) btn.textContent = icon;

  const sidebarIcon  = document.getElementById("sidebarThemeIcon");
  const sidebarLabel = document.getElementById("sidebarThemeLabel");
  if (sidebarIcon)  sidebarIcon.textContent  = icon;
  if (sidebarLabel) sidebarLabel.textContent = label;

  // Update Chart.js global defaults
  const textColor   = isDark ? "#8b949e" : "#636c76";
  const borderColor = isDark ? "#30363d" : "#d0d7de";
  if (typeof Chart !== "undefined") {
    Chart.defaults.color       = textColor;
    Chart.defaults.borderColor = borderColor;
  }

  // Re-render charts if data exists
  if (_lastData) renderAllCharts(_lastData);
}

function toggleTheme() {
  const next = getTheme() === "dark" ? "light" : "dark";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
}

// ============================================================
// TAB NAVIGATION
// ============================================================
function switchTab(tabId) {
  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  // Tab panels
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === tabId);
  });
  // Sidebar nav
  document.querySelectorAll("[data-tab-link]").forEach(li => {
    li.classList.toggle("active", li.dataset.tabLink === tabId);
  });
}

// ============================================================
// CHART INSTANCES
// ============================================================
let timelineChart      = null;
let statusChart        = null;
let methodChart        = null;
let pieChart           = null;
let riskDistChart      = null;
let topIpsChart        = null;
let topIpsVolumeChart  = null;
let scoreHistChart     = null;
let scatterChart       = null;
let offHoursChart      = null;
let endpointChart      = null;

// Chart.js defaults (guarded in case CDN fails to load)
if (typeof Chart !== "undefined") {
  Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
  Chart.defaults.font.size   = 12;
}

// ============================================================
// CACHED DATA
// ============================================================
let _lastData       = null;
let _allAnomalies   = [];
let _pageSize       = 20;
let _currentPage    = 1;
let _sortCol        = "anomaly_score";
let _sortAsc        = false;
let _lastRunId      = null;
let _chains         = [];

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function fmtHour(isoStr) {
  if (!isoStr) return "—";
  return new Date(isoStr).toISOString().substring(0, 16).replace("T", " ") + "Z";
}

function riskBadge(score) {
  const pct = (score * 100).toFixed(1);
  if (score >= 0.7) return `<span class="badge badge-critical">CRITICAL ${pct}%</span>`;
  if (score >= 0.5) return `<span class="badge badge-danger">HIGH ${pct}%</span>`;
  if (score >= 0.3) return `<span class="badge badge-warn">MEDIUM ${pct}%</span>`;
  return `<span class="badge badge-ok">LOW ${pct}%</span>`;
}

function riskLevel(score) {
  if (score >= 0.7) return "critical";
  if (score >= 0.5) return "high";
  if (score >= 0.3) return "medium";
  return "low";
}

function riskLabel(score) {
  if (score >= 0.7) return "Critical";
  if (score >= 0.5) return "High";
  if (score >= 0.3) return "Medium";
  return "Low";
}

function yesNo(val) {
  return val ? `<span class="badge badge-danger">YES</span>` : `<span style="color:var(--text-muted)">—</span>`;
}

function pct(val) {
  return ((val || 0) * 100).toFixed(1) + "%";
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================
function showToast(msg, type = "info", durationMs = 3500) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), durationMs);
}

// ============================================================
// CHART COLOUR HELPERS
// ============================================================
function isDark() { return getTheme() === "dark"; }
function gridColor() { return isDark() ? "#30363d" : "#d0d7de"; }
function textColor() { return isDark() ? "#8b949e" : "#636c76"; }

const PALETTE = ["#58a6ff","#3fb950","#f85149","#d29922","#bc8cff","#79c0ff","#ffa657","#ff7b72","#56d364","#e3b341"];

// ============================================================
// RENDER: OVERVIEW CARDS
// ============================================================
function renderCards(data) {
  document.getElementById("cardTotalRequests").textContent = (data.total_requests || 0).toLocaleString();
  document.getElementById("cardBuckets").textContent       = (data.total_ip_hour_buckets || 0).toLocaleString();
  document.getElementById("cardAnomalies").textContent     = (data.anomaly_count || 0).toLocaleString();
  document.getElementById("cardNormal").textContent        = (data.normal_count || 0).toLocaleString();
  document.getElementById("cardAnomalyRate").textContent   = (data.anomaly_rate || 0).toFixed(1) + "%";

  const criticalCard = document.getElementById("cardCritical");
  const critVal  = document.getElementById("cardCriticalVal");
  if (data.risk_distribution && data.risk_distribution.Critical) {
    critVal.textContent = data.risk_distribution.Critical.toLocaleString();
    criticalCard.style.display = "";
  }
}

// ============================================================
// RENDER: RISK TIMELINE
// ============================================================
function renderTimeline(timeline) {
  if (!timeline || !timeline.length) return;
  const labels = timeline.map(r => fmtHour(r.hour_bucket));
  const scores = timeline.map(r => +(r.mean_risk_score * 100).toFixed(2));

  if (timelineChart) timelineChart.destroy();
  const ctx = document.getElementById("timelineChart").getContext("2d");
  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Mean Risk Score (%)",
        data: scores,
        borderColor: "#f85149",
        backgroundColor: "rgba(248,81,73,.1)",
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointHoverRadius: 6,
      }],
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: { min: 0, max: 100, grid: { color: gridColor() }, ticks: { callback: v => v + "%" } },
        x: { grid: { color: gridColor() }, ticks: { maxRotation: 45, maxTicksLimit: 10 } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` Risk: ${ctx.parsed.y.toFixed(1)}%` } },
      },
    },
  });
}

// ============================================================
// RENDER: STATUS CODE DOUGHNUT
// ============================================================
function renderStatusChart(dist) {
  if (!dist) return;
  const labels = Object.keys(dist).sort();
  const values = labels.map(k => dist[k]);

  if (statusChart) statusChart.destroy();
  const ctx = document.getElementById("statusChart").getContext("2d");
  statusChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: PALETTE, borderWidth: 2, borderColor: "transparent" }],
    },
    options: {
      responsive: true,
      cutout: "60%",
      plugins: { legend: { position: "right" } },
    },
  });
}

// ============================================================
// RENDER: METHOD BAR CHART
// ============================================================
function renderMethodChart(dist) {
  if (!dist) return;
  const labels = Object.keys(dist);
  const values = labels.map(k => dist[k]);

  if (methodChart) methodChart.destroy();
  const ctx = document.getElementById("methodChart").getContext("2d");
  methodChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Requests", data: values, backgroundColor: PALETTE, borderRadius: 5 }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: gridColor() } },
        x: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: NORMAL vs ANOMALY PIE
// ============================================================
function renderPieChart(normalCount, anomalyCount) {
  if (pieChart) pieChart.destroy();
  const ctx = document.getElementById("pieChart").getContext("2d");
  pieChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Normal", "Anomalous"],
      datasets: [{
        data: [normalCount, anomalyCount],
        backgroundColor: ["#3fb950", "#f85149"],
        borderWidth: 2,
        borderColor: "transparent",
      }],
    },
    options: {
      responsive: true,
      cutout: "55%",
      plugins: {
        legend: { position: "right" },
        tooltip: {
          callbacks: {
            label: ctx => {
              const total = normalCount + anomalyCount;
              const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
              return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

// ============================================================
// RENDER: RISK DISTRIBUTION BAR
// ============================================================
function renderRiskDistChart(dist) {
  if (!dist) return;
  const order  = ["Critical", "High", "Medium", "Low"];
  const labels = order.filter(k => dist[k] !== undefined);
  const values = labels.map(k => dist[k] || 0);
  const colors = { Critical: "#d175e1", High: "#f85149", Medium: "#d29922", Low: "#3fb950" };

  if (riskDistChart) riskDistChart.destroy();
  const ctx = document.getElementById("riskDistChart").getContext("2d");
  riskDistChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Buckets",
        data: values,
        backgroundColor: labels.map(l => colors[l]),
        borderRadius: 5,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: gridColor() }, beginAtZero: true },
        x: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: TOP ANOMALOUS IPs (Anomaly Explorer tab)
// ============================================================
function renderTopIpsChart(topIps) {
  if (!topIps || !topIps.length) return;
  const labels = topIps.map(r => r.ip_address);
  const scores = topIps.map(r => +(r.max_score * 100).toFixed(1));

  if (topIpsChart) topIpsChart.destroy();
  const ctx = document.getElementById("topIpsChart").getContext("2d");
  topIpsChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Max Risk Score (%)",
        data: scores,
        backgroundColor: scores.map(s =>
          s >= 70 ? "rgba(209,117,225,.8)"
          : s >= 50 ? "rgba(248,81,73,.75)"
          : s >= 30 ? "rgba(210,153,34,.75)"
          : "rgba(63,185,80,.75)"
        ),
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { min: 0, max: 100, grid: { color: gridColor() }, ticks: { callback: v => v + "%" } },
        y: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: HOURLY HEATMAP
// ============================================================
function renderHeatmap(hourlyDist) {
  if (!hourlyDist) return;
  const grid   = document.getElementById("heatmapGrid");
  const labels = document.getElementById("heatmapLabels");
  if (!grid || !labels) return;

  const maxVal = Math.max(1, ...Object.values(hourlyDist).map(Number));

  grid.innerHTML   = "";
  labels.innerHTML = "";

  for (let h = 0; h < 24; h++) {
    const count     = hourlyDist[String(h)] || 0;
    const intensity = count / maxVal;
    const cell      = document.createElement("div");
    cell.className  = "heatmap-cell";
    cell.title      = `Hour ${String(h).padStart(2,"0")}:00 — ${count.toLocaleString()} requests`;
    const r = Math.round(248 * intensity);
    const g = Math.round(81  * intensity);
    const b = Math.round(73  * intensity);
    const alpha = 0.15 + intensity * 0.75;
    cell.style.background = `rgba(${r},${g},${b},${alpha})`;
    grid.appendChild(cell);

    const lbl = document.createElement("span");
    lbl.textContent = h % 3 === 0 ? String(h).padStart(2,"0") : "";
    labels.appendChild(lbl);
  }
}

// ============================================================
// RENDER: TOP IPs VOLUME (Export tab)
// ============================================================
function renderTopIpsVolumeChart(topIps) {
  if (!topIps || !topIps.length) return;
  const labels = topIps.map(r => r.ip_address);
  const values = topIps.map(r => r.request_count);

  if (topIpsVolumeChart) topIpsVolumeChart.destroy();
  const ctx = document.getElementById("topIpsVolumeChart").getContext("2d");
  topIpsVolumeChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Requests", data: values, backgroundColor: "#58a6ff", borderRadius: 4 }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: gridColor() } },
        y: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: SCORE HISTOGRAM
// ============================================================
function renderScoreHistogram(allResults) {
  if (!allResults || !allResults.length) return;
  const bins    = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
  const counts  = new Array(bins.length - 1).fill(0);
  const labels  = bins.slice(0, -1).map((b, i) => `${b}–${bins[i+1]}%`);

  allResults.forEach(r => {
    const pct = (r.anomaly_score || 0) * 100;
    const idx = Math.min(Math.floor(pct / 10), counts.length - 1);
    counts[idx]++;
  });

  if (scoreHistChart) scoreHistChart.destroy();
  const ctx = document.getElementById("scoreHistogramChart").getContext("2d");
  scoreHistChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Buckets",
        data: counts,
        backgroundColor: bins.slice(0,-1).map(b => {
          if (b >= 70) return "rgba(209,117,225,.75)";
          if (b >= 50) return "rgba(248,81,73,.75)";
          if (b >= 30) return "rgba(210,153,34,.75)";
          return "rgba(63,185,80,.75)";
        }),
        borderRadius: 4,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: gridColor() }, beginAtZero: true },
        x: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: SCATTER — Error Rate vs Requests
// ============================================================
function renderScatter(allResults) {
  if (!allResults || !allResults.length) return;
  const points = allResults.map(r => ({
    x: r.requests_per_hour || 0,
    y: (r.error_rate || 0) * 100,
    anomaly: r.is_anomaly,
  }));

  if (scatterChart) scatterChart.destroy();
  const ctx = document.getElementById("scatterChart").getContext("2d");
  scatterChart = new Chart(ctx, {
    type: "scatter",
    data: {
      datasets: [
        {
          label: "Normal",
          data: points.filter(p => !p.anomaly).map(p => ({ x: p.x, y: p.y })),
          backgroundColor: "rgba(63,185,80,.6)",
          pointRadius: 4,
        },
        {
          label: "Anomalous",
          data: points.filter(p => p.anomaly).map(p => ({ x: p.x, y: p.y })),
          backgroundColor: "rgba(248,81,73,.7)",
          pointRadius: 5,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: {
        x: { title: { display: true, text: "Requests/hr", color: textColor() }, grid: { color: gridColor() } },
        y: { title: { display: true, text: "Error Rate (%)", color: textColor() }, grid: { color: gridColor() } },
      },
    },
  });
}

// ============================================================
// RENDER: OFF-HOURS vs BUSINESS HOURS
// ============================================================
function renderOffHoursChart(allResults) {
  if (!allResults || !allResults.length) return;
  let offNormal = 0, offAnomaly = 0, onNormal = 0, onAnomaly = 0;
  allResults.forEach(r => {
    const off = r.is_off_hours;
    if (r.is_anomaly) { off ? offAnomaly++ : onAnomaly++; }
    else              { off ? offNormal++  : onNormal++;  }
  });

  if (offHoursChart) offHoursChart.destroy();
  const ctx = document.getElementById("offHoursChart").getContext("2d");
  offHoursChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Business Hours", "Off-Hours"],
      datasets: [
        { label: "Normal",    data: [onNormal,  offNormal],  backgroundColor: "rgba(63,185,80,.75)",  borderRadius: 4 },
        { label: "Anomalous", data: [onAnomaly, offAnomaly], backgroundColor: "rgba(248,81,73,.75)", borderRadius: 4 },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "top" } },
      scales: {
        y: { grid: { color: gridColor() }, stacked: false },
        x: { grid: { display: false } },
      },
    },
  });
}

// ============================================================
// RENDER: TOP ENDPOINTS
// ============================================================
function renderEndpointChart(topEndpoints) {
  if (!topEndpoints) return;
  const labels = Object.keys(topEndpoints).map(e => e.length > 30 ? e.slice(0, 28) + "…" : e);
  const values = Object.values(topEndpoints);

  if (endpointChart) endpointChart.destroy();
  const ctx = document.getElementById("endpointChart").getContext("2d");
  endpointChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Requests", data: values, backgroundColor: "#79c0ff", borderRadius: 4 }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: gridColor() } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } },
      },
    },
  });
}

// ============================================================
// RENDER: ALL CHARTS (called on theme change too)
// ============================================================
function renderAllCharts(data) {
  renderTimeline(data.timeline);
  renderStatusChart(data.status_code_distribution);
  renderMethodChart(data.method_distribution);
  renderPieChart(data.normal_count, data.anomaly_count);
  renderRiskDistChart(data.risk_distribution);
  renderTopIpsChart(data.top_anomalous_ips);
  renderHeatmap(data.hourly_distribution);
  renderTopIpsVolumeChart(data.top_ips);
  renderScoreHistogram(data.all_results);
  renderScatter(data.all_results);
  renderOffHoursChart(data.all_results);
  renderEndpointChart(data.top_endpoints);
}

// ============================================================
// ANOMALY TABLE (with pagination, sort, filter)
// ============================================================
function filterAndSortRows(rows, search, riskFilter) {
  let out = rows.slice();

  if (search) {
    const q = search.toLowerCase();
    out = out.filter(r =>
      (r.ip_address || "").toLowerCase().includes(q) ||
      (fmtHour(r.hour_bucket) || "").toLowerCase().includes(q)
    );
  }

  if (riskFilter) {
    const thresholds = { critical: 0.7, high: 0.5, medium: 0.3, low: 0 };
    const maxThresholds = { critical: 1.01, high: 0.7, medium: 0.5, low: 0.3 };
    const min = thresholds[riskFilter] || 0;
    const max = maxThresholds[riskFilter] || 1.01;
    out = out.filter(r => r.anomaly_score >= min && r.anomaly_score < max);
  }

  // Sort
  out.sort((a, b) => {
    let va = a[_sortCol], vb = b[_sortCol];
    if (va === undefined) va = "";
    if (vb === undefined) vb = "";
    if (typeof va === "string") return _sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return _sortAsc ? va - vb : vb - va;
  });

  return out;
}

function renderTable(rows) {
  const search     = (document.getElementById("tableSearch")?.value || "").trim();
  const riskFilter = document.getElementById("riskFilter")?.value || "";
  const filtered   = filterAndSortRows(rows, search, riskFilter);

  const totalPages = Math.max(1, Math.ceil(filtered.length / _pageSize));
  _currentPage = Math.min(_currentPage, totalPages);
  const start  = (_currentPage - 1) * _pageSize;
  const page   = filtered.slice(start, start + _pageSize);

  const tbody = document.getElementById("anomalyBody");
  const colCount = 12;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${colCount}" class="placeholder">No anomalies match the current filter.</td></tr>`;
  } else {
    tbody.innerHTML = page.map((r, i) => {
      const risk = riskLevel(r.anomaly_score);
      return `<tr class="${r.anomaly_score >= 0.7 ? "row-danger" : ""}">
        <td>${start + i + 1}</td>
        <td><code>${r.ip_address || "—"}</code></td>
        <td>${fmtHour(r.hour_bucket)}</td>
        <td>${riskBadge(r.anomaly_score)}</td>
        <td>${Math.round(r.requests_per_hour || 0).toLocaleString()}</td>
        <td>${pct(r.error_rate)}</td>
        <td>${(r.unique_endpoints || 0).toLocaleString()}</td>
        <td>${pct(r.post_ratio)}</td>
        <td>${yesNo(r.is_off_hours)}</td>
        <td>${r.has_scanner_ua ? '<span class="badge badge-danger">YES</span>' : '<span style="color:var(--text-muted)">—</span>'}</td>
        <td><span class="badge badge-${risk === "critical" ? "critical" : risk === "high" ? "danger" : risk === "medium" ? "warn" : "ok"}">${riskLabel(r.anomaly_score)}</span></td>
        <td><button class="btn btn-secondary btn-sm drill-btn" data-idx="${start + i}" style="padding:3px 8px;font-size:.75rem;">🔍 Drill</button></td>
      </tr>`;
    }).join("");

    // Attach drill-down listeners
    tbody.querySelectorAll(".drill-btn").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        const idx = parseInt(btn.dataset.idx);
        openDrillDown(filtered[idx]);
      });
    });

    // Row click also opens drill-down
    tbody.querySelectorAll("tr").forEach((tr, i) => {
      tr.style.cursor = "pointer";
      tr.addEventListener("click", e => {
        if (e.target.tagName === "BUTTON") return;
        openDrillDown(filtered[start + i]);
      });
    });
  }

  // Pagination
  const paginationEl = document.getElementById("tablePagination");
  const infoEl       = document.getElementById("paginationInfo");
  const btnsEl       = document.getElementById("paginationBtns");

  if (filtered.length > _pageSize) {
    paginationEl.style.display = "";
    infoEl.textContent = `Showing ${start + 1}–${Math.min(start + _pageSize, filtered.length)} of ${filtered.length.toLocaleString()} results`;

    const maxBtns  = 7;
    let btnHtml    = "";
    btnHtml += `<button ${_currentPage <= 1 ? "disabled" : ""} data-page="${_currentPage - 1}">‹ Prev</button>`;
    const half  = Math.floor(maxBtns / 2);
    let pStart  = Math.max(1, _currentPage - half);
    let pEnd    = Math.min(totalPages, pStart + maxBtns - 1);
    pStart      = Math.max(1, pEnd - maxBtns + 1);
    for (let p = pStart; p <= pEnd; p++) {
      btnHtml += `<button class="${p === _currentPage ? "current" : ""}" data-page="${p}">${p}</button>`;
    }
    btnHtml += `<button ${_currentPage >= totalPages ? "disabled" : ""} data-page="${_currentPage + 1}">Next ›</button>`;
    btnsEl.innerHTML = btnHtml;
    btnsEl.querySelectorAll("button[data-page]").forEach(btn => {
      btn.addEventListener("click", () => {
        _currentPage = parseInt(btn.dataset.page);
        renderTable(_allAnomalies);
      });
    });
  } else {
    paginationEl.style.display = "none";
  }
}

// ============================================================
// RENDER: EVIDENCE PANEL
// ============================================================
function renderEvidence(data) {
  const engagement = document.getElementById("engagementSelect")?.value || "—";

  // Audit summary
  const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setEl("auditEngagement",   engagement);
  setEl("auditDate",         new Date().toLocaleString());
  setEl("auditTotalEntries", (data.total_requests || 0).toLocaleString());
  setEl("auditAnomalyRate",  (data.anomaly_rate || 0).toFixed(2) + "%");

  const rate = data.anomaly_rate || 0;
  const overallRisk = rate >= 20 ? "🔴 Critical"
    : rate >= 10 ? "🟠 High"
    : rate >= 5  ? "🟡 Medium"
    : "🟢 Low";
  setEl("auditOverallRisk", overallRisk);

  // COBIT domain scores (computed from data)
  const critCount = (data.risk_distribution?.Critical || 0);
  const highCount = (data.risk_distribution?.High || 0);
  const total     = data.total_ip_hour_buckets || 1;
  const critRate  = critCount / total;
  const highRate  = highCount / total;

  function updateDomain(prefix, score100, desc) {
    const color = score100 <= 30 ? "domain-danger" : score100 <= 60 ? "domain-warn" : "domain-ok";
    const barColor = score100 <= 30 ? "var(--danger)" : score100 <= 60 ? "var(--warning)" : "var(--success)";
    const el = document.getElementById(`${prefix}Score`);
    const barEl = document.getElementById(`${prefix}Bar`);
    const descEl = document.getElementById(`${prefix}Desc`);
    if (el) { el.textContent = score100 + "%"; el.className = `domain-score ${color}`; }
    if (barEl) { barEl.style.width = score100 + "%"; barEl.style.background = barColor; }
    if (descEl) descEl.textContent = desc;
  }

  // DSS05: Security — inversely proportional to critical anomalies
  const dss05 = Math.max(0, Math.round(100 - critRate * 200));
  updateDomain("dss05", dss05, dss05 < 50 ? "Critical anomalies detected. Immediate investigation required." : dss05 < 70 ? "Elevated risk. Review flagged IPs." : "Security posture acceptable.");

  // MEA02: Internal control monitoring
  const mea02 = Math.max(0, Math.round(100 - (critRate + highRate) * 150));
  updateDomain("mea02", mea02, mea02 < 50 ? "Significant control weaknesses. Escalate to management." : mea02 < 70 ? "Some control gaps identified." : "Controls appear effective.");

  // DSS01: Operations
  const scannerCount = (data.top_anomalies || []).filter(r => r.has_scanner_ua).length;
  const dss01 = Math.max(0, Math.round(100 - (scannerCount / Math.max(1, (data.top_anomalies || []).length)) * 100));
  updateDomain("dss01", dss01, scannerCount > 0 ? `${scannerCount} scanner/bot user-agent(s) detected in top anomalies.` : "No scanner activity detected.");

  // APO12: Risk management
  const offHoursCount = (data.all_results || []).filter(r => r.is_off_hours && r.is_anomaly).length;
  const apo12 = Math.max(0, Math.round(100 - (offHoursCount / Math.max(1, data.anomaly_count)) * 100));
  updateDomain("apo12", apo12, offHoursCount > 0 ? `${offHoursCount} off-hours anomaly(ies) detected. Review access policies.` : "No off-hours anomalies detected.");

  // Key findings
  const findings = [];

  if (critCount > 0) {
    findings.push({
      title: "Critical Risk — Immediate Action Required",
      severity: "badge-critical",
      desc: `${critCount} IP/hour bucket(s) scored Critical risk (≥70%). These represent the most anomalous behaviour in the log and require immediate investigation.`,
      ref: "IT Audit Standard 1205.A2 — Sufficiency of Evidence",
      domain: "DSS05.07 — Monitor the infrastructure",
    });
  }

  if (data.anomaly_rate > 10) {
    findings.push({
      title: "High Anomaly Rate",
      severity: "badge-danger",
      desc: `Overall anomaly rate is ${data.anomaly_rate?.toFixed(1)}%, which exceeds the 10% threshold. This may indicate a systemic security issue or ongoing attack.`,
      ref: "IT Audit Standard 1402 — Reporting",
      domain: "APO12 — Managed Risk",
    });
  }

  const scannerRows = (data.top_anomalies || []).filter(r => r.has_scanner_ua);
  if (scannerRows.length > 0) {
    findings.push({
      title: "Scanner / Automated Tool Activity Detected",
      severity: "badge-danger",
      desc: `${scannerRows.length} bucket(s) contain user-agents associated with scanning or attack tools (e.g., Nikto, sqlmap, Nmap). These represent a direct threat to system integrity.`,
      ref: "IT Audit Standard 1205.B — Reliability of Evidence",
      domain: "DSS05.02 — Manage network and connectivity security",
    });
  }

  const offHoursAnomalies = (data.all_results || []).filter(r => r.is_off_hours && r.is_anomaly);
  if (offHoursAnomalies.length > 0) {
    findings.push({
      title: "Off-Hours Anomalous Activity",
      severity: "badge-warn",
      desc: `${offHoursAnomalies.length} anomalous IP/hour bucket(s) occurred outside business hours (22:00–06:00). This may indicate unauthorised access or insider threat activity.`,
      ref: "IT Audit Standard 1001.B — Organisational Independence",
      domain: "DSS05.04 — Manage user identity and logical access",
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: "No Significant Findings",
      severity: "badge-ok",
      desc: "No significant anomalies were detected in the analysed log data. Anomaly rate is within acceptable thresholds.",
      ref: "IT Audit Standard 1402 — Reporting",
      domain: "MEA02 — Managed System of Internal Control",
    });
  }

  const grid = document.getElementById("findingsGrid");
  if (grid) {
    grid.innerHTML = findings.map(f => `
      <div class="finding-card">
        <div class="finding-card-header">
          <h4>${f.title}</h4>
          <span class="badge ${f.severity}">${f.severity.replace("badge-","").toUpperCase()}</span>
        </div>
        <p>${f.desc}</p>
        <div class="finding-meta">
          <span>📚 ${f.ref}</span>
          <span>🏛 ${f.domain}</span>
        </div>
      </div>
    `).join("");
  }
}

// ============================================================
// DRILL-DOWN PANEL
// ============================================================
function openDrillDown(row) {
  if (!row) return;
  const overlay = document.getElementById("drillOverlay");
  if (!overlay) return;

  // Title
  document.getElementById("drillTitle").textContent =
    `${row.ip_address || "Unknown IP"} — ${fmtHour(row.hour_bucket)}`;

  // KV overview
  const kvGrid = document.getElementById("drillKvGrid");
  const risk   = riskLabel(row.anomaly_score || 0);
  kvGrid.innerHTML = [
    ["Ensemble Score", ((row.ensemble_score || row.anomaly_score || 0) * 100).toFixed(1) + "%"],
    ["Risk Level", risk],
    ["Label", row.ensemble_label || (row.is_anomaly ? "anomaly" : "normal")],
    ["Model Agreement", row.agreement_pct !== undefined ? ((row.agreement_pct || 0) * 100).toFixed(0) + "%" : "—"],
  ].map(([l, v]) => `<div class="drill-kv"><div class="drill-kv-label">${l}</div><div class="drill-kv-value">${v}</div></div>`).join("");

  // Reason codes
  const reasonsEl = document.getElementById("drillReasons");
  let explanations = {};
  if (row.explanations_json) {
    try { explanations = JSON.parse(row.explanations_json); } catch (_) {}
  }
  const reasons = explanations.reasons || [];
  if (reasons.length > 0) {
    reasonsEl.innerHTML = reasons.map(([code, desc]) =>
      `<span class="reason-tag">⚠ ${code}: ${desc}</span>`
    ).join("");
  } else {
    reasonsEl.innerHTML = `<span style="color:var(--text-muted);font-size:.82rem;">No specific reason codes flagged.</span>`;
  }

  // Feature deviations
  const devsEl  = document.getElementById("drillDeviations");
  const devs    = explanations.feature_deviations || [];
  if (devs.length > 0) {
    const sorted = devs.slice().sort((a, b) => Math.abs(b.z_score || 0) - Math.abs(a.z_score || 0));
    devsEl.innerHTML = sorted.slice(0, 6).map(d => {
      const z    = (d.z_score || 0).toFixed(2);
      const cls  = d.z_score > 0 ? "deviation-pos" : "deviation-neg";
      const pctl = d.percentile !== undefined ? ` (p${Math.round(d.percentile)})` : "";
      return `<div class="deviation-row">
        <span class="deviation-feat">${d.feature}</span>
        <span class="deviation-score ${cls}">z=${z}${pctl}</span>
      </div>`;
    }).join("");
  } else {
    devsEl.innerHTML = `<span style="color:var(--text-muted);font-size:.82rem;">Deviation data not available.</span>`;
  }

  // Per-model scores
  const modelsEl = document.getElementById("drillModelScores");
  const models   = [
    ["Isolation Forest", row.score_isolation_forest],
    ["LOF",              row.score_lof],
    ["One-Class SVM",    row.score_ocsvm],
    ["Autoencoder",      row.score_autoencoder],
  ];
  modelsEl.innerHTML = models.map(([name, score]) => {
    if (score === undefined || score === null) return "";
    const pctVal = (score * 100).toFixed(1);
    const color  = score >= 0.7 ? "#f85149" : score >= 0.5 ? "#d29922" : "#3fb950";
    return `<div class="model-score-bar">
      <div class="model-score-label"><span>${name}</span><span>${pctVal}%</span></div>
      <div class="model-score-track">
        <div class="model-score-fill" style="width:${pctVal}%;background:${color};"></div>
      </div>
    </div>`;
  }).join("") || `<span style="color:var(--text-muted);font-size:.82rem;">Model scores not available.</span>`;

  // Chain membership
  const chainSection = document.getElementById("drillChainSection");
  const chainInfo    = document.getElementById("drillChainInfo");
  const ipChains = _chains.filter(c => c.ip_address === row.ip_address);
  if (ipChains.length > 0) {
    chainSection.style.display = "";
    chainInfo.innerHTML = ipChains.map(c => `
      <div class="chain-badge" style="margin-bottom:6px;display:flex;flex-direction:column;align-items:flex-start;gap:4px;">
        <span>🔗 Chain #${c.chain_id} — ${c.severity || "Unknown"} severity</span>
        <span style="font-size:.75rem;font-weight:400;">${c.anomaly_count} anomaly(ies) · ${fmtHour(c.start_time)} → ${fmtHour(c.end_time)}</span>
        <span style="font-size:.75rem;font-weight:400;font-style:italic;">${c.narrative || ""}</span>
      </div>
    `).join("");
  } else {
    chainSection.style.display = "none";
  }

  // Raw features grid
  const featsEl = document.getElementById("drillFeaturesGrid");
  const featCols = ["requests_per_hour","error_rate","unique_endpoints","avg_bytes_sent",
                    "post_ratio","is_off_hours","is_weekend","has_scanner_ua",
                    "requests_vs_expected","bytes_vs_expected","error_rate_delta"];
  const fmtVal = (k, v) => {
    if (v === null || v === undefined) return "—";
    if (["error_rate","post_ratio","requests_vs_expected","bytes_vs_expected","error_rate_delta"].includes(k))
      return (v * 100).toFixed(1) + (["requests_vs_expected","bytes_vs_expected"].includes(k) ? "x" : "%");
    if (["is_off_hours","is_weekend","has_scanner_ua"].includes(k))
      return v ? "Yes" : "No";
    if (typeof v === "number") return v.toFixed(2);
    return String(v);
  };
  featsEl.innerHTML = featCols.filter(k => row[k] !== undefined).map(k =>
    `<div class="drill-kv"><div class="drill-kv-label">${k}</div><div class="drill-kv-value">${fmtVal(k, row[k])}</div></div>`
  ).join("");

  overlay.classList.add("open");
}

function closeDrillDown() {
  const overlay = document.getElementById("drillOverlay");
  if (overlay) overlay.classList.remove("open");
}

// ============================================================
// RENDER: ATTACK CHAINS
// ============================================================
function renderChains(chains) {
  _chains = chains || [];
  const listEl = document.getElementById("chainsList");
  if (!listEl) return;
  if (!_chains.length) {
    listEl.innerHTML = `<div class="finding-card"><p style="color:var(--text-muted)">No attack chains detected — all anomalies appear isolated.</p></div>`;
    return;
  }
  const sevColor = { Critical: "#f85149", High: "#d29922", Medium: "#3fb950" };
  listEl.innerHTML = _chains.map(c => {
    const color = sevColor[c.severity] || "var(--text-muted)";
    const tacticBadge = c.tactic && c.tactic !== "Unknown"
      ? `<span class="chain-tactic-badge">${c.tactic}</span>` : "";
    const stageChips = (c.stages || []).filter(s => s !== "Unknown")
      .map(s => `<span class="stage-chip">${s}</span>`).join("");
    return `<div class="chain-card">
      <div class="chain-card-header">
        <code class="chain-card-ip">${c.ip_address}</code>
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
          <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}44;">${c.severity || "Unknown"}</span>
          ${tacticBadge}
        </div>
      </div>
      ${stageChips ? `<div class="chain-stages">${stageChips}</div>` : ""}
      <div class="chain-narrative">${c.narrative || ""}</div>
      <div class="chain-meta">
        <span class="chain-meta-item">🔗 ${c.anomaly_count} anomaly bucket(s)</span>
        <span class="chain-meta-item">⏱ ${fmtHour(c.start_time)} → ${fmtHour(c.end_time)}</span>
        <span class="chain-meta-item">📊 Max score: ${((c.max_score || 0) * 100).toFixed(1)}%</span>
      </div>
    </div>`;
  }).join("");
}

// ============================================================
// RENDER: BEHAVIORAL PROFILES
// ============================================================
function renderProfiles(profiles) {
  const grid = document.getElementById("profilesGrid");
  if (!grid) return;
  if (!profiles || Object.keys(profiles).length === 0) {
    grid.innerHTML = `<div class="finding-card"><p style="color:var(--text-muted)">No behavioral profiles available.</p></div>`;
    return;
  }

  const catColor = {
    "Scanner":           "#f85149",
    "Credential Attack": "#d29922",
    "Data Exfiltration": "#bc8cff",
    "High Volume":       "#e8a14f",
    "Suspicious Timing": "#d29922",
    "Normal":            "#3fb950",
  };

  // Sort: anomalous categories first, then alphabetically by IP
  const order = ["Scanner","Credential Attack","Data Exfiltration","High Volume","Suspicious Timing","Normal"];
  const entries = Object.entries(profiles).sort(([ipA, a], [ipB, b]) => {
    const catDiff = order.indexOf(a.category) - order.indexOf(b.category);
    return catDiff !== 0 ? catDiff : ipA.localeCompare(ipB);
  });

  const fmtNum = (v, decimals = 2) => (v == null ? "—" : Number(v).toFixed(decimals));
  const fmtPct = (v, decimals = 1) => (v == null ? "—" : (Number(v) * 100).toFixed(decimals) + "%");

  grid.innerHTML = entries.map(([ip, p]) => {
    const color = catColor[p.category] || "var(--text-muted)";
    return `<div class="profile-card">
      <div class="profile-card-header">
        <code class="profile-ip">${ip}</code>
        <span class="profile-category" style="color:${color};border-color:${color}40;background:${color}15;">${p.category ?? "—"}</span>
      </div>
      <div class="profile-stats">
        <div class="profile-stat"><span class="profile-stat-label">Avg Req/hr</span><span class="profile-stat-val">${fmtNum(p.avg_requests_per_hour)}</span></div>
        <div class="profile-stat"><span class="profile-stat-label">Peak Req/hr</span><span class="profile-stat-val">${fmtNum(p.max_requests_per_hour)}</span></div>
        <div class="profile-stat"><span class="profile-stat-label">Avg Error Rate</span><span class="profile-stat-val">${fmtPct(p.avg_error_rate)}</span></div>
        <div class="profile-stat"><span class="profile-stat-label">Off-Hours</span><span class="profile-stat-val">${fmtPct(p.off_hours_ratio, 0)}</span></div>
        <div class="profile-stat"><span class="profile-stat-label">POST Ratio</span><span class="profile-stat-val">${fmtPct(p.avg_post_ratio, 0)}</span></div>
        <div class="profile-stat"><span class="profile-stat-label">Scanner UA</span><span class="profile-stat-val">${p.has_scanner_activity ? "⚠ Yes" : "No"}</span></div>
      </div>
    </div>`;
  }).join("");
}

// ============================================================
// MAIN RENDER
// ============================================================
function renderResults(data) {
  _lastData     = data;
  _allAnomalies = data.top_anomalies || [];
  _chains       = data.chains || [];
  _currentPage  = 1;
  if (data.run_id) _lastRunId = data.run_id;

  renderCards(data);
  renderAllCharts(data);
  renderTable(_allAnomalies);
  renderEvidence(data);
  renderChains(data.chains);
  renderProfiles(data.behavioral_profiles);

  // Show run ID badge in topbar if available
  if (data.run_id) {
    const tsEl = document.getElementById("analysisTimestamp");
    if (tsEl) {
      tsEl.innerHTML = `Last analysed: ${new Date().toLocaleString()} <span class="run-id-badge">Run #${data.run_id}</span>`;
      tsEl.classList.remove("hidden");
    }
  } else {
    const tsEl = document.getElementById("analysisTimestamp");
    if (tsEl) {
      tsEl.textContent = `Last analysed: ${new Date().toLocaleString()}`;
      tsEl.classList.remove("hidden");
    }
  }

  showToast("Analysis complete — " + (data.anomaly_count || 0) + " anomalies found", "info");
}

// ============================================================
// UPLOAD HISTORY
// ============================================================
async function loadRunHistory() {
  const tbody = document.getElementById("historyBody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="placeholder">Loading…</td></tr>';

  try {
    const resp = await apiFetch("/api/runs");
    if (!resp) return;
    const data = await resp.json();
    const runs = data.runs || [];

    if (!runs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="placeholder">No runs yet. Upload a log file to get started.</td></tr>';
      return;
    }

    tbody.innerHTML = runs.map(run => {
      const ts = run.timestamp
        ? new Date(run.timestamp).toLocaleString("en-GB", { timeZone: "UTC", hour12: false }) + " UTC"
        : "—";
      const typeBadge = `<span class="history-badge-${run.input_type || 'sample'}">${run.input_type || 'sample'}</span>`;
      const escapedFile = (run.filename || (run.input_type === "sample" ? "sample_logs.txt" : "—"))
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
      return `<tr>
        <td><span class="run-id-badge">Run #${run.id}</span></td>
        <td>${ts}</td>
        <td>${(run.username || "—").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}</td>
        <td>${typeBadge}</td>
        <td style="font-family:monospace;font-size:.82rem;">${escapedFile}</td>
        <td id="hist-anomalies-${run.id}">—</td>
        <td>
          <button class="btn btn-primary btn-sm history-load-btn" data-run-id="${run.id}">▶ Load</button>
          <button class="btn btn-secondary btn-sm history-load-btn history-report-btn" data-run-id="${run.id}" style="margin-left:6px;">📑 Report</button>
        </td>
      </tr>`;
    }).join("");

    // Attach handlers via event delegation
    tbody.querySelectorAll(".history-load-btn:not(.history-report-btn)").forEach(btn => {
      btn.addEventListener("click", () => loadHistoryRun(parseInt(btn.dataset.runId)));
    });
    tbody.querySelectorAll(".history-report-btn").forEach(btn => {
      btn.addEventListener("click", () => downloadRunReport(parseInt(btn.dataset.runId)));
    });

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="placeholder">Error loading history: ${err.message}</td></tr>`;
  }
}

async function loadHistoryRun(runId) {
  showToast(`Loading Run #${runId}…`, "info", 2000);
  try {
    const resp = await apiFetch(`/api/runs/${runId}/summary`);
    if (!resp) return;
    const data = await resp.json();
    if (data.error) {
      showToast("Could not load run: " + data.error, "error");
      return;
    }
    renderResults(data);
    switchTab("tab-overview");
    showToast(`Run #${runId} loaded successfully.`, "success");
  } catch (err) {
    showToast("Network error loading run: " + err.message, "error");
  }
}

function downloadRunReport(runId) {
  const a = document.createElement("a");
  a.href = `/api/runs/${runId}/report`;
  a.target = "_blank";
  a.download = `logguard_report_run_${runId}.html`;
  a.click();
  showToast(`HTML report for Run #${runId} download started.`, "success");
}

// ============================================================
// ADMIN PANEL
// ============================================================
async function loadAdminPanel() {
  await Promise.all([loadAdminStats(), loadAdminUsers()]);
}

async function loadAdminStats() {
  try {
    const resp = await apiFetch("/api/admin/stats");
    if (!resp) return;
    const data = await resp.json();
    if (data.error) return;
    const uc = document.getElementById("adminUserCount");
    const rc = document.getElementById("adminRunCount");
    if (uc) uc.textContent = data.user_count ?? "—";
    if (rc) rc.textContent = data.total_runs ?? "—";
  } catch (_) { /* ignore */ }
}

async function loadAdminUsers() {
  const tbody = document.getElementById("adminUsersBody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" class="placeholder">Loading…</td></tr>';
  try {
    const resp = await apiFetch("/api/admin/users");
    if (!resp) return;
    const data = await resp.json();
    if (data.error) {
      tbody.innerHTML = `<tr><td colspan="4" class="placeholder">${data.error}</td></tr>`;
      return;
    }
    const users = data.users || [];
    const currentId = parseInt(document.body.dataset.userid || "0");
    tbody.innerHTML = users.map(u => {
      const isSelf = u.id === currentId;
      const delBtn = isSelf
        ? `<span style="color:var(--text-muted);font-size:.8rem;">(current user)</span>`
        : `<button class="btn btn-sm admin-del-user-btn"
              data-user-id="${u.id}"
              style="background:rgba(248,81,73,.15);color:var(--danger);border:1px solid rgba(248,81,73,.3);font-size:.8rem;">🗑 Delete</button>`;
      const escapedUsername = u.username.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
      return `<tr data-username="${escapedUsername}">
        <td>${u.id}</td>
        <td><strong>${escapedUsername}</strong></td>
        <td><span class="user-role role-${u.role}">${u.role}</span></td>
        <td>${delBtn}</td>
      </tr>`;
    }).join("");

    // Attach delete handlers via event delegation
    tbody.querySelectorAll(".admin-del-user-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const userId = parseInt(btn.dataset.userId);
        const row = btn.closest("tr");
        const username = row ? (row.dataset.username || "") : "";
        deleteAdminUser(userId, username);
      });
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="placeholder">Error: ${err.message}</td></tr>`;
  }
}

async function createAdminUser() {
  const username = (document.getElementById("newUsername")?.value || "").trim();
  const password = document.getElementById("newPassword")?.value || "";
  const role = document.getElementById("newRole")?.value || "auditor";
  const msgEl = document.getElementById("createUserMsg");

  if (!username || !password) {
    if (msgEl) { msgEl.textContent = "Username and password are required."; msgEl.style.color = "var(--danger)"; }
    return;
  }

  try {
    const resp = await apiFetch("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    if (!resp) return;
    const data = await resp.json();
    if (data.error) {
      if (msgEl) { msgEl.textContent = data.error; msgEl.style.color = "var(--danger)"; }
      return;
    }
    if (msgEl) { msgEl.textContent = `User '${username}' created successfully.`; msgEl.style.color = "var(--success)"; }
    document.getElementById("newUsername").value = "";
    document.getElementById("newPassword").value = "";
    await loadAdminUsers();
    await loadAdminStats();
    showToast(`User '${username}' (${role}) created.`, "success");
  } catch (err) {
    if (msgEl) { msgEl.textContent = "Network error: " + err.message; msgEl.style.color = "var(--danger)"; }
  }
}

async function deleteAdminUser(userId, username) {
  if (!confirm(`Delete user '${username}'? This cannot be undone.`)) return;
  try {
    const resp = await apiFetch(`/api/admin/users/${userId}`, { method: "DELETE" });
    if (!resp) return;
    const data = await resp.json();
    if (data.error) { showToast(data.error, "error"); return; }
    showToast(`User '${username}' deleted.`, "success");
    await loadAdminUsers();
    await loadAdminStats();
  } catch (err) {
    showToast("Network error: " + err.message, "error");
  }
}

async function verifyLedger() {
  const resultEl = document.getElementById("ledgerVerifyResult");
  if (resultEl) resultEl.textContent = "Verifying…";
  try {
    const resp = await apiFetch("/api/audit/verify");
    if (!resp) return;
    const data = await resp.json();
    if (resultEl) {
      if (data.valid) {
        resultEl.innerHTML = `<span style="color:var(--success)">✅ Ledger is intact — all ${data.entry_count} entries verified.</span>`;
      } else {
        resultEl.innerHTML = `<span style="color:var(--danger)">❌ Integrity failure: ${data.error || "chain broken"}</span>`;
      }
    }
  } catch (err) {
    if (resultEl) resultEl.textContent = "Error: " + err.message;
  }
}

async function loadLedgerEntries() {
  const wrapper = document.getElementById("ledgerEntriesWrapper");
  const tbody = document.getElementById("ledgerBody");
  if (!wrapper || !tbody) return;
  wrapper.style.display = "";
  tbody.innerHTML = '<tr><td colspan="4" class="placeholder">Loading…</td></tr>';
  try {
    const resp = await apiFetch("/api/audit/entries");
    if (!resp) return;
    const data = await resp.json();
    const entries = (data.entries || []).slice().reverse();
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="placeholder">No entries yet.</td></tr>';
      return;
    }
    tbody.innerHTML = entries.map((e, i) => {
      const ts = e.timestamp ? new Date(e.timestamp).toLocaleString("en-GB", { timeZone: "UTC", hour12: false }) + " UTC" : "—";
      const shortHash = e.entry_hash ? e.entry_hash.substring(0, 16) + "…" : "—";
      return `<tr><td>${entries.length - i}</td><td>${ts}</td><td>${e.actor || "—"}</td><td style="font-family:monospace;font-size:.78rem;">${shortHash}</td></tr>`;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="placeholder">Error: ${err.message}</td></tr>`;
  }
}

// ============================================================
// API FETCH
// ============================================================
async function apiFetch(url, options = {}) {
  const resp = await fetch(url, options);
  if (resp.status === 401) {
    window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
    return null;
  }
  return resp;
}

async function runAnalysis(body, headers = {}) {
  const spinner = document.getElementById("spinner");
  spinner.classList.remove("hidden");

  try {
    const resp = await apiFetch("/api/analyze", { method: "POST", headers, body });
    if (!resp) return;
    const data = await resp.json();
    if (data.error) {
      showToast("Analysis error: " + data.error, "error");
      return;
    }
    renderResults(data);
  } catch (err) {
    showToast("Network error: " + err.message, "error");
  } finally {
    spinner.classList.add("hidden");
  }
}

// ============================================================
// CSV EXPORT (client-side for table)
// ============================================================
function exportTableCsv() {
  if (!_allAnomalies.length) { showToast("No data to export.", "error"); return; }
  const cols = ["ip_address","hour_bucket","anomaly_score","requests_per_hour","error_rate","unique_endpoints","post_ratio","is_off_hours","has_scanner_ua"];
  const header = cols.join(",");
  const rows = _allAnomalies.map(r => cols.map(c => {
    const v = r[c];
    if (v === null || v === undefined) return "";
    if (typeof v === "string" && v.includes(",")) return `"${v}"`;
    return v;
  }).join(","));
  const csv = [header, ...rows].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "logguard_anomalies.csv";
  a.click();
  showToast("CSV downloaded.", "success");
}

function copySummary() {
  if (!_lastData) { showToast("No data to copy.", "error"); return; }
  const d = _lastData;
  const text = [
    `LogGuard Audit Summary — ${new Date().toLocaleString()}`,
    `Engagement: ${document.getElementById("engagementSelect")?.value || "—"}`,
    `Auditor: ${document.body.dataset.username || "—"}`,
    "",
    `Total Log Entries:   ${(d.total_requests||0).toLocaleString()}`,
    `IP/Hour Buckets:     ${(d.total_ip_hour_buckets||0).toLocaleString()}`,
    `Anomalous Buckets:   ${(d.anomaly_count||0).toLocaleString()}`,
    `Normal Buckets:      ${(d.normal_count||0).toLocaleString()}`,
    `Anomaly Rate:        ${(d.anomaly_rate||0).toFixed(2)}%`,
    "",
    `Risk Distribution:`,
    ...Object.entries(d.risk_distribution||{}).map(([k,v]) => `  ${k}: ${v}`),
  ].join("\n");
  navigator.clipboard.writeText(text)
    .then(() => showToast("Summary copied to clipboard.", "success"))
    .catch(() => showToast("Clipboard access denied.", "error"));
}

// ============================================================
// EVENT LISTENERS
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
  // Apply saved theme
  applyTheme(getTheme());

  // Theme toggles
  document.getElementById("themeToggle")?.addEventListener("click", toggleTheme);
  document.getElementById("sidebarThemeToggle")?.addEventListener("click", toggleTheme);

  // Tab navigation (topbar)
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Sidebar tab links
  document.querySelectorAll("[data-tab-link]").forEach(li => {
    li.querySelector("a")?.addEventListener("click", () => switchTab(li.dataset.tabLink));
  });

  // Sidebar toggle
  document.getElementById("sidebarToggle")?.addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("collapsed");
    document.getElementById("workbenchMain").classList.toggle("sidebar-collapsed");
  });

  // File upload
  document.getElementById("fileInput")?.addEventListener("change", function () {
    const file = this.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("logfile", file);
    runAnalysis(fd);
  });

  // Sample logs
  document.getElementById("btnSample")?.addEventListener("click", () => {
    runAnalysis(JSON.stringify({ use_sample: true }), { "Content-Type": "application/json" });
  });

  // Drag & drop
  const uploadBox = document.getElementById("uploadBox");
  uploadBox?.addEventListener("dragover", e => { e.preventDefault(); uploadBox.classList.add("drag-over"); });
  uploadBox?.addEventListener("dragleave", () => uploadBox.classList.remove("drag-over"));
  uploadBox?.addEventListener("drop", e => {
    e.preventDefault();
    uploadBox.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("logfile", file);
    runAnalysis(fd);
  });

  // Table filters
  document.getElementById("tableSearch")?.addEventListener("input", () => { _currentPage = 1; renderTable(_allAnomalies); });
  document.getElementById("riskFilter")?.addEventListener("change", () => { _currentPage = 1; renderTable(_allAnomalies); });

  // Table page size
  document.getElementById("pageSizeSelect")?.addEventListener("change", function () {
    _pageSize = parseInt(this.value);
    _currentPage = 1;
    renderTable(_allAnomalies);
  });

  // Global search → sync table search
  document.getElementById("globalSearch")?.addEventListener("input", function () {
    const ts = document.getElementById("tableSearch");
    if (ts) { ts.value = this.value; ts.dispatchEvent(new Event("input")); }
    switchTab("tab-anomalies");
  });

  // Column sort
  document.querySelectorAll("thead th[data-sort]").forEach(th => {
    th.addEventListener("click", () => {
      if (_sortCol === th.dataset.sort) { _sortAsc = !_sortAsc; }
      else { _sortCol = th.dataset.sort; _sortAsc = false; }
      document.querySelectorAll("thead th").forEach(t => t.classList.remove("sorted-asc","sorted-desc"));
      th.classList.add(_sortAsc ? "sorted-asc" : "sorted-desc");
      _currentPage = 1;
      renderTable(_allAnomalies);
    });
  });

  // Export buttons
  document.getElementById("btnExportTableCsv")?.addEventListener("click", exportTableCsv);
  document.getElementById("btnCopySummary")?.addEventListener("click", copySummary);
  document.getElementById("btnPrintReport")?.addEventListener("click", () => window.print());

  // HTML Report download
  document.getElementById("btnDownloadHtmlReport")?.addEventListener("click", async () => {
    if (!_lastRunId) { showToast("Run an analysis first to generate a report.", "error"); return; }
    const a = document.createElement("a");
    a.href = `/api/runs/${_lastRunId}/report`;
    a.target = "_blank";
    a.download = `logguard_report_run_${_lastRunId}.html`;
    a.click();
    showToast("HTML report download started.", "success");
  });

  // PDF Report download
  document.getElementById("btnDownloadPdf")?.addEventListener("click", () => {
    if (!_lastRunId) { showToast("Run an analysis first to generate a report.", "error"); return; }
    const a = document.createElement("a");
    a.href = `/api/runs/${_lastRunId}/report/pdf`;
    a.download = `logguard_report_run_${_lastRunId}.pdf`;
    a.click();
    showToast("PDF report download started.", "success");
  });

  // Send via Email button
  document.getElementById("btnSendEmail")?.addEventListener("click", () => {
    if (!_lastRunId) { showToast("Run an analysis first to generate a report.", "error"); return; }
    openSendModal("email");
  });

  // Send via WhatsApp button
  document.getElementById("btnSendWhatsapp")?.addEventListener("click", () => {
    if (!_lastRunId) { showToast("Run an analysis first to generate a report.", "error"); return; }
    openSendModal("whatsapp");
  });

  // History tab
  document.getElementById("btnRefreshHistory")?.addEventListener("click", loadRunHistory);

  // Admin tab
  document.getElementById("btnCreateUser")?.addEventListener("click", createAdminUser);
  document.getElementById("btnVerifyLedger")?.addEventListener("click", verifyLedger);
  document.getElementById("btnLoadLedger")?.addEventListener("click", loadLedgerEntries);

  // Load history/admin panels when their tabs are activated
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      if (btn.dataset.tab === "tab-history") loadRunHistory();
      if (btn.dataset.tab === "tab-admin") loadAdminPanel();
    });
  });
  document.querySelectorAll("[data-tab-link]").forEach(li => {
    li.querySelector("a")?.addEventListener("click", () => {
      if (li.dataset.tabLink === "tab-history") loadRunHistory();
      if (li.dataset.tabLink === "tab-admin") loadAdminPanel();
    });
  });

  // Drill-down modal close
  document.getElementById("drillClose")?.addEventListener("click", closeDrillDown);
  document.getElementById("drillOverlay")?.addEventListener("click", e => {
    if (e.target === document.getElementById("drillOverlay")) closeDrillDown();
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      if (document.getElementById("sendModalOverlay")?.classList.contains("open")) {
        closeSendModal();
      } else {
        closeDrillDown();
      }
    }
  });

  // Send modal close / cancel
  document.getElementById("sendModalClose")?.addEventListener("click", closeSendModal);
  document.getElementById("sendModalCancel")?.addEventListener("click", closeSendModal);
  document.getElementById("sendModalOverlay")?.addEventListener("click", e => {
    if (e.target === document.getElementById("sendModalOverlay")) closeSendModal();
  });

  // Send modal submit
  document.getElementById("sendModalSubmit")?.addEventListener("click", submitSendModal);

  // Auto-load if results exist
  try {
    const resp = await apiFetch("/api/results");
    if (!resp) return;
    if (resp.ok) {
      const data = await resp.json();
      if (!data.error) renderResults(data);
    }
  } catch (_) { /* not ready */ }
});

// ============================================================
// SEND MODAL
// ============================================================
let _sendModalMode = ""; // "email" or "whatsapp"

function openSendModal(mode) {
  _sendModalMode = mode;
  const overlay   = document.getElementById("sendModalOverlay");
  const title     = document.getElementById("sendModalTitle");
  const desc      = document.getElementById("sendModalDesc");
  const label     = document.getElementById("sendModalLabel");
  const input     = document.getElementById("sendModalRecipient");
  const status    = document.getElementById("sendModalStatus");
  const submitBtn = document.getElementById("sendModalSubmit");

  if (!overlay) return;

  if (mode === "email") {
    title.textContent = "✉️ Send Report via Email";
    desc.textContent  = "Enter the recipient's email address. The PDF report will be attached and sent from the configured SMTP server.";
    label.textContent = "Recipient email address";
    input.type        = "email";
    input.placeholder = "colleague@example.com";
    submitBtn.className = "btn btn-primary";
    submitBtn.textContent = "Send Email";
  } else {
    title.textContent = "💬 Send Report via WhatsApp";
    desc.textContent  = "Enter the recipient's phone number in international format (e.g. +447911123456). The PDF will be sent via the Twilio WhatsApp API.";
    label.textContent = "Recipient WhatsApp number (E.164 format)";
    input.type        = "tel";
    input.placeholder = "+447911123456";
    submitBtn.className = "btn btn-success";
    submitBtn.textContent = "Send WhatsApp";
  }

  input.value = "";
  status.textContent = "";
  status.className = "send-modal-status hidden";
  overlay.classList.add("open");
  setTimeout(() => input.focus(), 120);
}

function closeSendModal() {
  const overlay = document.getElementById("sendModalOverlay");
  if (overlay) overlay.classList.remove("open");
}

async function submitSendModal() {
  const input     = document.getElementById("sendModalRecipient");
  const status    = document.getElementById("sendModalStatus");
  const submitBtn = document.getElementById("sendModalSubmit");
  if (!input || !status) return;

  const recipient = input.value.trim();
  if (!recipient) {
    showSendStatus("Please enter a recipient.", "error");
    return;
  }

  const endpoint = _sendModalMode === "email"
    ? `/api/runs/${_lastRunId}/send/email`
    : `/api/runs/${_lastRunId}/send/whatsapp`;

  submitBtn.disabled = true;
  submitBtn.textContent = "Sending…";
  showSendStatus("Sending, please wait…", "info");

  try {
    const resp = await apiFetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to: recipient }),
    });
    const data = resp ? await resp.json() : null;
    if (resp && resp.ok && data && data.ok) {
      showSendStatus(`✅ ${data.message}`, "ok");
      showToast(data.message, "success");
      setTimeout(closeSendModal, 2400);
    } else {
      const msg = data?.error || "Unknown error.";
      showSendStatus(`❌ ${msg}`, "error");
    }
  } catch (err) {
    showSendStatus(`❌ Network error: ${err.message}`, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = _sendModalMode === "email" ? "Send Email" : "Send WhatsApp";
  }
}

function showSendStatus(message, type) {
  const el = document.getElementById("sendModalStatus");
  if (!el) return;
  el.textContent = message;
  el.className = `send-modal-status status-${type}`;
}


