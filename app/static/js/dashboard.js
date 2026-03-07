/* ============================================================
   LogGuard – Dashboard JavaScript
   ============================================================ */

"use strict";

// ---------- Chart.js instances (kept for destroy/re-init) ----------
let timelineChart = null;
let statusChart   = null;
let methodChart   = null;
let pieChart      = null;

// ---------- Chart.js global defaults ----------
Chart.defaults.color         = "#8b949e";
Chart.defaults.borderColor   = "#30363d";
Chart.defaults.font.family   = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";

// ---------- Utility: format ISO string to HH:MM ----------
function fmtHour(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  return d.toISOString().substring(0, 16).replace("T", " ") + "Z";
}

// ---------- Utility: risk-score badge HTML ----------
function riskBadge(score) {
  const pct = (score * 100).toFixed(1);
  if (score >= 0.7) return `<span class="badge badge-danger">${pct}%</span>`;
  if (score >= 0.4) return `<span class="badge badge-warn">${pct}%</span>`;
  return `<span class="badge badge-ok">${pct}%</span>`;
}

// ---------- Utility: yes/no indicator ----------
function yesNo(val) {
  return val ? "✓" : "—";
}

// ---------- Render overview cards ----------
function renderCards(data) {
  document.getElementById("cardTotalRequests").textContent = data.total_requests.toLocaleString();
  document.getElementById("cardBuckets").textContent       = data.total_ip_hour_buckets.toLocaleString();
  document.getElementById("cardAnomalies").textContent     = data.anomaly_count.toLocaleString();
  document.getElementById("cardNormal").textContent        = data.normal_count.toLocaleString();
  document.getElementById("cardAnomalyRate").textContent   = data.anomaly_rate.toFixed(1) + "%";
}

// ---------- Render the timeline chart ----------
function renderTimeline(timeline) {
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
        backgroundColor: "rgba(248,81,73,.12)",
        fill: true,
        tension: 0.3,
        pointRadius: 4,
      }],
    },
    options: {
      responsive: true,
      scales: {
        y: { min: 0, max: 100, grid: { color: "#30363d" } },
        x: { grid: { color: "#30363d" }, ticks: { maxRotation: 45 } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

// ---------- Render HTTP status donut ----------
function renderStatusChart(dist) {
  const labels = Object.keys(dist).sort();
  const values = labels.map(k => dist[k]);
  const palette = ["#3fb950","#58a6ff","#d29922","#f85149","#bc8cff","#79c0ff"];

  if (statusChart) statusChart.destroy();
  const ctx = document.getElementById("statusChart").getContext("2d");
  statusChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: palette, borderWidth: 2, borderColor: "#1c2128" }],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "right" } },
    },
  });
}

// ---------- Render request method bar chart ----------
function renderMethodChart(dist) {
  const labels = Object.keys(dist);
  const values = labels.map(k => dist[k]);

  if (methodChart) methodChart.destroy();
  const ctx = document.getElementById("methodChart").getContext("2d");
  methodChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Requests",
        data: values,
        backgroundColor: "#58a6ff",
        borderRadius: 4,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { grid: { color: "#30363d" } },
        x: { grid: { display: false } },
      },
    },
  });
}

// ---------- Render normal vs anomaly pie ----------
function renderPieChart(normalCount, anomalyCount) {
  if (pieChart) pieChart.destroy();
  const ctx = document.getElementById("pieChart").getContext("2d");
  pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["Normal", "Anomalous"],
      datasets: [{
        data: [normalCount, anomalyCount],
        backgroundColor: ["#3fb950", "#f85149"],
        borderWidth: 2,
        borderColor: "#1c2128",
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "right" } },
    },
  });
}

// ---------- Build anomaly table ----------
function renderTable(anomalies) {
  const tbody = document.getElementById("anomalyBody");
  if (!anomalies || anomalies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="10" class="placeholder">No anomalies detected.</td></tr>';
    return;
  }

  tbody.innerHTML = anomalies.map((r, i) => `
    <tr class="${r.anomaly_score >= 0.7 ? "row-danger" : ""}">
      <td>${i + 1}</td>
      <td><code>${r.ip_address}</code></td>
      <td>${fmtHour(r.hour_bucket)}</td>
      <td>${riskBadge(r.anomaly_score)}</td>
      <td>${Math.round(r.requests_per_hour)}</td>
      <td>${(r.error_rate * 100).toFixed(1)}%</td>
      <td>${r.unique_endpoints}</td>
      <td>${(r.post_ratio * 100).toFixed(1)}%</td>
      <td>${yesNo(r.is_off_hours)}</td>
      <td>${r.has_scanner_ua ? '<span class="badge badge-danger">YES</span>' : "—"}</td>
    </tr>
  `).join("");
}

// ---------- Render full results ----------
function renderResults(data) {
  renderCards(data);
  if (data.timeline && data.timeline.length)           renderTimeline(data.timeline);
  if (data.status_code_distribution)                   renderStatusChart(data.status_code_distribution);
  if (data.method_distribution)                        renderMethodChart(data.method_distribution);
  renderPieChart(data.normal_count, data.anomaly_count);
  renderTable(data.top_anomalies || []);

  // Smooth-scroll to overview
  document.getElementById("overview").scrollIntoView({ behavior: "smooth" });
}

// ---------- Call backend /api/analyze ----------
async function runAnalysis(body, headers = {}) {
  const spinner = document.getElementById("spinner");
  spinner.classList.remove("hidden");

  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers,
      body,
    });
    const data = await resp.json();
    if (data.error) {
      alert("Analysis error: " + data.error);
      return;
    }
    renderResults(data);
  } catch (err) {
    alert("Network error: " + err.message);
  } finally {
    spinner.classList.add("hidden");
  }
}

// ---------- Event: file input ----------
document.getElementById("fileInput").addEventListener("change", function () {
  const file = this.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("logfile", file);
  runAnalysis(fd);
});

// ---------- Event: analyse sample ----------
document.getElementById("btnSample").addEventListener("click", function () {
  runAnalysis(
    JSON.stringify({ use_sample: true }),
    { "Content-Type": "application/json" }
  );
});

// ---------- Event: drag & drop ----------
const uploadBox = document.getElementById("uploadBox");
uploadBox.addEventListener("dragover", e => { e.preventDefault(); uploadBox.classList.add("drag-over"); });
uploadBox.addEventListener("dragleave", ()  => uploadBox.classList.remove("drag-over"));
uploadBox.addEventListener("drop", e => {
  e.preventDefault();
  uploadBox.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("logfile", file);
  runAnalysis(fd);
});

// ---------- Table search filter ----------
document.getElementById("tableSearch").addEventListener("input", function () {
  const q = this.value.toLowerCase();
  const rows = document.querySelectorAll("#anomalyBody tr");
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(q) ? "" : "none";
  });
});

// ---------- Auto-load results if they already exist ----------
window.addEventListener("DOMContentLoaded", async () => {
  try {
    const resp = await fetch("/api/results");
    if (resp.ok) {
      const data = await resp.json();
      if (!data.error) renderResults(data);
    }
  } catch (_) { /* server not ready yet */ }
});
