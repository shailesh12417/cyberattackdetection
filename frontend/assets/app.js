/* ===== SAMPLE PAYLOADS ===== */
const samplePayload = [
  { duration:0, src_bytes:181, dst_bytes:5450, count:2, srv_count:2, same_srv_rate:1.0, diff_srv_rate:0.0, dst_host_count:9, dst_host_srv_count:9, protocol_type:"tcp", service:"http", flag:"SF" },
  { duration:0, src_bytes:0, dst_bytes:0, count:240, srv_count:12, same_srv_rate:0.05, diff_srv_rate:0.87, dst_host_count:255, dst_host_srv_count:17, protocol_type:"tcp", service:"smtp", flag:"S0" },
  { duration:10, src_bytes:500, dst_bytes:120, count:1, srv_count:1, same_srv_rate:1.0, diff_srv_rate:0.0, dst_host_count:3, dst_host_srv_count:3, protocol_type:"tcp", service:"telnet", flag:"SF" }
];

const attackScenarioPayload = [
  { duration:0, src_bytes:0, dst_bytes:0, count:240, srv_count:15, same_srv_rate:0.04, diff_srv_rate:0.89, dst_host_count:255, dst_host_srv_count:12, protocol_type:"tcp", service:"smtp", flag:"S0" },
  { duration:1, src_bytes:18, dst_bytes:0, count:7, srv_count:2, same_srv_rate:0.22, diff_srv_rate:0.75, dst_host_count:90, dst_host_srv_count:16, protocol_type:"udp", service:"private", flag:"REJ" },
  { duration:12, src_bytes:3900, dst_bytes:250, count:1, srv_count:1, same_srv_rate:1.0, diff_srv_rate:0.0, dst_host_count:2, dst_host_srv_count:2, protocol_type:"tcp", service:"shell", flag:"SF" }
];

/* ===== STATE ===== */
const el = (id) => document.getElementById(id);

const AppState = {
  chatHistory: [],
  latestSummary: null,
  latestDashboard: null,
  currentPredictions: [],
  currentPage: 1,
  rowsPerPage: 50,
  chatOpen: false,
  activePage: "dashboard",
  attackChart: null,
  radarChart: null,
  timelineChart: null,
  timelineData: [],
  sparklines: { total: [], malicious: [], benign: [] },
  sparkCharts: {},
  liveInterval: null,
  cumulative: { total: 0, malicious: 0, benign: 0 }
};

/* ===== PAGE TITLES ===== */
const pageMeta = {
  dashboard: { title: "Dashboard", subtitle: "Real-time threat overview and system health" },
  analysis: { title: "Analysis", subtitle: "Submit traffic data for ML-powered classification" },
  predictions: { title: "Predictions", subtitle: "Per-record classification results and confidence" },
  investigation: { title: "Investigation", subtitle: "Focused triage for the most critical incident" },
  benchmark: { title: "Benchmark", subtitle: "Multi-model performance comparison" }
};

/* ===== NAVIGATION ===== */
function navigateTo(pageId) {
  AppState.activePage = pageId;
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item[data-page]").forEach(n => n.classList.remove("active"));
  const page = el("page" + pageId.charAt(0).toUpperCase() + pageId.slice(1));
  const nav = document.querySelector(`.nav-item[data-page="${pageId}"]`);
  if (page) page.classList.add("active");
  if (nav) nav.classList.add("active");
  const meta = pageMeta[pageId];
  if (meta) {
    el("pageTitle").textContent = meta.title;
    el("pageSubtitle").textContent = meta.subtitle;
  }
  // close mobile sidebar
  el("sidebar").classList.remove("mobile-open");
  el("sidebarOverlay").classList.remove("visible");
  // re-trigger scroll reveals on the new page
  if (page) page.querySelectorAll('.reveal').forEach(r => { r.classList.remove('visible'); requestAnimationFrame(() => r.classList.add('visible')); });
}

/* ===== THEME ===== */
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute("data-theme");
  html.setAttribute("data-theme", current === "dark" ? "light" : "dark");
  localStorage.setItem("theme", html.getAttribute("data-theme"));
}

function restoreTheme() {
  const saved = localStorage.getItem("theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
}

/* ===== SIDEBAR COLLAPSE ===== */
function toggleSidebar() {
  el("sidebar").classList.toggle("collapsed");
  localStorage.setItem("sidebar-collapsed", el("sidebar").classList.contains("collapsed"));
}

function restoreSidebar() {
  if (localStorage.getItem("sidebar-collapsed") === "true") el("sidebar").classList.add("collapsed");
}

/* ===== CHAT PANEL ===== */
function toggleChat() {
  AppState.chatOpen = !AppState.chatOpen;
  el("chatPanel").classList.toggle("open", AppState.chatOpen);
  el("chatFab").classList.toggle("open", AppState.chatOpen);
}

/* ===== TOAST ===== */
function showToast(message, type = "info") {
  const container = el("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "toastOut 0.3s ease forwards";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

/* ===== API HELPERS ===== */
const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : "";
const TOKEN_KEY = 'cyberguard_token';

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function clearSessionAndRedirect() {
  localStorage.removeItem(TOKEN_KEY);
  window.location.href = 'auth.html';
}

async function fetchJSON(url, options = {}) {
  const token = getToken();
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const response = await fetch(url, { ...options, headers });
  if (response.status === 401) {
    clearSessionAndRedirect();
  }
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}

async function fetchForm(url, formData) {
  const token = getToken();
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const response = await fetch(url, { method: "POST", headers, body: formData });
  if (response.status === 401) {
    clearSessionAndRedirect();
  }
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}

async function fetchProtectedBlob(url) {
  const token = getToken();
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const response = await fetch(url, { headers });
  if (response.status === 401) {
    clearSessionAndRedirect();
  }
  if (!response.ok) {
    let data = {};
    try { data = await response.json(); } catch {}
    throw new Error(data.detail || "Download failed");
  }
  return response.blob();
}

async function validateSession() {
  if (!getToken()) {
    clearSessionAndRedirect();
    return false;
  }
  try {
    await fetchJSON(`${API_BASE}/api/v1/health`);
    return true;
  } catch {
    return false;
  }
}

/* ===== STATUS ===== */
function renderStatus(health, model) {
  el("healthStatus").textContent = health.status === "ok" ? "Healthy" : "Down";
  el("modelStatus").textContent = model.ready ? "Model Ready" : "Not Trained";
  el("llmStatus").textContent = model.llm_enabled ? "LLM On" : "Fallback";
}

async function loadStatus() {
  const [health, model] = await Promise.all([fetchJSON(`${API_BASE}/api/v1/health`), fetchJSON(`${API_BASE}/api/v1/model/status`)]);
  renderStatus(health, model);
}

/* ===== BENCHMARK ===== */
function renderBenchmark(benchmark) {
  el("benchmarkTable").innerHTML = Object.entries(benchmark.models || {})
    .map(([name, p]) => {
      const isBest = benchmark.selected_model === name;
      const acc = p.metrics.accuracy, f1 = p.metrics.f1_score;
      return `
      <tr class="${isBest ? 'bench-best' : ''}">
        <td><strong>${name}</strong>${isBest ? ' <span style="color:var(--accent)">★ Best</span>' : ''}</td>
        <td><div class="bench-bar-cell"><span class="bench-bar bench-bar-accuracy" style="width:${acc * 100}px"></span>${acc}</div></td>
        <td>${p.metrics.precision}</td>
        <td>${p.metrics.recall}</td>
        <td><div class="bench-bar-cell"><span class="bench-bar bench-bar-f1" style="width:${f1 * 100}px"></span>${f1}</div></td>
        <td>${p.metrics.roc_auc ?? "n/a"}</td>
      </tr>`;
    }).join("");
}

async function loadBenchmark() {
  try {
    const b = await fetchJSON(`${API_BASE}/api/v1/benchmark`);
    renderBenchmark(b);
  } catch { el("benchmarkTable").innerHTML = `<tr><td colspan="6" class="empty-state">Train the model to view benchmark results.</td></tr>`; }
}

/* ===== BAR LIST ===== */
function renderBarList(targetId, entries = [], formatter = i => i.value) {
  el(targetId).innerHTML = (entries || []).map(item => `
    <div class="bar-row">
      <div class="bar-label">${item.label}</div>
      <div class="bar-track"><span style="width:${Math.max(6, Number(item.value) * 18)}%"></span></div>
      <div class="bar-value">${formatter(item)}</div>
    </div>
  `).join("");
}

/* ===== CHARTS ===== */
function updateAttackChart(distribution = {}) {
  const ctx = el("attackChart");
  if (!ctx) return;
  const labels = Object.keys(distribution);
  const data = Object.values(distribution);
  const colorMap = {
    normal: '#34d399', benign: '#34d399',
    dos: '#fb7185', probe: '#fbbf24',
    r2l: '#38bdf8', u2r: '#c084fc'
  };
  const colors = labels.map(l => colorMap[l.toLowerCase()] || '#f97316');

  if (AppState.attackChart) {
    AppState.attackChart.data.labels = labels;
    AppState.attackChart.data.datasets[0].data = data;
    AppState.attackChart.data.datasets[0].backgroundColor = colors;
    AppState.attackChart.update();
  } else {
    AppState.attackChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderWidth: 0,
          hoverOffset: 10
        }]
      },
      options: {
        cutout: "70%",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

/* ===== DASHBOARD RENDERING ===== */
function renderDashboard(dashboard) {
  AppState.latestDashboard = dashboard;
  if (!dashboard) return;
  renderBarList("severityBreakdown", Object.entries(dashboard.severity_breakdown || {}).map(([label, value]) => ({ label, value })), i => i.value);
  renderBarList("confidenceBands", dashboard.confidence_bands || [], i => i.value);
  el("recentAlerts").innerHTML = (dashboard.recent_alerts || [])
    .map(a => `
      <div class="alert-card severity-${a.severity}">
        <strong>${a.label.toUpperCase()}</strong>
        <span>${a.message}</span>
        <small>Seq ${a.sequence} · ${a.severity} · conf ${a.confidence}</small>
      </div>
    `).join("") || `<p class="empty-state">No alerts yet.</p>`;
}

function renderInvestigation(predictions, summary) {
  if (!predictions || !predictions.length) return;
  const ranked = [...predictions].sort((a, b) => {
    const r = { low: 0, medium: 1, high: 2, critical: 3 };
    return ((r[b.severity] || 0) - (r[a.severity] || 0)) || ((b.confidence || 0) - (a.confidence || 0));
  });
  const p = ranked[0];
  el("incidentHeadline").textContent = `${p.label.toUpperCase()} is the primary incident.`;
  el("incidentNarrative").textContent = `Highest severity: ${summary.highest_severity}, confidence ${p.confidence}. Analyst attention should focus on ${p.label} patterns first.`;
  el("riskIndicators").innerHTML = (p.top_contributors || []).length
    ? p.top_contributors.map(i => `<div class="signal-card"><strong>${i.feature}</strong><span>${i.value}</span><p>${i.note}</p></div>`).join("")
    : `<div class="signal-card"><strong>No strong heuristic signals</strong><p>Use prediction probabilities for deeper analysis.</p></div>`;
  el("incidentActions").innerHTML = "";
  (p.mitigation || []).forEach(i => {
    const li = document.createElement("li");
    li.textContent = i;
    el("incidentActions").appendChild(li);
  });
  const topP = Object.entries(p.probabilities || {}).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([l, s]) => `${l}: ${s}`).join(" | ");
  el("modelInsight").textContent = `Model prioritized ${p.label} due to high-risk behavioral features. Top scores: ${topP}.`;
}

/* ===== ANIMATED COUNTER ===== */
function animateValue(elementId, end, duration = 800) {
  const elem = el(elementId);
  if (!elem) return;
  const start = parseInt(elem.textContent) || 0;
  if (start === end) { elem.textContent = end; return; }
  const range = end - start;
  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    elem.textContent = Math.round(start + range * eased);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ===== RADAR CHART ===== */
function initRadarChart() {
  const ctx = el('radarChart');
  if (!ctx) return;
  const labels = ['DoS', 'Probe', 'R2L', 'U2R', 'Normal'];
  AppState.radarChart = new Chart(ctx, {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Threat Level',
        data: [0, 0, 0, 0, 0],
        borderColor: 'rgba(168,85,247,0.8)',
        backgroundColor: 'rgba(168,85,247,0.15)',
        borderWidth: 2,
        pointBackgroundColor: '#a855f7',
        pointBorderColor: '#fff',
        pointRadius: 4
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { r: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.1)' }, ticks: { display: false }, pointLabels: { color: 'rgba(148,163,184,0.7)', font: { size: 11 } } } },
      plugins: { legend: { display: false } },
      animation: { duration: 1000, easing: 'easeOutQuart' }
    }
  });
}

function updateRadarChart(distribution) {
  if (!AppState.radarChart || !distribution) return;
  const map = { dos: 0, probe: 1, r2l: 2, u2r: 3, normal: 4 };
  const data = [0, 0, 0, 0, 0];
  Object.entries(distribution).forEach(([k, v]) => { const i = map[k.toLowerCase()]; if (i !== undefined) data[i] = v; });
  AppState.radarChart.data.datasets[0].data = data;
  AppState.radarChart.update('active');
}

/* ===== TIMELINE CHART ===== */
function initTimelineChart() {
  const ctx = el('timelineChart');
  if (!ctx) return;
  AppState.timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Malicious', data: [], borderColor: '#fb7185', backgroundColor: 'rgba(251,113,133,0.1)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3 },
        { label: 'Benign', data: [], borderColor: '#34d399', backgroundColor: 'rgba(52,211,153,0.1)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3 }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(148,163,184,0.08)' }, ticks: { color: 'rgba(148,163,184,0.5)', maxTicksLimit: 8 } },
        y: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.08)' }, ticks: { color: 'rgba(148,163,184,0.5)' } }
      },
      plugins: { legend: { labels: { color: 'rgba(148,163,184,0.7)', usePointStyle: true, pointStyle: 'circle' } } },
      animation: { duration: 800, easing: 'easeOutQuart' }
    }
  });
}

function updateTimelineChart(summary) {
  if (!AppState.timelineChart || !summary) return;
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const ds = AppState.timelineChart.data;
  ds.labels.push(now);
  ds.datasets[0].data.push(summary.malicious_records || 0);
  ds.datasets[1].data.push(summary.benign_records || 0);
  if (ds.labels.length > 12) { ds.labels.shift(); ds.datasets[0].data.shift(); ds.datasets[1].data.shift(); }
  AppState.timelineChart.update('active');
}

/* ===== SPARKLINES ===== */
function updateSparkline(canvasId, dataArr, color) {
  const ctx = el(canvasId);
  if (!ctx) return;
  if (AppState.sparkCharts[canvasId]) { AppState.sparkCharts[canvasId].destroy(); }
  AppState.sparkCharts[canvasId] = new Chart(ctx, {
    type: 'line',
    data: { labels: dataArr.map((_, i) => i), datasets: [{ data: dataArr, borderColor: color, borderWidth: 1.5, fill: false, tension: 0.4, pointRadius: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { display: false }, y: { display: false } }, plugins: { legend: { display: false }, tooltip: { enabled: false } }, animation: { duration: 400 } }
  });
}

function pushSparklineData(summary) {
  AppState.sparklines.total.push(AppState.cumulative.total || 0);
  AppState.sparklines.malicious.push(AppState.cumulative.malicious || 0);
  AppState.sparklines.benign.push(AppState.cumulative.benign || 0);
  if (AppState.sparklines.total.length > 15) { AppState.sparklines.total.shift(); AppState.sparklines.malicious.shift(); AppState.sparklines.benign.shift(); }
  updateSparkline('sparkTotal', AppState.sparklines.total, '#a855f7');
  updateSparkline('sparkMalicious', AppState.sparklines.malicious, '#fb7185');
  updateSparkline('sparkBenign', AppState.sparklines.benign, '#34d399');
}

/* ===== ACTIVITY FEED ===== */
function addActivityEntries(predictions) {
  const feed = el('activityFeed');
  if (!feed || !predictions || !predictions.length) return;
  // Clear empty state
  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  // Add top 3 predictions as feed entries
  predictions.slice(0, 3).forEach(p => {
    const isMalicious = p.label !== 'normal' && p.label !== 'benign';
    const entry = document.createElement('div');
    entry.className = `activity-entry type-${isMalicious ? 'malicious' : 'benign'}`;
    entry.innerHTML = `<span class="activity-time">${now}</span><span class="activity-label severity-${p.severity || 'low'}">${p.label}</span><span class="activity-detail">conf ${p.confidence} · ${p.severity || 'low'}</span>`;
    feed.insertBefore(entry, feed.firstChild);
  });
  // Keep max 20 entries
  while (feed.children.length > 20) feed.removeChild(feed.lastChild);
}

function renderSummary(payload) {
  // 1. Update the raw cumulative numbers
  AppState.cumulative.total += (payload.summary.total_records || 0);
  AppState.cumulative.malicious += (payload.summary.malicious_records || 0);
  AppState.cumulative.benign += (payload.summary.benign_records || 0);

  // 2. Build/Update the Global Summary (This is what the Chatbot sees)
  if (!AppState.latestSummary) {
    AppState.latestSummary = JSON.parse(JSON.stringify(payload.summary));
  }
  
  // Always force global totals into the latestSummary object
  AppState.latestSummary.total_records = AppState.cumulative.total;
  AppState.latestSummary.malicious_records = AppState.cumulative.malicious;
  AppState.latestSummary.benign_records = AppState.cumulative.benign;
  
  // Accumulate attack distribution across the session
  if (AppState.latestSummary !== payload.summary) {
    Object.entries(payload.summary.attack_distribution || {}).forEach(([label, count]) => {
      // If we just initialized from payload.summary, don't double-add the first batch
      if (AppState.cumulative.total > payload.summary.total_records) {
        AppState.latestSummary.attack_distribution[label] = (AppState.latestSummary.attack_distribution[label] || 0) + count;
      }
    });
  }

  // Update highest severity observed in the session
  const severityOrder = ["low", "medium", "high", "critical"];
  const currentIdx = severityOrder.indexOf((AppState.latestSummary.highest_severity || "low").toLowerCase());
  const newIdx = severityOrder.indexOf((payload.summary.highest_severity || "low").toLowerCase());
  if (newIdx > currentIdx) {
    AppState.latestSummary.highest_severity = payload.summary.highest_severity;
  }

  // 3. Update the Dashboard Cards
  el("chatContextText").textContent = `Session: ${AppState.latestSummary.highest_severity} severity`;
  
  animateValue("totalRecords", AppState.cumulative.total);
  animateValue("maliciousRecords", AppState.cumulative.malicious);
  animateValue("benignRecords", AppState.cumulative.benign);

  const hs = AppState.latestSummary.highest_severity;
  const hsEl = el("highestSeverity");
  hsEl.textContent = hs === "—" ? hs : hs.charAt(0).toUpperCase() + hs.slice(1);
  hsEl.className = hs === "—" ? "stat-value" : `stat-value severity-${hs}`;
  
  // Distribution legend (Cumulative)
  el("distribution").innerHTML = Object.entries(AppState.latestSummary.attack_distribution || {})
    .map(([l, c]) => `<span class="badge">${l}: ${c}</span>`).join("");
    
  // 4. Update the Analyst Assistant Card (Cumulative)
  // We reconstruct the narrative to use session totals so it "moves" with the live monitor.
  const dist = Object.entries(AppState.latestSummary.attack_distribution)
    .map(([l, c]) => `${l}: ${c}`).join(", ");
  
  const cumulativeNarrative = `Analyzed ${AppState.cumulative.total} records total. ` +
    `Highest severity observed is ${AppState.latestSummary.highest_severity}. ` +
    `Session Attack Mix: ${dist || 'no attacks detected'}.`;

  el("assistantSummary").innerHTML = `<small style="opacity:0.7; display:block; margin-bottom:4px;">[Session Intelligence]</small>${cumulativeNarrative}`;
  
  el("remediationList").innerHTML = "";
  // We use the highest severity of the session to determine remediation steps
  const hsKey = AppState.latestSummary.highest_severity.toLowerCase();
  const guidance = {
    critical: [
      "Isolate affected hosts showing repeated malicious patterns.",
      "Block suspicious IPs and ports at the firewall layer.",
      "Collect packet captures for forensic validation.",
      "Rotate credentials for potentially impacted users."
    ],
    high: [
      "Rate-limit or block suspected sources at the edge.",
      "Check server capacity and connection bursts.",
      "Review firewall logs for repeated discovery attempts."
    ],
    medium: [
      "Inspect source hosts for scanning behavior.",
      "Tune IDS rules for reconnaissance detection.",
      "Validate probes against trusted asset lists."
    ],
    low: [
      "Continue baseline monitoring.",
      "Store flow as reference traffic for model retraining."
    ]
  };
  
  (guidance[hsKey] || guidance.low).forEach(i => {
    const li = document.createElement("li");
    li.textContent = i;
    el("remediationList").appendChild(li);
  });
  
  // 5. Update UI Charts and Predictions
  const newPredictions = payload.predictions || [];
  AppState.currentPredictions = [...newPredictions, ...AppState.currentPredictions].slice(0, 1000);
  
  renderPredictionPage(1);
  renderDashboard(payload.dashboard);
  renderInvestigation(payload.predictions, payload.summary);
  updateAttackChart(AppState.latestSummary.attack_distribution);
  updateRadarChart(AppState.latestSummary.attack_distribution);
  updateTimelineChart(payload.summary);
  pushSparklineData(payload.summary);
  addActivityEntries(payload.predictions);
}

function renderSavedAnalysis(payload) {
  if (!payload || !payload.summary) return;

  AppState.cumulative = {
    total: payload.summary.total_records || 0,
    malicious: payload.summary.malicious_records || 0,
    benign: payload.summary.benign_records || 0
  };
  AppState.latestSummary = JSON.parse(JSON.stringify(payload.summary));
  AppState.currentPredictions = payload.predictions || [];

  el("chatContextText").textContent = `Session: ${AppState.latestSummary.highest_severity} severity`;
  el("totalRecords").textContent = AppState.cumulative.total;
  el("maliciousRecords").textContent = AppState.cumulative.malicious;
  el("benignRecords").textContent = AppState.cumulative.benign;

  const hs = AppState.latestSummary.highest_severity || "low";
  const hsEl = el("highestSeverity");
  hsEl.textContent = hs === "â€”" ? hs : hs.charAt(0).toUpperCase() + hs.slice(1);
  hsEl.className = hs === "â€”" ? "stat-value" : `stat-value severity-${hs}`;

  el("distribution").innerHTML = Object.entries(AppState.latestSummary.attack_distribution || {})
    .map(([l, c]) => `<span class="badge">${l}: ${c}</span>`).join("");

  const dist = Object.entries(AppState.latestSummary.attack_distribution || {})
    .map(([l, c]) => `${l}: ${c}`).join(", ");
  el("assistantSummary").innerHTML = `<small style="opacity:0.7; display:block; margin-bottom:4px;">[Saved Session]</small>` +
    (payload.assistant_summary || `Analyzed ${AppState.cumulative.total} records total. Highest severity observed is ${hs}. Session Attack Mix: ${dist || 'no attacks detected'}.`);

  el("remediationList").innerHTML = "";
  (payload.remediation || []).forEach(i => {
    const li = document.createElement("li");
    li.textContent = i;
    el("remediationList").appendChild(li);
  });

  renderPredictionPage(1);
  renderDashboard(payload.dashboard);
  renderInvestigation(AppState.currentPredictions, AppState.latestSummary);
  updateAttackChart(AppState.latestSummary.attack_distribution);
  updateRadarChart(AppState.latestSummary.attack_distribution);
  addActivityEntries(AppState.currentPredictions.slice(0, 5));
}

async function loadSavedAnalysis() {
  try {
    const payload = await fetchJSON(`${API_BASE}/api/v1/analysis/state`);
    if (payload.has_data && payload.state) {
      renderSavedAnalysis(payload.state);
      showToast("Previous analysis loaded", "success");
    }
  } catch (err) {
    showToast(`Saved analysis could not load: ${err.message}`, "error");
  }
}

/* ===== LIVE MONITORING ===== */
function toggleLiveMonitoring() {
  const btn = el("liveMonitorBtn");
  if (AppState.liveInterval) {
    clearInterval(AppState.liveInterval);
    AppState.liveInterval = null;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v10"/><path d="M18.4 4.6l-4.4 4.4"/><path d="M2 12h10"/><path d="M4.6 18.4l4.4-4.4"/><path d="M12 22v-10"/><path d="M5.6 5.6l4.4 4.4"/><path d="M22 12h-10"/><path d="M19.4 19.4l-4.4-4.4"/></svg> Live Monitor: Off`;
    btn.classList.remove("active");
    showToast("Live monitoring stopped", "info");
  } else {
    showToast("Live monitoring started", "success");
    btn.classList.add("active");
    btn.innerHTML = `<span class="pill-dot" style="background:var(--danger); box-shadow:0 0 8px var(--danger); margin-right:8px;"></span> Live Monitor: ON`;
    
    AppState.liveInterval = setInterval(async () => {
      try {
        const isAttack = Math.random() > 0.7;
        const data = isAttack ? attackScenarioPayload : samplePayload;
        const payload = await fetchJSON(`${API_BASE}/api/v1/predict`, { 
          method: "POST", 
          body: JSON.stringify({ records: data, explain: true }) 
        });
        renderSummary(payload);
      } catch (err) {
        console.error("Live monitoring failed", err);
      }
    }, 4000);
  }
}

async function resetDashboard() {
  try {
    await fetchJSON(`${API_BASE}/api/v1/analysis/state`, { method: "DELETE" });
  } catch (err) {
    showToast(`Reset failed: ${err.message}`, "error");
    return;
  }

  AppState.cumulative = { total: 0, malicious: 0, benign: 0 };
  AppState.latestSummary = null;
  AppState.currentPredictions = [];
  AppState.sparklines = { total: [], malicious: [], benign: [] };
  AppState.timelineData = [];
  
  // Clear UI elements
  el("totalRecords").textContent = "0";
  el("maliciousRecords").textContent = "0";
  el("benignRecords").textContent = "0";
  el("highestSeverity").textContent = "—";
  el("highestSeverity").className = "stat-value";
  el("predictionTable").innerHTML = "";
  el("activityFeed").innerHTML = '<p class="empty-state">Activity will appear here when analysis runs.</p>';
  el("recentAlerts").innerHTML = '<p class="empty-state">No alerts yet — run an analysis to see results.</p>';
  el("remediationList").innerHTML = "";
  el("assistantSummary").textContent = "Run an analysis to generate an attack narrative.";
  
  // Reset charts if possible
  if (AppState.attackChart) AppState.attackChart.destroy(); AppState.attackChart = null;
  if (AppState.radarChart) { AppState.radarChart.data.datasets[0].data = [0,0,0,0,0]; AppState.radarChart.update(); }
  if (AppState.timelineChart) { AppState.timelineChart.data.labels = []; AppState.timelineChart.data.datasets.forEach(d => d.data = []); AppState.timelineChart.update(); }
  Object.values(AppState.sparkCharts).forEach(c => c.destroy());
  AppState.sparkCharts = {};
  
  showToast("Dashboard metrics reset", "info");
}

/* ===== PREDICTIONS TABLE ===== */
window.renderPredictionPage = function(page) {
  AppState.currentPage = page;
  const s = (page - 1) * AppState.rowsPerPage, e = s + AppState.rowsPerPage;
  const data = AppState.currentPredictions.slice(s, e);
  el("predictionTable").innerHTML = data.map((item, i) => {
    const idx = s + i + 1;
    const probs = Object.entries(item.probabilities || {}).sort((a,b) => b[1]-a[1]).slice(0,3).map(([l,v]) => `${l}: ${v}`).join(", ");
    return `<tr><td>${idx}</td><td>${item.label}</td><td>${item.confidence}</td><td class="severity-${item.severity || "unknown"}">${item.severity || "unknown"}</td><td>${item.attack_description||"—"}</td><td>${probs}</td></tr>`;
  }).join("");
  renderPaginationControls();
};

window.renderPaginationControls = function() {
  const total = Math.ceil(AppState.currentPredictions.length / AppState.rowsPerPage);
  const c = el("paginationControls");
  if (!c) return;
  if (total <= 1) { c.innerHTML = ""; return; }
  c.innerHTML = `
    <button class="btn btn-outline btn-sm" onclick="renderPredictionPage(${AppState.currentPage - 1})" ${AppState.currentPage === 1 ? 'disabled' : ''}>Prev</button>
    <span class="page-info">Page ${AppState.currentPage} / ${total}</span>
    <button class="btn btn-outline btn-sm" onclick="renderPredictionPage(${AppState.currentPage + 1})" ${AppState.currentPage === total ? 'disabled' : ''}>Next</button>
  `;
};

/* ===== ACTIONS ===== */
async function bootstrapModel() {
  const btn = el("trainBtn");
  btn.disabled = true; btn.innerHTML = "Training...";
  try {
    await fetchJSON(`${API_BASE}/api/v1/train`, { method: "POST", body: JSON.stringify({ csv_path: "data/network_traffic_sample.csv", target_column: "label", dataset_profile: el("datasetProfile").value }) });
    await Promise.all([loadStatus(), loadBenchmark()]);
    btn.innerHTML = "✓ Model Ready"; showToast("Model trained successfully", "success");
  } catch (err) { showToast(err.message, "error"); btn.innerHTML = "Prepare Model"; }
  finally { btn.disabled = false; }
}

async function analyzeTraffic() {
  try {
    const records = JSON.parse(el("trafficInput").value);
    const payload = await fetchJSON(`${API_BASE}/api/v1/predict`, { method: "POST", body: JSON.stringify({ records, explain: true }) });
    renderSummary(payload);
    showToast("Analysis complete", "success");
    navigateTo("dashboard");
  } catch (err) { showToast(`Analysis failed: ${err.message}`, "error"); }
}

async function analyzeCsv() {
  const file = el("csvFileInput").files[0];
  if (!file) { showToast("Choose a CSV file first", "error"); return; }
  const fd = new FormData(); fd.append("file", file);
  try {
    const payload = await fetchForm(`${API_BASE}/api/v1/predict/csv`, fd);
    renderSummary(payload);
    showToast("CSV analysis complete", "success");
    navigateTo("dashboard");
  } catch (err) { showToast(`CSV failed: ${err.message}`, "error"); }
}

function handleLoadSample() {
  el("trafficInput").value = JSON.stringify(samplePayload, null, 2);
  navigateTo("analysis");
  showToast("Sample traffic loaded", "success");
}

function handleLoadScenario() {
  el("trafficInput").value = JSON.stringify(attackScenarioPayload, null, 2);
  navigateTo("analysis");
  showToast("Attack scenario loaded", "success");
}

/* ===== CHAT ===== */
function appendChatMessage(role, content) {
  // Remove typing indicator if present
  const existing = el('chatMessages').querySelector('.typing-indicator');
  if (existing) existing.remove();
  const wrap = document.createElement("div");
  wrap.className = `chat-bubble ${role === "user" ? "chat-user" : "chat-assistant"}`;
  const label = document.createElement("span");
  label.className = "chat-role"; label.textContent = role;
  const body = document.createElement("div");
  // Simple markdown for assistant
  if (role === 'assistant') {
    body.innerHTML = content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
      .replace(/\n/g, '<br>');
  } else { body.textContent = content; }
  wrap.appendChild(label); wrap.appendChild(body);
  el("chatMessages").appendChild(wrap);
  requestAnimationFrame(() => { el("chatMessages").scrollTop = el("chatMessages").scrollHeight; });
}

function showTypingIndicator() {
  const ind = document.createElement('div');
  ind.className = 'chat-bubble chat-assistant typing-indicator';
  ind.innerHTML = '<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>';
  el('chatMessages').appendChild(ind);
  el('chatMessages').scrollTop = el('chatMessages').scrollHeight;
}

function seedChat() {
  el("chatMessages").innerHTML = "";
  AppState.chatHistory.length = 0;
  el("chatContextText").textContent = AppState.latestSummary
    ? `Live: ${AppState.latestSummary.highest_severity} severity` : "General cyber guidance";
  appendChatMessage("assistant", "I can explain attacks, predictions, mitigation steps, and model behavior. Ask me anything.");
}

async function sendChatMessage() {
  const input = el("chatInput");
  const message = input.value.trim();
  if (!message) return;
  AppState.chatHistory.push({ role: "user", content: message });
  appendChatMessage("user", message);
  input.value = "";
  const btn = el("sendChatBtn");
  btn.disabled = true;
  showTypingIndicator();
  try {
    const payload = await fetchJSON(`${API_BASE}/api/v1/chat`, {
      method: "POST",
      body: JSON.stringify({ message, history: AppState.chatHistory, latest_summary: AppState.latestSummary })
    });
    AppState.chatHistory.push({ role: "assistant", content: payload.reply });
    appendChatMessage("assistant", payload.reply);
  } catch (err) { appendChatMessage("assistant", `Error: ${err.message}`); }
  finally { btn.disabled = false; el("chatMessages").classList.remove("is-busy"); }
}

/* ===== INIT ===== */
document.addEventListener("DOMContentLoaded", async () => {
  if (!(await validateSession())) return;
  restoreTheme();
  restoreSidebar();
  seedChat();
  el("trafficInput").value = JSON.stringify(samplePayload, null, 2);

  // Navigation
  document.querySelectorAll(".nav-item[data-page]").forEach(btn => {
    btn.addEventListener("click", () => navigateTo(btn.dataset.page));
  });

  const htmlReportLink = el("htmlReportLink");
  if (htmlReportLink) {
    htmlReportLink.href = "#";
    htmlReportLink.addEventListener("click", async (event) => {
      event.preventDefault();
      try {
        const blob = await fetchProtectedBlob(`${API_BASE}/api/v1/report/html`);
        const objectUrl = URL.createObjectURL(blob);
        window.open(objectUrl, "_blank", "noopener,noreferrer");
        setTimeout(() => URL.revokeObjectURL(objectUrl), 30000);
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  }

  // Sidebar
  el("collapseBtn").addEventListener("click", toggleSidebar);
  el("themeToggle").addEventListener("click", toggleTheme);
  el("mobileMenuBtn").addEventListener("click", () => {
    el("sidebar").classList.toggle("mobile-open");
    el("sidebarOverlay").classList.toggle("visible");
  });
  el("sidebarOverlay").addEventListener("click", () => {
    el("sidebar").classList.remove("mobile-open");
    el("sidebarOverlay").classList.remove("visible");
  });

  // Chat
  el("chatFab").addEventListener("click", toggleChat);
  el("sendChatBtn").addEventListener("click", sendChatMessage);
  el("clearChatBtn").addEventListener("click", () => { seedChat(); el("chatInput").value = ""; });
  el("chatInput").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChatMessage(); } });
  document.querySelectorAll(".chip").forEach(c => {
    c.addEventListener("click", () => { el("chatInput").value = c.dataset.prompt; el("chatInput").focus(); });
  });

  // Actions
  el("loadSampleBtn").addEventListener("click", handleLoadSample);
  el("scenarioBtn").addEventListener("click", handleLoadScenario);
  el("trainBtn").addEventListener("click", bootstrapModel);
  el("analyzeBtn").addEventListener("click", analyzeTraffic);
  el("analyzeCsvBtn").addEventListener("click", analyzeCsv);
  el("liveMonitorBtn").addEventListener("click", toggleLiveMonitoring);
  el("resetMetricsBtn").addEventListener("click", resetDashboard);

  const logoutBtn = el("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await fetchJSON(`${API_BASE}/api/v1/auth/logout`, { method: 'POST' });
      } catch (e) {}
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = 'auth.html';
    });
  }

  // Init new charts
  initRadarChart();
  initTimelineChart();

  // Scroll reveal — only on active page elements initially
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
  }, { threshold: 0.05 });
  document.querySelectorAll('.page.active .card, .page.active .stat-card, .page.active .hero-banner').forEach(c => {
    c.classList.add('reveal');
    revealObserver.observe(c);
  });

  try {
    await Promise.all([loadStatus(), loadBenchmark()]);
    await loadSavedAnalysis();
  }
  catch { el("healthStatus").textContent = "Offline"; el("modelStatus").textContent = "Offline"; el("llmStatus").textContent = "Offline"; }
});
