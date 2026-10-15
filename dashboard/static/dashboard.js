/**
 * dashboard.js — Frontend Controller for Real-Time Syscall Anomaly Detection
 */

let isPaused = false;
let lastSeenEventId = 0;
let activeEvents = [];
let activeAlerts = [];
let currentStatus = {};
let topProcesses = [];
let timelineData = [];

// DOM Elements
const elStatusBadge = document.getElementById('detectorStatusBadge');
const elStatusPulse = document.getElementById('detectorPulse');
const elStatusText = document.getElementById('detectorStatusText');
const elDatasetPicker = document.getElementById('datasetPicker');
const elValTotal = document.getElementById('valTotalEvents');
const elValAlerts = document.getElementById('valAlerts');
const elValNormal = document.getElementById('valNormal');
const elValPids = document.getElementById('valPids');
const elValAnomalyPct = document.getElementById('valAnomalyPct');
const elEventsBody = document.getElementById('eventsTableBody');
const elAlertsContainer = document.getElementById('alertFeedContainer');
const elLiveEventCount = document.getElementById('liveEventCount');
const elAlertCountBadge = document.getElementById('alertCountBadge');
const elDistRatio = document.getElementById('chartDistRatio');

// Filters
const elFilterProc = document.getElementById('filterProcess');
const elFilterPid = document.getElementById('filterPid');
const elToggleSusp = document.getElementById('toggleSuspiciousOnly');
const elBtnPause = document.getElementById('btnTogglePause');
const elBtnExport = document.getElementById('btnExport');
const elBtnRefresh = document.getElementById('btnRefresh');

// Canvases
const canvasDist = document.getElementById('canvasDistribution');
const canvasTimeline = document.getElementById('canvasTimeline');
const canvasTopProcs = document.getElementById('canvasTopProcs');

// Copy Command Helper
window.copyCommand = function(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert("Command copied to clipboard:\n" + text);
  }).catch(() => {
    prompt("Copy this command:", text);
  });
};

// Event Listeners
elBtnPause.addEventListener('click', () => {
  isPaused = !isPaused;
  elBtnPause.innerHTML = isPaused ? '▶️ Resume' : '⏸️ Pause';
  elBtnPause.style.borderColor = isPaused ? 'var(--anomaly-red)' : 'var(--border-color)';
});

elBtnRefresh.addEventListener('click', () => {
  lastSeenEventId = 0;
  fetchData();
});

elToggleSusp.addEventListener('change', () => {
  renderEvents();
});

elFilterProc.addEventListener('input', () => {
  renderEvents();
});

elFilterPid.addEventListener('input', () => {
  renderEvents();
});

elDatasetPicker.addEventListener('change', (e) => {
  const dataset = e.target.value;
  fetch('/api/set_dataset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dataset: dataset })
  })
  .then(res => res.json())
  .then(data => {
    lastSeenEventId = 0;
    activeEvents = [];
    activeAlerts = [];
    fetchData();
  })
  .catch(err => console.error("Error setting dataset:", err));
});

elBtnExport.addEventListener('click', () => {
  const suspOnly = elToggleSusp.checked ? "1" : "0";
  window.location.href = `/api/export?suspicious_only=${suspOnly}`;
});

// Fetch Data from Backend
async function fetchData() {
  if (isPaused) return;

  try {
    // 1. Fetch System Status
    const statusRes = await fetch('/api/status');
    currentStatus = await statusRes.json();
    updateStatusUI(currentStatus);

    // 2. Fetch Latest Events
    const queryParams = new URLSearchParams({
      limit: 100,
      since: lastSeenEventId
    });
    const eventsRes = await fetch(`/api/events?${queryParams}`);
    const eventsData = await eventsRes.json();

    if (eventsData.events && eventsData.events.length > 0) {
      // Prepend newly arrived events and bound to 500
      activeEvents = [...eventsData.events, ...activeEvents].slice(0, 500);
      lastSeenEventId = Math.max(...activeEvents.map(e => e.id));
      renderEvents();
    } else if (activeEvents.length === 0) {
      renderEvents();
    }

    // 3. Fetch Latest Alerts
    const alertsRes = await fetch('/api/alerts?limit=30');
    const alertsData = await alertsRes.json();
    if (alertsData.alerts) {
      activeAlerts = alertsData.alerts;
      renderAlerts();
    }

    // 4. Fetch Top Processes
    const procRes = await fetch('/api/stats/processes');
    const procData = await procRes.json();
    if (procData.processes) {
      topProcesses = procData.processes;
      drawTopProcessesChart();
    }

    // 5. Fetch Timeline Data
    const timeRes = await fetch('/api/stats/timeline');
    const timeData = await timeRes.json();
    if (timeData.timeline) {
      timelineData = timeData.timeline;
      drawTimelineChart();
    }

    // Update Distribution Chart
    drawDistributionChart();

  } catch (err) {
    console.error("Dashboard update error:", err);
  }
}

// Update UI Indicators
function updateStatusUI(s) {
  if (s.detector_running) {
    elStatusPulse.className = "pulse-dot pulse-green";
    elStatusText.innerText = `eBPF DETECTOR ACTIVE (PID ${s.detector_pid})`;
  } else {
    elStatusPulse.className = "pulse-dot pulse-red";
    elStatusText.innerText = `eBPF DETECTOR IDLE (Reading ${s.dataset_file})`;
  }

  elValTotal.innerText = (s.total_processed || 0).toLocaleString();
  elValAlerts.innerText = (s.suspicious_count || 0).toLocaleString();
  elValNormal.innerText = (s.normal_count || 0).toLocaleString();
  elValPids.innerText = (s.unique_pids_count || 0).toLocaleString();
  elValAnomalyPct.innerText = `${s.anomaly_percentage || 0}%`;
  elDistRatio.innerText = `${s.anomaly_percentage || 0}% Anomalies`;

  // Dynamically ensure active dataset exists and is selected in picker
  if (s.dataset_file && elDatasetPicker) {
    let exists = false;
    for (let i = 0; i < elDatasetPicker.options.length; i++) {
      if (elDatasetPicker.options[i].value === s.dataset_file || 
          elDatasetPicker.options[i].value === s.dataset_path) {
        exists = true;
        break;
      }
    }
    if (!exists) {
      const opt = document.createElement('option');
      opt.value = s.dataset_path || s.dataset_file;
      opt.text = `${s.dataset_file} (Active Target)`;
      elDatasetPicker.add(opt, 0);
      elDatasetPicker.selectedIndex = 0;
    }
  }
}

// Render Event Stream Table with Active Filters
function renderEvents() {
  const procFilter = elFilterProc.value.trim().toLowerCase();
  const pidFilter = elFilterPid.value.trim();
  const suspOnly = elToggleSusp.checked;

  const filtered = activeEvents.filter(ev => {
    if (suspOnly && !ev.is_suspicious) return false;
    if (pidFilter && String(ev.pid) !== pidFilter) return false;
    if (procFilter && !ev.process_name.toLowerCase().includes(procFilter)) return false;
    return true;
  });

  elLiveEventCount.innerText = `${filtered.length} visible`;

  if (filtered.length === 0) {
    elEventsBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
          No events match the selected criteria.
        </td>
      </tr>`;
    return;
  }

  const rowsHtml = filtered.map(ev => {
    const rowClass = ev.is_suspicious ? 'row-suspicious' : '';
    const statusTag = ev.is_suspicious 
      ? '<span class="tag tag-suspicious">SUSPICIOUS</span>'
      : '<span class="tag tag-normal">NORMAL</span>';
    const scoreColor = ev.is_suspicious ? 'color: var(--anomaly-red);' : 'color: var(--normal-green);';

    return `
      <tr class="${rowClass}">
        <td style="font-family: var(--font-mono); color: var(--text-secondary);">${ev.timestamp_fmt}</td>
        <td style="font-family: var(--font-mono);">${ev.pid}</td>
        <td style="font-weight: 600;">${escapeHtml(ev.process_name)}</td>
        <td class="seq-code">${escapeHtml(ev.sequence_str)}</td>
        <td class="score-badge" style="${scoreColor}">${ev.anomaly_score.toFixed(4)}</td>
        <td>${statusTag}</td>
      </tr>
    `;
  }).join('');

  elEventsBody.innerHTML = rowsHtml;
}

// Render Anomaly Alert Cards Feed
function renderAlerts() {
  elAlertCountBadge.innerText = `${activeAlerts.length} alerts`;

  if (activeAlerts.length === 0) {
    elAlertsContainer.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 30px;">
        No anomaly alerts recorded in active stream.
      </div>`;
    return;
  }

  const cardsHtml = activeAlerts.slice(0, 30).map(alert => {
    return `
      <div class="alert-item">
        <div class="alert-header">
          <div class="alert-proc">
            <span>🚨 ${escapeHtml(alert.process_name)}</span>
            <span class="alert-pid">(PID ${alert.pid})</span>
          </div>
          <div>
            <span class="tag tag-suspicious">SCORE: ${alert.anomaly_score.toFixed(4)}</span>
          </div>
        </div>
        <div style="font-family: var(--font-mono); font-size: 11.5px; color: #93c5fd;">
          Sequence: ${escapeHtml(alert.sequence_str)}
        </div>
        <div class="alert-body">
          <strong>Root Cause:</strong> ${escapeHtml(alert.explanation || "Syscall transition not seen in training.")}
        </div>
      </div>
    `;
  }).join('');

  elAlertsContainer.innerHTML = cardsHtml;
}

// Helper: Escape HTML to prevent XSS
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  })[m]);
}

// =========================================================================
// Pure Canvas Charts (Offline & Zero-Dependency Safe)
// =========================================================================

function resizeCanvas(canvas) {
  const rect = canvas.getBoundingClientRect();
  if (canvas.width !== rect.width || canvas.height !== rect.height) {
    canvas.width = rect.width * window.devicePixelRatio || rect.width || 300;
    canvas.height = rect.height * window.devicePixelRatio || rect.height || 200;
  }
}

// 1. Doughnut Distribution Chart
function drawDistributionChart() {
  if (!canvasDist) return;
  resizeCanvas(canvasDist);
  const ctx = canvasDist.getContext('2d');
  const w = canvasDist.width;
  const h = canvasDist.height;
  ctx.clearRect(0, 0, w, h);

  const total = (currentStatus.normal_count || 0) + (currentStatus.suspicious_count || 0);
  const normal = currentStatus.normal_count || 0;
  const suspicious = currentStatus.suspicious_count || 0;

  const cx = w * 0.38;
  const cy = h * 0.5;
  const radius = Math.min(cx, cy) * 0.72;
  const innerRadius = radius * 0.55;

  if (total === 0) {
    ctx.strokeStyle = '#283548';
    ctx.lineWidth = radius - innerRadius;
    ctx.beginPath();
    ctx.arc(cx, cy, (radius + innerRadius) / 2, 0, 2 * Math.PI);
    ctx.stroke();
    return;
  }

  const normalAngle = (normal / total) * 2 * Math.PI;

  // Normal Arc
  ctx.lineWidth = radius - innerRadius;
  ctx.strokeStyle = '#10b981';
  ctx.beginPath();
  ctx.arc(cx, cy, (radius + innerRadius) / 2, -Math.PI / 2, -Math.PI / 2 + normalAngle);
  ctx.stroke();

  // Suspicious Arc
  ctx.strokeStyle = '#ef4444';
  ctx.beginPath();
  ctx.arc(cx, cy, (radius + innerRadius) / 2, -Math.PI / 2 + normalAngle, -Math.PI / 2 + 2 * Math.PI);
  ctx.stroke();

  // Legend
  const lx = w * 0.72;
  ctx.font = `${Math.max(11, Math.floor(h * 0.06))}px sans-serif`;
  ctx.fillStyle = '#10b981';
  ctx.fillRect(lx, cy - 25, 10, 10);
  ctx.fillStyle = '#f3f4f6';
  ctx.fillText(`Normal: ${normal.toLocaleString()}`, lx + 16, cy - 16);

  ctx.fillStyle = '#ef4444';
  ctx.fillRect(lx, cy + 5, 10, 10);
  ctx.fillStyle = '#f3f4f6';
  ctx.fillText(`Alerts: ${suspicious.toLocaleString()}`, lx + 16, cy + 14);
}

// 2. Timeline Rate Chart
function drawTimelineChart() {
  if (!canvasTimeline) return;
  resizeCanvas(canvasTimeline);
  const ctx = canvasTimeline.getContext('2d');
  const w = canvasTimeline.width;
  const h = canvasTimeline.height;
  ctx.clearRect(0, 0, w, h);

  if (timelineData.length < 2) {
    ctx.fillStyle = '#6b7280';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Accumulating time-series activity...', w / 2, h / 2);
    return;
  }

  const padLeft = 40;
  const padBottom = 25;
  const plotW = w - padLeft - 15;
  const plotH = h - padBottom - 15;

  const maxVal = Math.max(...timelineData.map(d => d.normal + d.suspicious), 10);

  // Axes
  ctx.strokeStyle = '#283548';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padLeft, 10);
  ctx.lineTo(padLeft, h - padBottom);
  ctx.lineTo(w - 10, h - padBottom);
  ctx.stroke();

  // Normal line (green)
  ctx.strokeStyle = '#10b981';
  ctx.lineWidth = 2;
  ctx.beginPath();
  timelineData.forEach((d, i) => {
    const x = padLeft + (i / (timelineData.length - 1)) * plotW;
    const y = (h - padBottom) - (d.normal / maxVal) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Suspicious line (red)
  ctx.strokeStyle = '#ef4444';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  timelineData.forEach((d, i) => {
    const x = padLeft + (i / (timelineData.length - 1)) * plotW;
    const y = (h - padBottom) - (d.suspicious / maxVal) * plotH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Label
  ctx.fillStyle = '#9ca3af';
  ctx.font = '10px monospace';
  ctx.textAlign = 'right';
  ctx.fillText(String(maxVal), padLeft - 5, 20);
  ctx.fillText('0', padLeft - 5, h - padBottom);
}

// 3. Top Anomaly-Generating Processes (Horizontal Bars)
function drawTopProcessesChart() {
  if (!canvasTopProcs) return;
  resizeCanvas(canvasTopProcs);
  const ctx = canvasTopProcs.getContext('2d');
  const w = canvasTopProcs.width;
  const h = canvasTopProcs.height;
  ctx.clearRect(0, 0, w, h);

  if (topProcesses.length === 0) {
    ctx.fillStyle = '#6b7280';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No process alerts to display.', w / 2, h / 2);
    return;
  }

  const items = topProcesses.slice(0, 6);
  const maxCount = Math.max(...items.map(i => i.count), 1);
  const barHeight = Math.min(22, (h - 20) / items.length - 8);
  const labelWidth = 90;

  items.forEach((item, idx) => {
    const y = 15 + idx * (barHeight + 10);
    const barW = ((w - labelWidth - 60) * (item.count / maxCount));

    // Process Name
    ctx.fillStyle = '#f3f4f6';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(item.process.slice(0, 11), labelWidth - 8, y + barHeight * 0.72);

    // Bar
    ctx.fillStyle = '#ef4444';
    ctx.fillRect(labelWidth, y, Math.max(barW, 4), barHeight);

    // Value count
    ctx.fillStyle = '#9ca3af';
    ctx.font = '11px monospace';
    ctx.textAlign = 'left';
    ctx.fillText(String(item.count), labelWidth + barW + 8, y + barHeight * 0.72);
  });
}

// Start polling loop
fetchData();
setInterval(fetchData, 1000);
