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
        <td style="font-weight: 600;"><a class="proc-link" onclick="openProcessDetail(${ev.pid}, '${escapeHtml(ev.process_name)}')" title="Inspect process activity">${escapeHtml(ev.process_name)}</a></td>
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
    const sevBadge = alert.severity ? getSeverityBadgeHtml(alert.severity) : '';
    return `
      <div class="alert-item">
        <div class="alert-header">
          <div class="alert-proc">
            <span>🚨 ${escapeHtml(alert.process_name)}</span>
            <span class="alert-pid">(PID ${alert.pid})</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            ${sevBadge}
            <span class="tag tag-suspicious">SCORE: ${alert.anomaly_score.toFixed(4)}</span>
          </div>
        </div>
        <div style="font-family: var(--font-mono); font-size: 11.5px; color: #93c5fd;">
          Sequence: ${escapeHtml(alert.sequence_str)}
        </div>
        <div class="alert-body">
          <strong>Root Cause:</strong> ${escapeHtml(alert.explanation || "Syscall transition not seen in training.")}
        </div>
        ${alert.severity_reason ? `<div style="font-size: 11.5px; color: #fbbf24; margin-top: 4px;"><strong>Triage Reason:</strong> ${escapeHtml(alert.severity_reason)}</div>` : ''}
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


// ==============================================================================
// STAGE 20 — ALERT HISTORY & INCIDENT MANAGEMENT CONTROLLER
// ==============================================================================

let histCurrentPage = 1;
let histTotalPages = 1;
let histCurrentAlert = null;
let histLoadedAlerts = [];

// DOM Elements: History Stats (Task 6)
const elValHistTotal = document.getElementById('valHistTotal');
const elValHistNew = document.getElementById('valHistNew');
const elValHistInvestigating = document.getElementById('valHistInvestigating');
const elValHistResolved = document.getElementById('valHistResolved');
const elValHistFalseAlarm = document.getElementById('valHistFalseAlarm');
const elHistAlertCountBadge = document.getElementById('histAlertCountBadge');

// DOM Elements: History Filters
const elHistFilterProc = document.getElementById('histFilterProcess');
const elHistFilterPid = document.getElementById('histFilterPid');
const elHistFilterStatus = document.getElementById('histFilterStatus');
const elHistFilterScore = document.getElementById('histFilterScore');
const elHistFilterStartTime = document.getElementById('histFilterStartTime');
const elHistFilterEndTime = document.getElementById('histFilterEndTime');
const elHistSortOrder = document.getElementById('histSortOrder');
const elHistPageSize = document.getElementById('histPageSize');
const elBtnHistReset = document.getElementById('btnHistResetFilters');
const elBtnHistRefresh = document.getElementById('btnHistRefresh');
const elBtnHistExport = document.getElementById('btnHistExport');

// DOM Elements: Table & Pagination
const elHistTableBody = document.getElementById('histTableBody');
const elHistPaginationInfo = document.getElementById('histPaginationInfo');
const elHistPageCurrent = document.getElementById('histPageCurrent');
const elBtnHistFirst = document.getElementById('btnHistFirst');
const elBtnHistPrev = document.getElementById('btnHistPrev');
const elBtnHistNext = document.getElementById('btnHistNext');
const elBtnHistLast = document.getElementById('btnHistLast');

// DOM Elements: Modal Dialog
const elModal = document.getElementById('modalAlertDetail');
const elModalTitle = document.getElementById('modalAlertTitle');
const elModalStatusBadge = document.getElementById('modalStatusBadge');
const elModalAlertId = document.getElementById('modalValAlertId');
const elModalProcPid = document.getElementById('modalValProcPid');
const elModalScore = document.getElementById('modalValScore');
const elModalDataset = document.getElementById('modalValDataset');
const elModalSequence = document.getElementById('modalValSequence');
const elModalExplanation = document.getElementById('modalValExplanation');
const elModalTimestamp = document.getElementById('modalValTimestamp');
const elModalCreatedAt = document.getElementById('modalValCreatedAt');
const elModalLastUpdated = document.getElementById('modalValLastUpdated');
const elModalSelectStatus = document.getElementById('modalSelectStatus');
const elModalNotesText = document.getElementById('modalNotesText');
const elModalToast = document.getElementById('modalToastMsg');
const elBtnModalSave = document.getElementById('btnModalSave');
const elBtnModalCancel = document.getElementById('btnModalCancel');
const elBtnCloseModal = document.getElementById('btnCloseModal');

// Helper: Status badge HTML
function getStatusBadgeHtml(status) {
  const norm = (status || 'NEW').toUpperCase();
  const cls = 'status-' + norm.toLowerCase();
  return `<span class="badge-status ${cls}">${escapeHtml(norm)}</span>`;
}

// STAGE 22: Severity badge HTML with accessible text labels
function getSeverityBadgeHtml(severity) {
  const norm = (severity || 'MEDIUM').toUpperCase();
  const cls = 'severity-' + norm.toLowerCase();
  return `<span class="badge-severity ${cls}" title="Security Triage Severity: ${escapeHtml(norm)}">[${escapeHtml(norm)}]</span>`;
}

// DOM Elements: Severity & Triage (Stage 22)
const elHistFilterSeverity = document.getElementById('histFilterSeverity');
const elModalSeverityBadge = document.getElementById('modalSeverityBadge');
const elModalValSeverity = document.getElementById('modalValSeverity');
const elModalValRule = document.getElementById('modalValRule');
const elModalValRuleVersion = document.getElementById('modalValRuleVersion');
const elModalValSeverityReason = document.getElementById('modalValSeverityReason');

const elValTriageCritical = document.getElementById('valTriageCritical');
const elValTriageHigh = document.getElementById('valTriageHigh');
const elValTriageMedium = document.getElementById('valTriageMedium');
const elValTriageLow = document.getElementById('valTriageLow');
const elTriageUnresolvedBadge = document.getElementById('triageUnresolvedBadge');
const elTriageTopProcessesList = document.getElementById('triageTopProcessesList');

// 1. Fetch Incident Management & Security Triage Statistics (Task 6 & 9)
async function fetchAlertHistoryStats() {
  try {
    const res = await fetch('/api/alert_history/stats');
    if (!res.ok) return;
    const stats = await res.json();

    if (elValHistTotal) elValHistTotal.innerText = (stats.total_alerts || 0).toLocaleString();
    if (elValHistNew) elValHistNew.innerText = (stats.new_alerts || 0).toLocaleString();
    if (elValHistInvestigating) elValHistInvestigating.innerText = (stats.investigating_alerts || 0).toLocaleString();
    if (elValHistResolved) elValHistResolved.innerText = (stats.resolved_alerts || 0).toLocaleString();
    if (elValHistFalseAlarm) elValHistFalseAlarm.innerText = (stats.false_alarms || 0).toLocaleString();
    if (elHistAlertCountBadge) elHistAlertCountBadge.innerText = `${(stats.total_alerts || 0).toLocaleString()} stored alerts`;

    // Fetch Security Triage statistics
    await fetchTriageStats();
  } catch (err) {
    console.error("Error fetching alert history stats:", err);
  }
}

async function fetchTriageStats() {
  try {
    const res = await fetch('/api/triage/stats');
    if (!res.ok) return;
    const stats = await res.json();

    if (elValTriageCritical) elValTriageCritical.innerText = (stats.critical_alerts || 0).toLocaleString();
    if (elValTriageHigh) elValTriageHigh.innerText = (stats.high_alerts || 0).toLocaleString();
    if (elValTriageMedium) elValTriageMedium.innerText = (stats.medium_alerts || 0).toLocaleString();
    if (elValTriageLow) elValTriageLow.innerText = (stats.low_alerts || 0).toLocaleString();

    const unres = stats.unresolved_high_priority || 0;
    if (elTriageUnresolvedBadge) {
      elTriageUnresolvedBadge.innerText = `${unres.toLocaleString()} UNRESOLVED HIGH-PRIORITY`;
      elTriageUnresolvedBadge.style.color = unres > 0 ? '#ef4444' : 'var(--normal-green)';
      elTriageUnresolvedBadge.style.borderColor = unres > 0 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)';
    }

    if (elTriageTopProcessesList) {
      const procs = stats.top_flagged_processes || [];
      if (procs.length === 0) {
        elTriageTopProcessesList.innerHTML = '<span style="color: var(--normal-green);">Zero unresolved critical/high alerts across processes.</span>';
      } else {
        elTriageTopProcessesList.innerHTML = procs.map(p =>
          `<span style="display: inline-block; margin-right: 14px;"><strong>${escapeHtml(p.process_name)}</strong>: <span style="color: #f87171; font-weight: 700;">${p.unresolved_count} unres</span></span>`
        ).join('');
      }
    }
  } catch (err) {
    console.error("Error fetching triage stats:", err);
  }
}

// 2. Fetch Paginated and Filtered Alert History (Task 5, 7, 8)
async function fetchAlertHistory() {
  try {
    const params = new URLSearchParams();
    params.set('page', histCurrentPage);

    const pageSize = elHistPageSize ? elHistPageSize.value : '25';
    params.set('limit', pageSize);

    if (elHistFilterProc && elHistFilterProc.value.trim()) {
      params.set('process', elHistFilterProc.value.trim());
    }
    if (elHistFilterPid && elHistFilterPid.value.trim()) {
      params.set('pid', elHistFilterPid.value.trim());
    }
    if (elHistFilterSeverity && elHistFilterSeverity.value) {
      params.set('severity', elHistFilterSeverity.value);
    }
    if (elHistFilterStatus && elHistFilterStatus.value) {
      params.set('status', elHistFilterStatus.value);
    }
    if (elHistFilterScore && elHistFilterScore.value) {
      params.set('min_score', elHistFilterScore.value);
    }
    if (elHistFilterStartTime && elHistFilterStartTime.value.trim()) {
      params.set('start_time', elHistFilterStartTime.value.trim());
    }
    if (elHistFilterEndTime && elHistFilterEndTime.value.trim()) {
      params.set('end_time', elHistFilterEndTime.value.trim());
    }

    if (elHistSortOrder && elHistSortOrder.value) {
      if (elHistSortOrder.value === 'severity') {
        params.set('sort_by', 'severity');
        params.set('order', 'asc'); // Critical first
      } else if (elHistSortOrder.value === 'score') {
        params.set('sort_by', 'score');
        params.set('order', 'desc');
      } else {
        params.set('order', elHistSortOrder.value);
      }
    }

    const res = await fetch(`/api/alert_history?${params.toString()}`);
    if (!res.ok) {
      elHistTableBody.innerHTML = `
        <tr>
          <td colspan="10" style="text-align: center; color: var(--anomaly-red); padding: 30px;">
            Error loading alert history (HTTP ${res.status}).
          </td>
        </tr>`;
      return;
    }

    const data = await res.json();
    histLoadedAlerts = data.alerts || [];
    histCurrentPage = data.page || 1;
    histTotalPages = data.total_pages || 1;

    renderAlertHistoryTable(data);
    updatePaginationControls(data);
  } catch (err) {
    console.error("Error fetching alert history:", err);
  }
}

// Render Alert History Table Rows
function renderAlertHistoryTable(data) {
  if (!elHistTableBody) return;

  const alerts = data.alerts || [];
  if (alerts.length === 0) {
    elHistTableBody.innerHTML = `
      <tr>
        <td colspan="10" style="text-align: center; color: var(--text-muted); padding: 30px;">
          No alert records match the selected filter criteria.
        </td>
      </tr>`;
    return;
  }

  const rowsHtml = alerts.map(a => {
    const statusBadge = getStatusBadgeHtml(a.incident_status);
    const sevBadge = getSeverityBadgeHtml(a.severity);
    const scoreColor = a.anomaly_score >= 1.0 ? 'color: var(--anomaly-red); font-weight: 700;' : 'color: #f87171;';
    const timeDisplay = a.created_at || a.event_timestamp;
    const ruleInfo = a.severity_rule ? ` | [${a.severity_rule}] ${a.severity_reason || ''}` : '';

    return `
      <tr id="row-alert-${a.alert_id}">
        <td style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11.5px;">#${a.alert_id}</td>
        <td style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-secondary);" title="Timestamp ns: ${a.event_timestamp}">${escapeHtml(String(timeDisplay))}</td>
        <td style="font-family: var(--font-mono);">${a.pid}</td>
        <td style="font-weight: 600;"><a class="proc-link" onclick="openProcessDetail(${a.pid}, '${escapeHtml(a.process_name)}')" title="Inspect process activity">${escapeHtml(a.process_name)}</a></td>
        <td>${sevBadge}</td>
        <td class="seq-code" style="font-size: 11px;">${escapeHtml(a.sequence_str || `${a.syscall_1} -> ${a.syscall_2} -> ${a.syscall_3}`)}</td>
        <td style="${scoreColor}; font-family: var(--font-mono);">${Number(a.anomaly_score).toFixed(4)}</td>
        <td>${statusBadge}</td>
        <td style="font-size: 11.5px; color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.explanation)}${escapeHtml(ruleInfo)}">
          ${escapeHtml(a.explanation)}
        </td>
        <td style="text-align: center;">
          <button class="btn-action" onclick="openAlertDetail(${a.alert_id})" title="Investigate & Edit Notes">
            🔍 Details
          </button>
        </td>
      </tr>
    `;
  }).join('');

  elHistTableBody.innerHTML = rowsHtml;
}

// Update Pagination Bar
function updatePaginationControls(data) {
  const total = data.total || 0;
  const page = data.page || 1;
  const limit = data.limit || 25;
  const totalPages = data.total_pages || 1;

  const startIdx = total === 0 ? 0 : (page - 1) * limit + 1;
  const endIdx = Math.min(total, page * limit);

  if (elHistPaginationInfo) {
    elHistPaginationInfo.innerText = `Showing ${startIdx.toLocaleString()} - ${endIdx.toLocaleString()} of ${total.toLocaleString()} alerts`;
  }
  if (elHistPageCurrent) {
    elHistPageCurrent.innerText = `Page ${page} of ${totalPages}`;
  }

  if (elBtnHistFirst) elBtnHistFirst.disabled = (page <= 1);
  if (elBtnHistPrev) elBtnHistPrev.disabled = (page <= 1);
  if (elBtnHistNext) elBtnHistNext.disabled = (page >= totalPages);
  if (elBtnHistLast) elBtnHistLast.disabled = (page >= totalPages);
}

// 3. Alert Detail & Investigation Notes Modal (Task 4 & 5)
window.openAlertDetail = async function(alertId) {
  try {
    const res = await fetch(`/api/alert_history/detail?id=${alertId}`);
    if (!res.ok) {
      alert("Failed to load alert details.");
      return;
    }
    const data = await res.json();
    const alertData = data.alert;
    if (!alertData) return;

    histCurrentAlert = alertData;

    if (elModalTitle) elModalTitle.innerText = `Incident Alert #${alertData.alert_id}`;
    if (elModalAlertId) elModalAlertId.innerText = String(alertData.alert_id);
    if (elModalProcPid) elModalProcPid.innerText = `${alertData.process_name} (PID ${alertData.pid})`;
    if (elModalScore) elModalScore.innerText = Number(alertData.anomaly_score).toFixed(4);
    if (elModalDataset) elModalDataset.innerText = alertData.source_dataset || "live";
    if (elModalSequence) elModalSequence.innerText = alertData.sequence_str || `${alertData.syscall_1} -> ${alertData.syscall_2} -> ${alertData.syscall_3}`;
    if (elModalExplanation) elModalExplanation.innerText = alertData.explanation || "No explanation provided.";
    if (elModalTimestamp) elModalTimestamp.innerText = String(alertData.event_timestamp);
    if (elModalCreatedAt) elModalCreatedAt.innerText = alertData.created_at || "-";
    if (elModalLastUpdated) elModalLastUpdated.innerText = alertData.last_updated || "-";

    // STAGE 22: Populate Severity Details in Modal
    const sev = (alertData.severity || 'MEDIUM').toUpperCase();
    if (elModalSeverityBadge) {
      elModalSeverityBadge.className = `badge-severity severity-${sev.toLowerCase()}`;
      elModalSeverityBadge.innerText = `[${sev}]`;
    }
    if (elModalValSeverity) {
      elModalValSeverity.innerText = sev;
      elModalValSeverity.style.color = sev === 'CRITICAL' ? '#f87171' : (sev === 'HIGH' ? '#fb923c' : (sev === 'MEDIUM' ? '#fbbf24' : '#38bdf8'));
    }
    if (elModalValRule) elModalValRule.innerText = alertData.severity_rule || 'DEFAULT_CLASSIFICATION';
    if (elModalValRuleVersion) elModalValRuleVersion.innerText = alertData.severity_rule_version || '1.0.0';
    if (elModalValSeverityReason) elModalValSeverityReason.innerText = alertData.severity_reason || 'Standard classification.';

    if (elModalSelectStatus) elModalSelectStatus.value = alertData.incident_status || "NEW";
    updateModalStatusBadge(alertData.incident_status || "NEW");

    if (elModalNotesText) elModalNotesText.value = alertData.investigation_notes || "";
    if (elModalToast) {
      elModalToast.className = "toast-msg";
      elModalToast.innerText = "";
    }

    if (elModal) elModal.classList.add('open');
  } catch (err) {
    console.error("Error opening alert detail:", err);
  }
};

function updateModalStatusBadge(status) {
  if (!elModalStatusBadge) return;
  const norm = (status || 'NEW').toUpperCase();
  elModalStatusBadge.className = `badge-status status-${norm.toLowerCase()}`;
  elModalStatusBadge.innerText = norm;
}

if (elModalSelectStatus) {
  elModalSelectStatus.addEventListener('change', (e) => {
    updateModalStatusBadge(e.target.value);
  });
}

// Save Alert Status and Notes Changes
async function saveAlertChanges() {
  if (!histCurrentAlert) return;
  const alertId = histCurrentAlert.alert_id;
  const newStatus = elModalSelectStatus.value;
  const newNotes = elModalNotesText.value;

  try {
    // 1. Update Status
    const statusRes = await fetch('/api/alert_history/update_status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, status: newStatus })
    });
    const statusData = await statusRes.json();
    if (!statusRes.ok || statusData.error) {
      showModalToast(statusData.error || "Failed to update status", false);
      return;
    }

    // 2. Update Notes
    const notesRes = await fetch('/api/alert_history/update_notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId, notes: newNotes })
    });
    const notesData = await notesRes.json();
    if (!notesRes.ok || notesData.error) {
      showModalToast(notesData.error || "Failed to update notes", false);
      return;
    }

    showModalToast("Incident record updated successfully!", true);

    // Refresh timestamps in modal
    if (notesData.alert && elModalLastUpdated) {
      elModalLastUpdated.innerText = notesData.alert.last_updated;
    }

    // Refresh history stats and table
    fetchAlertHistoryStats();
    fetchAlertHistory();
  } catch (err) {
    showModalToast(String(err), false);
  }
}

function showModalToast(msg, isSuccess) {
  if (!elModalToast) return;
  elModalToast.innerText = msg;
  elModalToast.className = isSuccess ? "toast-msg toast-success" : "toast-msg toast-error";
}

function closeModal() {
  if (elModal) elModal.classList.remove('open');
  histCurrentAlert = null;
}

// Modal Event Listeners
if (elBtnModalSave) elBtnModalSave.addEventListener('click', saveAlertChanges);
if (elBtnModalCancel) elBtnModalCancel.addEventListener('click', closeModal);
if (elBtnCloseModal) elBtnCloseModal.addEventListener('click', closeModal);
if (elModal) {
  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closeModal();
  });
}

// Filter and Pagination Event Listeners
if (elHistFilterProc) {
  let debounceTimer;
  elHistFilterProc.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      histCurrentPage = 1;
      fetchAlertHistory();
    }, 250);
  });
}

if (elHistFilterPid) {
  elHistFilterPid.addEventListener('input', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistFilterSeverity) {
  elHistFilterSeverity.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistFilterStatus) {
  elHistFilterStatus.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistFilterScore) {
  elHistFilterScore.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistFilterStartTime) {
  elHistFilterStartTime.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistFilterEndTime) {
  elHistFilterEndTime.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistSortOrder) {
  elHistSortOrder.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elHistPageSize) {
  elHistPageSize.addEventListener('change', () => {
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elBtnHistReset) {
  elBtnHistReset.addEventListener('click', () => {
    if (elHistFilterProc) elHistFilterProc.value = '';
    if (elHistFilterPid) elHistFilterPid.value = '';
    if (elHistFilterSeverity) elHistFilterSeverity.value = '';
    if (elHistFilterStatus) elHistFilterStatus.value = '';
    if (elHistFilterScore) elHistFilterScore.value = '';
    if (elHistFilterStartTime) elHistFilterStartTime.value = '';
    if (elHistFilterEndTime) elHistFilterEndTime.value = '';
    if (elHistSortOrder) elHistSortOrder.value = 'desc';
    if (elHistPageSize) elHistPageSize.value = '25';
    histCurrentPage = 1;
    fetchAlertHistory();
  });
}

if (elBtnHistRefresh) {
  elBtnHistRefresh.addEventListener('click', () => {
    fetchAlertHistoryStats();
    fetchAlertHistory();
  });
}

// CSV Export for Alert History
if (elBtnHistExport) {
  elBtnHistExport.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (elHistFilterProc && elHistFilterProc.value.trim()) {
      params.set('process', elHistFilterProc.value.trim());
    }
    if (elHistFilterPid && elHistFilterPid.value.trim()) {
      params.set('pid', elHistFilterPid.value.trim());
    }
    if (elHistFilterSeverity && elHistFilterSeverity.value) {
      params.set('severity', elHistFilterSeverity.value);
    }
    if (elHistFilterStatus && elHistFilterStatus.value) {
      params.set('status', elHistFilterStatus.value);
    }
    if (elHistFilterScore && elHistFilterScore.value) {
      params.set('min_score', elHistFilterScore.value);
    }
    if (elHistSortOrder && elHistSortOrder.value) {
      params.set('order', elHistSortOrder.value);
    }
    window.location.href = `/api/alert_history/export?${params.toString()}`;
  });
}

// Pagination Navigation
if (elBtnHistFirst) {
  elBtnHistFirst.addEventListener('click', () => {
    if (histCurrentPage > 1) {
      histCurrentPage = 1;
      fetchAlertHistory();
    }
  });
}

if (elBtnHistPrev) {
  elBtnHistPrev.addEventListener('click', () => {
    if (histCurrentPage > 1) {
      histCurrentPage--;
      fetchAlertHistory();
    }
  });
}

if (elBtnHistNext) {
  elBtnHistNext.addEventListener('click', () => {
    if (histCurrentPage < histTotalPages) {
      histCurrentPage++;
      fetchAlertHistory();
    }
  });
}

if (elBtnHistLast) {
  elBtnHistLast.addEventListener('click', () => {
    if (histCurrentPage < histTotalPages) {
      histCurrentPage = histTotalPages;
      fetchAlertHistory();
    }
  });
}

// Initial fetch for Alert History & Incident Stats
fetchAlertHistoryStats();
fetchAlertHistory();
setInterval(fetchAlertHistoryStats, 5000);


// ==============================================================================
// STAGE 21 — PROCESS-WISE MONITORING & BEHAVIORAL ANALYTICS CONTROLLER
// ==============================================================================

let procCurrentPage = 1;
let procTotalPages = 1;
let currentSelectedPid = null;
let currentSelectedName = null;

// DOM Elements: Process Overview
const elProcessesListView = document.getElementById('processesListView');
const elProcessDetailView = document.getElementById('processDetailView');
const elProcessesCountBadge = document.getElementById('processesCountBadge');
const elBtnRefreshProcesses = document.getElementById('btnRefreshProcesses');
const elProcFilterName = document.getElementById('procFilterName');
const elProcFilterPid = document.getElementById('procFilterPid');
const elProcSortBy = document.getElementById('procSortBy');
const elProcSortOrder = document.getElementById('procSortOrder');
const elProcPageSize = document.getElementById('procPageSize');
const elBtnProcReset = document.getElementById('btnProcResetFilters');
const elProcessesTableBody = document.getElementById('processesTableBody');
const elProcPaginationInfo = document.getElementById('procPaginationInfo');
const elProcPageCurrent = document.getElementById('procPageCurrent');
const elBtnProcFirst = document.getElementById('btnProcFirst');
const elBtnProcPrev = document.getElementById('btnProcPrev');
const elBtnProcNext = document.getElementById('btnProcNext');
const elBtnProcLast = document.getElementById('btnProcLast');

// DOM Elements: Process Detail
const elBtnBackToProcList = document.getElementById('btnBackToProcList');
const elProcDetailTitle = document.getElementById('procDetailTitle');
const elProcDetailStatusBadge = document.getElementById('procDetailStatusBadge');
const elBtnViewProcAlerts = document.getElementById('btnViewProcAlerts');
const elDetailValTotal = document.getElementById('detailValTotal');
const elDetailValNormal = document.getElementById('detailValNormal');
const elDetailValSuspicious = document.getElementById('detailValSuspicious');
const elDetailValRate = document.getElementById('detailValRate');
const elDetailValFirstTs = document.getElementById('detailValFirstTs');
const elDetailValLastTs = document.getElementById('detailValLastTs');
const elProcChartDistRatio = document.getElementById('procChartDistRatio');
const elProcDetailRecentEventsBody = document.getElementById('procDetailRecentEventsBody');
const elProcDetailAlertsBadge = document.getElementById('procDetailAlertsBadge');
const elProcDetailAlertsBody = document.getElementById('procDetailAlertsBody');

// Canvas Elements for Process Detail
const canvasProcTimeline = document.getElementById('canvasProcTimeline');
const canvasProcDist = document.getElementById('canvasProcDist');
const canvasProcTopNgrams = document.getElementById('canvasProcTopNgrams');
const canvasProcAnomalyTimeline = document.getElementById('canvasProcAnomalyTimeline');

function resizeProcCanvas(canvas) {
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = rect.width > 0 ? rect.width : (canvas.parentElement ? canvas.parentElement.clientWidth : 420);
  const h = rect.height > 0 ? rect.height : 220;
  canvas.width = Math.max(w, 300) * dpr;
  canvas.height = Math.max(h, 180) * dpr;
}

// 1. Fetch Paginated Process List (Task 2)
async function fetchProcesses() {
  try {
    const params = new URLSearchParams();
    params.set('page', procCurrentPage);

    const pageSize = elProcPageSize ? elProcPageSize.value : '25';
    params.set('limit', pageSize);

    if (elProcFilterName && elProcFilterName.value.trim()) {
      params.set('name', elProcFilterName.value.trim());
    }
    if (elProcFilterPid && elProcFilterPid.value.trim()) {
      params.set('pid', elProcFilterPid.value.trim());
    }
    if (elProcSortBy && elProcSortBy.value) {
      params.set('sort_by', elProcSortBy.value);
    }
    if (elProcSortOrder && elProcSortOrder.value) {
      params.set('order', elProcSortOrder.value);
    }

    const res = await fetch(`/api/processes?${params.toString()}`);
    if (!res.ok) {
      if (elProcessesTableBody) {
        elProcessesTableBody.innerHTML = `
          <tr>
            <td colspan="9" style="text-align: center; color: var(--anomaly-red); padding: 30px;">
              Error loading process monitoring data (HTTP ${res.status}).
            </td>
          </tr>`;
      }
      return;
    }

    const data = await res.json();
    procCurrentPage = data.page || 1;
    procTotalPages = data.total_pages || 1;

    if (elProcessesCountBadge) {
      elProcessesCountBadge.innerText = `${(data.total || 0).toLocaleString()} processes`;
    }

    renderProcessesTable(data);
    updateProcPaginationControls(data);
  } catch (err) {
    console.error("Error fetching process list:", err);
  }
}

// Render Process Table Rows
function renderProcessesTable(data) {
  if (!elProcessesTableBody) return;

  const procs = data.processes || [];
  if (procs.length === 0) {
    elProcessesTableBody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">
          No processes match the selected filter criteria.
        </td>
      </tr>`;
    return;
  }

  const rowsHtml = procs.map(p => {
    const isRunning = !!p.is_running;
    const statusBadge = isRunning
      ? '<span class="badge-status status-active">ACTIVE</span>'
      : '<span class="badge-status status-historical">HISTORICAL</span>';

    const anomalyPct = Number(p.anomaly_percentage || 0);
    const pctColor = anomalyPct > 0 ? 'color: var(--anomaly-red); font-weight: 700;' : 'color: var(--normal-green);';
    const alertCountColor = p.suspicious_events > 0 ? 'color: var(--anomaly-red); font-weight: 700;' : 'color: var(--text-secondary);';

    return `
      <tr id="row-proc-${p.pid}">
        <td style="font-family: var(--font-mono); font-weight: 600;">${p.pid}</td>
        <td style="font-weight: 600;">
          <a class="proc-link" onclick="openProcessDetail(${p.pid}, '${escapeHtml(p.process_name)}')" title="Inspect process behavioral profile">
            ${escapeHtml(p.process_name)}
          </a>
        </td>
        <td>${statusBadge}</td>
        <td style="font-family: var(--font-mono);">${(p.total_events || 0).toLocaleString()}</td>
        <td style="font-family: var(--font-mono); color: var(--normal-green);">${(p.normal_events || 0).toLocaleString()}</td>
        <td style="font-family: var(--font-mono); ${alertCountColor}">${(p.suspicious_events || 0).toLocaleString()}</td>
        <td style="font-family: var(--font-mono); ${pctColor}">${anomalyPct.toFixed(2)}%</td>
        <td style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-secondary);" title="Monotonic timestamp">${p.last_timestamp || '-'}</td>
        <td style="text-align: center;">
          <button class="btn-action" onclick="openProcessDetail(${p.pid}, '${escapeHtml(p.process_name)}')" title="Inspect behavioral details">
            📊 Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');

  elProcessesTableBody.innerHTML = rowsHtml;
}

// Update Process Pagination Bar
function updateProcPaginationControls(data) {
  const total = data.total || 0;
  const page = data.page || 1;
  const limit = data.limit || 25;
  const totalPages = data.total_pages || 1;

  const startIdx = total === 0 ? 0 : (page - 1) * limit + 1;
  const endIdx = Math.min(total, page * limit);

  if (elProcPaginationInfo) {
    elProcPaginationInfo.innerText = `Showing ${startIdx.toLocaleString()} - ${endIdx.toLocaleString()} of ${total.toLocaleString()} processes`;
  }
  if (elProcPageCurrent) {
    elProcPageCurrent.innerText = `Page ${page} of ${totalPages}`;
  }

  if (elBtnProcFirst) elBtnProcFirst.disabled = (page <= 1);
  if (elBtnProcPrev) elBtnProcPrev.disabled = (page <= 1);
  if (elBtnProcNext) elBtnProcNext.disabled = (page >= totalPages);
  if (elBtnProcLast) elBtnProcLast.disabled = (page >= totalPages);
}

// 2. Open Process Details View (Task 3 & 4)
window.openProcessDetail = async function(pid, processName) {
  currentSelectedPid = pid;
  currentSelectedName = processName;

  // Switch Views
  if (elProcessesListView) elProcessesListView.classList.add('view-hidden');
  if (elProcessDetailView) elProcessDetailView.classList.remove('view-hidden');

  // Ensure scroll is positioned at the processes section
  const secProc = document.getElementById('section-processes');
  if (secProc) secProc.scrollIntoView({ behavior: 'smooth' });

  // Update Header Title
  if (elProcDetailTitle) {
    elProcDetailTitle.innerText = `${processName} (PID ${pid})`;
  }

  // Load process details and charts
  await loadProcessDetailData(pid, processName);
};

// Return to Process Overview
function closeProcessDetail() {
  if (elProcessDetailView) elProcessDetailView.classList.add('view-hidden');
  if (elProcessesListView) elProcessesListView.classList.remove('view-hidden');
  currentSelectedPid = null;
  currentSelectedName = null;
  fetchProcesses();
}

if (elBtnBackToProcList) {
  elBtnBackToProcList.addEventListener('click', closeProcessDetail);
}

// Jump from Process Details to Alert History (Task 3 & 5 Cross-Navigation)
if (elBtnViewProcAlerts) {
  elBtnViewProcAlerts.addEventListener('click', () => {
    if (!currentSelectedPid) return;

    if (elHistFilterPid) elHistFilterPid.value = currentSelectedPid;
    if (elHistFilterProc) elHistFilterProc.value = currentSelectedName || '';
    if (elHistFilterStatus) elHistFilterStatus.value = '';
    if (elHistFilterScore) elHistFilterScore.value = '';

    histCurrentPage = 1;
    fetchAlertHistory();

    const histSec = document.getElementById('section-alert-history');
    if (histSec) histSec.scrollIntoView({ behavior: 'smooth' });
  });
}

// 3. Load All Process Detail Data
async function loadProcessDetailData(pid, name) {
  try {
    const encodedName = encodeURIComponent(name || '');

    // Fetch in parallel
    const [detailRes, eventsRes, alertsRes, ngramsRes, timelineRes] = await Promise.all([
      fetch(`/api/processes/detail?pid=${pid}&name=${encodedName}`),
      fetch(`/api/processes/events?pid=${pid}&name=${encodedName}&limit=50`),
      fetch(`/api/processes/alerts?pid=${pid}&name=${encodedName}&limit=50`),
      fetch(`/api/processes/top_ngrams?pid=${pid}&name=${encodedName}&limit=8`),
      fetch(`/api/processes/timeline?pid=${pid}&name=${encodedName}`)
    ]);

    const detailData = detailRes.ok ? await detailRes.json() : {};
    const eventsData = eventsRes.ok ? await eventsRes.json() : { events: [] };
    const alertsData = alertsRes.ok ? await alertsRes.json() : { alerts: [] };
    const ngramsData = ngramsRes.ok ? await ngramsRes.json() : { top_ngrams: [] };
    const timelineData = timelineRes.ok ? await timelineRes.json() : { timeline: [] };

    const proc = detailData.process || {};

    // Update Header Status Badge
    if (elProcDetailStatusBadge) {
      if (proc.is_running) {
        elProcDetailStatusBadge.className = "badge-status status-active";
        elProcDetailStatusBadge.innerText = "ACTIVE";
      } else {
        elProcDetailStatusBadge.className = "badge-status status-historical";
        elProcDetailStatusBadge.innerText = "HISTORICAL";
      }
    }

    // Populate Key Metrics
    const totalEvents = proc.total_events || 0;
    const normalEvents = proc.normal_events || 0;
    const suspiciousEvents = proc.suspicious_events || 0;
    const anomalyPct = Number(proc.anomaly_percentage || 0);

    if (elDetailValTotal) elDetailValTotal.innerText = totalEvents.toLocaleString();
    if (elDetailValNormal) elDetailValNormal.innerText = normalEvents.toLocaleString();
    if (elDetailValSuspicious) elDetailValSuspicious.innerText = suspiciousEvents.toLocaleString();
    if (elDetailValRate) elDetailValRate.innerText = `${anomalyPct.toFixed(2)}%`;
    if (elDetailValFirstTs) elDetailValFirstTs.innerText = proc.first_timestamp || '-';
    if (elDetailValLastTs) elDetailValLastTs.innerText = proc.last_timestamp || '-';
    if (elProcChartDistRatio) elProcChartDistRatio.innerText = `${anomalyPct.toFixed(2)}% Anomalies`;

    // Render Canvas Charts
    drawProcTimelineChart(timelineData.timeline || []);
    drawProcDistChart(normalEvents, suspiciousEvents);
    drawProcTopNgramsChart(ngramsData.top_ngrams || []);
    drawProcAnomalyTimelineChart(timelineData.timeline || []);

    // Render Recent Syscall Sequences Table
    renderProcRecentEvents(eventsData.events || []);

    // Render Recent Anomaly Alerts Feed
    renderProcRecentAlerts(alertsData.alerts || []);

  } catch (err) {
    console.error("Error loading process detail data:", err);
  }
}

// 4. Pure Canvas Charts for Process Behavioral Analysis (Task 4)

// Chart A: Process Activity Timeline
function drawProcTimelineChart(timeline) {
  if (!canvasProcTimeline) return;
  resizeProcCanvas(canvasProcTimeline);
  const ctx = canvasProcTimeline.getContext('2d');
  const w = canvasProcTimeline.width;
  const h = canvasProcTimeline.height;
  ctx.clearRect(0, 0, w, h);

  if (!timeline || timeline.length === 0) {
    ctx.fillStyle = '#6b7280';
    ctx.font = `${Math.max(12, Math.floor(h * 0.065))}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText('No timeline activity recorded for this process.', w / 2, h / 2);
    return;
  }

  const padLeft = 45;
  const padBottom = 25;
  const plotW = w - padLeft - 15;
  const plotH = h - padBottom - 15;

  const maxVal = Math.max(...timeline.map(d => d.total_events || 0), 5);

  // Axes
  ctx.strokeStyle = '#283548';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padLeft, 10);
  ctx.lineTo(padLeft, h - padBottom);
  ctx.lineTo(w - 10, h - padBottom);
  ctx.stroke();

  // Draw Activity Area / Line (Cyan)
  ctx.strokeStyle = '#06b6d4';
  ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
  ctx.lineWidth = 2;
  ctx.beginPath();

  if (timeline.length === 1) {
    const y = (h - padBottom) - (timeline[0].total_events / maxVal) * plotH;
    ctx.arc(w / 2, y, 4, 0, 2 * Math.PI);
    ctx.fill();
    ctx.stroke();
  } else {
    timeline.forEach((d, i) => {
      const x = padLeft + (i / (timeline.length - 1)) * plotW;
      const y = (h - padBottom) - (d.total_events / maxVal) * plotH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Fill under curve
    ctx.lineTo(padLeft + plotW, h - padBottom);
    ctx.lineTo(padLeft, h - padBottom);
    ctx.closePath();
    ctx.fill();
  }

  // Labels
  ctx.fillStyle = '#9ca3af';
  ctx.font = `${Math.max(10, Math.floor(h * 0.055))}px monospace`;
  ctx.textAlign = 'right';
  ctx.fillText(String(maxVal), padLeft - 6, 20);
  ctx.fillText('0', padLeft - 6, h - padBottom);
}

// Chart B: Normal vs Suspicious Distribution (Doughnut)
function drawProcDistChart(normal, suspicious) {
  if (!canvasProcDist) return;
  resizeProcCanvas(canvasProcDist);
  const ctx = canvasProcDist.getContext('2d');
  const w = canvasProcDist.width;
  const h = canvasProcDist.height;
  ctx.clearRect(0, 0, w, h);

  const total = normal + suspicious;
  const cx = w * 0.36;
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

  // Normal Arc (Green)
  ctx.lineWidth = radius - innerRadius;
  ctx.strokeStyle = '#10b981';
  ctx.beginPath();
  ctx.arc(cx, cy, (radius + innerRadius) / 2, -Math.PI / 2, -Math.PI / 2 + normalAngle);
  ctx.stroke();

  // Suspicious Arc (Red)
  if (suspicious > 0) {
    ctx.strokeStyle = '#ef4444';
    ctx.beginPath();
    ctx.arc(cx, cy, (radius + innerRadius) / 2, -Math.PI / 2 + normalAngle, -Math.PI / 2 + 2 * Math.PI);
    ctx.stroke();
  }

  // Legend
  const lx = w * 0.68;
  const fontSize = Math.max(11, Math.floor(h * 0.065));
  ctx.font = `${fontSize}px sans-serif`;

  ctx.fillStyle = '#10b981';
  ctx.fillRect(lx, cy - 25, 10, 10);
  ctx.fillStyle = '#f3f4f6';
  ctx.textAlign = 'left';
  ctx.fillText(`Normal: ${normal.toLocaleString()}`, lx + 16, cy - 16);

  ctx.fillStyle = '#ef4444';
  ctx.fillRect(lx, cy + 5, 10, 10);
  ctx.fillStyle = '#f3f4f6';
  ctx.fillText(`Alerts: ${suspicious.toLocaleString()}`, lx + 16, cy + 14);
}

// Chart C: Most Frequent Syscall Sequences (Horizontal Bars)
function drawProcTopNgramsChart(ngrams) {
  if (!canvasProcTopNgrams) return;
  resizeProcCanvas(canvasProcTopNgrams);
  const ctx = canvasProcTopNgrams.getContext('2d');
  const w = canvasProcTopNgrams.width;
  const h = canvasProcTopNgrams.height;
  ctx.clearRect(0, 0, w, h);

  if (!ngrams || ngrams.length === 0) {
    ctx.fillStyle = '#6b7280';
    ctx.font = `${Math.max(12, Math.floor(h * 0.065))}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText('No syscall sequences observed.', w / 2, h / 2);
    return;
  }

  const items = ngrams.slice(0, 6);
  const maxCount = Math.max(...items.map(i => i.count), 1);
  const barHeight = Math.min(22, (h - 25) / items.length - 8);
  const labelWidth = Math.min(180, w * 0.42);

  items.forEach((item, idx) => {
    const y = 14 + idx * (barHeight + 10);
    const barW = Math.max(((w - labelWidth - 65) * (item.count / maxCount)), 4);

    // Sequence Label
    ctx.fillStyle = '#93c5fd';
    ctx.font = `${Math.max(10, Math.floor(h * 0.052))}px monospace`;
    ctx.textAlign = 'right';
    const cleanSeq = item.sequence_str || `${item.syscall_1} -> ${item.syscall_2} -> ${item.syscall_3}`;
    ctx.fillText(cleanSeq.slice(0, 24), labelWidth - 8, y + barHeight * 0.72);

    // Bar (Cyan-Blue)
    ctx.fillStyle = '#0284c7';
    ctx.fillRect(labelWidth, y, barW, barHeight);

    // Count text
    ctx.fillStyle = '#f3f4f6';
    ctx.font = `${Math.max(10, Math.floor(h * 0.052))}px monospace`;
    ctx.textAlign = 'left';
    ctx.fillText(String(item.count.toLocaleString()), labelWidth + barW + 8, y + barHeight * 0.72);
  });
}

// Chart D: Process Anomaly Timeline
function drawProcAnomalyTimelineChart(timeline) {
  if (!canvasProcAnomalyTimeline) return;
  resizeProcCanvas(canvasProcAnomalyTimeline);
  const ctx = canvasProcAnomalyTimeline.getContext('2d');
  const w = canvasProcAnomalyTimeline.width;
  const h = canvasProcAnomalyTimeline.height;
  ctx.clearRect(0, 0, w, h);

  const totalAnomalies = timeline ? timeline.reduce((acc, d) => acc + (d.suspicious_events || 0), 0) : 0;

  if (!timeline || timeline.length === 0 || totalAnomalies === 0) {
    ctx.fillStyle = '#10b981';
    ctx.font = `${Math.max(12, Math.floor(h * 0.065))}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText('✅ Zero anomaly spikes recorded across timeline.', w / 2, h / 2);
    return;
  }

  const padLeft = 45;
  const padBottom = 25;
  const plotW = w - padLeft - 15;
  const plotH = h - padBottom - 15;

  const maxVal = Math.max(...timeline.map(d => d.suspicious_events || 0), 1);

  // Axes
  ctx.strokeStyle = '#283548';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padLeft, 10);
  ctx.lineTo(padLeft, h - padBottom);
  ctx.lineTo(w - 10, h - padBottom);
  ctx.stroke();

  // Draw Suspicious Bars / Spikes (Alert Red)
  const barW = Math.max(3, plotW / timeline.length - 2);

  timeline.forEach((d, i) => {
    const count = d.suspicious_events || 0;
    if (count > 0) {
      const x = padLeft + (i / timeline.length) * plotW;
      const barH = (count / maxVal) * plotH;
      const y = (h - padBottom) - barH;

      ctx.fillStyle = '#ef4444';
      ctx.fillRect(x, y, barW, barH);
    }
  });

  // Labels
  ctx.fillStyle = '#ef4444';
  ctx.font = `${Math.max(10, Math.floor(h * 0.055))}px monospace`;
  ctx.textAlign = 'right';
  ctx.fillText(String(maxVal), padLeft - 6, 20);
  ctx.fillStyle = '#9ca3af';
  ctx.fillText('0', padLeft - 6, h - padBottom);
}

// 5. Render Recent Syscall Sequences Table
function renderProcRecentEvents(events) {
  if (!elProcDetailRecentEventsBody) return;

  if (events.length === 0) {
    elProcDetailRecentEventsBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 25px;">
          No recent syscall sequences logged for this process.
        </td>
      </tr>`;
    return;
  }

  const rows = events.slice(0, 30).map(ev => {
    const isSusp = !!ev.is_suspicious;
    const scoreColor = isSusp ? 'color: var(--anomaly-red); font-weight: 700;' : 'color: var(--normal-green);';
    const statusTag = isSusp
      ? '<span class="tag tag-suspicious">SUSPICIOUS</span>'
      : '<span class="tag tag-normal">NORMAL</span>';

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${ev.event_timestamp || '-'}</td>
        <td class="seq-code" style="font-size: 11px;">${escapeHtml(ev.sequence_str || '')}</td>
        <td style="font-family: var(--font-mono); ${scoreColor}">${Number(ev.anomaly_score || 0).toFixed(4)}</td>
        <td>${statusTag}</td>
      </tr>
    `;
  }).join('');

  elProcDetailRecentEventsBody.innerHTML = rows;
}

// 6. Render Recent Anomaly Alerts Feed
function renderProcRecentAlerts(alerts) {
  if (!elProcDetailAlertsBody) return;

  if (elProcDetailAlertsBadge) {
    elProcDetailAlertsBadge.innerText = `${alerts.length} alerts`;
  }

  if (alerts.length === 0) {
    elProcDetailAlertsBody.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 30px;">
        ✅ No suspicious syscall transitions recorded for this process.
      </div>`;
    return;
  }

  const cardsHtml = alerts.slice(0, 20).map(a => {
    const statusBadge = getStatusBadgeHtml(a.incident_status);
    const sevBadge = getSeverityBadgeHtml(a.severity);
    return `
      <div class="alert-item" style="margin-bottom: 10px;">
        <div class="alert-header">
          <div class="alert-proc">
            <span>🚨 Alert #${a.alert_id}</span>
            <span style="font-size: 11px; color: var(--text-muted);">(${a.created_at || a.event_timestamp})</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            ${sevBadge}
            ${statusBadge}
            <span class="tag tag-suspicious">SCORE: ${Number(a.anomaly_score).toFixed(4)}</span>
          </div>
        </div>
        <div style="font-family: var(--font-mono); font-size: 11px; color: #93c5fd; margin-top: 4px;">
          Sequence: ${escapeHtml(a.sequence_str || `${a.syscall_1} -> ${a.syscall_2} -> ${a.syscall_3}`)}
        </div>
        <div class="alert-body" style="margin-top: 4px;">
          <strong>Root Cause:</strong> ${escapeHtml(a.explanation || "Syscall transition not seen in training.")}
        </div>
        ${a.severity_reason ? `<div style="font-size: 11px; color: #fbbf24; margin-top: 4px;"><strong>Triage:</strong> [${escapeHtml(a.severity || 'MEDIUM')}] ${escapeHtml(a.severity_reason)}</div>` : ''}
        <div style="margin-top: 8px; text-align: right;">
          <button class="btn-action" onclick="openAlertDetail(${a.alert_id})">🔍 Investigate Alert</button>
        </div>
      </div>
    `;
  }).join('');

  elProcDetailAlertsBody.innerHTML = cardsHtml;
}

// 7. Event Listeners for Process Overview Controls
if (elProcFilterName) {
  let debounceTimer;
  elProcFilterName.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      procCurrentPage = 1;
      fetchProcesses();
    }, 250);
  });
}

if (elProcFilterPid) {
  elProcFilterPid.addEventListener('input', () => {
    procCurrentPage = 1;
    fetchProcesses();
  });
}

if (elProcSortBy) {
  elProcSortBy.addEventListener('change', () => {
    procCurrentPage = 1;
    fetchProcesses();
  });
}

if (elProcSortOrder) {
  elProcSortOrder.addEventListener('change', () => {
    procCurrentPage = 1;
    fetchProcesses();
  });
}

if (elProcPageSize) {
  elProcPageSize.addEventListener('change', () => {
    procCurrentPage = 1;
    fetchProcesses();
  });
}

if (elBtnProcReset) {
  elBtnProcReset.addEventListener('click', () => {
    if (elProcFilterName) elProcFilterName.value = '';
    if (elProcFilterPid) elProcFilterPid.value = '';
    if (elProcSortBy) elProcSortBy.value = 'total';
    if (elProcSortOrder) elProcSortOrder.value = 'desc';
    if (elProcPageSize) elProcPageSize.value = '25';
    procCurrentPage = 1;
    fetchProcesses();
  });
}

if (elBtnRefreshProcesses) {
  elBtnRefreshProcesses.addEventListener('click', () => {
    fetchProcesses();
  });
}

// Pagination navigation for processes
if (elBtnProcFirst) {
  elBtnProcFirst.addEventListener('click', () => {
    if (procCurrentPage > 1) {
      procCurrentPage = 1;
      fetchProcesses();
    }
  });
}

if (elBtnProcPrev) {
  elBtnProcPrev.addEventListener('click', () => {
    if (procCurrentPage > 1) {
      procCurrentPage--;
      fetchProcesses();
    }
  });
}

if (elBtnProcNext) {
  elBtnProcNext.addEventListener('click', () => {
    if (procCurrentPage < procTotalPages) {
      procCurrentPage++;
      fetchProcesses();
    }
  });
}

if (elBtnProcLast) {
  elBtnProcLast.addEventListener('click', () => {
    if (procCurrentPage < procTotalPages) {
      procCurrentPage = procTotalPages;
      fetchProcesses();
    }
  });
}

// Initial fetch for Process-Wise Monitoring
fetchProcesses();
setInterval(() => {
  // Only refresh list if detail view is not active
  if (elProcessDetailView && elProcessDetailView.classList.contains('view-hidden')) {
    fetchProcesses();
  }
}, 5000);

