/**
 * IoMT Adaptive SDN Mitigation Dashboard — Frontend Controller (v2.0 Hardened)
 * Component: Safety-Constrained Adaptive SDN Mitigation and Monitoring (IT23306936)
 *
 * Core Fixes Implemented:
 * - Issue A: Live mode ingestion and clearing DEMO data on mode change.
 * - Issue B: Rejection of mock execution for live mode requests without privileges.
 * - Issue C: Distinct scenario dispatching.
 * - Issue D: Sequential Replay with play/pause/step controls and nested run discovery.
 * - Issue E: Unified RTT field names (icmp_reply_rtt_avg_ms & icmp_rtt_avg_ms).
 * - Issue F: Charts draw true gaps/breaks for missing measurements instead of plunging to zero.
 * - Issue G: Natural process completion and lock release tracking.
 * - Issue H: Loopback default binding and token authentication on control endpoints.
 * - Issue J: History parsing separating execution failure from valid QoS failure.
 */

let currentMode = 'DEMO';
let authToken = '';
let telemetryHistory = {
    labels: [],
    throughput: [],
    loss: [],
    rtt: [],
    freshness: []
};
const MAX_CHART_POINTS = 30;
let lastRenderedEventId = null;

// Replay Timer
let replayTimer = null;
let isReplaying = false;
let replaySpeedSeconds = 1.0;
let currentReplayTotalWindows = 0;
let currentReplayIndex = 0;

// Initialize when DOM ready
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initAuthToken();
    initCharts();
    refreshHistory();
    startTelemetryStream();
});

// Clock display
function initClock() {
    function update() {
        const now = new Date();
        const str = now.toISOString().substring(11, 19) + ' UTC';
        const el = document.getElementById('sys-clock');
        if (el) el.innerText = str;
    }
    update();
    setInterval(update, 1000);
}

// Fetch auth token
function initAuthToken() {
    fetch('/api/auth/token')
        .then(res => res.json())
        .then(data => {
            if (data.auth_token) authToken = data.auth_token;
        })
        .catch(console.error);
}

// Helper: Secure API fetch with token
function secureFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (authToken) {
        options.headers['X-IoMT-Token'] = authToken;
    }
    return fetch(url, options);
}

// Mode Switcher
function switchMode(newMode) {
    if (newMode === currentMode) return;
    currentMode = newMode;
    document.querySelectorAll('.segmented-btn, .mode-btn').forEach(b => b.classList.remove('active'));

    // Reset chart history when switching modes
    resetChartHistory();

    const badge = document.getElementById('header-mode-badge');

    if (newMode === 'DEMO') {
        const b = document.getElementById('btn-mode-demo');
        if (b) b.classList.add('active');
        const rc = document.getElementById('replay-controls');
        if (rc) rc.style.display = 'none';
        const lc = document.getElementById('live-controls-group');
        if (lc) lc.style.display = 'flex';
        updateConnectionStatus('Connected (DEMO)', 'demo');
        if (badge) {
            badge.innerText = 'DEMO • Synthetic data';
            badge.className = 'mode-provenance-badge badge-demo';
        }
    } else if (newMode === 'REPLAY') {
        const b = document.getElementById('btn-mode-replay');
        if (b) b.classList.add('active');
        const rc = document.getElementById('replay-controls');
        if (rc) rc.style.display = 'flex';
        const lc = document.getElementById('live-controls-group');
        if (lc) lc.style.display = 'none';
        updateConnectionStatus('Replay Mode', 'replay');
        if (badge) {
            badge.innerText = 'REPLAY • Historical run';
            badge.className = 'mode-provenance-badge badge-replay';
        }
        loadReplayList();
    } else if (newMode === 'LIVE') {
        const b = document.getElementById('btn-mode-live');
        if (b) b.classList.add('active');
        const rc = document.getElementById('replay-controls');
        if (rc) rc.style.display = 'none';
        const lc = document.getElementById('live-controls-group');
        if (lc) lc.style.display = 'flex';
        updateConnectionStatus('Waiting for Live Telemetry', 'waiting');
        if (badge) {
            badge.innerText = 'LIVE • Waiting for stream';
            badge.className = 'mode-provenance-badge badge-waiting';
        }
    }

    secureFetch('/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode })
    })
    .then(res => res.json())
    .then(data => {
        pollTelemetry();
    })
    .catch(console.error);
}

function updateConnectionStatus(label, type) {
    const pill = document.getElementById('connection-pill');
    const lbl = document.getElementById('conn-label');
    const dot = document.getElementById('conn-dot');
    if (lbl) lbl.innerText = label;
    if (pill) {
        pill.className = 'connection-status-pill';
        if (type === 'stale') pill.classList.add('stale');
        else if (type === 'disconnected' || type === 'waiting') pill.classList.add('disconnected');
    }
}

// Reset chart data
function resetChartHistory() {
    telemetryHistory = {
        labels: [],
        throughput: [],
        loss: [],
        rtt: [],
        freshness: []
    };
    lastRenderedEventId = null;
    renderCharts();
}

// Telemetry Polling & SSE Stream
function startTelemetryStream() {
    if (window.EventSource) {
        const source = new EventSource('/api/stream');
        source.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                renderTelemetry(data);
            } catch (err) {
                console.error("SSE parse error", err);
            }
        };
        source.onerror = () => {
            source.close();
            setInterval(pollTelemetry, 1500);
        };
    } else {
        setInterval(pollTelemetry, 1500);
    }
}

function pollTelemetry() {
    fetch('/api/telemetry')
        .then(res => res.json())
        .then(renderTelemetry)
        .catch(console.error);
}

// Render Telemetry Data into UI
function renderTelemetry(data) {
    if (!data) return;

    // Check mode alignment
    const mode = data.mode || currentMode;
    const freshness = data.data_freshness || 'fresh';

    // Update connection status
    if (mode === 'LIVE') {
        if (freshness === 'waiting') updateConnectionStatus('Waiting for Live Stream...', 'waiting');
        else if (freshness === 'stale') updateConnectionStatus('Live Stream STALE', 'stale');
        else updateConnectionStatus('Live Kernel Telemetry', 'live');
    }

    // 1. Throughput KPI
    const tpVal = data.sensor_throughput_kbps != null ? Number(data.sensor_throughput_kbps).toFixed(1) : '--';
    const tpEl = document.getElementById('kpi-tp-val');
    if (tpEl) tpEl.innerText = tpVal;
    const tpBadge = document.getElementById('kpi-tp-badge');
    const tpFill = document.getElementById('kpi-tp-fill');

    if (data.sensor_throughput_kbps != null) {
        const tpNum = Number(data.sensor_throughput_kbps);
        if (tpFill) tpFill.style.width = Math.min(100, (tpNum / 100.0) * 100) + '%';
        const pctDiff = ((tpNum - 97.8) / 97.8 * 100).toFixed(1);
        const sign = (pctDiff >= 0) ? '+' : '';
        const arrow = (pctDiff >= 0) ? '&blacktriangle;' : '&blacktriangledown;';
        const cls = (pctDiff >= 0) ? 'delta-positive' : 'text-red';
        if (tpBadge) {
            tpBadge.className = `metric-delta ${cls}`;
            tpBadge.innerHTML = `<span class="delta-arrow">${arrow}</span> ${sign}${pctDiff}% vs. baseline`;
        }
    } else {
        if (tpBadge) {
            tpBadge.className = 'metric-delta delta-neutral';
            tpBadge.innerHTML = `<span class="delta-arrow">&bull;</span> ${freshness === 'waiting' ? 'WAITING' : 'UNAVAILABLE'}`;
        }
        if (tpFill) tpFill.style.width = '0%';
    }

    // 2. Packet Loss KPI
    const lossVal = data.sensor_packet_loss_percent != null ? Number(data.sensor_packet_loss_percent).toFixed(1) : '--';
    const lossEl = document.getElementById('kpi-loss-val');
    if (lossEl) lossEl.innerText = lossVal;
    const lossBadge = document.getElementById('kpi-loss-badge');
    const lossFill = document.getElementById('kpi-loss-fill');

    if (data.sensor_packet_loss_percent != null) {
        const lossNum = Number(data.sensor_packet_loss_percent);
        if (lossFill) lossFill.style.width = Math.min(100, lossNum) + '%';
        const diff = (lossNum - 1.2).toFixed(1);
        const sign = (diff >= 0) ? '+' : '';
        const arrow = (diff <= 0) ? '&blacktriangledown;' : '&blacktriangle;';
        const cls = (lossNum <= 1.0) ? 'delta-positive' : 'text-red';
        if (lossBadge) {
            lossBadge.className = `metric-delta ${cls}`;
            lossBadge.innerHTML = `<span class="delta-arrow">${arrow}</span> ${sign}${diff}% vs. before mitigation`;
        }
    } else {
        if (lossBadge) {
            lossBadge.className = 'metric-delta delta-neutral';
            lossBadge.innerHTML = `<span class="delta-arrow">&bull;</span> ${freshness === 'waiting' ? 'WAITING' : 'UNAVAILABLE'}`;
        }
        if (lossFill) lossFill.style.width = '0%';
    }

    // 3. ICMP RTT KPI (Issues E: supports both aliases)
    const rawRtt = (data.icmp_rtt_avg_ms != null) ? data.icmp_rtt_avg_ms : data.icmp_reply_rtt_avg_ms;
    const rttVal = rawRtt != null ? Number(rawRtt).toFixed(1) : '--';
    const rttEl = document.getElementById('kpi-rtt-val');
    if (rttEl) rttEl.innerText = rttVal;
    const rttBadge = document.getElementById('kpi-rtt-badge');
    const rttFill = document.getElementById('kpi-rtt-fill');
    if (rawRtt != null) {
        const rttNum = Number(rawRtt);
        if (rttFill) rttFill.style.width = Math.min(100, (rttNum / 100.0) * 100) + '%';
        const diff = (rttNum - 3.0).toFixed(1);
        const sign = (diff >= 0) ? '+' : '';
        const arrow = (diff <= 0) ? '&blacktriangledown;' : '&blacktriangle;';
        if (rttBadge) {
            rttBadge.className = 'metric-delta delta-neutral';
            rttBadge.innerHTML = `<span class="delta-arrow">${arrow}</span> ${sign}${diff} ms vs. before mitigation`;
        }
    } else {
        if (rttBadge) {
            rttBadge.className = 'metric-delta delta-neutral';
            rttBadge.innerHTML = `<span class="delta-arrow">&bull;</span> ${freshness === 'waiting' ? 'WAITING' : 'UNAVAILABLE'}`;
        }
        if (rttFill) rttFill.style.width = '0%';
    }

    // 4. Mitigation Status KPI
    const action = data.mitigation_action || 'none';
    const rateLimit = data.rate_limit_kbps;
    const cookie = data.rule_cookie || '--';
    const stage = data.lifecycle_stage || 'idle';

    const meterVal = document.getElementById('kpi-meter-val');
    const meterUnit = document.getElementById('kpi-meter-unit');
    const cookieEl = document.getElementById('kpi-cookie-val');
    if (cookieEl) cookieEl.innerText = cookie;
    const lifecycleEl = document.getElementById('kpi-lifecycle-val');

    if (action === 'rate_limit') {
        if (meterVal) meterVal.innerText = `Rate limited • ${rateLimit || 1000} Kbit/s`;
        if (meterUnit) meterUnit.innerText = '';
        if (lifecycleEl) lifecycleEl.innerText = 'Adaptive rule active';
    } else if (action === 'block') {
        if (meterVal) meterVal.innerText = 'Static Block • 0 Kbit/s';
        if (meterUnit) meterUnit.innerText = '';
        if (lifecycleEl) lifecycleEl.innerText = 'Drop rule enforced';
    } else {
        if (meterVal) meterVal.innerText = 'Monitoring • Unlimited';
        if (meterUnit) meterUnit.innerText = '';
        if (lifecycleEl) lifecycleEl.innerText = 'Baseline monitoring';
    }

    // 5. Timeline Stepper update
    const wIdx = data.window_index || 1;
    const winBadge = document.getElementById('current-window-badge');
    if (winBadge) winBadge.innerText = `Window ${wIdx} / 8`;
    for (let i = 1; i <= 8; i++) {
        const stepEl = document.getElementById(`step-w${i}`);
        if (stepEl) {
            stepEl.className = 'step-node';
            if (i < wIdx) stepEl.classList.add('completed');
            else if (i === wIdx) stepEl.classList.add('active');
        }
    }

    // 6. Security Alert update
    if (data.latest_alert) {
        const alt = data.latest_alert;
        const b = document.getElementById('alert-type-badge');
        if (b) b.innerText = alt.attack_type || 'Alert';
        const aId = document.getElementById('alert-id-val');
        if (aId) aId.innerText = alt.alert_id || '--';
        const aSrc = document.getElementById('alert-src-val');
        if (aSrc) aSrc.innerText = alt.source_ip || '--';
        const aDst = document.getElementById('alert-dst-val');
        if (aDst) aDst.innerText = alt.target_ip || '--';
        const aPort = document.getElementById('alert-port-val');
        if (aPort) aPort.innerText = alt.target_port ? `UDP ${alt.target_port}` : 'UDP 5201';
        const aSvc = document.getElementById('alert-service-val');
        if (aSvc) aSvc.innerText = alt.affected_service || 'ECG_Monitoring';
        const aCrit = document.getElementById('alert-criticality-val');
        if (aCrit) aCrit.innerText = (alt.criticality || 'CRITICAL').toUpperCase();
        const aReas = document.getElementById('policy-reasoning-text');
        if (aReas && alt.reasoning) {
            aReas.innerText = alt.reasoning;
        }
    }

    // 7. Update Charts without duplicate point spam
    const currentEventId = `${data.run_id}_${data.window_index}_${data.sensor_throughput_kbps}_${data.sensor_packet_loss_percent}`;
    if (currentEventId !== lastRenderedEventId) {
        lastRenderedEventId = currentEventId;
        pushChartData(data);
    }

    // 8. Update 3D Topology Animation state
    if (window.updateTopologyState) {
        window.updateTopologyState(data);
    }
}

// Canvas Charts Implementation with True Gaps (Issue F)
let chartCtxTP = null;
let chartCtxLoss = null;
let chartCtxRTT = null;

function initCharts() {
    const c1 = document.getElementById('chart-throughput') || document.getElementById('chart-throughput-loss');
    if (c1) chartCtxTP = c1.getContext('2d');
    const c2 = document.getElementById('chart-loss');
    if (c2) chartCtxLoss = c2.getContext('2d');
    const c3 = document.getElementById('chart-rtt');
    if (c3) chartCtxRTT = c3.getContext('2d');
}

function pushChartData(data) {
    const now = new Date();
    const timeLabel = now.toTimeString().substring(3, 8);

    const tp = data.sensor_throughput_kbps != null ? Number(data.sensor_throughput_kbps) : null;
    const loss = data.sensor_packet_loss_percent != null ? Number(data.sensor_packet_loss_percent) : null;
    const rtt = (data.icmp_rtt_avg_ms != null) ? Number(data.icmp_rtt_avg_ms) : ((data.icmp_reply_rtt_avg_ms != null) ? Number(data.icmp_reply_rtt_avg_ms) : null);

    telemetryHistory.labels.push(timeLabel);
    telemetryHistory.throughput.push(tp);
    telemetryHistory.loss.push(loss);
    telemetryHistory.rtt.push(rtt);
    telemetryHistory.freshness.push(data.data_freshness || 'fresh');

    if (telemetryHistory.labels.length > MAX_CHART_POINTS) {
        telemetryHistory.labels.shift();
        telemetryHistory.throughput.shift();
        telemetryHistory.loss.shift();
        telemetryHistory.rtt.shift();
        telemetryHistory.freshness.shift();
    }

    renderCharts();
}

function renderCharts() {
    // --- Chart 1: Sensor Throughput (h1) with True Gaps ---
    if (chartCtxTP) {
        const ctx1 = chartCtxTP;
        const w1 = ctx1.canvas.width = ctx1.canvas.clientWidth;
        const h1 = ctx1.canvas.height = ctx1.canvas.clientHeight;
        ctx1.clearRect(0, 0, w1, h1);

        const padLeft = 40, padRight = 20, padTop = 20, padBottom = 25;
        const plotW = w1 - padLeft - padRight;
        const plotH = h1 - padTop - padBottom;

        // Subtle Grid lines
        ctx1.strokeStyle = 'rgba(0, 0, 0, 0.05)';
        ctx1.lineWidth = 1;
        for (let yPct of [0, 0.33, 0.66, 1]) {
            const y = padTop + plotH * (1 - yPct);
            ctx1.beginPath();
            ctx1.moveTo(padLeft, y);
            ctx1.lineTo(w1 - padRight, y);
            ctx1.stroke();
        }

        // Horizontal Threshold line: 90 kbps (Green dashed)
        const y90 = padTop + plotH * (1 - 90 / 150);
        ctx1.strokeStyle = 'rgba(22, 163, 74, 0.65)';
        ctx1.setLineDash([4, 4]);
        ctx1.beginPath();
        ctx1.moveTo(padLeft, y90);
        ctx1.lineTo(w1 - padRight, y90);
        ctx1.stroke();
        ctx1.setLineDash([]);

        // Mitigation applied marker line (at ~55% of width if mitigated)
        const xMit = padLeft + plotW * 0.55;
        ctx1.strokeStyle = 'rgba(15, 23, 42, 0.35)';
        ctx1.setLineDash([3, 3]);
        ctx1.beginPath();
        ctx1.moveTo(xMit, padTop);
        ctx1.lineTo(xMit, padTop + plotH);
        ctx1.stroke();
        ctx1.setLineDash([]);

        // Labels
        ctx1.fillStyle = '#64748b';
        ctx1.font = '10px Inter, sans-serif';
        ctx1.textAlign = 'right';
        ctx1.fillText('150', padLeft - 6, padTop + 4);
        ctx1.fillText('90', padLeft - 6, y90 + 4);
        ctx1.fillText('0', padLeft - 6, padTop + plotH);

        // Mitigation text marker
        ctx1.textAlign = 'left';
        ctx1.fillStyle = '#334155';
        ctx1.font = '9.5px Inter, sans-serif';
        ctx1.fillText('Mitigation applied', xMit + 4, padTop + 10);

        // Throughput Curve with Area Fill & True Gap Handling
        const pts = telemetryHistory.throughput.length;
        if (pts > 1) {
            // Draw Gradient Area
            const grad = ctx1.createLinearGradient(0, padTop, 0, padTop + plotH);
            grad.addColorStop(0, 'rgba(13, 148, 136, 0.22)');
            grad.addColorStop(1, 'rgba(13, 148, 136, 0.01)');

            ctx1.fillStyle = grad;
            ctx1.beginPath();
            let startedArea = false;
            let firstX = padLeft, lastX = padLeft;
            for (let i = 0; i < pts; i++) {
                const val = telemetryHistory.throughput[i];
                if (val === null || isNaN(val)) continue;
                const x = padLeft + (i / (pts - 1)) * plotW;
                const y = padTop + plotH * (1 - Math.min(150, val) / 150);
                if (!startedArea) {
                    ctx1.moveTo(x, padTop + plotH);
                    ctx1.lineTo(x, y);
                    firstX = x;
                    startedArea = true;
                } else {
                    ctx1.lineTo(x, y);
                }
                lastX = x;
            }
            if (startedArea) {
                ctx1.lineTo(lastX, padTop + plotH);
                ctx1.closePath();
                ctx1.fill();
            }

            // Draw Line
            ctx1.strokeStyle = '#0d9488';
            ctx1.lineWidth = 2.5;
            ctx1.beginPath();
            let inSegment = false;
            for (let i = 0; i < pts; i++) {
                const val = telemetryHistory.throughput[i];
                if (val === null || isNaN(val)) {
                    inSegment = false;
                    continue;
                }
                const x = padLeft + (i / (pts - 1)) * plotW;
                const y = padTop + plotH * (1 - Math.min(150, val) / 150);
                if (!inSegment) {
                    ctx1.moveTo(x, y);
                    inSegment = true;
                } else {
                    ctx1.lineTo(x, y);
                }
            }
            ctx1.stroke();
        }
    }

    // --- Chart 2: UDP Packet Loss (h1) with True Gaps ---
    if (chartCtxLoss) {
        const ctx2 = chartCtxLoss;
        const w2 = ctx2.canvas.width = ctx2.canvas.clientWidth;
        const h2 = ctx2.canvas.height = ctx2.canvas.clientHeight;
        ctx2.clearRect(0, 0, w2, h2);

        const padLeft = 35, padRight = 20, padTop = 20, padBottom = 25;
        const plotW2 = w2 - padLeft - padRight;
        const plotH2 = h2 - padTop - padBottom;

        // Subtle Grid
        ctx2.strokeStyle = 'rgba(0, 0, 0, 0.05)';
        ctx2.lineWidth = 1;
        for (let yPct of [0, 0.33, 0.66, 1]) {
            const y = padTop + plotH2 * (1 - yPct);
            ctx2.beginPath();
            ctx2.moveTo(padLeft, y);
            ctx2.lineTo(w2 - padRight, y);
            ctx2.stroke();
        }

        // Mitigation marker line
        const xMit2 = padLeft + plotW2 * 0.55;
        ctx2.strokeStyle = 'rgba(15, 23, 42, 0.35)';
        ctx2.setLineDash([3, 3]);
        ctx2.beginPath();
        ctx2.moveTo(xMit2, padTop);
        ctx2.lineTo(xMit2, padTop + plotH2);
        ctx2.stroke();
        ctx2.setLineDash([]);

        // Labels
        ctx2.fillStyle = '#64748b';
        ctx2.font = '10px Inter, sans-serif';
        ctx2.textAlign = 'right';
        ctx2.fillText('20', padLeft - 6, padTop + 4);
        ctx2.fillText('10', padLeft - 6, padTop + plotH2 * 0.5 + 4);
        ctx2.fillText('0', padLeft - 6, padTop + plotH2);

        ctx2.textAlign = 'left';
        ctx2.fillStyle = '#334155';
        ctx2.font = '9.5px Inter, sans-serif';
        ctx2.fillText('Mitigation applied', xMit2 + 4, padTop + 10);

        // Packet Loss Line with Area Fill
        const pts = telemetryHistory.loss.length;
        if (pts > 1) {
            const gradLoss = ctx2.createLinearGradient(0, padTop, 0, padTop + plotH2);
            gradLoss.addColorStop(0, 'rgba(239, 68, 68, 0.2)');
            gradLoss.addColorStop(1, 'rgba(239, 68, 68, 0.01)');

            ctx2.fillStyle = gradLoss;
            ctx2.beginPath();
            let startedLoss = false;
            let firstX = padLeft, lastX = padLeft;
            for (let i = 0; i < pts; i++) {
                const lossVal = telemetryHistory.loss[i];
                if (lossVal === null || isNaN(lossVal)) continue;
                const x = padLeft + (i / (pts - 1)) * plotW2;
                const y = padTop + plotH2 * (1 - Math.min(25, lossVal) / 25);
                if (!startedLoss) {
                    ctx2.moveTo(x, padTop + plotH2);
                    ctx2.lineTo(x, y);
                    firstX = x;
                    startedLoss = true;
                } else {
                    ctx2.lineTo(x, y);
                }
                lastX = x;
            }
            if (startedLoss) {
                ctx2.lineTo(lastX, padTop + plotH2);
                ctx2.closePath();
                ctx2.fill();
            }

            ctx2.strokeStyle = '#ef4444';
            ctx2.lineWidth = 2.2;
            ctx2.beginPath();
            let inSegment = false;
            for (let i = 0; i < pts; i++) {
                const lossVal = telemetryHistory.loss[i];
                if (lossVal === null || isNaN(lossVal)) {
                    inSegment = false;
                    continue;
                }
                const x = padLeft + (i / (pts - 1)) * plotW2;
                const y = padTop + plotH2 * (1 - Math.min(25, lossVal) / 25);
                if (!inSegment) {
                    ctx2.moveTo(x, y);
                    inSegment = true;
                } else {
                    ctx2.lineTo(x, y);
                }
            }
            ctx2.stroke();
        }
    }
}

// Experiments: Start / Stop
function startExperiment() {
    const scen = document.getElementById('scenario-selector').value;
    const statusText = document.getElementById('experiment-status-text');
    statusText.innerText = `Starting ${scen}...`;
    statusText.style.color = '#38bdf8';

    secureFetch('/api/experiments/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scen, live: (currentMode === 'LIVE') })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            statusText.innerText = `Error: ${data.error}`;
            statusText.style.color = '#f87171';
            alert(`Execution Guard: ${data.error}`);
        } else {
            statusText.innerText = `Running (PID ${data.pid})`;
            statusText.style.color = '#4ade80';
        }
    })
    .catch(err => {
        statusText.innerText = `Network error: ${err}`;
        statusText.style.color = '#f87171';
    });
}

function stopExperiment() {
    const statusText = document.getElementById('experiment-status-text');
    statusText.innerText = 'Stopping...';
    secureFetch('/api/experiments/stop', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            statusText.innerText = 'Stopped';
            statusText.style.color = '#cbd5e1';
            refreshHistory();
        })
        .catch(console.error);
}

// History & Replay Functions (Issue D & J)
function refreshHistory() {
    fetch('/api/history')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById('history-table-body');
            tbody.innerHTML = '';
            if (!data.history || data.history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No benchmark records found</td></tr>';
                return;
            }

            data.history.forEach(item => {
                const tr = document.createElement('tr');
                const hasNested = item.nested_runs && item.nested_runs.length > 0;
                tr.innerHTML = `
                    <td class="mono font-semibold text-highlight">${escapeHTML(item.id)}</td>
                    <td>${escapeHTML(String(item.timestamp))}</td>
                    <td><span class="badge ${item.mode === 'live' ? 'badge-green' : 'badge-neutral'}">${escapeHTML(item.mode)}</span></td>
                    <td>${escapeHTML(item.type)}</td>
                    <td>${item.repeats}</td>
                    <td class="text-emerald font-semibold">${item.total_valid_runs}</td>
                    <td class="${item.total_execution_failures > 0 ? 'text-red font-semibold' : 'text-muted'}">${item.total_execution_failures}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="quickReplay('${item.id}')">Replay</button>
                    </td>
                `;
                tbody.appendChild(tr);

                // Add expandable nested rows if available
                if (hasNested) {
                    item.nested_runs.forEach(sub => {
                        const trSub = document.createElement('tr');
                        trSub.className = 'sub-run-row';
                        trSub.innerHTML = `
                            <td class="mono text-muted" style="padding-left: 28px;">&bull; ${escapeHTML(sub.sub_name)} (${escapeHTML(sub.scenario)})</td>
                            <td>--</td>
                            <td><span class="badge badge-neutral">nested</span></td>
                            <td>individual_run</td>
                            <td>1</td>
                            <td class="${sub.qos_passed ? 'text-emerald' : 'text-amber'}">${sub.qos_passed ? 'QoS PASS' : 'QoS DEGRADED'}</td>
                            <td class="text-muted">0</td>
                            <td>
                                <button class="btn btn-secondary btn-sm" onclick="quickReplay('${sub.run_id}')">Replay Run</button>
                            </td>
                        `;
                        tbody.appendChild(trSub);
                    });
                }
            });

            // Update statistical evaluation table
            updateStatisticalTable(data.history);
        })
        .catch(console.error);
}

function updateStatisticalTable(history) {
    // Find latest matched comparison summary
    const mc = history.find(h => h.type === 'matched_comparison');
    if (!mc || !mc.summary_path) return;

    fetch(`/api/runs/${mc.id}`)
        .then(res => res.json())
        .then(sum => {
            if (!sum.statistics) return;
            const stats = sum.statistics;

            if (stats.baseline) {
                const b = stats.baseline;
                const fw = b.final_window_metrics || {};
                document.getElementById('stat-base-valid').innerText = `${b.completed_valid_runs} / ${b.total_scheduled_runs}`;
                document.getElementById('stat-base-fails').innerText = b.execution_failure_count;
                document.getElementById('stat-base-inv').innerText = b.measurement_invalid_count;
                document.getElementById('stat-base-pass').innerText = `${fw.qos_pass_rate_pct != null ? fw.qos_pass_rate_pct : 0.0}% (${fw.qos_pass_count || 0}/${b.completed_valid_runs})`;
                document.getElementById('stat-base-tp').innerText = formatStat(fw.throughput_kbps);
                document.getElementById('stat-base-loss').innerText = formatStat(fw.packet_loss_percent);
                document.getElementById('stat-base-rtt').innerText = formatStat(fw.icmp_reply_rtt_ms);
            }

            if (stats.static_block) {
                const s = stats.static_block;
                const fw = s.final_window_metrics || {};
                document.getElementById('stat-stat-valid').innerText = `${s.completed_valid_runs} / ${s.total_scheduled_runs}`;
                document.getElementById('stat-stat-fails').innerText = s.execution_failure_count;
                document.getElementById('stat-stat-inv').innerText = s.measurement_invalid_count;
                document.getElementById('stat-stat-pass').innerText = `${fw.qos_pass_rate_pct != null ? fw.qos_pass_rate_pct : 0.0}% (${fw.qos_pass_count || 0}/${s.completed_valid_runs})`;
                document.getElementById('stat-stat-tp').innerText = formatStat(fw.throughput_kbps);
                document.getElementById('stat-stat-loss').innerText = formatStat(fw.packet_loss_percent);
                document.getElementById('stat-stat-rtt').innerText = formatStat(fw.icmp_reply_rtt_ms);
            }

            if (stats.adaptive) {
                const a = stats.adaptive;
                const fw = a.final_window_metrics || {};
                document.getElementById('stat-adap-valid').innerText = `${a.completed_valid_runs} / ${a.total_scheduled_runs}`;
                document.getElementById('stat-adap-fails').innerText = a.execution_failure_count;
                document.getElementById('stat-adap-inv').innerText = a.measurement_invalid_count;
                document.getElementById('stat-adap-pass').innerText = `${fw.qos_pass_rate_pct != null ? fw.qos_pass_rate_pct : 0.0}% (${fw.qos_pass_count || 0}/${a.completed_valid_runs})`;
                document.getElementById('stat-adap-tp').innerText = formatStat(fw.throughput_kbps);
                document.getElementById('stat-adap-loss').innerText = formatStat(fw.packet_loss_percent);
                document.getElementById('stat-adap-rtt').innerText = formatStat(fw.icmp_reply_rtt_ms);
            }
        })
        .catch(console.error);
}

function formatStat(series) {
    if (!series || series.mean == null) return '--';
    const sdStr = series.sample_sd != null ? `± ${series.sample_sd}` : 'SD null (n<2)';
    return `${series.mean} (${sdStr})`;
}

function escapeHTML(str) {
    return String(str).replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag] || tag));
}

// Replay List Loader (Populates select dropdown with both top-level and nested runs)
function loadReplayList() {
    fetch('/api/history')
        .then(res => res.json())
        .then(data => {
            const sel = document.getElementById('replay-selector');
            sel.innerHTML = '<option value="">-- Select Recorded Benchmark or Run --</option>';
            if (data.history) {
                data.history.forEach(item => {
                    if (item.nested_runs && item.nested_runs.length > 0) {
                        const optGroup = document.createElement('optgroup');
                        optGroup.label = `${item.id} (${item.mode})`;
                        item.nested_runs.forEach(sub => {
                            const opt = document.createElement('option');
                            opt.value = sub.run_id;
                            opt.innerText = `${sub.sub_name}: ${sub.scenario} (${sub.qos_passed ? 'PASS' : 'DEGRADED'})`;
                            optGroup.appendChild(opt);
                        });
                        sel.appendChild(optGroup);
                    } else {
                        const opt = document.createElement('option');
                        opt.value = item.id;
                        opt.innerText = `${item.id} (${item.mode}, Valid: ${item.total_valid_runs})`;
                        sel.appendChild(opt);
                    }
                });
            }
        });
}

function quickReplay(runId) {
    switchMode('REPLAY');
    document.getElementById('replay-selector').value = runId;
    loadSelectedReplay(runId);
}

function loadSelectedReplay(runId) {
    if (!runId) return;
    if (replayTimer) clearInterval(replayTimer);
    isReplaying = false;
    document.getElementById('btn-replay-play').innerText = '▶ Play';

    secureFetch('/api/replay/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: runId })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            alert(`Replay Error: ${data.error}`);
            return;
        }
        currentReplayTotalWindows = data.total_windows;
        currentReplayIndex = 0;
        document.getElementById('replay-progress-text').innerText = `Window: 1 / ${data.total_windows}`;
        pollTelemetry();
    })
    .catch(console.error);
}

function stepReplay(direction) {
    secureFetch('/api/replay/step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ direction: direction })
    })
    .then(res => res.json())
    .then(data => {
        if (data.current_index != null) {
            currentReplayIndex = data.current_index;
            document.getElementById('replay-progress-text').innerText = `Window: ${data.current_index + 1} / ${data.total_windows}`;
            pollTelemetry();
        }
    })
    .catch(console.error);
}

function toggleReplayPlay() {
    const btn = document.getElementById('btn-replay-play');
    if (isReplaying) {
        clearInterval(replayTimer);
        isReplaying = false;
        btn.innerText = '▶ Play';
    } else {
        isReplaying = true;
        btn.innerText = '❚❚ Pause';
        replayTimer = setInterval(() => {
            if (currentReplayIndex >= currentReplayTotalWindows - 1) {
                toggleReplayPlay();
                return;
            }
            stepReplay('next');
        }, replaySpeedSeconds * 1000);
    }
}

function setReplaySpeed(val) {
    replaySpeedSeconds = Number(val) || 1.0;
    if (isReplaying) {
        clearInterval(replayTimer);
        replayTimer = setInterval(() => {
            if (currentReplayIndex >= currentReplayTotalWindows - 1) {
                toggleReplayPlay();
                return;
            }
            stepReplay('next');
        }, replaySpeedSeconds * 1000);
    }
}
