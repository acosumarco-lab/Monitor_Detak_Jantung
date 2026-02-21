/**
 * ===================================================================================
 * SECURE HEART MONITOR — WEB RECEIVER v2 (Minimalist Modern)
 * 
 * Fitur:
 * - MQTT via WebSocket → Live BPM + Secure block verification
 * - DWT Haar + QIM + SHA-256 (identik dengan sender.ino & receiver.py)
 * - Heart Rate Zones (Rest / Moderate / Cardio / Peak)
 * - Min / Max / Average BPM statistics
 * - Latency timer (waktu sejak blok terakhir)
 * - BER History chart
 * - Integrity Score (kumulatif valid/invalid)
 * - Alert system (abnormal BPM)
 * - Packet & Block counter
 * ===================================================================================
 */

// ======================== 1. CONFIG ========================
const CFG = {
    MQTT_URL: 'wss://broker.emqx.io:8084/mqtt',
    MQTT_TOPIC: 'polban/iot/jantung/syauqi',
    SECRET_KEY: 'RahasiaPolban',
    QIM_DELTA: 2.0,
    BER_THRESHOLD: 30.0,
    MAX_BPM_REF: 200.0,
    CHART_MAX: 60,
    BER_CHART_MAX: 20,
    LOG_MAX_LINES: 200,
    ALERT_BPM_LOW: 40,
    ALERT_BPM_HIGH: 180,
};

// ======================== 2. STATE ========================
let attackMode = 'NORMAL';
let bpmHistory = [];
let berHistory = [];
let bpmChart = null;
let berChart = null;
let mqttClient = null;

// Statistics
let stats = {
    packetCount: 0,
    blockCount: 0,
    validBlocks: 0,
    invalidBlocks: 0,
    allBPM: [],
    lastBlockTime: null,
};

// ======================== 3. DOM ========================
const $ = (id) => document.getElementById(id);

const dom = {
    mqttBadge: $('mqttBadge'),
    clock: $('clock'),
    // Stats
    bpmValue: $('bpmValue'),
    bpmZone: $('bpmZone'),
    avgValue: $('avgValue'),
    minValue: $('minValue'),
    maxValue: $('maxValue'),
    packetCount: $('packetCount'),
    blockCount: $('blockCount'),
    latencyValue: $('latencyValue'),
    lastBlockTime: $('lastBlockTime'),
    dpCount: $('dpCount'),
    // Watermark
    wmIcon: $('wmIcon'),
    wmStatusText: $('wmStatusText'),
    mBER: $('mBER'),
    mPSNR: $('mPSNR'),
    mMSE: $('mMSE'),
    mSEQ: $('mSEQ'),
    integrityPct: $('integrityPct'),
    integrityFill: $('integrityFill'),
    validBlocks: $('validBlocks'),
    invalidBlocks: $('invalidBlocks'),
    berAvg: $('berAvg'),
    modeBadge: $('modeBadge'),
    // Alert
    alertBar: $('alertBar'),
    alertMsg: $('alertMsg'),
    alertClose: $('alertClose'),
    // Log
    logArea: $('logArea'),
    logWrap: $('logWrap'),
    btnClear: $('btnClear'),
    // Logo
    logoIcon: $('logoIcon'),
};

// ======================== 4. MATH (Identical to sender/receiver) ========================

function haarDWT(data) {
    const half = data.length / 2;
    const INV_SQRT2 = 0.70710678118;
    const cA = new Float64Array(half);
    const cD = new Float64Array(half);
    for (let i = 0; i < half; i++) {
        cA[i] = (data[2 * i] + data[2 * i + 1]) * INV_SQRT2;
        cD[i] = (data[2 * i] - data[2 * i + 1]) * INV_SQRT2;
    }
    return { cA, cD };
}

function robustRound(n) {
    return Math.floor((n / 5.0) + 0.5) * 5;
}

function extractQIMBit(val) {
    const rounded = Math.round(val / CFG.QIM_DELTA);
    return (rounded % 2 !== 0) ? '1' : '0';
}

function getExpectedBits(cA, seq, numBits) {
    let s = '';
    for (let i = 0; i < cA.length; i++) s += robustRound(cA[i]).toString();
    const raw = s + CFG.SECRET_KEY + seq.toString();
    const hex = sha256(raw);
    // Konversi hex ke biner, ambil sejumlah numBits (= jumlah cD koefisien)
    let bits = '';
    const bytesNeeded = Math.ceil(numBits / 8);
    for (let i = 0; i < bytesNeeded; i++) {
        bits += parseInt(hex.substring(i * 2, i * 2 + 2), 16).toString(2).padStart(8, '0');
    }
    bits = bits.substring(0, numBits);
    return { bits, raw, hex };
}

function verifyWatermark(received, processed, seq, mode) {
    const log = [];
    log.push('='.repeat(50));
    log.push(`PROSES VERIFIKASI BLOK SEQ: ${seq}`);
    log.push('='.repeat(50));

    // [0] Data Masuk — tampilkan lengkap
    log.push(`[0] Data Diterima (Raw ${processed.length}): [${processed.map(x => x.toFixed(2)).join(', ')}]`);

    // Hitung MSE & PSNR
    let mseSum = 0;
    for (let i = 0; i < received.length; i++) mseSum += (received[i] - processed[i]) ** 2;
    const mse = mseSum / received.length;
    const psnr = mse === 0 ? 100.0 : 20 * Math.log10(CFG.MAX_BPM_REF / Math.sqrt(mse));

    if (mode !== 'NORMAL') {
        log.push(`[SIMULASI: ${mode}]`);
        log.push(`  > MSE: ${mse.toFixed(4)} | PSNR: ${psnr.toFixed(2)} dB`);
    }

    // [1] DWT — tampilkan LL dan LH lengkap
    const { cA, cD } = haarDWT(processed);
    log.push(`[1] LL (Sinyal Utama): [${Array.from(cA).map(x => x.toFixed(2)).join(', ')}]`);
    log.push(`[1] LH (Detail/Koefisien): [${Array.from(cD).map(x => x.toFixed(2)).join(', ')}]`);

    // [2] Proses Hash SHA-256
    log.push('[2] Proses Hash SHA-256...');
    const numBits = cD.length;
    const { bits: expected, raw, hex } = getExpectedBits(cA, seq, numBits);
    log.push(`  > [HASH] Input String (Robust): ${raw}`);
    log.push(`  > [HASH] Hex: ${hex}`);
    log.push(`  > [HASH] Expected Watermark Bits: ${expected}`);

    // [3] Ekstraksi QIM — detail per koefisien
    log.push('[3] Ekstraksi QIM dari LH...');
    let extracted = '';
    for (let i = 0; i < cD.length; i++) {
        const val = cD[i];
        const rounded = Math.round(val / CFG.QIM_DELTA);
        const bit = (rounded % 2 !== 0) ? '1' : '0';
        extracted += bit;
        log.push(`  > cD[${i}] = ${val.toFixed(4)} → step=${rounded} → bit=${bit}`);
    }
    log.push(`  > [QIM] Extracted Bits: ${extracted}`);

    // [4] Verifikasi Integritas
    log.push('[4] Verifikasi Integritas');
    log.push(`  > Harapan: ${expected}`);
    log.push(`    Fakta:   ${extracted}`);

    let errors = 0;
    for (let i = 0; i < numBits; i++) if (extracted[i] !== expected[i]) errors++;
    const ber = (errors / numBits) * 100;

    // [5] Kesimpulan
    const status = ber <= CFG.BER_THRESHOLD ? 'VALID' : 'INVALID';
    log.push('[5] KESIMPULAN');
    log.push(`  > Error Bits: ${errors}/${numBits}`);
    log.push(`  > BER: ${ber.toFixed(2)}%`);
    log.push(`  > MSE: ${mse.toFixed(4)} | PSNR: ${psnr.toFixed(2)} dB`);
    log.push(`  > STATUS: ${status === 'VALID' ? '✅ DATA OTENTIK' : '❌ DATA DIMANIPULASI'}`);
    log.push('='.repeat(50));

    return { status, ber, mse, psnr, log: log.join('\n') };
}

// ======================== 5. HEART RATE ZONES ========================

function getHRZone(bpm) {
    if (bpm < 60) return { label: 'Rest', cls: 'rest' };
    if (bpm < 100) return { label: 'Moderate', cls: 'moderate' };
    if (bpm < 140) return { label: 'Cardio', cls: 'cardio' };
    return { label: 'Peak', cls: 'peak' };
}

// ======================== 6. CHARTS ========================

function initCharts() {
    // BPM Chart
    const ctx1 = $('bpmChart').getContext('2d');
    const grad = ctx1.createLinearGradient(0, 0, 0, 280);
    grad.addColorStop(0, 'rgba(239, 68, 68, 0.2)');
    grad.addColorStop(1, 'rgba(239, 68, 68, 0)');

    bpmChart = new Chart(ctx1, {
        type: 'line',
        data: { labels: [], datasets: [{ data: [], borderColor: '#ef4444', backgroundColor: grad, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: { display: false },
                y: { grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false }, ticks: { color: '#475569', font: { size: 10, family: "'Inter'" } } }
            },
            plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1e293b', titleColor: '#f1f5f9', bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1, cornerRadius: 8, padding: 8, displayColors: false } },
            interaction: { intersect: false, mode: 'index' }
        }
    });

    // BER Chart
    const ctx2 = $('berChart').getContext('2d');
    berChart = new Chart(ctx2, {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, maxBarThickness: 20 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 200 },
            scales: {
                x: { display: false },
                y: {
                    min: 0, max: 100,
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false },
                    ticks: { color: '#475569', font: { size: 10 }, callback: v => v + '%' }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => `BER: ${ctx.parsed.y.toFixed(2)}%` }, backgroundColor: '#1e293b', titleColor: '#f1f5f9', bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1, cornerRadius: 8, padding: 8, displayColors: false }
            }
        }
    });

    // BER Threshold line
    const thresholdPlugin = {
        id: 'thresholdLine',
        afterDraw(chart) {
            const y = chart.scales.y.getPixelForValue(CFG.BER_THRESHOLD);
            const ctx = chart.ctx;
            ctx.save();
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(chart.chartArea.left, y);
            ctx.lineTo(chart.chartArea.right, y);
            ctx.stroke();
            ctx.restore();
        }
    };
    berChart.config.plugins = [thresholdPlugin];
}

function pushBPMChart(val) {
    bpmHistory.push(val);
    if (bpmHistory.length > CFG.CHART_MAX) bpmHistory.shift();
    bpmChart.data.labels = bpmHistory.map((_, i) => i);
    bpmChart.data.datasets[0].data = [...bpmHistory];
    bpmChart.update('none');
    dom.dpCount.textContent = `${bpmHistory.length} pts`;
}

function pushBERChart(ber, seq) {
    berHistory.push({ ber, seq });
    if (berHistory.length > CFG.BER_CHART_MAX) berHistory.shift();
    berChart.data.labels = berHistory.map(b => `#${b.seq}`);
    berChart.data.datasets[0].data = berHistory.map(b => b.ber);
    berChart.data.datasets[0].backgroundColor = berHistory.map(b =>
        b.ber <= CFG.BER_THRESHOLD ? 'rgba(34,197,94,0.6)' : 'rgba(239,68,68,0.6)'
    );
    berChart.update();

    // Avg BER
    const avg = berHistory.reduce((s, b) => s + b.ber, 0) / berHistory.length;
    dom.berAvg.textContent = `Avg: ${avg.toFixed(1)}%`;
}

// ======================== 7. UI UPDATE ========================

function updateLiveBPM(val) {
    // BPM display
    dom.bpmValue.textContent = val;
    pushBPMChart(val);

    // Heart rate zone
    const zone = getHRZone(val);
    const badge = dom.bpmZone.querySelector('.zone-badge');
    badge.textContent = zone.label;
    badge.className = `zone-badge ${zone.cls}`;

    // Stats
    stats.packetCount++;
    stats.allBPM.push(val);
    dom.packetCount.textContent = stats.packetCount;

    // Min / Max / Avg
    const min = Math.min(...stats.allBPM);
    const max = Math.max(...stats.allBPM);
    const avg = (stats.allBPM.reduce((s, v) => s + v, 0) / stats.allBPM.length).toFixed(0);
    dom.avgValue.textContent = avg;
    dom.minValue.textContent = `Min: ${min}`;
    dom.maxValue.textContent = `Max: ${max}`;

    // Limit stored BPM stats (prevent memory growth)
    if (stats.allBPM.length > 1000) stats.allBPM = stats.allBPM.slice(-500);

    // Logo heartbeat sync
    dom.logoIcon.style.animation = 'none';
    void dom.logoIcon.offsetWidth;
    dom.logoIcon.style.animation = 'pulse-logo 2s ease-in-out infinite';

    // Alert for abnormal BPM
    if (val < CFG.ALERT_BPM_LOW) {
        showAlert(`⚠️ BPM rendah terdeteksi: ${val} BPM (< ${CFG.ALERT_BPM_LOW})`, 'warning');
    } else if (val > CFG.ALERT_BPM_HIGH) {
        showAlert(`🔴 BPM tinggi terdeteksi: ${val} BPM (> ${CFG.ALERT_BPM_HIGH})`, 'danger');
    }
}

function updateSecure(result, seq) {
    // Metrics
    dom.mBER.textContent = `${result.ber.toFixed(2)}%`;
    dom.mPSNR.textContent = `${result.psnr.toFixed(2)} dB`;
    dom.mMSE.textContent = result.mse.toFixed(4);
    dom.mSEQ.textContent = `#${seq}`;

    // Status
    if (result.status === 'VALID') {
        dom.wmIcon.textContent = '✅';
        dom.wmStatusText.textContent = 'DATA OTENTIK';
        dom.wmStatusText.className = 'wm-status-text valid';
        stats.validBlocks++;
    } else {
        dom.wmIcon.textContent = '⚠️';
        dom.wmStatusText.textContent = 'DATA DIMANIPULASI';
        dom.wmStatusText.className = 'wm-status-text invalid';
        stats.invalidBlocks++;
    }

    // Block count
    stats.blockCount++;
    dom.blockCount.textContent = `Blocks: ${stats.blockCount}`;

    // Latency
    const now = new Date();
    if (stats.lastBlockTime) {
        const diff = ((now - stats.lastBlockTime) / 1000).toFixed(1);
        dom.latencyValue.textContent = `${diff}s`;
    }
    stats.lastBlockTime = now;
    dom.lastBlockTime.textContent = `Blok terakhir: ${now.toLocaleTimeString('id-ID')}`;

    // Integrity score
    const total = stats.validBlocks + stats.invalidBlocks;
    const pct = total > 0 ? ((stats.validBlocks / total) * 100).toFixed(1) : 0;
    dom.integrityPct.textContent = `${pct}%`;
    dom.integrityFill.style.width = `${pct}%`;
    dom.validBlocks.textContent = `✅ ${stats.validBlocks} valid`;
    dom.invalidBlocks.textContent = `❌ ${stats.invalidBlocks} invalid`;

    // Set integrity bar color
    if (pct >= 80) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #22c55e, #06b6d4)';
        dom.integrityPct.style.color = '#22c55e';
    } else if (pct >= 50) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #f59e0b, #f97316)';
        dom.integrityPct.style.color = '#f59e0b';
    } else {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
        dom.integrityPct.style.color = '#ef4444';
    }

    // BER history
    pushBERChart(result.ber, seq);

    // Log
    appendLog(result.log);
}

function showAlert(msg, type) {
    dom.alertBar.style.display = 'flex';
    dom.alertBar.className = `alert-bar ${type === 'warning' ? 'warning' : ''}`;
    dom.alertMsg.textContent = msg;

    // Auto-hide after 8 seconds
    clearTimeout(window._alertTimer);
    window._alertTimer = setTimeout(() => { dom.alertBar.style.display = 'none'; }, 8000);
}

function appendLog(text) {
    const el = dom.logArea;
    const lines = el.textContent.split('\n');
    if (lines.length > CFG.LOG_MAX_LINES) {
        el.textContent = lines.slice(-CFG.LOG_MAX_LINES).join('\n');
    }
    el.textContent += '\n' + text + '\n';
    dom.logWrap.scrollTop = dom.logWrap.scrollHeight;
}

function setMQTT(status) {
    const badge = dom.mqttBadge;
    const dot = badge.querySelector('.mqtt-dot');
    const txt = badge.querySelector('.mqtt-text');
    badge.className = 'mqtt-badge ' + (status === 'online' ? 'online' : status === 'offline' ? 'offline' : '');
    txt.textContent = status === 'online' ? 'Connected' : status === 'offline' ? 'Disconnected' : 'Connecting...';
}

// ======================== 8. ATTACK SIM ========================

function applyAttack(data, mode) {
    if (mode === 'NOISE') {
        return data.map((x, i) => i % 2 === 0 ? x + 0.4 : x - 0.4);
    } else if (mode === 'ATTACK') {
        return data.map(x => x + 30.0);
    }
    return [...data];
}

// ======================== 9. MQTT ========================

function connectMQTT() {
    setMQTT('');
    const id = 'webmon_' + Math.random().toString(16).slice(2, 10);

    mqttClient = mqtt.connect(CFG.MQTT_URL, {
        clientId: id, clean: true, connectTimeout: 10000, reconnectPeriod: 3000,
    });

    mqttClient.on('connect', () => {
        setMQTT('online');
        mqttClient.subscribe(CFG.MQTT_TOPIC, (err) => {
            if (!err) appendLog('[SYSTEM] MQTT online. Menunggu data ESP32...');
        });
    });

    mqttClient.on('error', () => setMQTT('offline'));
    mqttClient.on('close', () => setMQTT('offline'));
    mqttClient.on('reconnect', () => setMQTT(''));

    mqttClient.on('message', (topic, msg) => {
        try {
            const p = JSON.parse(msg.toString());
            if (p.type === 'live') {
                updateLiveBPM(p.val || 0);
            } else if (p.type === 'secure') {
                const raw = p.data || [];
                const processed = applyAttack(raw, attackMode);
                const result = verifyWatermark(raw, processed, p.seq || 0, attackMode);
                updateSecure(result, p.seq || 0);
            }
        } catch (e) {
            console.error('[MQTT] Parse:', e);
        }
    });
}

// ======================== 10. EVENTS ========================

function initEvents() {
    // Sim radio
    document.querySelectorAll('input[name="attackMode"]').forEach(r => {
        r.addEventListener('change', e => {
            attackMode = e.target.value;
            dom.modeBadge.textContent = attackMode;
            document.querySelectorAll('.sim-opt').forEach(l => l.classList.remove('active'));
            e.target.closest('.sim-opt').classList.add('active');
        });
    });

    // Clear log
    dom.btnClear.addEventListener('click', () => { dom.logArea.textContent = 'Log dibersihkan.\n'; });

    // Alert close
    dom.alertClose.addEventListener('click', () => { dom.alertBar.style.display = 'none'; });

    // Clock
    setInterval(() => {
        dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });
    }, 1000);
}

// ======================== 11. INIT ========================

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initEvents();
    connectMQTT();
    dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });
});
