/**
 * ===================================================================================
 * SECURE HEART MONITOR — WEB RECEIVER
 * Deskripsi: Menerima data detak jantung via MQTT WebSocket, memverifikasi
 *            watermark semi-fragile (DWT Haar + QIM + SHA-256).
 * Logika matematika 100% identik dengan sender.ino dan receiver.py
 * ===================================================================================
 */

// --- 1. KONFIGURASI ---
const CONFIG = {
    MQTT_BROKER: 'wss://broker.emqx.io:8084/mqtt',   // WebSocket Secure
    MQTT_TOPIC: 'polban/iot/jantung/syauqi',
    SECRET_KEY: 'RahasiaPolban',
    QIM_DELTA: 2.0,
    BER_THRESHOLD: 30.0,
    MAX_BPM_REF: 200.0,     // Untuk kalkulasi PSNR
    MAX_LOG_LINES: 200,
    CHART_MAX_POINTS: 60,
};

// --- 2. STATE ---
let attackMode = 'NORMAL';
let chartInstance = null;
let bpmData = [];
let mqttClient = null;

// --- 3. DOM ELEMENTS ---
const dom = {
    mqttBadge: document.getElementById('mqttBadge'),
    badgeDot: null,
    badgeText: null,
    bpmLive: document.getElementById('bpmLive'),
    bpmPulse: document.getElementById('bpmPulse'),
    wmIcon: document.getElementById('wmIcon'),
    wmLabel: document.getElementById('wmLabel'),
    metricBER: document.getElementById('metricBER'),
    metricPSNR: document.getElementById('metricPSNR'),
    metricMSE: document.getElementById('metricMSE'),
    metricSEQ: document.getElementById('metricSEQ'),
    dataPointCount: document.getElementById('dataPointCount'),
    logArea: document.getElementById('logArea'),
    logContainer: document.getElementById('logContainer'),
    btnClearLog: document.getElementById('btnClearLog'),
    bpmChart: document.getElementById('bpmChart'),
};

// Init sub-elements
dom.badgeDot = dom.mqttBadge.querySelector('.badge-dot');
dom.badgeText = dom.mqttBadge.querySelector('.badge-text');

// ===========================================================================
// 4. FUNGSI MATEMATIKA — Identik dengan sender.ino & receiver.py
// ===========================================================================

/**
 * Haar DWT Level 1 (Periodization mode)
 * Input: array of N floats → Output: {cA: N/2, cD: N/2}
 */
function haarDWT(data) {
    const n = data.length;
    const half = n / 2;
    const INV_SQRT2 = 0.70710678118;
    const cA = new Float64Array(half);
    const cD = new Float64Array(half);

    for (let i = 0; i < half; i++) {
        const a = data[2 * i];
        const b = data[2 * i + 1];
        cA[i] = (a + b) * INV_SQRT2;
        cD[i] = (a - b) * INV_SQRT2;
    }

    return { cA, cD };
}

/**
 * Robust round ke kelipatan 5 — identik dengan C++ floor((x/5)+0.5)*5
 */
function robustRound(n) {
    return Math.floor((n / 5.0) + 0.5) * 5;
}

/**
 * Ekstraksi 1 bit QIM dari koefisien detail
 */
function extractQIMBit(val) {
    const step = val / CONFIG.QIM_DELTA;
    const roundedStep = Math.round(step);
    return (roundedStep % 2 !== 0) ? '1' : '0';
}

/**
 * SHA-256 hash → 16-bit binary string
 * Menggunakan library js-sha256
 */
function generateExpectedBits(cA, sequenceNum) {
    // Build data string identik dengan sender
    let dataStr = '';
    for (let i = 0; i < cA.length; i++) {
        dataStr += robustRound(cA[i]).toString();
    }

    const rawInput = dataStr + CONFIG.SECRET_KEY + sequenceNum.toString();
    const hashHex = sha256(rawInput);

    // Ambil 2 byte pertama → 16 bit
    let bits = '';
    for (let i = 0; i < 4; i++) {  // 4 hex chars = 2 bytes = 16 bits
        const nibble = parseInt(hashHex[i], 16);
        bits += nibble.toString(2).padStart(4, '0');
    }

    return { bits, rawInput, hashHex };
}

/**
 * Verifikasi watermark penuh
 */
function verifyWatermark(receivedData, processedData, sequenceNum, mode) {
    const log = [];
    log.push(`--- ANALISIS BLOK SEQ ${sequenceNum} ---`);
    log.push(`[0] DATA MASUK (RAW)`);
    log.push(`  > ${processedData.length} samples`);

    // MSE & PSNR
    let mseSum = 0;
    for (let i = 0; i < receivedData.length; i++) {
        mseSum += (receivedData[i] - processedData[i]) ** 2;
    }
    const mse = mseSum / receivedData.length;
    const psnr = mse === 0 ? 100.0 : 20 * Math.log10(CONFIG.MAX_BPM_REF / Math.sqrt(mse));

    if (mode !== 'NORMAL') {
        log.push(`[SIMULASI: ${mode}]`);
        log.push(`  > MSE: ${mse.toFixed(4)} | PSNR: ${psnr.toFixed(2)} dB`);
    }

    // DWT
    const { cA, cD } = haarDWT(processedData);
    log.push(`[1] DWT Selesai`);
    log.push(`  > LL Sample: [${Array.from(cA).slice(0, 8).map(x => x.toFixed(1)).join(', ')}]...`);

    // Ekstraksi
    let extractedBits = '';
    for (let i = 0; i < cD.length; i++) {
        extractedBits += extractQIMBit(cD[i]);
    }
    log.push(`[2] Ekstraksi Watermark`);
    log.push(`  > Bit Hasil: ${extractedBits}`);

    // Hash
    const { bits: validBits, rawInput, hashHex } = generateExpectedBits(cA, sequenceNum);
    log.push(`  > Hash Input: ${rawInput.substring(0, 30)}...`);

    log.push(`[3] Verifikasi Integritas`);
    log.push(`  > Harapan: ${validBits}`);
    log.push(`  > Fakta:   ${extractedBits}`);

    // BER
    let errors = 0;
    for (let i = 0; i < 16; i++) {
        if (extractedBits[i] !== validBits[i]) errors++;
    }
    const ber = (errors / 16) * 100;

    log.push(`[4] KESIMPULAN`);
    log.push(`  > BER: ${ber.toFixed(2)}%`);

    let status;
    if (ber <= CONFIG.BER_THRESHOLD) {
        status = 'VALID';
        log.push(`  > STATUS: ✅ DATA OTENTIK`);
    } else {
        status = 'INVALID';
        log.push(`  > STATUS: ❌ DATA DIMANIPULASI`);
    }

    return { status, ber, mse, psnr, log: log.join('\n') };
}

// ===========================================================================
// 5. CHART.JS SETUP
// ===========================================================================

function initChart() {
    const ctx = dom.bpmChart.getContext('2d');

    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.3)');
    gradient.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

    chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'BPM',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: gradient,
                borderWidth: 2.5,
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                pointHitRadius: 10,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 300,
                easing: 'easeOutQuart',
            },
            scales: {
                x: {
                    display: false,
                },
                y: {
                    grid: {
                        color: 'rgba(255,255,255,0.04)',
                        drawBorder: false,
                    },
                    ticks: {
                        color: '#64748b',
                        font: { family: "'Inter', sans-serif", size: 11 },
                    },
                    title: {
                        display: true,
                        text: 'BPM',
                        color: '#94a3b8',
                        font: { family: "'Inter', sans-serif", size: 12, weight: '600' },
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.9)',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 10,
                    displayColors: false,
                }
            },
            interaction: {
                intersect: false,
                mode: 'index',
            }
        }
    });
}

function updateChart(bpm) {
    bpmData.push(bpm);
    if (bpmData.length > CONFIG.CHART_MAX_POINTS) {
        bpmData.shift();
    }

    chartInstance.data.labels = bpmData.map((_, i) => i);
    chartInstance.data.datasets[0].data = [...bpmData];
    chartInstance.update('none');  // Skip animation for performance

    dom.dataPointCount.textContent = `${bpmData.length} data points`;
}

// ===========================================================================
// 6. UI UPDATES
// ===========================================================================

function updateBPM(val) {
    dom.bpmLive.textContent = val;
    updateChart(val);

    // Pulse animation
    dom.bpmPulse.classList.remove('active');
    void dom.bpmPulse.offsetWidth; // Force reflow
    dom.bpmPulse.classList.add('active');
}

function updateWatermarkStatus(result, seq) {
    // Metrics
    dom.metricBER.textContent = `${result.ber.toFixed(2)}%`;
    dom.metricPSNR.textContent = `${result.psnr.toFixed(2)} dB`;
    dom.metricMSE.textContent = result.mse.toFixed(4);
    dom.metricSEQ.textContent = `#${seq}`;

    // Status icon & label
    if (result.status === 'VALID') {
        dom.wmIcon.textContent = '✅';
        dom.wmLabel.textContent = 'DATA OTENTIK';
        dom.wmLabel.className = 'wm-label valid';
    } else {
        dom.wmIcon.textContent = '⚠️';
        dom.wmLabel.textContent = 'DATA DIMANIPULASI';
        dom.wmLabel.className = 'wm-label invalid';
    }

    // Log
    appendLog(result.log);
}

function appendLog(text) {
    const logEl = dom.logArea;

    // Trim old lines
    const lines = logEl.textContent.split('\n');
    if (lines.length > CONFIG.MAX_LOG_LINES) {
        const trimmed = lines.slice(lines.length - CONFIG.MAX_LOG_LINES);
        logEl.textContent = trimmed.join('\n');
    }

    logEl.textContent += '\n' + text + '\n';
    dom.logContainer.scrollTop = dom.logContainer.scrollHeight;
}

function setMQTTStatus(status) {
    dom.mqttBadge.className = 'connection-badge ' + status;
    if (status === 'connected') {
        dom.badgeText.textContent = 'MQTT Connected';
    } else if (status === 'error') {
        dom.badgeText.textContent = 'Disconnected';
    } else {
        dom.badgeText.textContent = 'Connecting...';
    }
}

// ===========================================================================
// 7. SIMULASI SERANGAN
// ===========================================================================

function applyAttack(rawData, mode) {
    if (mode === 'NOISE') {
        const noiseAmp = 0.4;
        return rawData.map((x, i) => i % 2 === 0 ? x + noiseAmp : x - noiseAmp);
    } else if (mode === 'ATTACK') {
        return rawData.map(x => x + 30.0);
    }
    return [...rawData]; // NORMAL — copy
}

// ===========================================================================
// 8. MQTT HANDLER
// ===========================================================================

function connectMQTT() {
    setMQTTStatus('');

    const clientId = 'web_monitor_' + Math.random().toString(16).slice(2, 10);

    mqttClient = mqtt.connect(CONFIG.MQTT_BROKER, {
        clientId: clientId,
        clean: true,
        connectTimeout: 10000,
        reconnectPeriod: 3000,
    });

    mqttClient.on('connect', () => {
        console.log('[MQTT] Connected');
        setMQTTStatus('connected');
        mqttClient.subscribe(CONFIG.MQTT_TOPIC, (err) => {
            if (err) console.error('[MQTT] Subscribe error:', err);
            else appendLog('[SYSTEM] MQTT terhubung. Menunggu data dari ESP32...');
        });
    });

    mqttClient.on('error', (err) => {
        console.error('[MQTT] Error:', err);
        setMQTTStatus('error');
    });

    mqttClient.on('close', () => {
        setMQTTStatus('error');
    });

    mqttClient.on('reconnect', () => {
        setMQTTStatus('');
    });

    mqttClient.on('message', (topic, message) => {
        try {
            const payload = JSON.parse(message.toString());

            if (payload.type === 'live') {
                const val = payload.val || 0;
                updateBPM(val);
            } else if (payload.type === 'secure') {
                const seq = payload.seq || 0;
                const rawData = payload.data || [];

                // Apply attack simulation
                const processedData = applyAttack(rawData, attackMode);

                // Verify watermark
                const result = verifyWatermark(rawData, processedData, seq, attackMode);
                updateWatermarkStatus(result, seq);
            }
        } catch (e) {
            console.error('[MQTT] Parse error:', e);
        }
    });
}

// ===========================================================================
// 9. EVENT LISTENERS
// ===========================================================================

function initEventListeners() {
    // Attack mode radio buttons
    document.querySelectorAll('input[name="attackMode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            attackMode = e.target.value;

            // Update active styling
            document.querySelectorAll('.sim-radio').forEach(label => {
                label.classList.remove('active');
            });
            e.target.closest('.sim-radio').classList.add('active');
        });
    });

    // Clear log
    dom.btnClearLog.addEventListener('click', () => {
        dom.logArea.textContent = 'Log dibersihkan.\n';
    });
}

// ===========================================================================
// 10. INIT
// ===========================================================================

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    initEventListeners();
    connectMQTT();
});
