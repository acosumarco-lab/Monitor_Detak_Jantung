/**
 * ===================================================================================
 * TUGAS AKHIR: SECURE MEDICAL IOT — WEB RECEIVER (JavaScript)
 * ===================================================================================
 * Deskripsi:
 *   Aplikasi web penerima yang menerima data detak jantung yang sudah di-watermark
 *   dari ESP32 via MQTT WebSocket, lalu melakukan verifikasi integritas menggunakan
 *   teknik DWT Haar + QIM + SHA-256.
 *
 * Alur Kerja:
 *   1. Terhubung ke MQTT broker via WebSocket (wss://)
 *   2. Menerima 2 tipe paket: "live" (BPM real-time) dan "secure" (blok watermark)
 *   3. Untuk paket "secure":
 *      a. Opsional: simulasi serangan (NOISE / ATTACK_BPM / ATTACK_KEY)
 *      b. Dekomposisi DWT Haar
 *      c. Regenerasi expected watermark dari SHA-256
 *      d. Ekstraksi watermark dari koefisien detail via QIM
 *      e. Bandingkan expected vs extracted → hitung BER
 *      f. Update UI: grafik, status, metrik, log
 *
 * Mode Pengujian:
 *   - NORMAL:      Data asli tanpa modifikasi
 *   - NOISE:       Tambah noise ±0.4 (simulasi gangguan transmisi)
 *   - ATTACK_BPM:  Tambah +30 ke semua nilai BPM (serangan manipulasi data)
 *   - ATTACK_KEY:  Penyerang mencoba re-watermark dengan password & sequence palsu
 *                  → simulasi penyerang yang tidak tahu SECRET_KEY dan urutan paket
 *
 * Dependensi (dimuat via CDN di index.html):
 *   - Chart.js   : Grafik real-time
 *   - MQTT.js    : Koneksi MQTT via WebSocket
 *   - js-sha256  : Hashing SHA-256
 * ===================================================================================
 */

// ===================================================================================
// BAGIAN 1: KONFIGURASI
// ===================================================================================
const CFG = {
    // --- Koneksi MQTT ---
    MQTT_URL: 'wss://broker.emqx.io:8084/mqtt',      // URL broker MQTT via WebSocket (port 8084 = WSS)
    MQTT_TOPIC: 'polban/iot/jantung/syauqi',           // Topic MQTT (HARUS SAMA dengan pengirim)

    // --- Keamanan Watermark ---
    SECRET_KEY: 'RahasiaPolban',     // Kunci rahasia untuk verifikasi (HARUS SAMA dengan pengirim)
    QIM_DELTA: 2.0,                  // Step size QIM (HARUS SAMA dengan pengirim)
    BER_THRESHOLD: 30.0,             // Batas BER (%) — di bawah ini dianggap valid
    MAX_BPM_REF: 200.0,             // Nilai referensi untuk perhitungan PSNR

    // --- Parameter Serangan ATTACK_KEY ---
    FAKE_KEY: 'INIKUNCIPALSU',       // Kunci palsu — dipakai saat mode ATTACK_KEY

    // --- UI/Chart ---
    CHART_MAX: 60,                   // Maksimal data point di grafik BPM
    BER_CHART_MAX: 20,               // Maksimal bar di grafik BER history
    LOG_MAX_LINES: 200,              // Maksimal baris log (mencegah memory leak)
    ALERT_BPM_LOW: 40,              // Batas BPM rendah untuk alert
    ALERT_BPM_HIGH: 180,            // Batas BPM tinggi untuk alert
};

// ===================================================================================
// BAGIAN 2: STATE (Variabel Global)
// ===================================================================================
let attackMode = 'NORMAL';           // Mode simulasi serangan yang aktif
let bpmHistory = [];                 // Array riwayat BPM untuk grafik
let berHistory = [];                 // Array riwayat BER untuk grafik
let bpmChart = null;                 // Instance Chart.js untuk grafik BPM
let berChart = null;                 // Instance Chart.js untuk grafik BER
let mqttClient = null;               // Instance MQTT client

// Statistik kumulatif
let stats = {
    packetCount: 0,                  // Total paket live yang diterima
    blockCount: 0,                   // Total blok secure yang diproses
    validBlocks: 0,                  // Jumlah blok yang valid (watermark cocok)
    invalidBlocks: 0,                // Jumlah blok yang invalid (watermark tidak cocok)
    allBPM: [],                      // Array seluruh nilai BPM untuk statistik
    lastBlockTime: null,             // Timestamp blok secure terakhir
};

// ===================================================================================
// BAGIAN 3: DOM REFERENCES
// ===================================================================================
// Fungsi helper untuk mendapatkan elemen DOM berdasarkan ID
const $ = (id) => document.getElementById(id);

// Kumpulan referensi elemen DOM yang sering digunakan
const dom = {
    // Header
    mqttBadge: $('mqttBadge'),       // Badge status koneksi MQTT
    clock: $('clock'),               // Jam digital

    // Statistik
    bpmValue: $('bpmValue'),         // Nilai BPM live
    bpmZone: $('bpmZone'),           // Badge zona heart rate
    avgValue: $('avgValue'),         // Nilai BPM rata-rata
    minValue: $('minValue'),         // Nilai BPM minimum
    maxValue: $('maxValue'),         // Nilai BPM maksimum
    packetCount: $('packetCount'),   // Counter paket
    blockCount: $('blockCount'),     // Counter blok
    latencyValue: $('latencyValue'), // Nilai latency
    lastBlockTime: $('lastBlockTime'), // Waktu blok terakhir
    dpCount: $('dpCount'),           // Jumlah data point di grafik

    // Watermark Status
    wmIcon: $('wmIcon'),             // Ikon status watermark (✅ atau ⚠️)
    wmStatusText: $('wmStatusText'), // Text status watermark
    mBER: $('mBER'),                 // Metrik BER
    mPSNR: $('mPSNR'),             // Metrik PSNR
    mMSE: $('mMSE'),               // Metrik MSE
    mSEQ: $('mSEQ'),               // Metrik sequence number
    integrityPct: $('integrityPct'), // Persentase integritas
    integrityFill: $('integrityFill'), // Progress bar integritas
    validBlocks: $('validBlocks'),   // Label blok valid
    invalidBlocks: $('invalidBlocks'), // Label blok invalid
    berAvg: $('berAvg'),             // Rata-rata BER
    modeBadge: $('modeBadge'),       // Badge mode simulasi

    // Alert
    alertBar: $('alertBar'),         // Container alert
    alertMsg: $('alertMsg'),         // Pesan alert
    alertClose: $('alertClose'),     // Tombol tutup alert

    // Log
    logArea: $('logArea'),           // Area log output
    logWrap: $('logWrap'),           // Wrapper log (untuk scroll)
    btnClear: $('btnClear'),         // Tombol clear log

    // Logo
    logoIcon: $('logoIcon'),         // Ikon logo (untuk animasi heartbeat)
};

// ===================================================================================
// BAGIAN 4: FUNGSI MATEMATIKA (Identik dengan sender.ino & receiver.py)
// ===================================================================================

/**
 * Haar Discrete Wavelet Transform (DWT).
 * Memecah sinyal input menjadi 2 komponen:
 * - cA (Approximation): rata-rata ternormalisasi (tren sinyal)
 * - cD (Detail): selisih ternormalisasi (detail/noise)
 *
 * Rumus:
 *   cA[i] = (data[2i] + data[2i+1]) × (1/√2)
 *   cD[i] = (data[2i] - data[2i+1]) × (1/√2)
 *
 * @param {number[]} data - Array 16 sampel BPM
 * @returns {{cA: Float64Array, cD: Float64Array}} - Koefisien approximation dan detail
 */
function haarDWT(data) {
    const half = data.length / 2;                // Setengah panjang input (= 8)
    const INV_SQRT2 = 0.70710678118;             // 1/√2 — perkalian lebih cepat dari pembagian
    const cA = new Float64Array(half);           // Array koefisien approximation
    const cD = new Float64Array(half);           // Array koefisien detail
    for (let i = 0; i < half; i++) {
        cA[i] = (data[2 * i] + data[2 * i + 1]) * INV_SQRT2;  // Rata-rata ternormalisasi
        cD[i] = (data[2 * i] - data[2 * i + 1]) * INV_SQRT2;  // Selisih ternormalisasi
    }
    return { cA, cD };
}

/**
 * Haar Inverse DWT (IDWT) — Rekonstruksi sinyal.
 * Menggabungkan kembali cA dan cD menjadi sinyal utuh.
 *
 * Rumus:
 *   output[2i]     = (cA[i] + cD[i]) × (1/√2)
 *   output[2i + 1] = (cA[i] - cD[i]) × (1/√2)
 *
 * @param {Float64Array} cA - Koefisien approximation
 * @param {Float64Array} cD - Koefisien detail (mungkin sudah dimodifikasi)
 * @returns {number[]} - Array sinyal hasil rekonstruksi
 */
function haarIDWT(cA, cD) {
    const INV_SQRT2 = 0.70710678118;
    const output = [];
    for (let i = 0; i < cA.length; i++) {
        output.push((cA[i] + cD[i]) * INV_SQRT2);    // Rekonstruksi sampel genap
        output.push((cA[i] - cD[i]) * INV_SQRT2);    // Rekonstruksi sampel ganjil
    }
    return output;
}

/**
 * Pembulatan robust ke kelipatan 5 terdekat.
 * HARUS IDENTIK dengan implementasi di sender.ino dan receiver.py.
 *
 * Rumus: floor((n / 5) + 0.5) × 5
 *
 * Contoh:
 *   92.63 → floor(92.63/5 + 0.5) = floor(19.026) = 19 → 95
 *   87.7  → floor(87.7/5 + 0.5)  = floor(18.04)  = 18 → 90
 *
 * @param {number} n - Nilai yang akan dibulatkan
 * @returns {number} - Kelipatan 5 terdekat
 */
function robustRound(n) {
    return Math.floor((n / 5.0) + 0.5) * 5;
}

/**
 * Ekstraksi 1 bit watermark dari koefisien detail menggunakan QIM.
 *
 * Prinsip:
 * 1. Bagi koefisien dengan delta → dapat "step"
 * 2. Bulatkan ke bilangan bulat terdekat
 * 3. Ganjil → bit = 1, Genap → bit = 0
 *
 * @param {number} val - Nilai koefisien detail
 * @returns {string} - '0' atau '1'
 */
function extractQIMBit(val) {
    const rounded = Math.round(val / CFG.QIM_DELTA);  // Hitung dan bulatkan step
    return (rounded % 2 !== 0) ? '1' : '0';           // Ganjil=1, Genap=0
}

/**
 * Generate expected watermark bits dari SHA-256 hash.
 *
 * Alur:
 * 1. Robust round setiap cA → kelipatan 5 → gabung jadi string
 * 2. Gabung: "angka" + SECRET_KEY + seq
 * 3. SHA-256 hash
 * 4. Ambil numBits pertama dari hash (dalam biner)
 *
 * @param {Float64Array} cA - Koefisien approximation
 * @param {number} seq - Nomor sequence blok
 * @param {number} numBits - Jumlah bit yang dibutuhkan (= jumlah cD koefisien = 8)
 * @param {string} [key=CFG.SECRET_KEY] - Kunci rahasia (opsional, default: kunci asli)
 * @returns {{bits: string, raw: string, hex: string}} - Watermark bits, input string, hex hash
 */
function getExpectedBits(cA, seq, numBits, key) {
    // Gunakan kunci default jika tidak diberikan
    const secretKey = key || CFG.SECRET_KEY;

    // Langkah 1: Robust round setiap koefisien cA
    let s = '';
    for (let i = 0; i < cA.length; i++) s += robustRound(cA[i]).toString();

    // Langkah 2: Gabung dengan secret key dan sequence
    const raw = s + secretKey + seq.toString();

    // Langkah 3: SHA-256 hash
    const hex = sha256(raw);

    // Langkah 4: Konversi hex → biner, ambil numBits pertama
    let bits = '';
    const bytesNeeded = Math.ceil(numBits / 8);   // Berapa byte yang perlu dikonversi
    for (let i = 0; i < bytesNeeded; i++) {
        // Ambil 2 karakter hex (= 1 byte), konversi ke 8 bit biner
        bits += parseInt(hex.substring(i * 2, i * 2 + 2), 16).toString(2).padStart(8, '0');
    }
    bits = bits.substring(0, numBits);            // Potong ke jumlah bit yang dibutuhkan

    return { bits, raw, hex };
}

/**
 * Embed watermark palsu ke koefisien detail menggunakan QIM.
 * Digunakan dalam mode ATTACK_KEY.
 *
 * Prinsip sama dengan pengirim:
 * - step = floor(cD[i] / delta)
 * - Jika paritas step ≠ bit watermark → naikkan step
 * - cD[i] = step × delta
 *
 * @param {Float64Array} cD - Array koefisien detail
 * @param {string} watermarkBits - String bit watermark palsu (misal "10110010")
 * @returns {Float64Array} - Array cD yang sudah di-embed watermark palsu
 */
function embedQIMAttack(cD, watermarkBits) {
    const result = new Float64Array(cD.length);   // Buat copy baru
    for (let i = 0; i < cD.length; i++) {
        const val = cD[i];                         // Nilai koefisien asli
        const bit = parseInt(watermarkBits[i % watermarkBits.length]);  // Bit watermark palsu
        let step = Math.floor(val / CFG.QIM_DELTA);  // Hitung step
        if (Math.abs(step % 2) !== bit) {          // Jika paritas tidak cocok
            step++;                                 // Naikkan step
        }
        result[i] = step * CFG.QIM_DELTA;          // Koefisien baru
    }
    return result;
}

// ===================================================================================
// BAGIAN 5: VERIFIKASI WATERMARK
// ===================================================================================

/**
 * Fungsi utama verifikasi watermark.
 * Membandingkan watermark yang tertanam dalam data dengan yang seharusnya.
 *
 * Langkah-langkah:
 * [0] Tampilkan data mentah yang diterima
 * [1] Dekomposisi DWT → dapat cA dan cD
 * [2] Generate expected watermark dari SHA-256
 * [3] Ekstraksi watermark dari cD via QIM (detail per koefisien)
 * [4] Bandingkan expected vs extracted
 * [5] Kesimpulan: BER, MSE, PSNR, status
 *
 * @param {number[]} received - Data asli dari MQTT (sebelum attack)
 * @param {number[]} processed - Data setelah attack simulation
 * @param {number} seq - Nomor urut blok
 * @param {string} mode - Mode pengujian ('NORMAL', 'NOISE', 'ATTACK_BPM', 'ATTACK_KEY')
 * @returns {{status: string, ber: number, mse: number, psnr: number, log: string}}
 */
function verifyWatermark(received, processed, seq, mode) {
    const log = [];  // Array untuk menyimpan baris-baris log

    // === HEADER ===
    log.push('='.repeat(50));
    log.push(`PROSES VERIFIKASI BLOK SEQ: ${seq}`);
    log.push('='.repeat(50));

    // === [0] DATA MASUK — tampilkan seluruh nilai ===
    log.push(`[0] Data Diterima (Raw ${processed.length}): [${processed.map(x => x.toFixed(2)).join(', ')}]`);

    // === HITUNG MSE & PSNR ===
    let mseSum = 0;
    for (let i = 0; i < received.length; i++) mseSum += (received[i] - processed[i]) ** 2;
    const mse = mseSum / received.length;
    const psnr = mse === 0 ? 100.0 : 20 * Math.log10(CFG.MAX_BPM_REF / Math.sqrt(mse));

    // Tampilkan info serangan jika bukan NORMAL
    if (mode !== 'NORMAL') {
        log.push(`[SIMULASI: ${mode}]`);
        log.push(`  > MSE: ${mse.toFixed(4)} | PSNR: ${psnr.toFixed(2)} dB`);
    }

    // === [1] DWT — dekomposisi sinyal ===
    const { cA, cD } = haarDWT(processed);
    log.push(`[1] LL (Sinyal Utama): [${Array.from(cA).map(x => x.toFixed(2)).join(', ')}]`);
    log.push(`[1] LH (Detail/Koefisien): [${Array.from(cD).map(x => x.toFixed(2)).join(', ')}]`);

    // === [2] HASH SHA-256 ===
    // Pilih kunci: jika ATTACK_KEY → pakai FAKE_KEY, selainnya → SECRET_KEY
    const kunci = (mode === 'ATTACK_KEY') ? CFG.FAKE_KEY : CFG.SECRET_KEY;
    log.push(`[2] Proses Hash SHA-256 (Kunci: ${kunci})...`);
    const numBits = cD.length;
    const { bits: expected, raw, hex } = getExpectedBits(cA, seq, numBits, kunci);
    log.push(`  > [HASH] Input String (Robust): ${raw}`);
    log.push(`  > [HASH] Hex: ${hex}`);
    log.push(`  > [HASH] Expected Watermark Bits: ${expected}`);

    // === [3] EKSTRAKSI QIM — detail per koefisien ===
    log.push('[3] Ekstraksi QIM dari LH...');
    let extracted = '';
    for (let i = 0; i < cD.length; i++) {
        const val = cD[i];                         // Nilai koefisien detail
        const rounded = Math.round(val / CFG.QIM_DELTA);  // Hitung step
        const bit = (rounded % 2 !== 0) ? '1' : '0';     // Ganjil=1, Genap=0
        extracted += bit;
        // Log detail setiap koefisien
        log.push(`  > cD[${i}] = ${val.toFixed(4)} → step=${rounded} → bit=${bit}`);
    }
    log.push(`  > [QIM] Extracted Bits: ${extracted}`);

    // === [4] VERIFIKASI — bandingkan expected vs extracted ===
    log.push('[4] Verifikasi Integritas');
    log.push(`  > Harapan: ${expected}`);
    log.push(`    Fakta:   ${extracted}`);

    // Hitung jumlah bit yang berbeda (error)
    let errors = 0;
    for (let i = 0; i < numBits; i++) if (extracted[i] !== expected[i]) errors++;
    // BER (Bit Error Rate): persentase bit yang salah
    const ber = (errors / numBits) * 100;

    // === [5] KESIMPULAN ===
    const status = ber <= CFG.BER_THRESHOLD ? 'VALID' : 'INVALID';
    log.push('[5] KESIMPULAN');
    log.push(`  > Error Bits: ${errors}/${numBits}`);
    log.push(`  > BER: ${ber.toFixed(2)}%`);
    log.push(`  > MSE: ${mse.toFixed(4)} | PSNR: ${psnr.toFixed(2)} dB`);
    log.push(`  > STATUS: ${status === 'VALID' ? '✅ DATA OTENTIK' : '❌ DATA DIMANIPULASI'}`);
    log.push('='.repeat(50));

    return { status, ber, mse, psnr, log: log.join('\n') };
}

// ===================================================================================
// BAGIAN 6: HEART RATE ZONES
// ===================================================================================

/**
 * Tentukan zona heart rate berdasarkan nilai BPM.
 *
 * Zona:
 * - Rest:     BPM < 60
 * - Moderate: 60 ≤ BPM < 100
 * - Cardio:   100 ≤ BPM < 140
 * - Peak:     BPM ≥ 140
 *
 * @param {number} bpm - Nilai BPM
 * @returns {{label: string, cls: string}} - Label dan CSS class untuk zona
 */
function getHRZone(bpm) {
    if (bpm < 60) return { label: 'Rest', cls: 'rest' };
    if (bpm < 100) return { label: 'Moderate', cls: 'moderate' };
    if (bpm < 140) return { label: 'Cardio', cls: 'cardio' };
    return { label: 'Peak', cls: 'peak' };
}

// ===================================================================================
// BAGIAN 7: CHARTS (Chart.js)
// ===================================================================================

/**
 * Inisialisasi grafik BPM dan BER menggunakan Chart.js.
 */
function initCharts() {
    // --- Grafik BPM (Line Chart) ---
    const ctx1 = $('bpmChart').getContext('2d');
    // Gradient merah transparan untuk fill area
    const grad = ctx1.createLinearGradient(0, 0, 0, 280);
    grad.addColorStop(0, 'rgba(239, 68, 68, 0.2)');  // Merah transparan atas
    grad.addColorStop(1, 'rgba(239, 68, 68, 0)');     // Transparan penuh bawah

    bpmChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                data: [],
                borderColor: '#ef4444',            // Warna garis merah
                backgroundColor: grad,              // Fill gradient
                borderWidth: 2,
                fill: true,                          // Isi area di bawah garis
                tension: 0.4,                        // Kelengkungan garis (smooth)
                pointRadius: 0                       // Tanpa titik data
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },              // Animasi dimatikan (performa)
            scales: {
                x: { display: false },                // Sembunyikan sumbu X
                y: {
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false },
                    ticks: { color: '#475569', font: { size: 10, family: "'Inter'" } }
                }
            },
            plugins: {
                legend: { display: false },           // Sembunyikan legend
                tooltip: {
                    backgroundColor: '#1e293b',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 8,
                    displayColors: false
                }
            },
            interaction: { intersect: false, mode: 'index' }
        }
    });

    // --- Grafik BER History (Bar Chart) ---
    const ctx2 = $('berChart').getContext('2d');
    berChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
                borderRadius: 4,                     // Sudut bulat pada bar
                maxBarThickness: 20                   // Lebar maksimal bar
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 200 },             // Animasi cepat
            scales: {
                x: { display: false },
                y: {
                    min: 0, max: 100,                 // BER berkisar 0–100%
                    grid: { color: 'rgba(255,255,255,0.03)', drawBorder: false },
                    ticks: {
                        color: '#475569',
                        font: { size: 10 },
                        callback: v => v + '%'        // Tambah suffix %
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: { label: ctx => `BER: ${ctx.parsed.y.toFixed(2)}%` },
                    backgroundColor: '#1e293b',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    borderColor: '#334155',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 8,
                    displayColors: false
                }
            }
        }
    });

    // --- Plugin: Garis threshold BER ---
    // Menggambar garis putus-putus merah di nilai BER_THRESHOLD
    const thresholdPlugin = {
        id: 'thresholdLine',
        afterDraw(chart) {
            const y = chart.scales.y.getPixelForValue(CFG.BER_THRESHOLD);
            const ctx = chart.ctx;
            ctx.save();
            ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';  // Merah transparan
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);                       // Pola putus-putus
            ctx.beginPath();
            ctx.moveTo(chart.chartArea.left, y);
            ctx.lineTo(chart.chartArea.right, y);
            ctx.stroke();
            ctx.restore();
        }
    };
    berChart.config.plugins = [thresholdPlugin];
}

/**
 * Tambahkan data point baru ke grafik BPM.
 * Menampilkan maksimal CHART_MAX (60) data point terakhir.
 *
 * @param {number} val - Nilai BPM baru
 */
function pushBPMChart(val) {
    bpmHistory.push(val);                             // Tambah data baru
    if (bpmHistory.length > CFG.CHART_MAX) bpmHistory.shift();  // Hapus data tertua
    bpmChart.data.labels = bpmHistory.map((_, i) => i);          // Update label X
    bpmChart.data.datasets[0].data = [...bpmHistory];            // Update data Y
    bpmChart.update('none');                           // Update tanpa animasi
    dom.dpCount.textContent = `${bpmHistory.length} pts`;        // Update counter
}

/**
 * Tambahkan data point baru ke grafik BER history.
 * Warna bar: hijau jika BER ≤ threshold, merah jika di atas.
 *
 * @param {number} ber - Nilai BER (%)
 * @param {number} seq - Nomor sequence blok
 */
function pushBERChart(ber, seq) {
    berHistory.push({ ber, seq });                    // Tambah data baru
    if (berHistory.length > CFG.BER_CHART_MAX) berHistory.shift();  // Batasi jumlah bar
    berChart.data.labels = berHistory.map(b => `#${b.seq}`);        // Label: #1, #2, ...
    berChart.data.datasets[0].data = berHistory.map(b => b.ber);    // Data BER
    // Warna: hijau = valid, merah = invalid
    berChart.data.datasets[0].backgroundColor = berHistory.map(b =>
        b.ber <= CFG.BER_THRESHOLD ? 'rgba(34,197,94,0.6)' : 'rgba(239,68,68,0.6)'
    );
    berChart.update();

    // Hitung dan tampilkan rata-rata BER
    const avg = berHistory.reduce((s, b) => s + b.ber, 0) / berHistory.length;
    dom.berAvg.textContent = `Avg: ${avg.toFixed(1)}%`;
}

// ===================================================================================
// BAGIAN 8: UI UPDATE
// ===================================================================================

/**
 * Update tampilan BPM live — dipanggil setiap menerima paket "live".
 *
 * @param {number} val - Nilai BPM
 */
function updateLiveBPM(val) {
    // Update angka BPM
    dom.bpmValue.textContent = val;
    pushBPMChart(val);                                // Update grafik

    // Update zona heart rate
    const zone = getHRZone(val);
    const badge = dom.bpmZone.querySelector('.zone-badge');
    badge.textContent = zone.label;
    badge.className = `zone-badge ${zone.cls}`;       // Set warna sesuai zona

    // Update statistik
    stats.packetCount++;
    stats.allBPM.push(val);
    dom.packetCount.textContent = stats.packetCount;

    // Hitung min / max / avg
    const min = Math.min(...stats.allBPM);
    const max = Math.max(...stats.allBPM);
    const avg = (stats.allBPM.reduce((s, v) => s + v, 0) / stats.allBPM.length).toFixed(0);
    dom.avgValue.textContent = avg;
    dom.minValue.textContent = `Min: ${min}`;
    dom.maxValue.textContent = `Max: ${max}`;

    // Batasi array BPM (mencegah memory leak pada operasi lama)
    if (stats.allBPM.length > 1000) stats.allBPM = stats.allBPM.slice(-500);

    // Trigger animasi heartbeat pada logo
    dom.logoIcon.style.animation = 'none';
    void dom.logoIcon.offsetWidth;                    // Force reflow
    dom.logoIcon.style.animation = 'pulse-logo 2s ease-in-out infinite';

    // Alert untuk BPM abnormal
    if (val < CFG.ALERT_BPM_LOW) {
        showAlert(`⚠️ BPM rendah terdeteksi: ${val} BPM (< ${CFG.ALERT_BPM_LOW})`, 'warning');
    } else if (val > CFG.ALERT_BPM_HIGH) {
        showAlert(`🔴 BPM tinggi terdeteksi: ${val} BPM (> ${CFG.ALERT_BPM_HIGH})`, 'danger');
    }
}

/**
 * Update tampilan hasil verifikasi watermark — dipanggil setiap menerima paket "secure".
 *
 * @param {Object} result - Hasil dari verifyWatermark()
 * @param {number} seq - Nomor sequence blok
 */
function updateSecure(result, seq) {
    // Update metrik
    dom.mBER.textContent = `${result.ber.toFixed(2)}%`;
    dom.mPSNR.textContent = `${result.psnr.toFixed(2)} dB`;
    dom.mMSE.textContent = result.mse.toFixed(4);
    dom.mSEQ.textContent = `#${seq}`;

    // Update ikon dan teks status
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

    // Update counter blok
    stats.blockCount++;
    dom.blockCount.textContent = `Blocks: ${stats.blockCount}`;

    // Hitung latency (waktu sejak blok terakhir)
    const now = new Date();
    if (stats.lastBlockTime) {
        const diff = ((now - stats.lastBlockTime) / 1000).toFixed(1);
        dom.latencyValue.textContent = `${diff}s`;
    }
    stats.lastBlockTime = now;
    dom.lastBlockTime.textContent = `Blok terakhir: ${now.toLocaleTimeString('id-ID')}`;

    // Update integrity score (persentase blok valid)
    const total = stats.validBlocks + stats.invalidBlocks;
    const pct = total > 0 ? ((stats.validBlocks / total) * 100).toFixed(1) : 0;
    dom.integrityPct.textContent = `${pct}%`;
    dom.integrityFill.style.width = `${pct}%`;
    dom.validBlocks.textContent = `✅ ${stats.validBlocks} valid`;
    dom.invalidBlocks.textContent = `❌ ${stats.invalidBlocks} invalid`;

    // Warna progress bar berdasarkan persentase
    if (pct >= 80) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #22c55e, #06b6d4)';  // Hijau
        dom.integrityPct.style.color = '#22c55e';
    } else if (pct >= 50) {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #f59e0b, #f97316)';  // Kuning
        dom.integrityPct.style.color = '#f59e0b';
    } else {
        dom.integrityFill.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';  // Merah
        dom.integrityPct.style.color = '#ef4444';
    }

    // Update grafik BER history
    pushBERChart(result.ber, seq);

    // Tambahkan log detail
    appendLog(result.log);
}

/**
 * Tampilkan alert bar dengan pesan dan tipe.
 * Auto-hide setelah 8 detik.
 *
 * @param {string} msg - Pesan alert
 * @param {string} type - Tipe: 'warning' atau 'danger'
 */
function showAlert(msg, type) {
    dom.alertBar.style.display = 'flex';
    dom.alertBar.className = `alert-bar ${type === 'warning' ? 'warning' : ''}`;
    dom.alertMsg.textContent = msg;

    // Auto-hide setelah 8 detik
    clearTimeout(window._alertTimer);
    window._alertTimer = setTimeout(() => { dom.alertBar.style.display = 'none'; }, 8000);
}

/**
 * Tambahkan teks ke area log. Batasi jumlah baris untuk mencegah memory leak.
 *
 * @param {string} text - Teks log yang akan ditambahkan
 */
function appendLog(text) {
    const el = dom.logArea;
    const lines = el.textContent.split('\n');
    // Trim log jika melebihi batas
    if (lines.length > CFG.LOG_MAX_LINES) {
        el.textContent = lines.slice(-CFG.LOG_MAX_LINES).join('\n');
    }
    el.textContent += '\n' + text + '\n';
    dom.logWrap.scrollTop = dom.logWrap.scrollHeight;  // Auto-scroll ke bawah
}

/**
 * Update badge status koneksi MQTT.
 *
 * @param {string} status - 'online', 'offline', atau '' (connecting)
 */
function setMQTT(status) {
    const badge = dom.mqttBadge;
    const txt = badge.querySelector('.mqtt-text');
    badge.className = 'mqtt-badge ' + (status === 'online' ? 'online' : status === 'offline' ? 'offline' : '');
    txt.textContent = status === 'online' ? 'Connected' : status === 'offline' ? 'Disconnected' : 'Connecting...';
}

// ===================================================================================
// BAGIAN 9: SIMULASI SERANGAN
// ===================================================================================

/**
 * Terapkan simulasi serangan pada data yang diterima.
 *
 * Mode yang didukung:
 * - NORMAL:     Data dikembalikan tanpa perubahan
 * - NOISE:      Tambah/kurangi 0.4 secara bergantian (simulasi noise transmisi)
 * - ATTACK_BPM: Tambah 30 ke semua nilai (manipulasi data langsung)
 * - ATTACK_KEY: Penyerang re-watermark data dengan kunci dan sequence palsu
 *
 * @param {number[]} data - Array data asli dari MQTT
 * @param {string} mode - Mode simulasi ('NORMAL', 'NOISE', 'ATTACK_BPM', 'ATTACK_KEY')
 * @returns {number[]} - Data yang sudah diproses sesuai mode
 */
function applyAttack(data, mode) {
    if (mode === 'NOISE') {
        // NOISE: Tambah +0.4 pada index genap, -0.4 pada index ganjil
        return data.map((x, i) => i % 2 === 0 ? x + 0.4 : x - 0.4);

    } else if (mode === 'ATTACK_BPM') {
        // ATTACK BPM: Tambah 30 ke semua nilai BPM
        return data.map(x => x + 30.0);

    } else if (mode === 'ATTACK_KEY') {
        // ATTACK KEY: Data TIDAK diubah (sama seperti NORMAL)
        // Tapi saat verifikasi, kunci hash diganti dari "RahasiaPolban"
        // menjadi "INIKUNCIPALSU" → expected bits berbeda → INVALID
        return [...data];
    }

    // NORMAL: kembalikan copy data tanpa perubahan
    return [...data];
}

// ===================================================================================
// BAGIAN 10: MQTT CONNECTION
// ===================================================================================

/**
 * Hubungkan ke MQTT broker via WebSocket.
 * Menggunakan MQTT.js yang dimuat via CDN.
 */
function connectMQTT() {
    setMQTT('');  // Status: connecting

    // Generate client ID unik (mencegah konflik jika banyak tab terbuka)
    const id = 'webmon_' + Math.random().toString(16).slice(2, 10);

    // Connect ke broker MQTT via WebSocket
    mqttClient = mqtt.connect(CFG.MQTT_URL, {
        clientId: id,
        clean: true,                              // Session bersih (tidak simpan pesan lama)
        connectTimeout: 10000,                     // Timeout koneksi 10 detik
        reconnectPeriod: 3000,                     // Auto-reconnect setiap 3 detik
    });

    // Event: berhasil connect
    mqttClient.on('connect', () => {
        setMQTT('online');
        mqttClient.subscribe(CFG.MQTT_TOPIC, (err) => {
            if (!err) appendLog('[SYSTEM] MQTT online. Menunggu data ESP32...');
        });
    });

    // Event: error / disconnect / reconnect
    mqttClient.on('error', () => setMQTT('offline'));
    mqttClient.on('close', () => setMQTT('offline'));
    mqttClient.on('reconnect', () => setMQTT(''));

    // Event: menerima pesan MQTT
    mqttClient.on('message', (topic, msg) => {
        try {
            const p = JSON.parse(msg.toString());  // Parse JSON dari payload

            if (p.type === 'live') {
                // Paket live: update grafik dan BPM
                updateLiveBPM(p.val || 0);

            } else if (p.type === 'secure') {
                // Paket secure: proses verifikasi watermark
                const raw = p.data || [];           // Data asli dari ESP32
                const seqNum = p.seq || 0;
                const processed = applyAttack(raw, attackMode);  // Terapkan simulasi
                const result = verifyWatermark(raw, processed, seqNum, attackMode);
                updateSecure(result, seqNum);        // Update UI
            }
        } catch (e) {
            console.error('[MQTT] Parse error:', e);
        }
    });
}

// ===================================================================================
// BAGIAN 11: EVENT HANDLERS
// ===================================================================================

/**
 * Inisialisasi event handlers untuk interaksi UI.
 */
function initEvents() {
    // --- Radio buttons simulasi serangan ---
    document.querySelectorAll('input[name="attackMode"]').forEach(r => {
        r.addEventListener('change', e => {
            attackMode = e.target.value;           // Update mode aktif
            dom.modeBadge.textContent = attackMode; // Update badge

            // Highlight radio button yang aktif
            document.querySelectorAll('.sim-opt').forEach(l => l.classList.remove('active'));
            e.target.closest('.sim-opt').classList.add('active');
        });
    });

    // --- Tombol clear log ---
    dom.btnClear.addEventListener('click', () => {
        dom.logArea.textContent = 'Log dibersihkan.\n';
    });

    // --- Tombol tutup alert ---
    dom.alertClose.addEventListener('click', () => {
        dom.alertBar.style.display = 'none';
    });

    // --- Jam digital (update setiap detik) ---
    setInterval(() => {
        dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });
    }, 1000);
}

// ===================================================================================
// BAGIAN 12: INISIALISASI
// ===================================================================================

/**
 * Entry point — dijalankan saat DOM sudah siap.
 */
document.addEventListener('DOMContentLoaded', () => {
    initCharts();                                  // Inisialisasi grafik
    initEvents();                                  // Pasang event handlers
    connectMQTT();                                 // Hubungkan ke MQTT
    dom.clock.textContent = new Date().toLocaleTimeString('id-ID', { hour12: false });  // Set jam awal
});
