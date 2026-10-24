/**
 * PhishShield AI — Client-Side Application Logic
 * Handles interactive tabs, API analysis requests, animated SVG threat gauges,
 * preset scenario loading, token highlighting, and model statistics inspection.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements - Navigation & Tabs
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const detailTabButtons = document.querySelectorAll('.detail-tab-btn');
    const detailTabPanels = document.querySelectorAll('.detail-tab-panel');

    // DOM Elements - Inputs
    const fromHeaderInput = document.getElementById('fromHeader');
    const replyToHeaderInput = document.getElementById('replyToHeader');
    const subjectInput = document.getElementById('subjectInput');
    const bodyInput = document.getElementById('bodyInput');
    const singleUrlInput = document.getElementById('singleUrlInput');
    const rawHeadersInput = document.getElementById('rawHeadersInput');

    // DOM Elements - Buttons & Presets
    const btnAnalyze = document.getElementById('btnAnalyze');
    const btnClear = document.getElementById('btnClear');
    const btnExport = document.getElementById('btnExport');
    const btnModelStats = document.getElementById('btnModelStats');
    const btnCloseModal = document.getElementById('btnCloseModal');
    const modalStats = document.getElementById('modalStats');
    const modalStatsBody = document.getElementById('modalStatsBody');
    const presetPillsContainer = document.getElementById('presetPillsContainer');

    // DOM Elements - States & Results
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultsContent = document.getElementById('resultsContent');
    const threatBanner = document.getElementById('threatBanner');
    const gaugeFill = document.getElementById('gaugeFill');
    const riskScoreNumber = document.getElementById('riskScoreNumber');
    const verdictPill = document.getElementById('verdictPill');
    const verdictHeading = document.getElementById('verdictHeading');
    const verdictSummary = document.getElementById('verdictSummary');

    // DOM Elements - Sub-Scores
    const meterNlp = document.getElementById('meterNlp');
    const valNlp = document.getElementById('valNlp');
    const meterUrl = document.getElementById('meterUrl');
    const valUrl = document.getElementById('valUrl');
    const meterSe = document.getElementById('meterSe');
    const valSe = document.getElementById('valSe');
    const meterHeader = document.getElementById('meterHeader');
    const valHeader = document.getElementById('valHeader');

    // DOM Elements - Detail Panels
    const highlightedDisplayText = document.getElementById('highlightedDisplayText');
    const warningsList = document.getElementById('warningsList');
    const warningBadgeCount = document.getElementById('warningBadgeCount');
    const psychGrid = document.getElementById('psychGrid');
    const urlsContainer = document.getElementById('urlsContainer');
    const urlBadgeCount = document.getElementById('urlBadgeCount');
    const xaiTableBody = document.getElementById('xaiTableBody');
    const recommendationsList = document.getElementById('recommendationsList');

    let currentActiveTab = 'tab-email';
    let lastAnalysisReport = null;

    // -------------------------------------------------------------------------
    // 1. Tab Switching Handlers
    // -------------------------------------------------------------------------
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            currentActiveTab = target;
            document.getElementById(target).classList.add('active');
        });
    });

    detailTabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            detailTabButtons.forEach(b => b.classList.remove('active'));
            detailTabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const target = btn.getAttribute('data-detail');
            document.getElementById(target).classList.add('active');
        });
    });

    // -------------------------------------------------------------------------
    // 2. Preset Scenarios Loading
    // -------------------------------------------------------------------------
    async function loadPresets() {
        try {
            const resp = await fetch('/api/samples');
            const data = await resp.json();
            if (!data.samples) return;

            presetPillsContainer.innerHTML = '';
            data.samples.forEach(sample => {
                const pill = document.createElement('button');
                pill.className = 'preset-pill';
                const tagClass = sample.risk_tier === 'Safe' ? 'ham' : 'phish';
                pill.innerHTML = `
                    <span class="pill-tag ${tagClass}">${sample.risk_tier}</span>
                    <span>${sample.title}</span>
                `;
                pill.addEventListener('click', () => applyPreset(sample, pill));
                presetPillsContainer.appendChild(pill);
            });
        } catch (err) {
            console.error('Failed to load presets:', err);
            presetPillsContainer.innerHTML = '<span style="font-size:12px; color:#ef4444;">Failed to load presets</span>';
        }
    }

    function applyPreset(sample, clickedPill) {
        document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));
        clickedPill.classList.add('active');

        // Switch to Email tab
        tabButtons.forEach(b => b.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));
        document.querySelector('[data-tab="tab-email"]').classList.add('active');
        document.getElementById('tab-email').classList.add('active');
        currentActiveTab = 'tab-email';

        fromHeaderInput.value = sample.from_header || '';
        replyToHeaderInput.value = sample.reply_to || '';
        subjectInput.value = sample.subject || '';
        bodyInput.value = sample.body || '';

        // Auto trigger analysis
        triggerAnalysis();
    }

    // -------------------------------------------------------------------------
    // 3. Clear Form
    // -------------------------------------------------------------------------
    btnClear.addEventListener('click', () => {
        fromHeaderInput.value = '';
        replyToHeaderInput.value = '';
        subjectInput.value = '';
        bodyInput.value = '';
        singleUrlInput.value = '';
        rawHeadersInput.value = '';
        document.querySelectorAll('.preset-pill').forEach(p => p.classList.remove('active'));

        emptyState.style.display = 'flex';
        loadingState.style.display = 'none';
        resultsContent.style.display = 'none';
        btnExport.style.display = 'none';
        lastAnalysisReport = null;
    });

    // -------------------------------------------------------------------------
    // 4. Trigger Analysis
    // -------------------------------------------------------------------------
    btnAnalyze.addEventListener('click', triggerAnalysis);

    async function triggerAnalysis() {
        emptyState.style.display = 'none';
        resultsContent.style.display = 'none';
        loadingState.style.display = 'flex';

        try {
            let endpoint = '/api/analyze';
            let payload = {};

            if (currentActiveTab === 'tab-url') {
                const url = singleUrlInput.value.trim();
                if (!url) {
                    alert('Please enter a URL to inspect.');
                    resetToEmptyState();
                    return;
                }
                // Wrap into full analysis format for uniform dashboard display
                endpoint = '/api/analyze';
                payload = {
                    text: `Target inspected URL: ${url}`,
                    subject: 'URL Direct Deep Inspection'
                };
            } else if (currentActiveTab === 'tab-headers') {
                const rawHeaders = rawHeadersInput.value.trim();
                if (!rawHeaders) {
                    alert('Please paste raw email headers to analyze.');
                    resetToEmptyState();
                    return;
                }
                payload = { raw_headers: rawHeaders, text: '' };
            } else {
                // Email Tab
                const body = bodyInput.value.trim();
                const subject = subjectInput.value.trim();
                const fromHeader = fromHeaderInput.value.trim();
                const replyTo = replyToHeaderInput.value.trim();

                if (!body && !subject) {
                    alert('Please enter email body or subject line to analyze.');
                    resetToEmptyState();
                    return;
                }
                payload = {
                    text: body,
                    subject: subject,
                    from_header: fromHeader,
                    reply_to: replyTo
                };
            }

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            if (data.error) {
                alert(`Analysis Error: ${data.error}`);
                resetToEmptyState();
                return;
            }

            lastAnalysisReport = data;
            renderAnalysisResults(data);

        } catch (err) {
            console.error('Analysis request failed:', err);
            alert('Analysis failed. Check server logs.');
            resetToEmptyState();
        } finally {
            loadingState.style.display = 'none';
        }
    }

    function resetToEmptyState() {
        loadingState.style.display = 'none';
        resultsContent.style.display = 'none';
        emptyState.style.display = 'flex';
    }

    // -------------------------------------------------------------------------
    // 5. Render Analysis Results
    // -------------------------------------------------------------------------
    function renderAnalysisResults(report) {
        resultsContent.style.display = 'block';
        btnExport.style.display = 'inline-flex';

        // 1. Overall Verdict Banner & Threat Gauge
        const score = report.risk_score;
        threatBanner.className = `threat-banner ${report.verdict_class}`;
        verdictPill.innerText = report.overall_verdict.replace('_', ' ');
        verdictHeading.innerText = report.verdict_badge;

        if (report.overall_verdict === 'CRITICAL_PHISHING') {
            verdictSummary.innerText = `High-confidence malicious attempt detected. Multiple red flags across NLP language, deceptive links, and social engineering coercion.`;
        } else if (report.overall_verdict === 'SUSPICIOUS') {
            verdictSummary.innerText = `Suspicious traits detected. Displays urgency or unusual link parameters requiring caution before interaction.`;
        } else {
            verdictSummary.innerText = `Clean message pattern. No signs of credential harvesting, domain deception, or coercive manipulation detected.`;
        }

        // Animate circular gauge
        animateGauge(score);

        // 2. Multi-factor Sub-Scores
        const breakdown = report.scores_breakdown;
        updateMeter(meterNlp, valNlp, breakdown.ml_nlp_score);
        updateMeter(meterUrl, valUrl, breakdown.url_threat_score);
        updateMeter(meterSe, valSe, breakdown.social_engineering_score);
        updateMeter(meterHeader, valHeader, breakdown.header_spoof_score);

        // 3. Highlighted Text Display
        highlightedDisplayText.innerHTML = report.highlighted_html || '<p style="color:#94a3b8;">No message body provided.</p>';

        // 4. Warning Signs List
        const warnings = report.warning_signs || [];
        warningBadgeCount.innerText = warnings.length;
        if (warnings.length === 0) {
            warningsList.innerHTML = `
                <div class="warning-card severity-LOW">
                    <div class="warning-title">No Critical Warning Signs Detected</div>
                    <div class="warning-desc">The message passed lexical, domain reputation, and psychological trigger checks.</div>
                </div>
            `;
        } else {
            warningsList.innerHTML = warnings.map(w => `
                <div class="warning-card severity-${w.severity}">
                    <div class="warning-top">
                        <span class="warning-cat">${w.category}</span>
                        <span class="warning-sev ${w.severity}">${w.severity}</span>
                    </div>
                    <div class="warning-title">${w.title}</div>
                    <div class="warning-desc">${w.description}</div>
                </div>
            `).join('');
        }

        // 5. Psychological Vectors
        const psychCats = report.social_engineering.categories || {};
        const catKeys = Object.keys(psychCats);
        psychGrid.innerHTML = catKeys.map(k => {
            const cat = psychCats[k];
            const scoreColor = cat.score >= 70 ? '#ef4444' : (cat.score >= 30 ? '#f59e0b' : '#10b981');
            const matchesHtml = cat.matches && cat.matches.length > 0 
                ? cat.matches.map(m => `<span class="match-chip">${m}</span>`).join('') 
                : '<span style="font-size:11px; color:#64748b;">None detected</span>';

            return `
                <div class="psych-card">
                    <div class="psych-card-header">
                        <span class="psych-name">${cat.title}</span>
                        <span class="psych-score" style="color: ${scoreColor}">${cat.score}%</span>
                    </div>
                    <div class="psych-desc">${cat.description}</div>
                    <div class="psych-matches">${matchesHtml}</div>
                </div>
            `;
        }).join('');

        // 6. Detected URLs & Deep Dive
        const urls = report.url_analysis.results || [];
        urlBadgeCount.innerText = urls.length;
        if (urls.length === 0) {
            urlsContainer.innerHTML = `<p style="font-size:13px; color:#94a3b8; padding: 10px;">No links or domain names found in the message.</p>`;
        } else {
            urlsContainer.innerHTML = urls.map(u => {
                const flagsHtml = u.flags.length > 0
                    ? `<ul class="url-flags-list">${u.flags.map(f => `<li><strong>[${f.severity}] ${f.name}:</strong> ${f.description}</li>`).join('')}</ul>`
                    : '<p style="font-size:12px; color:#10b981; margin-top:6px;">Clean domain profile. No known malicious indicators.</p>';

                return `
                    <div class="url-detail-box">
                        <div class="url-headline">
                            <span style="color: #ffffff; font-weight: 700;">${u.url}</span>
                            <span class="warning-sev ${u.verdict === 'MALICIOUS' ? 'CRITICAL' : (u.verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW')}">${u.verdict} (${u.risk_score}%)</span>
                        </div>
                        <div style="font-size:12px; color:#94a3b8; font-family:var(--font-mono);">
                            Protocol: <strong>${u.protocol.toUpperCase()}</strong> | Host: <strong>${u.hostname}</strong> | TLD: <strong>.${u.tld}</strong> | Entropy: <strong>${u.entropy}</strong>
                        </div>
                        ${flagsHtml}
                    </div>
                `;
            }).join('');
        }

        // 7. Explainable AI Feature Table
        const features = report.nlp_analysis.contributing_features || [];
        if (features.length === 0) {
            xaiTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#94a3b8;">No non-zero TF-IDF vocabulary terms matched in this text.</td></tr>`;
        } else {
            xaiTableBody.innerHTML = features.map(f => {
                const dirClass = f.direction === 'phishing' ? 'dir-phish' : 'dir-ham';
                const dirLabel = f.direction === 'phishing' ? '▲ Pushes Phishing' : '▼ Pushes Legitimate';
                return `
                    <tr>
                        <td style="color:#ffffff; font-weight:600;">${f.term}</td>
                        <td class="${dirClass}">${dirLabel}</td>
                        <td>${f.tfidf}</td>
                        <td>${f.weight}</td>
                        <td class="${dirClass}">${f.impact > 0 ? '+' : ''}${f.impact}</td>
                    </tr>
                `;
            }).join('');
        }

        // 8. Recommendations
        const recs = report.recommendations || [];
        recommendationsList.innerHTML = recs.map(r => `<li>${r}</li>`).join('');
    }

    // Gauge Animation helper
    function animateGauge(targetScore) {
        // Circumference: 2 * PI * 50 = 314.159
        const circumference = 314.159;
        const offset = circumference - (targetScore / 100) * circumference;
        gaugeFill.style.strokeDashoffset = offset;

        // Color transition
        if (targetScore >= 65) {
            gaugeFill.style.stroke = '#ef4444';
        } else if (targetScore >= 30) {
            gaugeFill.style.stroke = '#f59e0b';
        } else {
            gaugeFill.style.stroke = '#10b981';
        }

        // Number count-up
        let current = 0;
        const step = Math.max(1, Math.floor(targetScore / 25));
        const timer = setInterval(() => {
            current += step;
            if (current >= targetScore) {
                current = targetScore;
                clearInterval(timer);
            }
            riskScoreNumber.innerText = Math.round(current);
        }, 20);
    }

    // Subscore Bar helper
    function updateMeter(barEl, valEl, val) {
        valEl.innerText = `${val}%`;
        barEl.style.width = `${val}%`;
        if (val >= 65) {
            barEl.style.background = '#ef4444';
        } else if (val >= 30) {
            barEl.style.background = '#f59e0b';
        } else {
            barEl.style.background = '#10b981';
        }
    }

    // -------------------------------------------------------------------------
    // 6. Export Incident Report
    // -------------------------------------------------------------------------
    btnExport.addEventListener('click', () => {
        if (!lastAnalysisReport) return;
        sessionStorage.setItem('last_phish_report', JSON.stringify(lastAnalysisReport));
        window.open('/report', '_blank');
    });

    // -------------------------------------------------------------------------
    // 7. Model Metrics Modal
    // -------------------------------------------------------------------------
    btnModelStats.addEventListener('click', async () => {
        modalStats.style.display = 'flex';
        modalStatsBody.innerHTML = '<div class="cyber-spinner" style="margin:40px auto;"></div>';

        try {
            const resp = await fetch('/api/model-stats');
            const data = await resp.json();
            if (data.error) {
                modalStatsBody.innerHTML = `<p style="color:#ef4444;">${data.error}</p>`;
                return;
            }

            modalStatsBody.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-num">${(data.accuracy * 100).toFixed(1)}%</div>
                        <div class="stat-lbl">Test Accuracy</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num">${(data.precision * 100).toFixed(1)}%</div>
                        <div class="stat-lbl">Precision</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num">${(data.recall * 100).toFixed(1)}%</div>
                        <div class="stat-lbl">Recall</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-num">${(data.f1_score * 100).toFixed(1)}%</div>
                        <div class="stat-lbl">F1 Score</div>
                    </div>
                </div>

                <div style="background:var(--bg-card); padding:16px; border-radius:6px; margin-bottom:20px; font-family:var(--font-mono); font-size:12px; line-height:1.6;">
                    <div><strong>Architecture:</strong> TF-IDF Vectorizer (ngram=(1,2), sublinear_tf=True) + LogisticRegression(C=2.0, class_weight='balanced')</div>
                    <div><strong>5-Fold Cross Validation F1:</strong> ${(data.cv_f1_mean * 100).toFixed(2)}% (+/- ${(data.cv_f1_std * 100).toFixed(2)}%)</div>
                    <div><strong>Vocabulary Size:</strong> ${data.vocabulary_size} n-grams</div>
                    <div><strong>Total Training Samples:</strong> ${data.total_samples} (Balanced Curated & Synthetic Corpus)</div>
                    <div><strong>Confusion Matrix:</strong> TN=${data.confusion_matrix.true_negative}, FP=${data.confusion_matrix.false_positive}, FN=${data.confusion_matrix.false_negative}, TP=${data.confusion_matrix.true_positive}</div>
                </div>

                <h4 style="margin-bottom:10px; color:#ffffff; font-size:14px;">Top Indicative Phishing N-Grams (Highest Positive Log-Odds):</h4>
                <div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:20px;">
                    ${data.top_phishing_features.slice(0, 20).map(f => `
                        <span style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); color:#fca5a5; font-family:var(--font-mono); font-size:11px; padding:3px 8px; border-radius:4px;">
                            ${f.feature} (+${f.weight})
                        </span>
                    `).join('')}
                </div>

                <h4 style="margin-bottom:10px; color:#ffffff; font-size:14px;">Top Indicative Legitimate N-Grams (Highest Negative Log-Odds):</h4>
                <div style="display:flex; flex-wrap:wrap; gap:6px;">
                    ${data.top_legitimate_features.slice(0, 20).map(f => `
                        <span style="background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.3); color:#86efac; font-family:var(--font-mono); font-size:11px; padding:3px 8px; border-radius:4px;">
                            ${f.feature} (${f.weight})
                        </span>
                    `).join('')}
                </div>
            `;
        } catch (err) {
            modalStatsBody.innerHTML = `<p style="color:#ef4444;">Failed to load model statistics.</p>`;
        }
    });

    btnCloseModal.addEventListener('click', () => {
        modalStats.style.display = 'none';
    });

    modalStats.addEventListener('click', (e) => {
        if (e.target === modalStats) {
            modalStats.style.display = 'none';
        }
    });

    // Initial load of preset scenarios
    loadPresets();
});
