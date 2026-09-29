"use strict";

/* =========================================================
   PHISHGUARD - FRONTEND JAVASCRIPT
   ========================================================= */

const API_URL = "http://127.0.0.1:8000/api/v1/scan";
const HISTORY_KEY = "phishguardHistory";

/* =========================================================
   HELPER FUNCTIONS
   ========================================================= */

function $(id) {
    return document.getElementById(id);
}

function safeNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
}

function formatDate(date = new Date()) {
    return date.toLocaleString();
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function isShortenedURL(url) {
    if (!url) return false;

    try {
        const host = new URL(url).hostname.toLowerCase();

        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "ow.ly",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorturl.at",
            "tiny.cc"
        ];

        return shorteners.some(
            domain => host === domain || host.endsWith("." + domain)
        );
    } catch {
        return false;
    }
}

function validateURL(value) {
    if (!value || !value.trim()) {
        return {
            valid: false,
            message: "Please enter a website URL."
        };
    }

    let url = value.trim();

    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
    }

    try {
        const parsed = new URL(url);

        if (!parsed.hostname) {
            return {
                valid: false,
                message: "Please enter a valid website URL."
            };
        }

        return {
            valid: true,
            url
        };
    } catch {
        return {
            valid: false,
            message: "Invalid URL. Example: https://google.com"
        };
    }
}

/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const urlInput = $("urlInput");
const clearInput = $("clearInput");
const analyzeBtn = $("analyzeBtn");
const analyzeText = $("analyzeText");
const analyzeArrow = $("analyzeArrow");

const scannerMessage = $("scannerMessage");
const scannerMessageText = $("scannerMessageText");
const scanLoading = $("scanLoading");
const scanAgainBtn = $("scanAgainBtn");

/* Result */

const riskScore = $("riskScore");
const riskGauge = $("riskGauge");
const riskStatus = $("riskStatus");
const riskLevel = $("riskLevel");

const verdictIcon = $("verdictIcon");
const verdictTitle = $("verdictTitle");
const verdictText = $("verdictText");
const verdictDescription = $("verdictDescription");

const confidenceValue = $("confidenceValue");
const confidenceBar = $("confidenceBar");

const resultStatus = $("resultStatus");

/* Explanation */

const explanationTitle = $("explanationTitle");
const explanationText = $("explanationText");
const reasonList = $("reasonList");

/* Features */

const featureHttps = $("featureHttps");

const featureLength =
    $("featureUrlLength") || $("featureLength");

const featureIP =
    $("featureIp") || $("featureIP");

const featureAt = $("featureAt");
const featureSubdomains = $("featureSubdomains");
const featureSpecial = $("featureSpecial");
const featureShortener = $("featureShortener");
const featureKeywords = $("featureKeywords");

const featureHttpsStatus = $("featureHttpsStatus");
const featureIPStatus = $("featureIPStatus");
const featureAtStatus = $("featureAtStatus");
const featureShortenerStatus = $("featureShortenerStatus");
const featureKeywordsStatus = $("featureKeywordsStatus");

/* Security checks */

const securityHttps = $("securityHttps");
const securitySsl = $("securitySsl");
const securityDns = $("securityDns");
const securityIp = $("securityIp");
const securityKeywords = $("securityKeywords");
const securityShortener = $("securityShortener");

const securityChecksStatus = $("securityChecksStatus");

/* Report */

const reportUrl = $("reportUrl");
const reportTime = $("reportTime");
const reportVerdict = $("reportVerdict");
const reportRisk = $("reportRisk");
const reportConfidence = $("reportConfidence");
const reportStatus = $("reportStatus");
const reportSummary = $("reportSummary");
const printReportBtn = $("printReportBtn");

/* History */

const historyList = $("historyList");
const historyTableBody = $("historyTableBody");
const clearHistoryBtn = $("clearHistoryBtn");

/* Dashboard stats */

const totalScans = $("totalScans");
const threatsDetected = $("threatsDetected");
const safeUrls = $("safeUrls");


/* =========================================================
   MESSAGE FUNCTIONS
   ========================================================= */

function showScannerMessage(message, type = "error") {
    if (!scannerMessage) return;

    scannerMessage.style.display = "block";

    if (scannerMessageText) {
        scannerMessageText.textContent = message;
    } else {
        scannerMessage.textContent = message;
    }

    scannerMessage.classList.remove(
        "error",
        "success",
        "warning"
    );

    scannerMessage.classList.add(type);
}

function hideScannerMessage() {
    if (scannerMessage) {
        scannerMessage.style.display = "none";
    }
}


/* =========================================================
   LOADING
   ========================================================= */

function setLoading(isLoading) {
    if (analyzeBtn) {
        analyzeBtn.disabled = isLoading;
    }

    if (analyzeText) {
        analyzeText.textContent =
            isLoading ? "Analyzing..." : "Analyze URL";
    }

    if (analyzeArrow) {
        analyzeArrow.style.display =
            isLoading ? "none" : "inline";
    }

    if (scanLoading) {
        scanLoading.style.display =
            isLoading ? "block" : "none";
    }
}


/* =========================================================
   BACKEND API
   ========================================================= */

async function analyzeWithBackend(url) {

    const response = await fetch(API_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            url: url
        })
    });

    if (!response.ok) {
        throw new Error(
            `Backend error: ${response.status}`
        );
    }

    return await response.json();
}


/* =========================================================
   CONVERT BACKEND RESULT
   ========================================================= */

function convertBackendResult(data) {

    const security = data.url_security || {};
    const dns = data.dns || {};
    const ssl = data.ssl || {};
    const ml = data.ml || {};

    let confidence = safeNumber(
        data.confidence ?? ml.confidence,
        0
    );

    if (confidence >= 0 && confidence <= 1) {
        confidence = confidence * 100;
    }

    confidence = Math.round(confidence * 10) / 10;

    const classification = String(
        data.classification ||
        ml.classification ||
        ""
    ).toLowerCase();

    const isPhishing =
        classification.includes("phish") ||
        classification.includes("malicious") ||
        classification.includes("danger");

    const prediction =
        isPhishing ? "Phishing" : "Safe";

    const riskScore = safeNumber(
        data.risk_score ??
        data.risk_engine?.risk_score,
        0
    );

    return {

        url: data.url || "",

        prediction: prediction,

        classification:
            data.classification ||
            ml.classification ||
            "",

        risk_score: riskScore,

        confidence: confidence,

        url_security: security,

        dns: dns,

        ssl: ssl,

        ml: ml,

        reasons:
            data.reasons ||
            data.url_security_reasons ||
            ml.signals ||
            [],

        risk_explanation:
            data.risk_explanation ||
            data.risk_engine?.explanation ||
            ml.explanation ||
            ""
    };
}


/* =========================================================
   DISPLAY RESULT
   ========================================================= */

function displayResult(result) {

    const score = safeNumber(
        result.risk_score,
        0
    );

    const confidence = safeNumber(
        result.confidence,
        0
    );

    /* Risk score */

    if (riskScore) {
        riskScore.textContent =
            Math.round(score);
    }

    /* Risk level */

    if (riskLevel) {

        riskLevel.textContent =
            score <= 30
                ? "Low Risk"
                : score <= 70
                    ? "Medium Risk"
                    : "High Risk";
    }

    /* Risk status */

    if (riskStatus) {

        riskStatus.textContent =
            score <= 30
                ? "LOW"
                : score <= 70
                    ? "MEDIUM"
                    : "HIGH";
    }

    /* Verdict */

    if (verdictTitle) {
        verdictTitle.textContent =
            result.prediction === "Phishing"
                ? "Phishing URL"
                : "Safe URL";
    }

    if (verdictText) {
        verdictText.textContent =
            result.prediction === "Phishing"
                ? "Phishing URL"
                : "Safe URL";
    }

    if (verdictDescription) {
        verdictDescription.textContent =
            result.prediction === "Phishing"
                ? "This URL has been classified as potentially dangerous."
                : "The security model has classified this URL as low risk.";
    }

    /* Confidence */

    if (confidenceValue) {
        confidenceValue.textContent =
            `${confidence.toFixed(1)}%`;
    }

    if (confidenceBar) {
        confidenceBar.style.width =
            `${Math.min(100, confidence)}%`;
    }

    /* Gauge */

    if (riskGauge) {

        const circumference = 314;

        const offset =
            circumference -
            (Math.min(100, score) / 100) *
            circumference;

        riskGauge.style.strokeDasharray =
            `${circumference}`;

        riskGauge.style.strokeDashoffset =
            `${offset}`;
    }

    if (resultStatus) {
        resultStatus.textContent =
            "Analysis Complete";
    }

    displayFeatures(result);

    displaySecurityChecks(result);

    displayExplanation(result);

    updateReport(result);

    updateDashboardStats();
}


/* =========================================================
   FEATURES
   ========================================================= */

function displayFeatures(result) {

    const security =
        result.url_security || {};

    const url = result.url || "";

    if (featureHttps) {
        featureHttps.textContent =
            security.uses_https
                ? "Secure"
                : "Not Secure";
    }

    if (featureLength) {
        featureLength.textContent =
            safeNumber(
                security.url_length,
                url.length
            );
    }

    if (featureIP) {
        featureIP.textContent =
            security.has_ip_address
                ? "Detected"
                : "Safe";
    }

    if (featureAt) {
        featureAt.textContent =
            security.has_at_symbol
                ? "Detected"
                : "Safe";
    }

    if (featureSubdomains) {
        featureSubdomains.textContent =
            safeNumber(
                security.subdomain_count,
                0
            );
    }

    if (featureSpecial) {
        featureSpecial.textContent =
            safeNumber(
                security.special_char_count,
                0
            );
    }

    if (featureShortener) {
        featureShortener.textContent =
            isShortenedURL(url)
                ? "Detected"
                : "Safe";
    }

    const keywordCount =
        safeNumber(
            security.suspicious_keyword_count,
            0
        );

    if (featureKeywords) {
        featureKeywords.textContent =
            keywordCount;
    }

    /* Status text */

    if (featureHttpsStatus) {
        featureHttpsStatus.textContent =
            security.uses_https
                ? "Secure"
                : "Warning";
    }

    if (featureIPStatus) {
        featureIPStatus.textContent =
            security.has_ip_address
                ? "Detected"
                : "Not Detected";
    }

    if (featureAtStatus) {
        featureAtStatus.textContent =
            security.has_at_symbol
                ? "Detected"
                : "Not Detected";
    }

    if (featureShortenerStatus) {
        featureShortenerStatus.textContent =
            isShortenedURL(url)
                ? "Detected"
                : "Not Detected";
    }

    if (featureKeywordsStatus) {
        featureKeywordsStatus.textContent =
            keywordCount > 0
                ? `${keywordCount} Detected`
                : "None Detected";
    }
}


/* =========================================================
   SECURITY CHECKS
   ========================================================= */

function setSecurityCheck(element, text, type) {

    if (!element) return;

    element.textContent = text;

    element.classList.remove(
        "secure",
        "warning",
        "danger"
    );

    element.classList.add(type);
}


function displaySecurityChecks(data) {

    if (!data) {
        return;
    }

    const security =
        data.url_security || {};

    const dns =
        data.dns || {};

    const ssl =
        data.ssl || {};

    const ml =
        data.ml || {};

    /* HTTPS */

    setSecurityCheck(
        securityHttps,
        security.uses_https
            ? "Secure"
            : "Not Secure",
        security.uses_https
            ? "secure"
            : "danger"
    );

    /* SSL */

    setSecurityCheck(
        securitySsl,
        ssl.valid
            ? "Valid"
            : "Invalid / Unavailable",
        ssl.valid
            ? "secure"
            : "warning"
    );

    /* DNS */

    setSecurityCheck(
        securityDns,
        dns.resolves
            ? "Resolved"
            : "Not Resolved",
        dns.resolves
            ? "secure"
            : "warning"
    );

    /* IP */

    setSecurityCheck(
        securityIp,
        security.has_ip_address
            ? "Detected"
            : "Not Detected",
        security.has_ip_address
            ? "warning"
            : "secure"
    );

    /* Suspicious Keywords */

    const keywordCount =
        safeNumber(
            security.suspicious_keyword_count,
            0
        );

    setSecurityCheck(
        securityKeywords,
        keywordCount > 0
            ? `${keywordCount} Detected`
            : "None Detected",
        keywordCount > 0
            ? "danger"
            : "secure"
    );

    /* URL Shortener */

    const shortener =
        isShortenedURL(data.url);

    setSecurityCheck(
        securityShortener,
        shortener
            ? "Detected"
            : "Not Detected",
        shortener
            ? "warning"
            : "secure"
    );

    /* Overall */

    if (securityChecksStatus) {

        const classification =
            String(
                data.classification ||
                ml.classification ||
                ""
            ).toLowerCase();

        const phishing =
            classification.includes("phish") ||
            classification.includes("malicious") ||
            classification.includes("danger");

        securityChecksStatus.textContent =
            phishing
                ? "THREAT DETECTED"
                : "SECURITY CHECK COMPLETE";

        securityChecksStatus.classList.remove(
            "secure",
            "warning",
            "danger"
        );

        securityChecksStatus.classList.add(
            phishing
                ? "danger"
                : "secure"
        );
    }
}


/* =========================================================
   EXPLANATION
   ========================================================= */

function displayExplanation(result) {

    if (explanationTitle) {
        explanationTitle.textContent =
            result.prediction === "Phishing"
                ? "Potential phishing indicators detected"
                : "No major phishing indicators detected";
    }

    if (explanationText) {

        explanationText.textContent =
            result.risk_explanation ||
            (
                result.prediction === "Phishing"
                    ? "The security analysis identified indicators associated with phishing."
                    : "The URL passed the available security checks with a low calculated risk."
            );
    }

    if (!reasonList) {
        return;
    }

    reasonList.innerHTML = "";

    let reasons = [];

    if (Array.isArray(result.reasons)) {
        reasons = result.reasons;
    }

    if (reasons.length === 0) {

        const li = document.createElement("li");

        li.textContent =
            result.prediction === "Phishing"
                ? "Potentially suspicious URL characteristics were detected."
                : "No additional suspicious indicators were reported.";

        reasonList.appendChild(li);

        return;
    }

    reasons.forEach(reason => {

        if (
            reason !== null &&
            reason !== undefined &&
            String(reason).trim()
        ) {

            const li =
                document.createElement("li");

            li.textContent =
                String(reason);

            reasonList.appendChild(li);
        }
    });
}


/* =========================================================
   REPORT
   ========================================================= */

function updateReport(result) {

    if (reportUrl) {
        reportUrl.textContent =
            result.url || "--";
    }

    if (reportTime) {
        reportTime.textContent =
            formatDate();
    }

    if (reportVerdict) {
        reportVerdict.textContent =
            result.prediction === "Phishing"
                ? "Phishing"
                : "Safe";
    }

  if (reportRisk) {
    reportRisk.textContent =
        Math.round(
            safeNumber(
                result.riskScore ?? result.risk_score,
                0
            )
        );
}

    if (reportConfidence) {
        reportConfidence.textContent =
            `${safeNumber(
                result.confidence,
                0
            ).toFixed(1)}%`;
    }

    if (reportStatus) {
        reportStatus.textContent =
            "Completed";
    }

    if (reportSummary) {
        reportSummary.textContent =
            result.prediction === "Phishing"
                ? "The URL has been classified as potentially dangerous."
                : "The URL has been classified as low risk by the security analysis.";
    }
}


/* =========================================================
   HISTORY
   ========================================================= */

function getHistory() {

    try {

        const saved =
            localStorage.getItem(HISTORY_KEY);

        return saved
            ? JSON.parse(saved)
            : [];

    } catch {
        return [];
    }
}


function saveHistory(result) {

    const history =
        getHistory();

    history.unshift({

        url: result.url,

        riskScore:
            Math.round(
                safeNumber(
                    result.risk_score,
                    0
                )
            ),

        prediction:
            result.prediction,

        confidence:
            safeNumber(
                result.confidence,
                0
            ),

        time:
            formatDate()

    });

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(
            history.slice(0, 50)
        )
    );

    renderHistory();

    updateDashboardStats();
}


function renderHistory() {

    const history =
        getHistory();

    if (historyTableBody) {

        historyTableBody.innerHTML = "";

        history.forEach(item => {

            const row =
                document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHTML(item.time)}</td>
                <td>${escapeHTML(item.url)}</td>
                <td>${escapeHTML(item.riskScore)}</td>
                <td>${escapeHTML(item.prediction)}</td>
                <td>Completed</td>
            `;

            historyTableBody.appendChild(row);
        });
    }

    if (historyList) {

        historyList.innerHTML = "";

        if (history.length === 0) {

            historyList.innerHTML =
                "<p>No Scan History</p>";

            return;
        }

        history.forEach(item => {

            const div =
                document.createElement("div");

            div.className =
                "history-item";

            div.innerHTML = `
                <strong>${escapeHTML(item.url)}</strong>
                <span>Risk: ${escapeHTML(item.riskScore)}</span>
                <span>${escapeHTML(item.prediction)}</span>
            `;

            historyList.appendChild(div);
        });
    }
}


/* =========================================================
   DASHBOARD STATS
   ========================================================= */

function updateDashboardStats() {

    const history =
        getHistory();

    const total =
        history.length;

    const threats =
        history.filter(
            item =>
                item.prediction === "Phishing"
        ).length;

    const safe =
        history.filter(
            item =>
                item.prediction !== "Phishing"
        ).length;

    if (totalScans) {
        totalScans.textContent =
            total;
    }

    if (threatsDetected) {
        threatsDetected.textContent =
            threats;
    }

    if (safeUrls) {
        safeUrls.textContent =
            safe;
    }
}


/* =========================================================
   MAIN SCAN FUNCTION
   ========================================================= */

async function scanURL() {

    const validation =
        validateURL(
            urlInput?.value
        );

    if (!validation.valid) {

        showScannerMessage(
            validation.message,
            "error"
        );

        return;
    }

    const url =
        validation.url;

    hideScannerMessage();

    setLoading(true);

    try {

        const backendData =
            await analyzeWithBackend(url);

        const result =
            convertBackendResult(
                backendData
            );

        displayResult(result);

        saveHistory(result);

        showScannerMessage(
            "URL analysis completed successfully.",
            "success"
        );

    } catch (error) {

        console.error(
            "PhishGuard scan error:",
            error
        );

        showScannerMessage(
            "Unable to connect to the security backend. Make sure the backend is running on port 8000.",
            "error"
        );

    } finally {

        setLoading(false);
    }
}


/* =========================================================
   CLEAR INPUT
   ========================================================= */

function clearURLInput() {

    if (urlInput) {
        urlInput.value = "";
        urlInput.focus();
    }

    hideScannerMessage();
}


/* =========================================================
   CLEAR HISTORY
   ========================================================= */

function clearHistory() {

    localStorage.removeItem(
        HISTORY_KEY
    );

    renderHistory();

    updateDashboardStats();
}


/* =========================================================
   PRINT REPORT
   ========================================================= */

function printReport() {
    window.print();
}


/* =========================================================
   NAVIGATION
   ========================================================= */

function setupNavigation() {

    const links =
        document.querySelectorAll(
            'a[href^="#"]'
        );

    links.forEach(link => {

        link.addEventListener(
            "click",
            () => {

                const target =
                    link.getAttribute("href");

                if (
                    target &&
                    target.length > 1
                ) {

                    setTimeout(() => {

                        window.scrollTo({
                            top: 0,
                            behavior: "smooth"
                        });

                    }, 50);
                }
            }
        );
    });
}


/* =========================================================
   EVENT LISTENERS
   ========================================================= */

if (analyzeBtn) {

    analyzeBtn.addEventListener(
        "click",
        scanURL
    );
}

if (scanAgainBtn) {

    scanAgainBtn.addEventListener(
        "click",
        scanURL
    );
}

if (clearInput) {

    clearInput.addEventListener(
        "click",
        clearURLInput
    );
}

if (clearHistoryBtn) {

    clearHistoryBtn.addEventListener(
        "click",
        clearHistory
    );
}

if (printReportBtn) {

    printReportBtn.addEventListener(
        "click",
        printReport
    );
}

if (urlInput) {

    urlInput.addEventListener(
        "keydown",
        event => {

            if (event.key === "Enter") {
                scanURL();
            }
        }
    );
}


/* =========================================================
   STARTUP
   ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        renderHistory();

        updateDashboardStats();

        setupNavigation();

        console.log(
            "PhishGuard frontend loaded successfully."
        );
    }
);