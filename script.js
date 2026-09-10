/* ============================================================
   PHISHGUARD FRONTEND JAVASCRIPT
   ============================================================

   IMPORTANT:

   This file contains FRONTEND functionality only.

   It does NOT:
   - perform ML prediction
   - calculate phishing probability
   - connect to a database
   - implement phishing detection rules

   Later, Raj's Flask API + Sumit's ML model can be connected
   inside the API integration section.
   ============================================================ */


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

const urlInput = document.getElementById("urlInput");
const clearInput = document.getElementById("clearInput");

const analyzeBtn = document.getElementById("analyzeBtn");
const analyzeText = document.getElementById("analyzeText");
const analyzeArrow = document.getElementById("analyzeArrow");

const scannerMessage = document.getElementById("scannerMessage");
const scannerMessageText = document.getElementById("scannerMessageText");

const scanLoading = document.getElementById("scanLoading");

const scanAgainBtn = document.getElementById("scanAgainBtn");

const riskScore = document.getElementById("riskScore");
const riskGauge = document.getElementById("riskGauge");
const riskStatus = document.getElementById("riskStatus");
const riskDescription = document.getElementById("riskDescription");

const verdictIcon = document.getElementById("verdictIcon");
const verdictTitle = document.getElementById("verdictTitle");
const verdictDescription = document.getElementById("verdictDescription");

const confidenceValue = document.getElementById("confidenceValue");
const confidenceBar = document.getElementById("confidenceBar");

const resultStatus = document.getElementById("resultStatus");

const explanationTitle = document.getElementById("explanationTitle");
const explanationText = document.getElementById("explanationText");
const reasonList = document.getElementById("reasonList");

const reportUrl = document.getElementById("reportUrl");
const reportTime = document.getElementById("reportTime");
const reportVerdict = document.getElementById("reportVerdict");
const reportRisk = document.getElementById("reportRisk");
const reportConfidence = document.getElementById("reportConfidence");
const reportStatus = document.getElementById("reportStatus");
const reportSummary = document.getElementById("reportSummary");

const printReportBtn = document.getElementById("printReportBtn");

const historyTableBody = document.getElementById("historyTableBody");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const filterButtons = document.querySelectorAll(".filter-btn");

const navItems = document.querySelectorAll(".nav-item");


/* ============================================================
   STATE
   ============================================================ */

let currentFilter = "all";

let scanHistory = [];


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {

    loadHistory();

    updateClearButton();

    updateNavigation();

    renderHistory();

});


/* ============================================================
   URL INPUT
   ============================================================ */

urlInput.addEventListener("input", () => {

    updateClearButton();

    clearScannerMessage();

});


function updateClearButton() {

    if (urlInput.value.trim().length > 0) {

        clearInput.classList.add("visible");

    } else {

        clearInput.classList.remove("visible");

    }

}


/* ============================================================
   CLEAR INPUT
   ============================================================ */

clearInput.addEventListener("click", () => {

    urlInput.value = "";

    updateClearButton();

    urlInput.focus();

    clearScannerMessage();

});


/* ============================================================
   ENTER KEY
   ============================================================ */

urlInput.addEventListener("keydown", (event) => {

    if (event.key === "Enter") {

        analyzeURL();

    }

});


/* ============================================================
   URL VALIDATION
   ============================================================ */

function validateURL(value) {

    const url = value.trim();

    if (!url) {

        return {
            valid: false,
            message: "Please enter a website URL."
        };

    }


    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://")
    ) {

        return {
            valid: false,
            message: "Please enter a complete URL starting with http:// or https://"
        };

    }


    try {

        const parsed = new URL(url);

        if (!parsed.hostname) {

            return {
                valid: false,
                message: "Please enter a valid website address."
            };

        }


        if (
            parsed.protocol !== "http:" &&
            parsed.protocol !== "https:"
        ) {

            return {
                valid: false,
                message: "Only HTTP and HTTPS website URLs are supported."
            };

        }


        return {
            valid: true,
            url: parsed.href
        };

    } catch (error) {

        return {
            valid: false,
            message: "The URL format is invalid. Please check it and try again."
        };

    }

}


/* ============================================================
   SCANNER MESSAGES
   ============================================================ */

function showScannerMessage(message, type = "") {

    scannerMessage.classList.remove(
        "error",
        "success"
    );

    if (type) {

        scannerMessage.classList.add(type);

    }

    scannerMessageText.textContent = message;

}


function clearScannerMessage() {

    scannerMessage.classList.remove(
        "error",
        "success"
    );

    scannerMessageText.textContent =
        "Your URL is analyzed securely. Do not enter passwords or sensitive information.";

}


/* ============================================================
   LOADING STATE
   ============================================================ */

function setLoading(isLoading) {

    if (isLoading) {

        analyzeBtn.classList.add("loading");

        analyzeText.textContent = "Analyzing";

        analyzeArrow.textContent = "•••";

        scanLoading.classList.add("active");

    } else {

        analyzeBtn.classList.remove("loading");

        analyzeText.textContent = "Analyze URL";

        analyzeArrow.textContent = "→";

        scanLoading.classList.remove("active");

    }

}


/* ============================================================
   MAIN ANALYZE FUNCTION
   ============================================================ */

async function analyzeURL() {

    const validation = validateURL(urlInput.value);


    /* Invalid URL */

    if (!validation.valid) {

        showScannerMessage(
            validation.message,
            "error"
        );

        urlInput.focus();

        return;

    }


    const url = validation.url;


    /* Start loading */

    setLoading(true);

    showScannerMessage(
        "Preparing URL for security analysis...",
        ""
    );


    /*
        --------------------------------------------------------
        FUTURE BACKEND INTEGRATION
        --------------------------------------------------------

        Raj's Flask API can be connected here later.

        Example:

        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const result = await response.json();

        displayResult(result);

        --------------------------------------------------------
    */


    /*
        IMPORTANT:

        We are NOT creating a fake ML result here.

        The frontend only demonstrates the scanning state.
    */

    await wait(1200);


    setLoading(false);

    showScannerMessage(
        "Frontend scanner is ready. Backend API connection will be added later.",
        ""
    );

}


/* ============================================================
   WAIT HELPER
   ============================================================ */

function wait(milliseconds) {

    return new Promise(resolve => {

        setTimeout(resolve, milliseconds);

    });

}


/* ============================================================
   FUTURE RESULT DISPLAY
   ============================================================ */

function displayResult(result) {

    /*
        This function is intentionally prepared for
        Raj's backend + Sumit's ML response.

        Example expected structure:

        {
            url: "...",
            prediction: "Safe",
            risk_score: 10,
            confidence: 96,
            features: {
                https: true,
                url_length: 20,
                ip_address: false,
                at_symbol: false,
                subdomains: 1,
                special_characters: 2,
                url_shortener: false,
                suspicious_keywords: 0
            },
            reasons: []
        }
    */


    if (!result) {

        return;

    }


    const prediction =
        result.prediction || "Unknown";

    const score =
        Number(result.risk_score ?? 0);

    const confidence =
        Number(result.confidence ?? 0);


    displayRiskScore(score);

    displayVerdict(
        prediction,
        confidence
    );


    if (result.features) {

        displayFeatures(result.features);

    }


    if (Array.isArray(result.reasons)) {

        displayReasons(result.reasons);

    }


    updateReport(
        result
    );


    addToHistory(
        result
    );

}


/* ============================================================
   DISPLAY RISK SCORE
   ============================================================ */

function displayRiskScore(score) {

    const safeScore =
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        );


    riskScore.textContent =
        Math.round(safeScore);


    const circumference =
        2 * Math.PI * 65;


    const offset =
        circumference -
        (safeScore / 100) * circumference;


    riskGauge.style.strokeDashoffset =
        offset;


    if (safeScore >= 70) {

        riskGauge.style.stroke =
            "#ff6673";

    } else if (safeScore >= 40) {

        riskGauge.style.stroke =
            "#eebd5d";

    } else {

        riskGauge.style.stroke =
            "#39d39b";

    }

}


/* ============================================================
   DISPLAY VERDICT
   ============================================================ */

function displayVerdict(
    prediction,
    confidence
) {

    const normalized =
        String(prediction)
            .toLowerCase()
            .trim();


    verdictIcon.classList.remove(
        "safe",
        "phishing"
    );

    riskStatus.classList.remove(
        "safe",
        "danger",
        "awaiting"
    );


    if (
        normalized.includes("phish") ||
        normalized.includes("malicious") ||
        normalized.includes("danger")
    ) {

        verdictIcon.textContent = "⚠";

        verdictIcon.classList.add(
            "phishing"
        );

        verdictTitle.textContent =
            "Phishing Detected";

        verdictDescription.textContent =
            "The security model has classified this URL as potentially dangerous.";

        riskStatus.textContent =
            "High Risk";

        riskStatus.classList.add(
            "danger"
        );

        resultStatus.textContent =
            "THREAT DETECTED";

    }


    else if (
        normalized.includes("safe") ||
        normalized.includes("legitimate")
    ) {

        verdictIcon.textContent = "✓";

        verdictIcon.classList.add(
            "safe"
        );

        verdictTitle.textContent =
            "URL Appears Safe";

        verdictDescription.textContent =
            "The security model has classified this URL as low risk.";

        riskStatus.textContent =
            "Low Risk";

        riskStatus.classList.add(
            "safe"
        );

        resultStatus.textContent =
            "SAFE URL";

    }


    else {

        verdictIcon.textContent = "?";

        verdictTitle.textContent =
            prediction;

        verdictDescription.textContent =
            "The security model returned an analysis result.";

        riskStatus.textContent =
            "Analyzed";

        resultStatus.textContent =
            "ANALYZED";

    }


    confidenceValue.textContent =
        `${confidence}%`;

    confidenceBar.style.width =
        `${Math.max(0, Math.min(100, confidence))}%`;


    riskDescription.textContent =
        `Model confidence: ${confidence}%`;

}


/* ============================================================
   DISPLAY FEATURES
   ============================================================ */

function displayFeatures(features) {

    updateFeature(
        "featureHttps",
        features.https,
        "featureHttpsStatus"
    );


    updateFeature(
        "featureIP",
        features.ip_address,
        "featureIPStatus"
    );


    updateFeature(
        "featureAt",
        features.at_symbol,
        "featureAtStatus"
    );


    updateFeature(
        "featureShortener",
        features.url_shortener,
        "featureShortenerStatus"
    );


    if (
        features.url_length !== undefined
    ) {

        document.getElementById(
            "featureLength"
        ).textContent =
            features.url_length;

    }


    if (
        features.subdomains !== undefined
    ) {

        document.getElementById(
            "featureSubdomains"
        ).textContent =
            features.subdomains;

    }


    if (
        features.special_characters !== undefined
    ) {

        document.getElementById(
            "featureSpecial"
        ).textContent =
            features.special_characters;

    }


    if (
        features.suspicious_keywords !== undefined
    ) {

        document.getElementById(
            "featureKeywords"
        ).textContent =
            features.suspicious_keywords;

    }

}


/* ============================================================
   FEATURE HELPER
   ============================================================ */

function updateFeature(
    valueId,
    value,
    statusId
) {

    const valueElement =
        document.getElementById(valueId);

    const statusElement =
        document.getElementById(statusId);


    if (!valueElement) {

        return;

    }


    if (typeof value === "boolean") {

        valueElement.textContent =
            value ? "Detected" : "Not Detected";


        if (statusElement) {

            statusElement.classList.remove(
                "secure",
                "detected"
            );


            if (value) {

                statusElement.textContent =
                    "Detected";

                statusElement.classList.add(
                    "detected"
                );

            } else {

                statusElement.textContent =
                    "Secure";

                statusElement.classList.add(
                    "secure"
                );

            }

        }

    } else {

        valueElement.textContent =
            value ?? "--";

    }

}


/* ============================================================
   DISPLAY REASONS
   ============================================================ */

function displayReasons(reasons) {

    reasonList.innerHTML = "";


    if (
        !reasons ||
        reasons.length === 0
    ) {

        const item =
            document.createElement("span");

        item.className =
            "reason-item";

        item.textContent =
            "No explanation provided";

        reasonList.appendChild(item);

        explanationTitle.textContent =
            "Analysis completed";

        explanationText.textContent =
            "The backend did not provide additional security reasons.";

        return;

    }


    explanationTitle.textContent =
        "Security factors identified";


    explanationText.textContent =
        "The following factors were returned by the analysis system.";


    reasons.forEach(reason => {

        const item =
            document.createElement("span");

        item.className =
            "reason-item";

        item.textContent =
            reason;

        reasonList.appendChild(item);

    });

}


/* ============================================================
   UPDATE SECURITY REPORT
   ============================================================ */

function updateReport(result) {

    const now =
        new Date();


    reportUrl.textContent =
        result.url || "--";


    reportTime.textContent =
        now.toLocaleString();


    reportVerdict.textContent =
        result.prediction || "--";


    reportRisk.textContent =
        `${result.risk_score ?? "--"} / 100`;


    reportConfidence.textContent =
        result.confidence !== undefined
            ? `${result.confidence}%`
            : "--";


    reportStatus.textContent =
        "Analysis Complete";


    reportSummary.textContent =
        result.summary ||
        "The security analysis has been completed. See the assessment and feature sections for additional details.";

}


/* ============================================================
   SCAN HISTORY
   ============================================================ */

function addToHistory(result) {

    const entry = {

        id: Date.now(),

        url:
            result.url || "--",

        time:
            new Date().toLocaleString(),

        risk:
            result.risk_score ?? "--",

        verdict:
            result.prediction || "Unknown"

    };


    scanHistory.unshift(entry);


    if (scanHistory.length > 50) {

        scanHistory =
            scanHistory.slice(0, 50);

    }


    saveHistory();

    renderHistory();

}


/* ============================================================
   RENDER HISTORY
   ============================================================ */

function renderHistory() {

    historyTableBody.innerHTML = "";


    let filtered =
        scanHistory;


    if (currentFilter !== "all") {

        filtered =
            scanHistory.filter(item => {

                const verdict =
                    item.verdict
                        .toLowerCase();


                if (
                    currentFilter === "safe"
                ) {

                    return (
                        verdict.includes("safe") ||
                        verdict.includes("legitimate")
                    );

                }


                if (
                    currentFilter === "phishing"
                ) {

                    return (
                        verdict.includes("phish") ||
                        verdict.includes("malicious") ||
                        verdict.includes("danger")
                    );

                }


                return true;

            });

    }


    if (filtered.length === 0) {

        const row =
            document.createElement("tr");


        row.innerHTML = `
            <td colspan="5">
                <div class="empty-history">
                    <div class="empty-history-icon">◷</div>
                    <strong>No scans found</strong>
                    <span>
                        Analyze a URL to create your scan history.
                    </span>
                </div>
            </td>
        `;


        historyTableBody.appendChild(row);

        return;

    }


    filtered.forEach(item => {

        const row =
            document.createElement("tr");


        const verdict =
            item.verdict.toLowerCase();


        let badgeClass =
            "pending";


        if (
            verdict.includes("safe") ||
            verdict.includes("legitimate")
        ) {

            badgeClass =
                "safe";

        }


        if (
            verdict.includes("phish") ||
            verdict.includes("malicious") ||
            verdict.includes("danger")
        ) {

            badgeClass =
                "phishing";

        }


        row.innerHTML = `

            <td>
                <div class="history-url"
                     title="${escapeHTML(item.url)}">
                    ${escapeHTML(item.url)}
                </div>
            </td>

            <td>
                ${escapeHTML(item.time)}
            </td>

            <td>
                ${escapeHTML(String(item.risk))}/100
            </td>

            <td>
                <span class="history-badge ${badgeClass}">
                    ${escapeHTML(item.verdict)}
                </span>
            </td>

            <td>
                <span class="history-badge ${badgeClass}">
                    ${badgeClass === "pending"
                        ? "Pending"
                        : "Complete"}
                </span>
            </td>

        `;


        historyTableBody.appendChild(row);

    });

}


/* ============================================================
   LOCAL STORAGE
   ============================================================ */

function saveHistory() {

    localStorage.setItem(
        "phishguardHistory",
        JSON.stringify(scanHistory)
    );

}


function loadHistory() {

    try {

        const stored =
            localStorage.getItem(
                "phishguardHistory"
            );


        if (stored) {

            scanHistory =
                JSON.parse(stored);

        }

    } catch (error) {

        scanHistory = [];

    }

}


/* ============================================================
   CLEAR HISTORY
   ============================================================ */

clearHistoryBtn.addEventListener(
    "click",
    () => {

        if (scanHistory.length === 0) {

            return;

        }


        const confirmed =
            confirm(
                "Are you sure you want to clear all scan history?"
            );


        if (!confirmed) {

            return;

        }


        scanHistory = [];

        saveHistory();

        renderHistory();

    }
);


/* ============================================================
   HISTORY FILTER
   ============================================================ */

filterButtons.forEach(button => {

    button.addEventListener(
        "click",
        () => {

            filterButtons.forEach(btn => {

                btn.classList.remove(
                    "active"
                );

            });


            button.classList.add(
                "active"
            );


            currentFilter =
                button.dataset.filter;


            renderHistory();

        }
    );

});


/* ============================================================
   SCAN AGAIN
   ============================================================ */

scanAgainBtn.addEventListener(
    "click",
    () => {

        document
            .getElementById("scanner")
            .scrollIntoView({
                behavior: "smooth"
            });


        setTimeout(() => {

            urlInput.focus();

        }, 500);

    }
);


/* ============================================================
   PRINT REPORT
   ============================================================ */

printReportBtn.addEventListener(
    "click",
    () => {

        window.print();

    }
);


/* ============================================================
   NAVIGATION
   ============================================================ */

function updateNavigation() {

    const sections = [
        "dashboard",
        "scanner",
        "history",
        "features",
        "report"
    ];


    window.addEventListener(
        "scroll",
        () => {

            let current =
                "dashboard";


            sections.forEach(id => {

                const section =
                    document.getElementById(id);


                if (!section) {

                    return;

                }


                const position =
                    section.getBoundingClientRect()
                        .top;


                if (
                    position <= 150 &&
                    position >= -500
                ) {

                    current = id;

                }

            });


            navItems.forEach(item => {

                item.classList.remove(
                    "active"
                );


                const href =
                    item.getAttribute("href");


                if (
                    href === `#${current}`
                ) {

                    item.classList.add(
                        "active"
                    );

                }

            });

        }
    );

}


/* ============================================================
   NAVIGATION CLICK
   ============================================================ */

navItems.forEach(item => {

    item.addEventListener(
        "click",
        () => {

            navItems.forEach(nav => {

                nav.classList.remove(
                    "active"
                );

            });


            item.classList.add(
                "active"
            );

        }
    );

});


/* ============================================================
   HTML ESCAPE
   ============================================================ */

function escapeHTML(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


/* ============================================================
   FUTURE API ADAPTER
   ============================================================ */

/*
    When Raj gives you the actual Flask endpoint,
    only this area needs to be connected.

    Example:

    async function analyzeWithBackend(url) {

        const response = await fetch("/api/analyze", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        });


        if (!response.ok) {
            throw new Error("Server error");
        }


        const result =
            await response.json();


        return result;
    }

    Then analyzeURL() can call:

    const result =
        await analyzeWithBackend(url);

    displayResult(result);

*/


console.log(
    "PhishGuard frontend loaded successfully."
);