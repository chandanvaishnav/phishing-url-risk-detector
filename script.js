/* ============================================================
   PHISHGUARD - FRONTEND
   Connected to FastAPI Backend
   ============================================================ */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API_BASE_URL = "http://127.0.0.1:8000";


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

const urlInput = document.getElementById("urlInput");
const clearInput = document.getElementById("clearInput");

const analyzeBtn = document.getElementById("analyzeBtn");
const analyzeText = document.getElementById("analyzeText");
const analyzeArrow = document.getElementById("analyzeArrow");

const scannerMessage = document.getElementById("scannerMessage");
const scannerMessageText =
    document.getElementById("scannerMessageText");

const scanLoading = document.getElementById("scanLoading");
const scanAgainBtn =
    document.getElementById("scanAgainBtn");

const riskScore =
    document.getElementById("riskScore");

const riskGauge =
    document.getElementById("riskGauge");

const riskStatus =
    document.getElementById("riskStatus");

const riskDescription =
    document.getElementById("riskDescription");

const verdictIcon =
    document.getElementById("verdictIcon");

const verdictTitle =
    document.getElementById("verdictTitle");

const verdictDescription =
    document.getElementById("verdictDescription");

const confidenceValue =
    document.getElementById("confidenceValue");

const confidenceBar =
    document.getElementById("confidenceBar");

const resultStatus =
    document.getElementById("resultStatus");

const explanationTitle =
    document.getElementById("explanationTitle");

const explanationText =
    document.getElementById("explanationText");

const reasonList =
    document.getElementById("reasonList");

const reportUrl =
    document.getElementById("reportUrl");

const reportTime =
    document.getElementById("reportTime");

const reportVerdict =
    document.getElementById("reportVerdict");

const reportRisk =
    document.getElementById("reportRisk");

const reportConfidence =
    document.getElementById("reportConfidence");

const reportStatus =
    document.getElementById("reportStatus");

const reportSummary =
    document.getElementById("reportSummary");

const printReportBtn =
    document.getElementById("printReportBtn");

const historyTableBody =
    document.getElementById("historyTableBody");

const clearHistoryBtn =
    document.getElementById("clearHistoryBtn");

const filterButtons =
    document.querySelectorAll(".filter-btn");

const navItems =
    document.querySelectorAll(".nav-item");


/* ============================================================
   STATE
   ============================================================ */

let currentFilter = "all";

let scanHistory = [];

let latestResult = null;


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", async () => {

    loadHistory();

    updateClearButton();

    renderHistory();

    setupInput();

    setupAnalyzeButton();

    setupHistoryControls();

    setupReportButton();

    setupNavigation();

    updateDashboardStats();

});


/* ============================================================
   INPUT SETUP
   ============================================================ */

function setupInput() {

    if (urlInput) {

        urlInput.addEventListener(
            "input",
            () => {

                hideScannerMessage();

            }
        );


        urlInput.addEventListener(
            "keydown",
            (event) => {

                if (event.key === "Enter") {

                    event.preventDefault();

                    analyzeURL();

                }

            }
        );

    }


    if (clearInput) {

        clearInput.addEventListener(
            "click",
            () => {

                if (urlInput) {

                    urlInput.value = "";

                    urlInput.focus();

                }

            }
        );

    }

}


/* ============================================================
   ANALYZE BUTTON
   ============================================================ */

function setupAnalyzeButton() {

    if (!analyzeBtn) {

        console.error(
            "PhishGuard: Analyze button not found."
        );

        return;

    }


    analyzeBtn.addEventListener(
        "click",
        analyzeURL
    );

}


/* ============================================================
   MAIN SCAN FUNCTION
   ============================================================ */

async function analyzeURL() {

    if (!urlInput) {

        return;

    }


    let url =
        urlInput.value.trim();


    if (!url) {

        showScannerMessage(
            "Please enter a URL."
        );

        urlInput.focus();

        return;

    }


    /*
     * Add https:// when the user enters
     * example.com instead of https://example.com
     */

    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://")
    ) {

        url =
            "https://" + url;

    }


    /*
     * Browser-side URL validation
     */

    try {

        new URL(url);

    } catch (error) {

        showScannerMessage(
            "Please enter a valid website URL."
        );

        return;

    }


    hideScannerMessage();

    setLoadingState(true);


    console.log(
        "PhishGuard: Sending URL to backend:",
        url
    );


    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/v1/scan`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        console.log(
            "PhishGuard: Backend status:",
            response.status
        );


        if (!response.ok) {

            let message =
                "The backend could not scan this URL.";

            try {

                const errorData =
                    await response.json();

                if (
                    errorData &&
                    errorData.detail
                ) {

                    message =
                        errorData.detail;

                }

            } catch (error) {

                console.log(
                    "Could not read backend error."
                );

            }


            throw new Error(message);

        }


        const result =
            await response.json();


        console.log(
            "PhishGuard: Backend result:",
            result
        );


        latestResult = result;


        /* Update result */

        displayResult(result);


        /* Update security features */

        displayFeatures(
            result.url_security || {}
        );


        /* Update security reasons */

        displayReasons(
            result.risk_engine &&
            Array.isArray(
                result.risk_engine.explanation
            )
                ? result.risk_engine.explanation
                : []
        );


        /* Update report */

        updateReport(result);


        /* Add to local history */

        addToHistory(result);


        /* Refresh dashboard */

        updateDashboardStats();


        /* Scroll to result */

        scrollToResult();


    } catch (error) {

        console.error(
            "PhishGuard scan failed:",
            error
        );


        let message =
            error.message ||
            "An unexpected error occurred.";


        if (
            error instanceof TypeError &&
            message.toLowerCase().includes("fetch")
        ) {

            message =
                "Could not connect to the backend. Make sure FastAPI is running on http://127.0.0.1:8000";

        }


        showScannerMessage(
            message
        );


    } finally {

        setLoadingState(false);

    }

}


/* ============================================================
   DISPLAY RESULT
   ============================================================ */

function displayResult(result) {

    const classification =
        String(
            result.classification || ""
        ).toLowerCase();


    let score =
        Number(
            result.risk_score
        );


    if (
        Number.isNaN(score)
    ) {

        score = 0;

    }


    let confidence =
        Number(
            result.confidence
        );


    if (
        Number.isNaN(confidence)
    ) {

        confidence = 0;

    }


    /*
     * Backend confidence is decimal:
     * 0.808672
     *
     * Convert to:
     * 80.87%
     */

    if (
        confidence <= 1
    ) {

        confidence *= 100;

    }


    confidence =
        Math.max(
            0,
            Math.min(
                100,
                confidence
            )
        );


    confidence =
        Math.round(
            confidence * 100
        ) / 100;


    /* Determine verdict */

    let verdict =
        "Safe";

    let title =
        "URL Appears Safe";

    let description =
        "The URL received a low-risk security assessment.";


    if (
        classification === "high_risk"
    ) {

        verdict =
            "Phishing";

        title =
            "Phishing Detected";

        description =
            "The security system identified this URL as high risk.";

    }

    else if (
        classification === "suspicious"
    ) {

        verdict =
            "Suspicious";

        title =
            "Suspicious URL";

        description =
            "The security system identified characteristics that require caution.";

    }


    /* Risk score */

    if (riskScore) {

        riskScore.textContent =
            score.toFixed(2);

    }


    if (riskDescription) {

        riskDescription.textContent =
            `Security risk score: ${score.toFixed(2)} / 100`;

    }


    /* Risk status */

    if (riskStatus) {

        riskStatus.classList.remove(
            "safe",
            "danger",
            "awaiting"
        );


        if (
            classification === "high_risk"
        ) {

            riskStatus.textContent =
                "High Risk";

            riskStatus.classList.add(
                "danger"
            );

        }

        else if (
            classification === "suspicious"
        ) {

            riskStatus.textContent =
                "Suspicious";

            riskStatus.classList.add(
                "danger"
            );

        }

        else {

            riskStatus.textContent =
                "Low Risk";

            riskStatus.classList.add(
                "safe"
            );

        }

    }


    /* Risk gauge */

    updateRiskGauge(score);


    /* Verdict icon */

    if (verdictIcon) {

        verdictIcon.classList.remove(
            "safe",
            "phishing"
        );


        if (
            classification === "high_risk" ||
            classification === "suspicious"
        ) {

            verdictIcon.textContent =
                "⚠";

            verdictIcon.classList.add(
                "phishing"
            );

        }

        else {

            verdictIcon.textContent =
                "✓";

            verdictIcon.classList.add(
                "safe"
            );

        }

    }


    /* Verdict title */

    if (verdictTitle) {

        verdictTitle.textContent =
            title;

    }


    /* Verdict description */

    if (verdictDescription) {

        verdictDescription.textContent =
            description;

    }


    /* Result status */

    if (resultStatus) {

        if (
            classification === "high_risk"
        ) {

            resultStatus.textContent =
                "THREAT DETECTED";

        }

        else if (
            classification === "suspicious"
        ) {

            resultStatus.textContent =
                "SUSPICIOUS";

        }

        else {

            resultStatus.textContent =
                "SAFE URL";

        }

    }


    /* Confidence */

    if (confidenceValue) {

        confidenceValue.textContent =
            `${confidence}%`;

    }


    if (confidenceBar) {

        confidenceBar.style.width =
            `${confidence}%`;

    }


    /* Store normalized values */

    result._frontend = {

        verdict:
            verdict,

        score:
            score,

        confidence:
            confidence

    };


    console.log(
        "PhishGuard: Result displayed."
    );

}


/* ============================================================
   RISK GAUGE
   ============================================================ */

function updateRiskGauge(score) {

    if (!riskGauge) {

        return;

    }


    if (
        typeof riskGauge.getTotalLength ===
        "function"
    ) {

        try {

            const length =
                riskGauge.getTotalLength();


            riskGauge.style.strokeDasharray =
                length;


            const offset =
                length -
                (
                    length *
                    (
                        score / 100
                    )
                );


            riskGauge.style.strokeDashoffset =
                offset;

        } catch (error) {

            console.log(
                "Risk gauge SVG update skipped."
            );

        }

    }


    riskGauge.style.setProperty(
        "--risk-score",
        score
    );


    riskGauge.style.setProperty(
        "--risk-percent",
        `${score}%`
    );

}


/* ============================================================
   DISPLAY FEATURES
   ============================================================ */

function displayFeatures(features) {

    updateFeature(
        "featureHttps",
        features.uses_https,
        "featureHttpsStatus"
    );


    updateFeature(
        "featureIP",
        features.has_ip_address,
        "featureIPStatus"
    );


    updateFeature(
        "featureAt",
        features.has_at_symbol,
        "featureAtStatus"
    );


    setText(
        "featureShortener",
        "Not checked"
    );


    setText(
        "featureShortenerStatus",
        "—"
    );


    setText(
        "featureLength",
        features.url_length
    );


    setText(
        "featureSubdomains",
        features.subdomain_count
    );


    setText(
        "featureSpecial",
        features.special_char_count
    );


    setText(
        "featureKeywords",
        features.suspicious_keyword_count
    );

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
        document.getElementById(
            valueId
        );


    const statusElement =
        document.getElementById(
            statusId
        );


    if (!valueElement) {

        return;

    }


    if (
        typeof value === "boolean"
    ) {

        valueElement.textContent =
            value
                ? "Detected"
                : "Not Detected";


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

            }

            else {

                statusElement.textContent =
                    "Secure";

                statusElement.classList.add(
                    "secure"
                );

            }

        }

    }

    else {

        valueElement.textContent =
            value ?? "--";

    }

}


/* ============================================================
   TEXT HELPER
   ============================================================ */

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);


    if (!element) {

        return;

    }


    if (
        value === undefined ||
        value === null
    ) {

        element.textContent =
            "--";

    }

    else {

        element.textContent =
            value;

    }

}


/* ============================================================
   SECURITY REASONS
   ============================================================ */

function displayReasons(reasons) {

    if (!reasonList) {

        return;

    }


    reasonList.innerHTML =
        "";


    if (
        !Array.isArray(reasons) ||
        reasons.length === 0
    ) {

        const item =
            document.createElement(
                "span"
            );


        item.className =
            "reason-item";


        item.textContent =
            "No additional security factors were returned.";


        reasonList.appendChild(
            item
        );


        if (explanationTitle) {

            explanationTitle.textContent =
                "Analysis completed";

        }


        if (explanationText) {

            explanationText.textContent =
                "The backend completed the security analysis.";

        }


        return;

    }


    if (explanationTitle) {

        explanationTitle.textContent =
            "Security factors identified";

    }


    if (explanationText) {

        explanationText.textContent =
            "The following factors were returned by the security analysis.";

    }


    reasons.forEach(
        reason => {

            const item =
                document.createElement(
                    "span"
                );


            item.className =
                "reason-item";


            item.textContent =
                reason;


            reasonList.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   SECURITY REPORT
   ============================================================ */

function updateReport(result) {

    const frontend =
        result._frontend || {};


    const verdict =
        frontend.verdict ||
        getVerdict(
            result.classification
        );


    const score =
        frontend.score ??
        Number(
            result.risk_score || 0
        );


    let confidence =
        frontend.confidence ??
        Number(
            result.confidence || 0
        );


    if (
        confidence <= 1
    ) {

        confidence *= 100;

    }


    confidence =
        Math.round(
            confidence * 100
        ) / 100;


    setText(
        "reportUrl",
        result.url
    );


    setText(
        "reportTime",
        formatDateTime(
            new Date()
        )
    );


    setText(
        "reportVerdict",
        verdict
    );


    setText(
        "reportRisk",
        `${score.toFixed(2)} / 100`
    );


    setText(
        "reportConfidence",
        `${confidence}%`
    );


    setText(
        "reportStatus",
        "Analysis Complete"
    );


    setText(
        "reportSummary",
        createSummary(
            result,
            verdict,
            score
        )
    );

}


/* ============================================================
   CREATE SUMMARY
   ============================================================ */

function createSummary(
    result,
    verdict,
    score
) {

    if (
        verdict === "Phishing"
    ) {

        return (
            `The URL was classified as high risk with a ` +
            `risk score of ${score.toFixed(2)} out of 100. ` +
            `The assessment combines machine-learning evidence ` +
            `with DNS, SSL, and URL security checks.`
        );

    }


    if (
        verdict === "Suspicious"
    ) {

        return (
            `The URL was classified as suspicious with a ` +
            `risk score of ${score.toFixed(2)} out of 100. ` +
            `The assessment combines machine-learning evidence ` +
            `with DNS, SSL, and URL security checks.`
        );

    }


    return (
        `The URL received a low-risk assessment with a ` +
        `risk score of ${score.toFixed(2)} out of 100. ` +
        `The assessment combines machine-learning evidence ` +
        `with DNS, SSL, and URL security checks.`
    );

}


/* ============================================================
   GET VERDICT
   ============================================================ */

function getVerdict(
    classification
) {

    const value =
        String(
            classification || ""
        ).toLowerCase();


    if (
        value === "high_risk" ||
        value === "phishing" ||
        value === "malicious"
    ) {

        return "Phishing";

    }


    if (
        value === "suspicious"
    ) {

        return "Suspicious";

    }


    return "Safe";

}


/* ============================================================
   HISTORY
   ============================================================ */

function addToHistory(result) {

    const verdict =
        getVerdict(
            result.classification
        );


    const entry = {

        id:
            Date.now(),

        url:
            result.url || "--",

        time:
            formatDateTime(
                new Date()
            ),

        risk:
            Number(
                result.risk_score || 0
            ),

        verdict:
            verdict

    };


    scanHistory =
        scanHistory.filter(
            item =>
                !(
                    item.url === entry.url &&
                    item.time === entry.time
                )
        );


    scanHistory.unshift(
        entry
    );


    if (
        scanHistory.length > 50
    ) {

        scanHistory =
            scanHistory.slice(
                0,
                50
            );

    }


    saveHistory();

    renderHistory();

    updateClearButton();

}


/* ============================================================
   RENDER HISTORY
   ============================================================ */

function renderHistory() {

    if (!historyTableBody) {

        return;

    }


    historyTableBody.innerHTML =
        "";


    let filtered =
        scanHistory;


    if (
        currentFilter !== "all"
    ) {

        filtered =
            scanHistory.filter(
                item => {

                    const verdict =
                        String(
                            item.verdict || ""
                        ).toLowerCase();


                    if (
                        currentFilter === "safe"
                    ) {

                        return (
                            verdict === "safe" ||
                            verdict === "legitimate"
                        );

                    }


                    if (
                        currentFilter === "phishing"
                    ) {

                        return (
                            verdict === "phishing" ||
                            verdict === "suspicious"
                        );

                    }


                    return true;

                }
            );

    }


    if (
        filtered.length === 0
    ) {

        const row =
            document.createElement(
                "tr"
            );


        row.innerHTML = `
            <td colspan="5">
                <div class="empty-history">
                    <div class="empty-history-icon">◇</div>
                    <strong>No scans found</strong>
                    <span>
                        Analyze a URL to create your scan history.
                    </span>
                </div>
            </td>
        `;


        historyTableBody.appendChild(
            row
        );


        return;

    }


    filtered.forEach(
        item => {

            const row =
                document.createElement(
                    "tr"
                );


            const verdict =
                String(
                    item.verdict || "Unknown"
                );


            const lowerVerdict =
                verdict.toLowerCase();


            let badgeClass =
                "pending";


            if (
                lowerVerdict === "safe" ||
                lowerVerdict === "legitimate"
            ) {

                badgeClass =
                    "safe";

            }

            else if (
                lowerVerdict === "phishing" ||
                lowerVerdict === "suspicious"
            ) {

                badgeClass =
                    "phishing";

            }


            const risk =
                Number(
                    item.risk
                );


            const riskText =
                Number.isNaN(risk)
                    ? "--"
                    : risk.toFixed(2);


            row.innerHTML = `

                <td>
                    <div
                        class="history-url"
                        title="${escapeHTML(item.url)}"
                    >
                        ${escapeHTML(item.url)}
                    </div>
                </td>

                <td>
                    ${escapeHTML(item.time)}
                </td>

                <td>
                    ${riskText}/100
                </td>

                <td>
                    <span
                        class="history-badge ${badgeClass}"
                    >
                        ${escapeHTML(verdict)}
                    </span>
                </td>

                <td>
                    <span
                        class="history-badge ${badgeClass}"
                    >
                        Complete
                    </span>
                </td>

            `;


            historyTableBody.appendChild(
                row
            );

        }
    );

}


/* ============================================================
   LOCAL STORAGE
   ============================================================ */

function saveHistory() {

    try {

        localStorage.setItem(
            "phishguardHistory",
            JSON.stringify(
                scanHistory
            )
        );

    } catch (error) {

        console.error(
            "Could not save history:",
            error
        );

    }

}


/* ============================================================
   LOAD HISTORY
   ============================================================ */

function loadHistory() {

    try {

        const stored =
            localStorage.getItem(
                "phishguardHistory"
            );


        if (!stored) {

            scanHistory = [];

            return;

        }


        const parsed =
            JSON.parse(
                stored
            );


        if (
            Array.isArray(parsed)
        ) {

            scanHistory =
                parsed.map(
                    item => ({

                        id:
                            item.id ||
                            Date.now(),

                        url:
                            item.url ||
                            "--",

                        time:
                            item.time ||
                            "--",

                        risk:
                            item.risk ??
                            "--",

                        verdict:
                            item.verdict ||
                            "Unknown"

                    })
                );

        }

        else {

            scanHistory = [];

        }

    } catch (error) {

        console.error(
            "Could not load history:",
            error
        );


        scanHistory = [];

    }

}


/* ============================================================
   HISTORY CONTROLS
   ============================================================ */

function setupHistoryControls() {

    if (clearHistoryBtn) {

        clearHistoryBtn.addEventListener(
            "click",
            clearHistory
        );

    }


    filterButtons.forEach(
        button => {

            button.addEventListener(
                "click",
                () => {

                    filterButtons.forEach(
                        btn => {

                            btn.classList.remove(
                                "active"
                            );

                        }
                    );


                    button.classList.add(
                        "active"
                    );


                    currentFilter =
                        button.dataset.filter ||
                        "all";


                    renderHistory();

                }
            );

        }
    );

}


/* ============================================================
   CLEAR HISTORY
   ============================================================ */

function clearHistory() {

    if (
        scanHistory.length === 0
    ) {

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

    updateClearButton();

}


/* ============================================================
   CLEAR BUTTON STATE
   ============================================================ */

function updateClearButton() {

    if (!clearHistoryBtn) {

        return;

    }


    clearHistoryBtn.disabled =
        scanHistory.length === 0;

}


/* ============================================================
   SCAN AGAIN
   ============================================================ */

function setupScanAgainButton() {

    if (!scanAgainBtn) {

        return;

    }


    scanAgainBtn.addEventListener(
        "click",
        () => {

            const scanner =
                document.getElementById(
                    "scanner"
                );


            if (scanner) {

                scanner.scrollIntoView({
                    behavior: "smooth"
                });

            }


            setTimeout(
                () => {

                    if (urlInput) {

                        urlInput.focus();

                    }

                },
                500
            );

        }
    );

}


/* ============================================================
   PRINT REPORT
   ============================================================ */

function setupReportButton() {

    if (!printReportBtn) {

        return;

    }


    printReportBtn.addEventListener(
        "click",
        () => {

            window.print();

        }
    );

}


/* ============================================================
   SCANNER LOADING STATE
   ============================================================ */

function setLoadingState(
    loading
) {

    if (analyzeBtn) {

        analyzeBtn.disabled =
            loading;

    }


    if (analyzeText) {

        analyzeText.textContent =
            loading
                ? "Analyzing..."
                : "Analyze URL";

    }


    if (analyzeArrow) {

        analyzeArrow.style.opacity =
            loading
                ? "0.5"
                : "1";

    }


    if (scanLoading) {

        scanLoading.style.display =
            loading
                ? "block"
                : "none";

    }

}


/* ============================================================
   SCANNER MESSAGE
   ============================================================ */

function showScannerMessage(
    message
) {

    if (scannerMessage) {

        scannerMessage.style.display =
            "block";

    }


    if (scannerMessageText) {

        scannerMessageText.textContent =
            message;

    }

}


/* ============================================================
   HIDE SCANNER MESSAGE
   ============================================================ */

function hideScannerMessage() {

    if (scannerMessage) {

        scannerMessage.style.display =
            "none";

    }

}


/* ============================================================
   SCROLL TO RESULT
   ============================================================ */

function scrollToResult() {

    const possibleSections = [

        document.getElementById(
            "result"
        ),

        document.getElementById(
            "assessment"
        ),

        document.getElementById(
            "features"
        )

    ];


    const target =
        possibleSections.find(
            element => element
        );


    if (target) {

        setTimeout(
            () => {

                target.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });

            },
            300
        );

    }

}


/* ============================================================
   NAVIGATION
   ============================================================ */

function setupNavigation() {

    navItems.forEach(
        item => {

            item.addEventListener(
                "click",
                event => {

                    const href =
                        item.getAttribute(
                            "href"
                        );


                    if (
                        href &&
                        href.startsWith("#")
                    ) {

                        const target =
                            document.querySelector(
                                href
                            );


                        if (target) {

                            event.preventDefault();


                            target.scrollIntoView({
                                behavior: "smooth"
                            });

                        }

                    }


                    navItems.forEach(
                        nav => {

                            nav.classList.remove(
                                "active"
                            );

                        }
                    );


                    item.classList.add(
                        "active"
                    );

                }
            );

        }
    );


    updateNavigationOnScroll();

}


/* ============================================================
   NAVIGATION ON SCROLL
   ============================================================ */

function updateNavigationOnScroll() {

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


            sections.forEach(
                id => {

                    const section =
                        document.getElementById(
                            id
                        );


                    if (!section) {

                        return;

                    }


                    const top =
                        section.getBoundingClientRect()
                            .top;


                    if (
                        top <= 160 &&
                        top >= -500
                    ) {

                        current =
                            id;

                    }

                }
            );


            navItems.forEach(
                item => {

                    const href =
                        item.getAttribute(
                            "href"
                        );


                    item.classList.remove(
                        "active"
                    );


                    if (
                        href ===
                        `#${current}`
                    ) {

                        item.classList.add(
                            "active"
                        );

                    }

                }
            );

        }
    );

}


/* ============================================================
   HTML ESCAPE
   ============================================================ */

function escapeHTML(
    value
) {

    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );

}


/* ============================================================
   DATE / TIME FORMAT
   ============================================================ */

function formatDateTime(
    date
) {

    return new Intl.DateTimeFormat(
        "en-IN",
        {
            day: "2-digit",
            month: "long",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: true
        }
    ).format(date);

}


/* ============================================================
   BACKEND CONNECTION TEST
   ============================================================ */

async function checkBackendConnection() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/`
            );


        if (!response.ok) {

            return false;

        }


        const data =
            await response.json();


        console.log(
            "PhishGuard backend:",
            data.message
        );


        return true;

    } catch (error) {

        console.error(
            "PhishGuard backend unavailable:",
            error
        );


        return false;

    }

}


/* ============================================================
   BACKEND HISTORY
   ============================================================ */

async function loadBackendHistory() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/v1/history`
            );


        if (!response.ok) {

            return;

        }


        const backendHistory =
            await response.json();


        if (
            !Array.isArray(
                backendHistory
            )
        ) {

            return;

        }


        const converted =
            backendHistory.map(
                item => ({

                    id:
                        item.id,

                    url:
                        item.url,

                    time:
                        formatBackendDate(
                            item.scan_time
                        ),

                    risk:
                        item.risk_score,

                    verdict:
                        getVerdict(
                            item.classification
                        )

                })
            );


        scanHistory =
            converted.slice(
                0,
                50
            );


        saveHistory();

        renderHistory();

        updateClearButton();


        console.log(
            "PhishGuard: Backend history loaded.",
            scanHistory
        );


    } catch (error) {

        console.log(
            "Backend history unavailable. Using local history."
        );

    }

}


/* ============================================================
   FORMAT BACKEND TIMESTAMP
   ============================================================ */

function formatBackendDate(
    value
) {

    if (!value) {

        return "--";

    }


    /*
     * SQLite CURRENT_TIMESTAMP is UTC.
     * Add Z so JavaScript interprets it
     * correctly and converts it to local time.
     */

    let dateString =
        String(value);


    if (
        !dateString.endsWith("Z")
    ) {

        dateString =
            dateString.replace(
                " ",
                "T"
            ) + "Z";

    }


    const date =
        new Date(
            dateString
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return value;

    }


    return formatDateTime(
        date
    );

}


/* ============================================================
   DASHBOARD STATISTICS
   ============================================================ */

async function updateDashboardStats() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/v1/history`
            );


        if (!response.ok) {

            throw new Error(
                "Could not load scan history."
            );

        }


        const history =
            await response.json();


        if (
            !Array.isArray(history)
        ) {

            return;

        }


        const total =
            history.length;


        const threats =
            history.filter(
                item => {

                    const classification =
                        String(
                            item.classification || ""
                        ).toLowerCase();


                    return (
                        classification === "high_risk" ||
                        classification === "phishing" ||
                        classification === "malicious"
                    );

                }
            ).length;


        const safe =
            history.filter(
                item => {

                    const classification =
                        String(
                            item.classification || ""
                        ).toLowerCase();


                    return (
                        classification === "low_risk" ||
                        classification === "legitimate" ||
                        classification === "safe"
                    );

                }
            ).length;


        /*
         * IMPORTANT:
         *
         * These IDs must match the IDs in index.html.
         */

        const totalElement =
            document.getElementById(
                "totalScans"
            );


        const threatsElement =
            document.getElementById(
                "threatsDetected"
            );


        const safeElement =
            document.getElementById(
                "safeUrls"
            );


        if (totalElement) {

            totalElement.textContent =
                total;

        }


        if (threatsElement) {

            threatsElement.textContent =
                threats;

        }


        if (safeElement) {

            safeElement.textContent =
                safe;

        }


        console.log(
            "PhishGuard dashboard statistics:",
            {
                total,
                threats,
                safe
            }
        );

    } catch (error) {

        console.error(
            "Dashboard statistics error:",
            error
        );

    }

}


/* ============================================================
   BACKEND STARTUP
   ============================================================ */

window.addEventListener(
    "load",
    async () => {

        const connected =
            await checkBackendConnection();


        if (connected) {

            console.log(
                "PhishGuard: Backend connection successful."
            );


            await loadBackendHistory();


            /*
             * Refresh dashboard after
             * loading database history.
             */

            await updateDashboardStats();

        }

        else {

            console.warn(
                "PhishGuard: Backend is not currently available."
            );

        }

    }
);


/* ============================================================
   END OF PHISHGUARD FRONTEND
   ============================================================ */