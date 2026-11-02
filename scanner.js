

const CONFIG = {
    ENGINE_URL: "/api/scan",
    TIMEOUT: 20000,
    DB_ROUTE: "#database",
    MIN_TEXT_LENGTH: 10,
    MAX_INPUT_LENGTH: 10000
};

const elements = {
    input: document.querySelector("#input"),
    scanButton: document.querySelector("#scanBtn"),
    clearButton: document.querySelector("#clearBtn"),
    result: document.querySelector("#result"),
    error: document.querySelector("#err")
};

// Identify the type of submission, whether it is only phone number, URL or normal text 
function classifyInput(value) {
    const input = value.trim();

    if (
        /^(https?:\/\/|www\.)/i.test(input) ||
        /^[a-z0-9-]+(\.[a-z0-9-]+)+(?::\d+)?(?:\/|$)/i.test(input)
    ) {
        return "url";
    }

    if (/^[+\d\s().-]+$/.test(input)) {
        return "phone";
    }

    return "text";
}

// Validates submitted content
function validateInput(value) {
    const input = value.trim();

    if (!input) {
        return {
            valid: false,
            message: "Please enter a message, email, phone number, or URL before scanning."
        };
    }

    if (input.length > CONFIG.MAX_INPUT_LENGTH) {
        return {
            valid: false,
            message: `Your submission is too long. Please keep it under ${CONFIG.MAX_INPUT_LENGTH.toLocaleString()} characters.`
        };
    }

    const type = classifyInput(input);

    if (type === "url") {
        try {
            const url = new URL(
                /^www\./i.test(input) ? `https://${input}` : input
            );

            if (
                !["http:", "https:"].includes(url.protocol) ||
                !url.hostname.includes(".") ||
                url.hostname.startsWith(".") ||
                url.hostname.endsWith(".")
            ) {
                throw new Error("Invalid URL");
            }

            return {
                valid: true,
                type: "url"
            };
        } catch {
            return {
                valid: false,
                message: "Please enter a valid web link, such as https://example.com."
            };
        }
    }

    if (type === "phone") {
        const digits = input.replace(/\D/g, "");

        if (digits.length !== 10) {
            return {
                valid: false,
                message: "Please enter a valid 10-digit phone number."
            };
        }

        return {
            valid: true,
            type: "phone"
        };
    }

    if (input.length < CONFIG.MIN_TEXT_LENGTH) {
        return {
            valid: false,
            message: `Your message is too short. Please enter at least ${CONFIG.MIN_TEXT_LENGTH} characters.`
        };
    }

    return {
        valid: true,
        type: "text"
    };
}

// Send valid user submissions to the backend to be scored with the Risk Engine
// needs to be updated once risk engine is developed, as current version is temp
async function scanWithEngine(value, type) {
    if (!CONFIG.ENGINE_URL) {
        return {
            status: "unavailable",
            message: "The scanning backend has not been connected yet."
        };
    }

    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, CONFIG.TIMEOUT);

    try {
        const response = await fetch(CONFIG.ENGINE_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                input: value,
                type: type
            }),
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error("Scanning request failed.");
        }

        return await response.json();
    } finally {
        clearTimeout(timeout);
    }
}

// Designed saftey mechanism so that if user submits potientially executable html code in submission, the browser app 
// won't execute
function escapeHTML(value) {

    // converts characters into normal raw text 

    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[character]);
}

// Displays the scanning results, risk engine still in devlopement, thus this is temporary
//needs further adjustment, when risk engine is devloped
function displayResults(data) {
    if (!elements.result) return;

    elements.result.hidden = false;

    if (data.status === "unavailable") {
        elements.result.innerHTML = `
            <div class="state">
                <h2>Backend not connected</h2>
                <p>${escapeHTML(data.message)}</p>
            </div>
        `;
        return;
    }

    if (data.status === "error") {
        elements.result.innerHTML = `
            <div class="state fail">
                <h2>Scan unsuccessful</h2>
                <p>${escapeHTML(data.message)}</p>
            </div>
        `;
        return;
    }

    const verdict = data.verdict || data.status || "Unknown";
    const explanation = data.explanation || data.message || "No additional details available.";
    const flags = Array.isArray(data.flags) ? data.flags : [];

    elements.result.innerHTML = `
        <div class="state">
            <h2>Scan Results</h2>
            <p><strong>Verdict:</strong> ${escapeHTML(verdict)}</p>
            <p>${escapeHTML(explanation)}</p>
            ${
                flags.length
                    ? `<ul>${flags.map(flag => `<li>${escapeHTML(flag)}</li>`).join("")}</ul>`
                    : "<p>No specific warning signs were returned.</p>"
            }
        </div>
    `;
}

// Display error message on screen
function showError(message) {
    if (!elements.error) return;

    elements.error.innerHTML = `
        <strong>Error:</strong> ${escapeHTML(message)}
    `;

    elements.error.style.display = "block";
}

// Removes error message displayed on screen
function clearError() {
    if (!elements.error) return;

    elements.error.textContent = "";
    elements.error.style.display = "none";
}

// Handles scan submission
async function scanMessage() {
    if (!elements.input || !elements.scanButton) return;

    const value = elements.input.value.trim();

    clearError();

    const validation = validateInput(value);

    if (!validation.valid) {
        showError(validation.message);
        return;
    }

    // If submission type is phone number, it is checked through the public database
    if (validation.type === "phone") {
        window.location.hash = CONFIG.DB_ROUTE;
        return;
    }

    // Clears the previous results
    if (elements.result) {
        elements.result.innerHTML = "";
        elements.result.hidden = true;
    }

    elements.scanButton.disabled = true;
    elements.scanButton.textContent = "Scanning...";

    try {
        const results = await scanWithEngine(
            value,
            validation.type
        );

        displayResults(results);
    } catch (error) {
        if (error.name === "AbortError") {
            showError(
                "The scan took longer than 20 seconds and timed out. Please check your internet connection and try again."
            );
        } else {
            showError(
                "We couldn't complete your scan. Please check your internet connection and try again."
            );
        }
    } finally {
        elements.scanButton.disabled = false;
        elements.scanButton.textContent = "Scan now";
    }
}

// clears input, errors and results
function clearResults() {
    if (elements.input) {
        elements.input.value = "";
    }

    if (elements.result) {
        elements.result.innerHTML = "";
        elements.result.hidden = true;
    }

    clearError();
}


// Handle navigation
function handleNavigation() {
    const route = window.location.hash;

    if (route === CONFIG.DB_ROUTE || route === "#report") {
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }
}

// Connects the all buttons to their own functions
function attachEventListeners() {
    elements.scanButton?.addEventListener("click", scanMessage);
    elements.clearButton?.addEventListener("click", clearResults);

    document.getElementById("databaseBtn")?.addEventListener("click", () => {
        window.location.hash = "database";
    });

    document.getElementById("reportBtn")?.addEventListener("click", () => {
        window.location.hash = "report";
    });

    window.addEventListener("hashchange", handleNavigation);
}

// Initialize the application
function initializeApp() {
    if (elements.result) {
        elements.result.hidden = true;
    }

    clearError();
    attachEventListeners();
    handleNavigation();
}

initializeApp();


