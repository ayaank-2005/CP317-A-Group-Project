
(function () {
    const reportView = document.getElementById("v-report");

    if (!reportView) return;

    let initialized = false;

    // Escapes HTML characters to prevent injected markup.
    function escapeHTML(value) {
        return String(value).replace(/[&<>"']/g, character => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        })[character]);
    }

    // Builds the report form using the categories returned by the API.
    function renderForm(categories) {
        reportView.innerHTML = `
            <section class="report-container">
                <h1>Report a Scam</h1>
                <p class="report-description">
                    Help protect others by reporting suspicious messages,
                    phone numbers, and websites.
                </p>

                <form id="reportForm">
                    <label for="reportCategory">Scam category</label>
                    <select id="reportCategory" required>
                        <option value="">Choose a category</option>
                        ${categories.map(category => `
                            <option value="${escapeHTML(category.code)}">
                                ${escapeHTML(category.name)}
                            </option>
                        `).join("")}
                    </select>

                    <label for="senderType">Sender type (optional)</label>
                    <select id="senderType">
                        <option value="">No sender information</option>
                        <option value="phone">Phone number</option>
                        <option value="domain">Website domain</option>
                        <option value="email">Email address</option>
                    </select>

                    <label for="senderValue">Sender information (optional)</label>
                    <input
                        id="senderValue"
                        type="text"
                        maxlength="254"
                        placeholder="Phone number, website, or email"
                    >

                    <label for="reportContent">Describe the scam</label>
                    <textarea
                        id="reportContent"
                        maxlength="10000"
                        minlength="10"
                        required
                        placeholder="Describe the suspicious message or interaction..."
                    ></textarea>

                    <p class="report-privacy">
                        Personal information such as phone numbers and email
                        addresses in your description will be masked before
                        the report is stored.
                    </p>

                    <div id="reportMessage" role="status" aria-live="polite"></div>

                    <button type="submit" id="submitReportBtn">
                        Submit Report
                    </button>
                </form>
            </section>
        `;

        document.getElementById("reportForm")
            .addEventListener("submit", submitReport);

        document.getElementById("senderType")
            .addEventListener("change", updateSenderPlaceholder);
    }

    // Updates the sender input placeholder based on the selected sender type.
    function updateSenderPlaceholder() {
        const type = document.getElementById("senderType").value;
        const input = document.getElementById("senderValue");

        const placeholders = {
            phone: "Example: 416-555-0123",
            domain: "Example: suspicious-site.com",
            email: "Example: sender@example.com"
        };

        input.placeholder = placeholders[type] || "Phone number, website, or email";
    }

    // Retrieves available scam categories from the database API.
    async function loadCategories() {
        try {
            const response = await fetch("/api/categories");

            if (!response.ok) {
                throw new Error("Could not load categories.");
            }

            const categories = await response.json();
            renderForm(categories);
        } catch (error) {
            reportView.innerHTML = `
                <section class="report-container">
                    <h1>Report a Scam</h1>
                    <p class="report-error">
                        We couldn't load the report form. Please refresh and try again.
                    </p>
                </section>
            `;
        }
    }

    // Validates and sends the report information to the submission API.
    async function submitReport(event) {
        event.preventDefault();

        const button = document.getElementById("submitReportBtn");
        const message = document.getElementById("reportMessage");

        const senderType = document.getElementById("senderType").value;
        const sender = document.getElementById("senderValue").value.trim();

        if ((senderType && !sender) || (!senderType && sender)) {
            message.className = "report-error";
            message.textContent = "Please provide both the sender type and sender value, or leave both empty.";
            return;
        }

        const payload = {
            category: document.getElementById("reportCategory").value,
            senderType: senderType,
            sender: sender,
            content: document.getElementById("reportContent").value.trim(),
            language: navigator.language.startsWith("fr") ? "fr" : "en"
        };

        button.disabled = true;
        button.textContent = "Submitting...";
        message.textContent = "";

        try {
            const response = await fetch("/api/reports", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || "Your report could not be submitted.");
            }

            message.className = "report-success";

            let confirmation = `Your report was submitted successfully. ${result.submissionCount} similar submission(s) have been received.`;

            if (result.redactionCount > 0) {
                confirmation += ` ${result.redactionCount} personal detail(s) were masked.`;
            }

            if (result.status === "pending_review") {
                confirmation += " This report has reached the review threshold.";
            }

            message.textContent = confirmation;
            document.getElementById("reportForm").reset();
            updateSenderPlaceholder();

        } catch (error) {
            message.className = "report-error";
            message.textContent = error.message;
        } finally {
            button.disabled = false;
            button.textContent = "Submit Report";
        }
    }

    // Loads the report form when the report page becomes active.
    document.addEventListener("viewchange", event => {
        if (event.detail.view === "report" && !initialized) {
            initialized = true;
            loadCategories();
        }
    });

    // Loads the form directly when the page opens on the report route.
    if (window.location.hash.replace(/^#/, "").split("?")[0] === "report") {
        initialized = true;
        loadCategories();
    }
})();

