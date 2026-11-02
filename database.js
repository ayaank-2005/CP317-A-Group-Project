// Public Scam Database page.
// Still need to get API endpoints for the frontend to access the backend data for
//the database

(function () {
    const DB_CONFIG = {
        API_BASE: "",
        PAGE_SIZE: 10,
        TIMEOUT: 15000,
        MAX_QUERY_LENGTH: 200,
        PREVIEW_LENGTH: 220
    };

    const SENDER_LABELS = {
        phone: "Phone",
        domain: "Website",
        email: "Email"
    };

    const state = {
        rendered: false,
        q: "",
        category: "",
        page: 1,
        controller: null
    };

    const ui = {};

    // Creates DOM elements 
    function el(tag, props = {}, ...children) {
        const node = document.createElement(tag);

        Object.entries(props).forEach(([key, value]) => {
            if (value === undefined || value === null || value === false) return;

            if (key === "class") node.className = value;
            else if (key === "text") node.textContent = value;
            else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
            else node.setAttribute(key, value === true ? "" : value);
        });

        children.flat().forEach(child => {
            if (child === null || child === undefined || child === false) return;
            node.append(child.nodeType ? child : document.createTextNode(String(child)));
        });

        return node;
    }

    //formats the phone numbers
    function formatSender(sender) {
        if (sender.type === "phone") {
            const digits = sender.value.replace(/\D/g, "");

            if (digits.length === 11 && digits.startsWith("1")) {
                return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`;
            }
        }

        return sender.value;
    }

    function formatDate(iso) {
        const date = new Date(iso);

        if (Number.isNaN(date.getTime())) return "";

        return date.toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric"
        });
    }

    // Displays the hidden/redacted info with labelled tags instead
    function renderRedacted(text) {
        const parts = String(text).split(/(\[(?:EMAIL|PHONE|CARD|SIN|ADDRESS|POSTAL_CODE|NAME)\])/);

        return parts.map(part =>
            /^\[[A-Z_]+\]$/.test(part)
                ? el("span", { class: "mask", title: "Personal detail hidden to protect privacy", text: part })
                : part
        );
    }

    // 
    function buildShell(root) {
        ui.search = el("input", {
            id: "dbSearch",
            type: "search",
            placeholder: "e.g. 416-555-0142, canada-post-redelivery.com, gift cards",
            maxlength: DB_CONFIG.MAX_QUERY_LENGTH,
            autocomplete: "off",
            enterkeyhint: "search"
        });

        ui.category = el("select", { id: "dbCategory" },
            el("option", { value: "", text: "All types of scam" })
        );

        ui.searchBtn = el("button", { class: "primary", type: "submit", text: "Search" });
        ui.clearBtn = el("button", { type: "button", text: "Clear", onclick: resetSearch });

        const form = el("form", { id: "dbForm", role: "search", onsubmit: onSubmit },
            el("label", { class: "field", for: "dbSearch", text: "Phone number, website, email or keywords" }),
            ui.search,
            el("div", { class: "row" },
                el("div", { class: "selectwrap" },
                    el("label", { class: "sr-only", for: "dbCategory", text: "Type of scam" }),
                    ui.category
                ),
                ui.searchBtn,
                ui.clearBtn
            )
        );

        ui.status = el("p", { class: "db-status", role: "status", "aria-live": "polite" });
        ui.results = el("div", { id: "dbResults" });
        ui.pager = el("nav", { class: "pager hidden", "aria-label": "Results pages" });

        root.append(
            el("h1", { text: "Public Scam Database" }),
            el("p", {
                class: "lede",
                text: "Look up a phone number, website or email, or search by keywords, to see if other people have reported it as a scam."
            }),
            el("div", { class: "panel" }, form),
            ui.status,
            ui.results,
            ui.pager
        );
    }

    async function loadCategories() {
        try {
            const response = await fetch(`${DB_CONFIG.API_BASE}/api/categories`);

            if (!response.ok) throw new Error("categories failed");

            const categories = await response.json();

            categories.forEach(c => {
                ui.category.append(el("option", { value: c.code, text: c.name }));
            });

            ui.category.value = state.category;
        } catch {
        }
    }

    // Functions display the loading, search, error and empty states
    function showLoading() {
        ui.status.textContent = "Searching…";
        ui.results.replaceChildren(
            el("div", { class: "state skeleton", "aria-hidden": "true" },
                el("div", { class: "bar w40" }),
                el("div", { class: "bar w90" }),
                el("div", { class: "bar w70" })
            )
        );
        ui.pager.classList.add("hidden");
    }

    function showError(message) {
        ui.status.textContent = "";
        ui.pager.classList.add("hidden");

        ui.results.replaceChildren(
            el("div", { class: "state fail", role: "alert" },
                el("h2", { text: "We couldn't load the database" }),
                el("p", { text: message }),
                el("div", { class: "row" },
                    el("button", { type: "button", text: "Try again", onclick: runSearch })
                )
            )
        );
    }

    function showEmpty() {
        ui.pager.classList.add("hidden");
        ui.status.textContent = "No reports found.";

        const searched = state.q || state.category;

        ui.results.replaceChildren(
            el("div", { class: "state" },
                el("h2", { text: searched ? "No matching reports" : "No reports have been published yet" }),
                el("p", {
                    text: searched
                        ? "Nothing in the database matches that search. That doesn't mean it's safe, as new scams can take time to be reported and reviewed."
                        : "Approved reports will appear here."
                }),
                el("div", { class: "row" },
                    el("button", { type: "button", text: "Scan a message instead", onclick: () => { window.location.hash = "#home"; } }),
                    el("button", { type: "button", text: "Report a scam", onclick: () => { window.location.hash = "#report"; } })
                )
            )
        );
    }

    function reportCard(report) {
        const preview = report.content.length > DB_CONFIG.PREVIEW_LENGTH;

        const body = el("p", { class: `report-body${preview ? " clamped" : ""}` }, renderRedacted(report.content));

        const toggle = preview
            ? el("button", {
                type: "button",
                class: "linklike",
                "aria-expanded": "false",
                text: "Show full message",
                onclick: event => {
                    const open = body.classList.toggle("clamped") === false;
                    event.currentTarget.setAttribute("aria-expanded", String(open));
                    event.currentTarget.textContent = open ? "Show less" : "Show full message";
                }
            })
            : null;

        const people = report.reportCount === 1 ? "1 report" : `${report.reportCount.toLocaleString()} reports`;
        const language = report.language && report.language !== "en" ? report.language.toUpperCase() : "";

        return el("article", { class: "report" },
            el("div", { class: "report-head" },
                el("span", { class: "tag cat", text: report.category.name }),
                report.sender
                    ? el("span", { class: "sender" },
                        el("span", { class: "sender-type", text: SENDER_LABELS[report.sender.type] || report.sender.type }),
                        el("code", { text: formatSender(report.sender) })
                    )
                    : null
            ),
            body,
            toggle,
            el("p", { class: "meta" },
                people,
                " · Approved ", formatDate(report.approvedAt),
                language ? ` · ${language}` : ""
            )
        );
    }

    function showResults(data) {
        if (!data.results.length) {
            showEmpty();
            return;
        }

        const totalPages = Math.max(1, Math.ceil(data.total / data.pageSize));
        const noun = data.total === 1 ? "report" : "reports";

        ui.status.textContent = `${data.total.toLocaleString()} ${noun} found`;
        ui.results.replaceChildren(...data.results.map(reportCard));

        renderPager(data.page, totalPages);
    }

    function renderPager(page, totalPages) {
        if (totalPages <= 1) {
            ui.pager.classList.add("hidden");
            return;
        }

        ui.pager.classList.remove("hidden");

        ui.pager.replaceChildren(
            el("button", {
                type: "button",
                text: "← Previous",
                disabled: page <= 1,
                onclick: () => goToPage(page - 1)
            }),
            el("span", { class: "hint", text: `Page ${page} of ${totalPages}` }),
            el("button", {
                type: "button",
                text: "Next →",
                disabled: page >= totalPages,
                onclick: () => goToPage(page + 1)
            })
        );
    }

    // Function syncs the search filters and the page naviagation with the URL
    function syncUrl() {
        const params = new URLSearchParams();

        if (state.q) params.set("q", state.q);
        if (state.category) params.set("category", state.category);
        if (state.page > 1) params.set("page", String(state.page));

        const query = params.toString();

        // replaceState doesn't trigger a hashchange, thus not causing another search 
        history.replaceState(null, "", `#database${query ? `?${query}` : ""}`);
    }

    async function runSearch() {
        if (state.controller) state.controller.abort();

        const controller = new AbortController();
        state.controller = controller;

        const timer = setTimeout(() => controller.abort(), DB_CONFIG.TIMEOUT);

        const params = new URLSearchParams({
            page: String(state.page),
            pageSize: String(DB_CONFIG.PAGE_SIZE)
        });

        if (state.q) params.set("q", state.q);
        if (state.category) params.set("category", state.category);

        showLoading();

        try {
            const response = await fetch(`${DB_CONFIG.API_BASE}/api/reports?${params}`, {
                signal: controller.signal,
                headers: { Accept: "application/json" }
            });

            if (!response.ok) {
                let message = "The server had a problem. Please try again in a moment.";

                try {
                    const body = await response.json();
                    if (body && body.error) message = body.error;
                } catch { /* keep the default message */ }

                throw new Error(message);
            }

            showResults(await response.json());
        } catch (error) {

            if (state.controller !== controller) return;

            if (error.name === "AbortError") {
                showError("The search took too long. Please check your connection and try again.");
            } else if (error instanceof TypeError) {
                showError("We couldn't reach the server. Please check your connection and try again.");
            } else {
                showError(error.message);
            }
        } finally {
            clearTimeout(timer);
        }
    }

    function onSubmit(event) {
        event.preventDefault();

        state.q = ui.search.value.trim();
        state.category = ui.category.value;
        state.page = 1;

        syncUrl();
        runSearch();
    }

    function goToPage(page) {
        state.page = page;
        syncUrl();
        runSearch();
        ui.status.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function resetSearch() {
        ui.search.value = "";
        ui.category.value = "";

        state.q = "";
        state.category = "";
        state.page = 1;

        syncUrl();
        runSearch();
        ui.search.focus();
    }

    // Function runs when this page is displayed to user
    function onViewChange(event) {
        if (event.detail.view !== "database") {
            if (state.controller) state.controller.abort();
            return;
        }

        const root = document.getElementById("v-db");
        if (!root) return;

        if (!state.rendered) {
            buildShell(root);
            loadCategories();
            state.rendered = true;
        }

        const params = event.detail.params;

        state.q = (params.get("q") || "").trim().slice(0, DB_CONFIG.MAX_QUERY_LENGTH);
        state.category = params.get("category") || "";
        state.page = Math.max(1, parseInt(params.get("page"), 10) || 1);

        ui.search.value = state.q;
        ui.category.value = state.category;

        runSearch();
    }

    document.addEventListener("viewchange", onViewChange);
})();