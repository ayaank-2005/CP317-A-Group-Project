// Shared helpers for the account, report, My Reports and moderation pages.

window.ScamShieldUI = (function () {
    const MASK_PATTERN = /(\[(?:EMAIL|PHONE|CARD|SIN|ADDRESS|POSTAL_CODE|NAME)\])/;

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

    // Displays the hidden/redacted info with labelled tags instead
    function renderRedacted(text) {
        // split() with a capture group puts the matched placeholders at odd indexes
        return String(text).split(MASK_PATTERN).map((part, i) =>
            i % 2 === 1
                ? el("span", { class: "mask", title: "Personal detail hidden to protect privacy", text: part })
                : part
        );
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

    // Fetches JSON from the API; throws an Error carrying the server's message.
    async function api(path, options = {}) {
        const init = {
            method: options.method || "GET",
            credentials: "same-origin",
            headers: { Accept: "application/json" }
        };

        if (options.body !== undefined) {
            init.headers["Content-Type"] = "application/json";
            init.body = JSON.stringify(options.body);
        }

        let response;
        try {
            response = await fetch(path, init);
        } catch {
            throw new Error("We couldn't reach the server. Please check your connection and try again.");
        }

        if (response.status === 204) return null;

        let data = null;
        try {
            data = await response.json();
        } catch { /* keep null */ }

        if (!response.ok) {
            const error = new Error((data && data.error) || "The server had a problem. Please try again in a moment.");
            error.status = response.status;
            throw error;
        }

        return data;
    }

    function errorState(title, message, retry) {
        return el("div", { class: "state fail", role: "alert" },
            el("h2", { text: title }),
            el("p", { text: message }),
            retry
                ? el("div", { class: "row" },
                    el("button", { type: "button", text: "Try again", onclick: retry }))
                : null
        );
    }

    function loadingState() {
        return el("div", { class: "state skeleton", "aria-hidden": "true" },
            el("div", { class: "bar w40" }),
            el("div", { class: "bar w90" }),
            el("div", { class: "bar w70" })
        );
    }

    return { el, renderRedacted, formatDate, api, errorState, loadingState };
})();
