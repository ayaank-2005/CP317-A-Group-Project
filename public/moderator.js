// Review page for moderators (#moderation): approve, reject or merge reports, and see the
// record of earlier decisions. There are no user accounts yet, so the page asks for the secret
// moderator access key (set on the server as MOD_ACCESS_KEY) and the moderator's name. Both are
// kept in memory only: reloading the page asks again, and "Lock" forgets them straight away.
// Report text shown here is already redacted by the server.

(function () {
    const MOD_CONFIG = {
        API_BASE: "",
        PAGE_SIZE: 10,
        HISTORY_LIMIT: 25,
        TIMEOUT: 15000,
        PREVIEW_LENGTH: 320
    };

    const SENDER_LABELS = { phone: "Phone", domain: "Website", email: "Email" };
    const DECISION_LABELS = { approved: "Approved", rejected: "Rejected", merged: "Merged" };

    const state = {
        rendered: false,
        tab: "queue",     // "queue" | "history"
        page: 1,
        busyId: null,     // report currently being decided
        key: "",          // access key, memory only
        name: ""          // moderator name, sent with each decision
    };

    const ui = {};

    // Creates DOM elements (text is always set as text, never as HTML)
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

    async function api(path, options = {}) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), MOD_CONFIG.TIMEOUT);

        try {
            const response = await fetch(`${MOD_CONFIG.API_BASE}${path}`, {
                credentials: "same-origin",
                signal: controller.signal,
                ...options,
                headers: {
                    Accept: "application/json",
                    ...(state.key ? { "X-Mod-Key": state.key } : {}),
                    ...(options.body ? { "Content-Type": "application/json" } : {})
                }
            });

            let body = null;
            try { body = await response.json(); } catch { /* no JSON in the reply */ }

            return { ok: response.ok, status: response.status, body };
        } catch (error) {
            const message = error.name === "AbortError"
                ? "That took too long. Please check your connection and try again."
                : "We couldn't reach the server. Please check your connection and try again.";

            return { ok: false, status: 0, body: { error: message } };
        } finally {
            clearTimeout(timer);
        }
    }

    function errorText(result) {
        return (result.body && result.body.error) || "Something went wrong. Please try again.";
    }

    function formatDate(iso) {
        const date = new Date(iso);
        if (Number.isNaN(date.getTime())) return "";

        return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    }

    function formatSender(sender) {
        if (sender.type === "phone") {
            const digits = sender.value.replace(/\D/g, "");

            if (digits.length === 11 && digits.startsWith("1")) {
                return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`;
            }
        }

        return sender.value;
    }

    // Shows the hidden/redacted details as labelled tags
    function renderRedacted(text) {
        const parts = String(text).split(/(\[(?:EMAIL|PHONE|CARD|SIN|ADDRESS|POSTAL_CODE|NAME)\])/);

        return parts.map(part =>
            /^\[[A-Z_]+\]$/.test(part)
                ? el("span", { class: "mask", title: "Personal detail hidden to protect privacy", text: part })
                : part
        );
    }

    function senderBadge(sender) {
        return sender
            ? el("span", { class: "sender" },
                el("span", { class: "sender-type", text: SENDER_LABELS[sender.type] || sender.type }),
                el("code", { text: formatSender(sender) })
            )
            : el("span", { class: "hint", text: "No sender recorded" });
    }

    // ---- page frame ----

    function buildShell(root) {
        ui.tabQueue = el("button", { type: "button", class: "mod-tab", role: "tab", text: "Review queue", onclick: () => switchTab("queue") });
        ui.tabHistory = el("button", { type: "button", class: "mod-tab", role: "tab", text: "Decision record", onclick: () => switchTab("history") });
        ui.status = el("p", { class: "db-status", role: "status", "aria-live": "polite" });
        ui.notice = el("div", { class: "mod-notice hidden", role: "status" });
        ui.body = el("div", { id: "modBody" });
        ui.pager = el("nav", { class: "pager hidden", "aria-label": "Queue pages" });
        ui.lock = el("button", { type: "button", class: "mod-lock", text: "Lock", title: "Forget the access key on this page", onclick: lock });
        ui.who = el("span", { class: "hint" });
        ui.gate = el("div", { class: "hidden" });
        ui.app = el("div", { class: "hidden" },
            el("div", { class: "mod-bar" }, ui.who, ui.lock),
            el("div", { class: "mod-tabs", role: "tablist" }, ui.tabQueue, ui.tabHistory),
            ui.notice,
            ui.status,
            ui.body,
            ui.pager
        );

        root.append(
            el("h1", { text: "Review reports" }),
            el("p", {
                class: "lede",
                text: "Approve reports that are real scams, reject ones that are not, and merge duplicates. Only approved reports appear in the public database."
            }),
            ui.gate,
            ui.app
        );
    }

    // ---- the access gate ----

    function showGate(message) {
        ui.app.classList.add("hidden");
        ui.gate.classList.remove("hidden");

        const error = el("div", { class: "err mod-err", role: "alert" });
        if (message) {
            error.textContent = message;
            error.classList.remove("hidden");
        } else {
            error.classList.add("hidden");
        }

        const key = el("input", { id: "modKey", type: "password", autocomplete: "off", required: true, maxlength: 200, spellcheck: "false" });
        const name = el("input", { id: "modName", type: "text", autocomplete: "name", required: true, maxlength: 60, value: state.name });

        ui.gate.replaceChildren(
            el("form", {
                class: "panel mod-gate",
                novalidate: true,
                onsubmit: event => {
                    event.preventDefault();

                    if (!key.value.trim() || !name.value.trim()) {
                        error.textContent = "Please enter the access key and your name.";
                        error.classList.remove("hidden");
                        return;
                    }

                    state.key = key.value.trim();
                    state.name = name.value.trim().replace(/\s+/g, " ");
                    key.value = "";
                    openApp();
                }
            },
                el("p", { class: "flush", text: "This page is for moderators. Enter the access key you were given, and your name so your decisions can be recorded." }),
                el("label", { class: "field mod-gap", for: "modKey", text: "Access key" }),
                key,
                el("label", { class: "field mod-gap", for: "modName", text: "Your name" }),
                name,
                error,
                el("div", { class: "row" }, el("button", { class: "primary", type: "submit", text: "Open the review queue" }))
            )
        );

        key.focus();
    }

    function openApp() {
        ui.gate.classList.add("hidden");
        ui.app.classList.remove("hidden");
        ui.who.textContent = `Reviewing as ${state.name}`;

        state.tab = "queue";
        state.page = 1;
        notice("");
        load();
    }

    // forget the key and go back to the gate
    function lock() {
        state.key = "";
        ui.body.replaceChildren();
        ui.status.textContent = "";
        showGate("");
    }

    function setTabState() {
        ui.tabQueue.setAttribute("aria-selected", String(state.tab === "queue"));
        ui.tabHistory.setAttribute("aria-selected", String(state.tab === "history"));
    }

    function switchTab(tab) {
        if (state.tab === tab) return;
        state.tab = tab;
        state.page = 1;
        notice("");
        load();
    }

    function notice(message, kind) {
        ui.notice.textContent = message;
        ui.notice.className = `mod-notice${kind ? ` ${kind}` : ""}${message ? "" : " hidden"}`;
    }

    function showMessage(title, text) {
        ui.pager.classList.add("hidden");
        ui.status.textContent = "";
        ui.body.replaceChildren(
            el("div", { class: "state" },
                el("h2", { text: title }),
                el("p", { text })
            )
        );
    }

    // ---- loading ----

    async function load() {
        setTabState();
        ui.status.textContent = "Loading…";
        ui.pager.classList.add("hidden");

        if (state.tab === "history") {
            await loadHistory();
        } else {
            await loadQueue();
        }
    }

    // Handles the replies every moderator route can give. Returns true if the page was replaced.
    function handleAccess(result) {
        if (result.status === 401) {
            state.key = "";
            showGate(errorText(result));
            return true;
        }

        if (result.status === 503) {
            showMessage("Review isn't available", errorText(result));
            return true;
        }

        if (!result.ok) {
            showMessage("We couldn't load this page", errorText(result));
            return true;
        }

        return false;
    }

    async function loadQueue() {
        const params = new URLSearchParams({ page: String(state.page), pageSize: String(MOD_CONFIG.PAGE_SIZE) });
        const result = await api(`/api/mod-queue?${params}`);

        if (handleAccess(result)) return;

        const data = result.body;
        const totalPages = Math.max(1, Math.ceil(data.total / data.pageSize));

        // the last page can empty out after decisions: step back one
        if (!data.results.length && data.total > 0 && state.page > 1) {
            state.page = totalPages;
            return loadQueue();
        }

        if (!data.results.length) {
            ui.status.textContent = "";
            ui.body.replaceChildren(
                el("div", { class: "state" },
                    el("h2", { text: "The queue is empty" }),
                    el("p", { text: "No reports are waiting for review. New ones appear here once enough similar reports have been submitted." })
                )
            );
            return;
        }

        ui.status.textContent = `${data.total.toLocaleString()} ${data.total === 1 ? "report" : "reports"} waiting, oldest first`;
        ui.body.replaceChildren(...data.results.map(reviewCard));
        renderPager(data.page, totalPages);
    }

    async function loadHistory() {
        const result = await api(`/api/mod-history?limit=${MOD_CONFIG.HISTORY_LIMIT}`);

        if (handleAccess(result)) return;

        const rows = result.body.results;

        if (!rows.length) {
            ui.status.textContent = "";
            ui.body.replaceChildren(el("div", { class: "state" }, el("h2", { text: "No decisions yet" }), el("p", { text: "Every approval, rejection and merge is recorded here." })));
            return;
        }

        ui.status.textContent = `Most recent ${rows.length} decisions`;
        ui.body.replaceChildren(
            el("ul", { class: "mod-history" }, rows.map(row =>
                el("li", { class: `mod-log ${row.decision}` },
                    el("div", { class: "mod-log-head" },
                        el("span", { class: `tag ${row.decision === "approved" ? "clean" : row.decision === "rejected" ? "malicious" : "suspicious"}`, text: DECISION_LABELS[row.decision] || row.decision }),
                        el("span", { class: "hint", text: `${row.moderator} · ${formatDate(row.decidedAt)}` })
                    ),
                    el("div", { class: "report-head" },
                        el("span", { class: "tag cat", text: row.category }),
                        senderBadge(row.sender)
                    ),
                    row.mergedIntoId
                        ? el("p", { class: "meta", text: "Merged into another report (ID " + row.mergedIntoId.slice(0, 8) + ")" })
                        : null,
                    row.reason ? el("p", { class: "mod-reason", text: `“${row.reason}”` }) : null
                )
            ))
        );
    }

    function renderPager(page, totalPages) {
        if (totalPages <= 1) {
            ui.pager.classList.add("hidden");
            return;
        }

        ui.pager.classList.remove("hidden");
        ui.pager.replaceChildren(
            el("button", { type: "button", text: "← Previous", disabled: page <= 1, onclick: () => { state.page = page - 1; load(); } }),
            el("span", { class: "hint", text: `Page ${page} of ${totalPages}` }),
            el("button", { type: "button", text: "Next →", disabled: page >= totalPages, onclick: () => { state.page = page + 1; load(); } })
        );
    }

    // ---- one report in the queue ----

    function reviewCard(report) {
        const long = report.content.length > MOD_CONFIG.PREVIEW_LENGTH;
        const body = el("p", { class: `report-body${long ? " clamped" : ""}` }, renderRedacted(report.content));

        const toggle = long
            ? el("button", {
                type: "button", class: "linklike", "aria-expanded": "false", text: "Show full message",
                onclick: event => {
                    const open = body.classList.toggle("clamped") === false;
                    event.currentTarget.setAttribute("aria-expanded", String(open));
                    event.currentTarget.textContent = open ? "Show less" : "Show full message";
                }
            })
            : null;

        const panel = el("div", { class: "mod-panel hidden" });
        const message = el("div", { class: "err mod-err hidden", role: "alert" });

        const card = el("article", { class: "report mod-card", "data-id": report.id },
            el("div", { class: "report-head" },
                el("span", { class: "tag cat", text: report.category.name }),
                senderBadge(report.sender)
            ),
            body,
            toggle,
            el("p", { class: "meta" },
                `${report.submissionCount.toLocaleString()} similar reports · received ${formatDate(report.createdAt)}`,
                report.language && report.language !== "en" ? ` · ${report.language.toUpperCase()}` : ""
            ),
            el("div", { class: "row mod-actions" },
                actionButton("Approve", "primary", () => openApprove(card, report, panel, message)),
                actionButton("Reject", "", () => openReject(card, report, panel, message)),
                actionButton("Merge into…", "", () => openMerge(card, report, panel, message))
            ),
            panel,
            message
        );

        return card;
    }

    function actionButton(text, kind, onclick) {
        return el("button", { type: "button", class: kind, text, onclick });
    }

    function setCardBusy(card, busy) {
        state.busyId = busy ? card.dataset.id : null;
        card.querySelectorAll("button").forEach(button => { button.disabled = busy; });
    }

    // Sends one decision. On success the card leaves the queue; on failure the message explains why.
    async function decide(card, message, payload, doneText) {
        if (state.busyId) return;

        message.classList.add("hidden");
        setCardBusy(card, true);

        const result = await api("/api/mod-decision", { method: "POST", body: JSON.stringify({ ...payload, moderator: state.name }) });

        setCardBusy(card, false);

        if (result.status === 401 || result.status === 503) {
            handleAccess(result);
            return;
        }

        if (!result.ok) {
            message.textContent = errorText(result);
            message.classList.remove("hidden");

            // someone else already dealt with it: reload so the queue is up to date
            if (result.status === 409) setTimeout(load, 1800);
            return;
        }

        notice(doneText, "ok");
        await load();
    }

    function closePanel(panel) {
        panel.classList.add("hidden");
        panel.replaceChildren();
    }

    function openApprove(card, report, panel, message) {
        message.classList.add("hidden");
        panel.classList.remove("hidden");

        const note = el("input", { type: "text", maxlength: 500, placeholder: "Optional note, e.g. “matches 5 independent reports”", "aria-label": "Optional note" });

        panel.replaceChildren(
            el("p", { class: "hint", text: "This report will become visible in the public database." }),
            note,
            el("div", { class: "row" },
                actionButton("Confirm approval", "primary", () => decide(card, message, { reportId: report.id, decision: "approve", reason: note.value }, "Report approved and published.")),
                actionButton("Cancel", "", () => closePanel(panel))
            )
        );
        note.focus();
    }

    function openReject(card, report, panel, message) {
        message.classList.add("hidden");
        panel.classList.remove("hidden");

        const reason = el("textarea", { rows: 2, maxlength: 500, placeholder: "Why is this being rejected? (required)", "aria-label": "Reason for rejecting" });

        panel.replaceChildren(
            el("p", { class: "hint", text: "The reason is saved in the decision record." }),
            reason,
            el("div", { class: "row" },
                actionButton("Confirm rejection", "primary", () => {
                    if (reason.value.trim().length < 3) {
                        message.textContent = "Please give a short reason for rejecting this report.";
                        message.classList.remove("hidden");
                        reason.focus();
                        return;
                    }

                    decide(card, message, { reportId: report.id, decision: "reject", reason: reason.value }, "Report rejected.");
                }),
                actionButton("Cancel", "", () => closePanel(panel))
            )
        );
        reason.focus();
    }

    async function openMerge(card, report, panel, message) {
        message.classList.add("hidden");
        panel.classList.remove("hidden");
        panel.replaceChildren(el("p", { class: "hint", role: "status", text: "Looking for similar reports…" }));

        const result = await api(`/api/mod-candidates?id=${encodeURIComponent(report.id)}`);

        if (!result.ok) {
            closePanel(panel);
            message.textContent = errorText(result);
            message.classList.remove("hidden");
            return;
        }

        const candidates = result.body.results;

        if (!candidates.length) {
            panel.replaceChildren(
                el("p", { class: "hint", text: "There are no other reports in this category to merge into." }),
                el("div", { class: "row" }, actionButton("Close", "", () => closePanel(panel)))
            );
            return;
        }

        let chosen = null;
        const confirm = actionButton("Confirm merge", "primary", () => {
            if (!chosen) {
                message.textContent = "Choose the report to merge this into.";
                message.classList.remove("hidden");
                return;
            }

            decide(card, message, { reportId: report.id, decision: "merge", mergeIntoId: chosen, reason: reasonBox.value }, "Reports merged.");
        });
        const reasonBox = el("input", { type: "text", maxlength: 500, placeholder: "Optional note", "aria-label": "Optional note" });

        const name = `merge-${report.id}`;

        panel.replaceChildren(
            el("p", { class: "hint", text: "Pick the report this is a duplicate of. Its similar-report count goes up by this report's count." }),
            el("div", { class: "mod-candidates", role: "radiogroup", "aria-label": "Merge target" },
                candidates.map((c, index) => {
                    const id = `${name}-${index}`;

                    return el("label", { class: "mod-candidate", for: id },
                        el("input", { type: "radio", name, id, value: c.id, onchange: () => { chosen = c.id; message.classList.add("hidden"); } }),
                        el("span", {},
                            el("span", { class: "mod-candidate-head" },
                                senderBadge(c.sender),
                                el("span", { class: `tag ${c.status === "approved" ? "clean" : "unknown"}`, text: c.status === "approved" ? "Published" : "In review" }),
                                el("span", { class: "hint", text: `${c.submissionCount} similar` })
                            ),
                            el("span", { class: "mod-candidate-text" }, renderRedacted(c.content.length > 180 ? `${c.content.slice(0, 180)}…` : c.content))
                        )
                    );
                })
            ),
            reasonBox,
            el("div", { class: "row" }, confirm, actionButton("Cancel", "", () => closePanel(panel)))
        );
    }

    // ---- page events ----

    // If index.html has no <main id="v-mod"> yet, this page creates its own container
    function ensureRoot() {
        let root = document.getElementById("v-mod");

        if (!root) {
            root = el("main", { id: "v-mod", class: "hidden" });
            (document.querySelector(".wrap") || document.body).append(root);
        }

        return root;
    }

    ensureRoot();

    function onViewChange(event) {
        if (event.detail.view !== "moderation") return;

        const root = ensureRoot();

        if (!state.rendered) {
            buildShell(root);
            state.rendered = true;
        }

        if (state.key) openApp();
        else showGate("");
    }

    document.addEventListener("viewchange", onViewChange);

    // leaving the page forgets the key, so a shared computer is not left unlocked
    document.addEventListener("viewchange", event => {
        if (event.detail.view !== "moderation" && state.key) {
            state.key = "";
            if (state.rendered) lock();
        }
    });
})();
