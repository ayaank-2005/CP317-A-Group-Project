// Moderation queue: moderators approve, reject or merge pending reports.

(function () {
    const { el, renderRedacted, formatDate, api, errorState, loadingState } = window.ScamShieldUI;

    let active = false;

    function root() {
        return document.getElementById("v-moderate");
    }

    function header(...rest) {
        return [
            el("h1", { text: "Moderation queue" }),
            el("p", {
                class: "lede",
                text: "Approve reports to publish them, reject ones that aren't scams, or merge duplicates into an existing public report."
            }),
            ...rest
        ];
    }

    function preview(text) {
        const flat = String(text).replace(/\s+/g, " ");
        return flat.length > 70 ? `${flat.slice(0, 70)}…` : flat;
    }

    function queueCard(report, targets) {
        const error = el("div", { class: "err", role: "alert" });
        const buttons = [];

        const mergeSelect = el("select", { "aria-label": "Public report to merge into" },
            el("option", { value: "", text: targets.length ? "Merge into…" : "No public reports to merge into" }),
            targets.map(t => el("option", { value: t.id, text: `${t.category.name}: ${preview(t.content)}` }))
        );

        async function decide(decision) {
            error.textContent = "";
            if (decision === "merge" && !mergeSelect.value) {
                error.textContent = "Choose the public report to merge this into.";
                return;
            }

            buttons.forEach(b => { b.disabled = true; });
            try {
                await api(`/api/moderation/reports/${encodeURIComponent(report.id)}/decision`, {
                    method: "POST",
                    body: { decision, mergeInto: decision === "merge" ? mergeSelect.value : "" }
                });
                load();
            } catch (err) {
                error.textContent = err.message;
                buttons.forEach(b => { b.disabled = false; });
            }
        }

        buttons.push(
            el("button", { class: "primary", type: "button", text: "Approve", onclick: () => decide("approve") }),
            el("button", { type: "button", text: "Reject", onclick: () => decide("reject") }),
            el("button", { type: "button", text: "Merge", disabled: !targets.length, onclick: () => decide("merge") })
        );

        const people = report.submissionCount === 1 ? "1 report" : `${report.submissionCount} reports`;

        return el("article", { class: "report status-pending" },
            el("div", { class: "report-head" },
                el("span", { class: "tag cat", text: report.category.name }),
                el("span", { class: "sender report-id" },
                    el("span", { class: "sender-type", text: "Report ID" }),
                    el("code", { text: report.id })
                )
            ),
            el("p", { class: "report-body" }, renderRedacted(report.content)),
            el("p", { class: "meta", text: `${people} · Submitted ${formatDate(report.createdAt)}` }),
            el("div", { class: "decision" }, buttons[0], buttons[1], mergeSelect, buttons[2]),
            error
        );
    }

    async function load() {
        await window.ScamShieldAuth.ready;
        if (!active) return;

        const user = window.ScamShieldAuth.user;
        if (!user || user.role !== "moderator") {
            root().replaceChildren(...header(
                el("div", { class: "state" },
                    el("h2", { text: "Moderators only" }),
                    el("p", { text: "Sign in with a moderator account to review reports." })
                )
            ));
            return;
        }

        root().replaceChildren(...header(loadingState()));

        try {
            const data = await api("/api/moderation/queue");
            if (!active) return;

            if (!data.queue.length) {
                root().replaceChildren(...header(
                    el("div", { class: "state" },
                        el("h2", { text: "Nothing to review" }),
                        el("p", { text: "New reports will appear here." })
                    )
                ));
                return;
            }

            root().replaceChildren(...header(
                el("p", { class: "db-status", role: "status", text: `${data.queue.length} waiting for review` }),
                data.queue.map(report => queueCard(report, data.mergeTargets))
            ));
        } catch (err) {
            root().replaceChildren(...header(errorState("We couldn't load the queue", err.message, load)));
        }
    }

    document.addEventListener("viewchange", event => {
        active = event.detail.view === "moderate";
        if (active && root()) load();
    });

    document.addEventListener("authchange", () => {
        if (active) load();
    });
})();
