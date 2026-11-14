// My Reports page: the signed-in user's reports and their review status.

(function () {
    const { el, renderRedacted, formatDate, api, errorState, loadingState } = window.ScamShieldUI;

    const STATUS = {
        Pending: { tag: "unknown", text: "Waiting for a moderator to review it." },
        Approved: { tag: "clean", text: "A moderator approved this report. It is now public." },
        Merged: { tag: "clean", text: "A moderator combined this with an existing public report about the same scam." },
        Rejected: { tag: "malicious", text: "A moderator reviewed this report and did not publish it." }
    };

    let active = false;

    function root() {
        return document.getElementById("v-myreports");
    }

    function header(...rest) {
        return [
            el("h1", { text: "My Reports" }),
            el("p", {
                class: "lede",
                text: "Track the scams you've reported. Approved and merged reports are public in the Scam Database."
            }),
            ...rest
        ];
    }

    function reportCard(report) {
        const status = STATUS[report.status] || STATUS.Pending;
        const decided = report.decidedAt ? ` · ${report.status} ${formatDate(report.decidedAt)}` : "";

        return el("article", { class: `report status-${report.status.toLowerCase()}`, id: `report-${report.id}` },
            el("div", { class: "report-head" },
                el("span", { class: `tag ${status.tag}`, text: report.status }),
                el("span", { class: "tag cat", text: report.category.name }),
                el("span", { class: "sender report-id" },
                    el("span", { class: "sender-type", text: "Report ID" }),
                    el("code", { text: report.id })
                )
            ),
            el("p", { class: "report-body clamped" }, renderRedacted(report.content)),
            el("p", { class: "hint flush", text: status.text }),
            el("p", { class: "meta", text: `Submitted ${formatDate(report.submittedAt)}${decided}` }),
            report.publicReportId
                ? el("a", {
                    class: "public-link",
                    href: `#database?report=${encodeURIComponent(report.publicReportId)}`,
                    text: report.status === "Merged"
                        ? "View the public report it was merged into →"
                        : "View public report →"
                })
                : null
        );
    }

    function showSignedOut() {
        root().replaceChildren(...header(
            el("div", { class: "state" },
                el("h2", { text: "Sign in to see your reports" }),
                el("p", { text: "Your reports and their review status are linked to your account." }),
                el("div", { class: "row" },
                    el("button", {
                        class: "primary",
                        type: "button",
                        text: "Sign in",
                        onclick: () => { window.location.hash = "#sign-in?next=my-reports"; }
                    })
                )
            )
        ));
    }

    function showEmpty() {
        root().replaceChildren(...header(
            el("div", { class: "state" },
                el("h2", { text: "You haven't reported any scams yet" }),
                el("p", { text: "When you report a scam, it will appear here with its review status." }),
                el("div", { class: "row" },
                    el("button", {
                        class: "primary",
                        type: "button",
                        text: "Report a scam",
                        onclick: () => { window.location.hash = "#report"; }
                    })
                )
            )
        ));
    }

    async function load() {
        await window.ScamShieldAuth.ready;
        if (!active) return;

        if (!window.ScamShieldAuth.user) {
            showSignedOut();
            return;
        }

        root().replaceChildren(...header(loadingState()));

        try {
            const data = await api("/api/my-reports");
            if (!active) return;

            if (!data.reports.length) {
                showEmpty();
                return;
            }

            const noun = data.reports.length === 1 ? "report" : "reports";
            root().replaceChildren(...header(
                el("p", { class: "db-status", role: "status", text: `${data.reports.length} ${noun}` }),
                el("div", { id: "myReports" }, data.reports.map(reportCard))
            ));
        } catch (err) {
            if (err.status === 401) showSignedOut();
            else root().replaceChildren(...header(errorState("We couldn't load your reports", err.message, load)));
        }
    }

    document.addEventListener("viewchange", event => {
        active = event.detail.view === "my-reports";
        if (active && root()) load();
    });

    document.addEventListener("authchange", () => {
        if (active) load();
    });
})();
