// Report a Scam page.

(function () {
    const { el, api } = window.ScamShieldUI;

    const MAX_LENGTH = 4000;

    const state = { rendered: false };
    const ui = {};

    async function loadCategories() {
        try {
            const categories = await api("/api/categories");
            categories.forEach(c => {
                ui.category.append(el("option", { value: c.code, text: c.name }));
            });
        } catch { /* the submit error explains if categories are missing */ }
    }

    function showForm() {
        ui.content.value = "";
        ui.category.value = "";
        ui.senderType.value = "";
        ui.senderValue.value = "";
        ui.error.textContent = "";
        ui.root.replaceChildren(ui.heading, ui.lede, ui.form);
    }

    function showSubmitted(data) {
        const masked = data.redactionCount === 1
            ? "1 personal detail was masked."
            : `${data.redactionCount} personal details were masked.`;

        ui.root.replaceChildren(
            el("h1", { text: "Thanks for your report" }),
            el("div", { class: "state" },
                el("h2", { text: "Your report is waiting for review" }),
                el("p", {}, "Report ID ", el("code", { text: data.id }), `. ${masked}`),
                el("p", {
                    text: data.tracked
                        ? "A moderator will review it. You can follow its status on your My Reports page."
                        : "A moderator will review it. Sign in before reporting next time to track your reports."
                }),
                el("div", { class: "row" },
                    data.tracked
                        ? el("button", {
                            class: "primary",
                            type: "button",
                            text: "View My Reports",
                            onclick: () => { window.location.hash = "#my-reports"; }
                        })
                        : null,
                    el("button", { type: "button", text: "Report another scam", onclick: showForm })
                )
            )
        );
    }

    async function onSubmit(event) {
        event.preventDefault();
        ui.error.textContent = "";

        const content = ui.content.value.trim();
        if (!ui.category.value) {
            ui.error.textContent = "Please choose what type of scam this is.";
            return;
        }
        if (!content) {
            ui.error.textContent = "Please paste the scam message you received.";
            return;
        }

        const senderValue = ui.senderValue.value.trim();
        const senderType = ui.senderType.value || (senderValue ? guessSenderType(senderValue) : "");
        if (senderValue && !senderType) {
            ui.error.textContent = "Please choose the sender type.";
            return;
        }

        ui.submit.disabled = true;
        try {
            const data = await api("/api/reports", {
                method: "POST",
                body: {
                    category: ui.category.value,
                    content,
                    sender: senderValue ? { type: senderType, value: senderValue } : null
                }
            });
            showSubmitted(data);
        } catch (err) {
            ui.error.textContent = err.message;
        } finally {
            ui.submit.disabled = false;
        }
    }

    // Guesses the sender type when the user fills in the sender but not its type
    function guessSenderType(value) {
        if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(value)) return "email";
        if (/^[+\d\s().-]+$/.test(value)) return "phone";
        if (/^(https?:\/\/)?[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(value)) return "domain";
        return "";
    }

    function buildShell(root) {
        ui.root = root;
        ui.heading = el("h1", { text: "Report a Scam" });
        ui.lede = el("p", {
            class: "lede",
            text: "Help protect others by reporting suspicious messages, phone numbers, and websites."
        });

        ui.category = el("select", { id: "reportCategory" },
            el("option", { value: "", text: "Choose a category" })
        );
        ui.senderType = el("select", { id: "reportSenderType" },
            el("option", { value: "", text: "No sender information" }),
            el("option", { value: "phone", text: "Phone number" }),
            el("option", { value: "domain", text: "Website" }),
            el("option", { value: "email", text: "Email address" })
        );
        ui.senderValue = el("input", {
            id: "reportSender",
            type: "text",
            maxlength: 254,
            autocomplete: "off",
            placeholder: "Phone number, website, or email"
        });
        ui.content = el("textarea", {
            id: "reportContent",
            maxlength: MAX_LENGTH,
            placeholder: "Describe the suspicious message or interaction..."
        });
        ui.submit = el("button", { class: "primary", type: "submit", text: "Submit report" });
        ui.error = el("div", { class: "err", role: "alert" });

        ui.form = el("form", { class: "panel account-form report-form", onsubmit: onSubmit },
            el("label", { class: "field", for: "reportCategory", text: "Scam category" }),
            ui.category,
            el("label", { class: "field", for: "reportSenderType", text: "Sender type (optional)" }),
            ui.senderType,
            el("label", { class: "field", for: "reportSender", text: "Sender information (optional)" }),
            ui.senderValue,
            el("label", { class: "field", for: "reportContent", text: "Describe the scam" }),
            ui.content,
            el("p", {
                class: "hint note",
                text: "Personal information such as phone numbers and email addresses in your description will be masked before the report is stored."
            }),
            el("div", { class: "row" }, ui.submit),
            ui.error
        );

        showForm();
    }

    function onViewChange(event) {
        if (event.detail.view !== "report") return;

        const root = document.getElementById("v-report");
        if (!root || state.rendered) return;

        buildShell(root);
        loadCategories();
        state.rendered = true;
    }

    document.addEventListener("viewchange", onViewChange);
})();
