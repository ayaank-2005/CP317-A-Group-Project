// Sign-in page and the signed-in user shared with the other pages.

window.ScamShieldAuth = (function () {
    const { el, api } = window.ScamShieldUI;

    const auth = {
        user: null,
        ready: null
    };

    function updateNav() {
        const signin = document.querySelector('nav a[data-view="sign-in"]');
        if (signin) signin.textContent = auth.user ? "Account" : "Sign in";

        document.querySelectorAll("nav [data-role]").forEach(link => {
            link.classList.toggle("hidden", !auth.user || auth.user.role !== link.dataset.role);
        });
    }

    function setUser(user) {
        auth.user = user;
        updateNav();
        document.dispatchEvent(new CustomEvent("authchange", { detail: { user } }));
    }

    async function load() {
        try {
            const data = await api("/api/auth/me");
            setUser(data.user);
        } catch {
            setUser(null);
        }
    }

    function nextView(params) {
        const next = params.get("next") || "";
        return /^[a-z-]+$/.test(next) ? next : "my-reports";
    }

    function renderSignedIn(root) {
        root.replaceChildren(
            el("h1", { text: "Your account" }),
            el("p", { class: "lede" }, "Signed in as ", el("strong", { text: auth.user.email }), "."),
            el("div", { class: "panel" },
                el("div", { class: "row" },
                    el("button", {
                        class: "primary",
                        type: "button",
                        text: "My Reports",
                        onclick: () => { window.location.hash = "#my-reports"; }
                    }),
                    auth.user.role === "moderator"
                        ? el("button", {
                            type: "button",
                            text: "Moderation queue",
                            onclick: () => { window.location.hash = "#moderate"; }
                        })
                        : null,
                    el("button", { type: "button", text: "Sign out", onclick: signOut })
                )
            )
        );
    }

    function renderForm(root, params) {
        const email = el("input", { id: "signinEmail", type: "email", autocomplete: "username", required: true });
        const password = el("input", { id: "signinPassword", type: "password", autocomplete: "current-password", required: true });
        const error = el("div", { class: "err", role: "alert" });
        const submit = el("button", { class: "primary", type: "submit", text: "Sign in" });

        async function onSubmit(event) {
            event.preventDefault();
            error.textContent = "";
            submit.disabled = true;

            try {
                const data = await api("/api/auth/login", {
                    method: "POST",
                    body: { email: email.value.trim(), password: password.value }
                });
                password.value = "";
                setUser(data.user);
                window.location.hash = `#${nextView(params)}`;
            } catch (err) {
                error.textContent = err.message;
            } finally {
                submit.disabled = false;
            }
        }

        root.replaceChildren(
            el("h1", { text: "Sign in" }),
            el("p", { class: "lede", text: "Sign in to track the scams you've reported." }),
            el("form", { class: "panel account-form", onsubmit: onSubmit },
                el("label", { class: "field", for: "signinEmail", text: "Email" }),
                email,
                el("label", { class: "field", for: "signinPassword", text: "Password" }),
                password,
                el("div", { class: "row" }, submit),
                error
            )
        );
    }

    async function signOut() {
        try {
            await api("/api/auth/logout", { method: "POST" });
        } finally {
            setUser(null);
            window.location.hash = "#home";
        }
    }

    async function onViewChange(event) {
        if (event.detail.view !== "sign-in") return;

        const root = document.getElementById("v-signin");
        if (!root) return;

        await auth.ready;

        if (auth.user) renderSignedIn(root);
        else renderForm(root, event.detail.params);
    }

    auth.ready = load();
    document.addEventListener("viewchange", onViewChange);

    return auth;
})();
