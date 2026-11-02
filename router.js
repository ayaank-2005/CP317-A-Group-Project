// Shows one page at a time (#home, #database, #report, #sign-in).

(function () {
    const VIEWS = {
        "home": "v-scan",
        "database": "v-db",
        "report": "v-report",
        "sign-in": "v-signin"
    };

    const DEFAULT_VIEW = "home";

    function parseHash() {
        const raw = window.location.hash.replace(/^#/, "");
        const [name, query = ""] = raw.split("?");
        const view = Object.prototype.hasOwnProperty.call(VIEWS, name) ? name : DEFAULT_VIEW;

        return {
            view,
            params: new URLSearchParams(query)
        };
    }

    function showView(view) {
        Object.entries(VIEWS).forEach(([name, id]) => {
            const section = document.getElementById(id);
            if (section) section.classList.toggle("hidden", name !== view);
        });

        document.querySelectorAll("nav a[data-view]").forEach(link => {
            if (link.dataset.view === view) {
                link.setAttribute("aria-current", "page");
            } else {
                link.removeAttribute("aria-current");
            }
        });
    }

    function route() {
        const { view, params } = parseHash();

        showView(view);

        document.dispatchEvent(new CustomEvent("viewchange", {
            detail: { view, params }
        }));
    }

    window.addEventListener("hashchange", route);
    document.addEventListener("DOMContentLoaded", route);
})();