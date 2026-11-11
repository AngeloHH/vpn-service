"use strict";

/* ---------- Delegación de eventos ---------- */
document.addEventListener("click", (e) => {
    if (menuBtn && !e.target.closest("[data-cmenu-pop],[data-cmenu]")) closeMenu();
    const mc = e.target.closest("[data-mc]");
    if (mc) {
        if (mc.disabled) return;
        const id = mc.closest("[data-cmenu-pop]").dataset.mid;
        closeMenu(true);
        return clientAction(mc.dataset.mc, id);
    }
    const mb = e.target.closest("[data-cmenu]");
    if (mb) return openMenu(mb);
    const el = e.target.closest("[data-act],[data-go],[data-ciface],[data-cpage],[data-loglevel]");
    if (!el || el.disabled) return;
    const d = el.dataset;
    if (d.act && ACT[d.act]) return ACT[d.act]();
    if (d.go) return go(d.go);
    if (d.ciface) {
        ui.clientIface = d.ciface;
        const select = $("[data-cnet]");
        if (select) {
            select.value = "";
            select.removeAttribute("data-active");
        }
        $$("[data-ciface]").forEach((b) => b.setAttribute("aria-pressed", b === el));
        return filterRows();
    }
    if (d.cpage) return turnPage(+d.cpage);
    if (d.loglevel) {
        ui.logLevel = d.loglevel;
        return render();
    }
});

function readInput(el) {
    const k = el.dataset.k;
    if (!k) return;
    let v = el.type === "checkbox" ? el.checked : el.value;
    if (el.hasAttribute("data-num")) v = v === "" ? "" : Number(v);
    setP(draft, k, v);
    if (errors[k]) {
        delete errors[k];
        el.removeAttribute("aria-invalid");
        const er = el.closest(".rt-field")?.querySelector(".rt-err");
        er && er.remove();
    }
    if (el.hasAttribute("data-rr")) render(); else syncSavebar();
}

document.addEventListener("input", (e) => {
    if (e.target.matches("[data-client-filter]")) {
        ui.clientFilter = e.target.value;
        return filterRows();
    }
    if (e.target.matches("[data-k]") && e.target.type !== "checkbox" && e.target.tagName !== "SELECT") readInput(e.target);
});
document.addEventListener("change", (e) => {
    if (e.target.matches("[data-k]") && (e.target.type === "checkbox" || e.target.tagName === "SELECT")) readInput(e.target);
    if (e.target.matches("[data-cnet]")) {
        const v = e.target.value;
        ui.clientIface = v ? "net:" + v : "all";
        e.target.toggleAttribute("data-active", !!v);
        $$("[data-ciface]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.ciface === ui.clientIface));
        return filterRows();
    }
    if (e.target.matches("[data-csize]")) {
        ui.clientSize = +e.target.value;
        return filterRows();
    }
});

/* Las vistas previas en iframe aislado bloquean el envío nativo de formularios:
   se intercepta el clic y la tecla Enter y se emite un evento submit propio. */
function fakeSubmit(f) {
    f.dispatchEvent(new Event("submit", {cancelable: true, bubbles: true}));
}

document.addEventListener("click", (e) => {
    const b = e.target.closest('button[type="submit"]');
    if (!b || b.disabled || !b.form) return;
    e.preventDefault();
    fakeSubmit(b.form);
}, true);
document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.isComposing) return;
    const el = e.target;
    if (!el.form || el.tagName !== "INPUT" || ["checkbox", "radio", "file"].includes(el.type)) return;
    e.preventDefault();
    fakeSubmit(el.form);
}, true);

function openApp() {
    $("[data-login-err]").textContent = "";
    $("[data-view=login]").hidden = true;
    $("[data-view=app]").hidden = false;
    const h = location.hash.slice(1);
    page = knownPage(h) ? h : "estado";
    draft = clone(S);
    errors = {};
    syncHeader();
    render();
    startStatus();
    refreshMe();
}

document.addEventListener("submit", (e) => {
    if (e.target.matches("[data-login]")) {
        e.preventDefault();
        const f = e.target, err = $("[data-login-err]"), b = $('button[type="submit"]', f);
        if (!f.p.value) {
            err.textContent = t("Ingrese la contraseña.");
            return;
        }
        b.disabled = true;
        err.textContent = "";
        api("POST", "/api/login", {password: f.p.value}).then(async (r) => {
            if (r.status === 204) {
                f.p.value = "";
                return openApp();
            }
            const data = await r.json().catch(() => ({}));
            const wait = data.retry_after ? " " + t("Espere {n} s antes de reintentar.", {n: data.retry_after}) : "";
            if (r.status === 429) err.textContent = t("Demasiados intentos.") + wait;
            else if (r.status === 401) err.textContent = t("Contraseña incorrecta.") + wait;
            else err.textContent = t("No se pudo iniciar sesión.");
            f.p.select();
        }).catch(() => {
            err.textContent = t("No se pudo conectar con el servidor.");
        }).finally(() => {
            b.disabled = false;
        });
    }
});
document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "s" && !$("[data-view=app]").hidden) {
        e.preventDefault();
        if (dirty()) save();
    }
});
window.addEventListener("hashchange", () => {
    const h = location.hash.slice(1);
    if (knownPage(h) && !$("[data-view=app]").hidden) go(h);
});
try {
    window.addEventListener("beforeunload", (e) => {
        if (dirty()) {
            e.preventDefault();
            e.returnValue = "";
        }
    });
} catch {
}

/* ---------- Arranque ---------- */
try {
    if (matchMedia("(prefers-color-scheme: dark)").matches) document.body.dataset.theme = "dark";
} catch {
}
translateStatic();
$("#rt-p").focus();
// The VPN session already names the account; a valid cookie skips the login.
api("GET", "/api/me").then((r) => (r.ok ? r.json() : null)).then((me) => {
    if (!me) throw new Error();
    ME = me;
    $("#rt-u").value = me.username || "";
    $("[data-router-corner]").textContent = me.router || "";
    if (me.logged_in) openApp();
}).catch(() => {
    // The panel only works through the VPN tunnel.
    $("[data-login-err]").textContent = t("No se pudo conectar con el servidor.");
});
