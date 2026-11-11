"use strict";

/* ---------- Avisos y ventanas ---------- */
function toast(msg, tone) {
    const el = document.createElement("div");
    el.className = "rt-toast";
    if (tone) el.dataset.tone = tone;
    el.textContent = msg;
    const box = $("[data-toasts]");
    box.append(el);
    while (box.children.length > 3) box.firstChild.remove();
    setTimeout(() => el.remove(), 3200);
}

let modalReturn = null;

function modal(title, body, okText, onOk, {danger} = {}) {
    modalReturn = document.activeElement;
    const host = $("[data-modal-host]");
    host.innerHTML = `<div class="rt-modal" data-modal><form class="rt-dialog" role="dialog" aria-modal="true" aria-labelledby="md-t" novalidate><h2 id="md-t">${title}</h2>${body}<div class="rt-err" data-md-err style="color:var(--anatomy-red);font-size:13px;min-height:18px;margin-top:8px"></div><div class="rt-dialog-act"><button class="rt-btn" type="button" data-md-cancel>${t("Cancelar")}</button><button class="rt-btn" ${danger ? "data-danger" : "data-primary"} type="submit">${okText}</button></div></form></div>`;
    const f = $("form", host);
    const close = () => {
        host.innerHTML = "";
        modalReturn && modalReturn.focus && modalReturn.focus();
    };
    f.addEventListener("submit", (e) => {
        e.preventDefault();
        const err = onOk(f);
        if (err) {
            $("[data-md-err]", f).textContent = err;
            return;
        }
        close();
    });
    $("[data-md-cancel]", f).onclick = close;
    $("[data-modal]", host).addEventListener("mousedown", (e) => {
        if (e.target.matches("[data-modal]")) close();
    });
    f.addEventListener("keydown", (e) => {
        if (e.key === "Escape") close();
    });
    (f.querySelector("input,select") || f.querySelector("[type=submit]")).focus();
}

const confirmBox = (title, text, okText, fn) => modal(title, `<p style="margin:0;font-size:14px">${text}</p>`, okText, () => {
    fn();
}, {danger: true});
const mfield = (label, name, val = "", o = {}) => `<div class="rt-field"><label for="m-${name}">${label}</label><div class="rt-ctl">${o.options ? `<select class="rt-in" id="m-${name}" name="${name}">${o.options.map(([v, t]) => `<option value="${esc(v)}"${String(v) === String(val) ? " selected" : ""}>${esc(t)}</option>`).join("")}</select>` : `<input class="rt-in" id="m-${name}" name="${name}" value="${esc(val)}"${o.ph ? ` placeholder="${esc(o.ph)}"` : ""}${o.type ? ` type="${o.type}"` : ""}>`}</div>${o.hint ? `<div class="rt-hint">${o.hint}</div>` : ""}</div>`;
const fv = (f, n) => (f.elements[n].value || "").trim();

function download(name, text, type = "application/json") {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], {type}));
    a.download = name;
    document.body.append(a);
    a.click();
    setTimeout(() => {
        URL.revokeObjectURL(a.href);
        a.remove();
    }, 500);
}

const ACT = {
    theme() {
        const b = document.body;
        b.dataset.theme = b.dataset.theme === "dark" ? "light" : "dark";
    },
    logout() {
        const out = () => {
            api("POST", "/api/logout").catch(() => {
            });
            showLogin();
            draft = clone(S);
            syncSavebar();
        };
        dirty() ? confirmBox(t("¿Salir sin guardar?"), t("Se perderán los cambios de esta sección."), t("Salir"), out) : out();
    },
    save, discard,
    "diag-run"() {
        runServerDiag();
    },
    "log-dl"() {
        downloadEvents();
    },
};

/* ---------- Menú de cada equipo conectado ---------- */
let menuBtn = null;

function closeMenu(focusBack) {
    const m = $("[data-cmenu-pop]");
    if (m) m.remove();
    if (menuBtn) {
        menuBtn.setAttribute("aria-expanded", "false");
        if (focusBack && document.contains(menuBtn)) menuBtn.focus();
    }
    menuBtn = null;
}

function placeMenu() {
    const m = $("[data-cmenu-pop]");
    if (!m || !menuBtn) return;
    const r = menuBtn.getBoundingClientRect();
    if (r.bottom < 0 || r.top > window.innerHeight || !document.contains(menuBtn)) return closeMenu();
    const mw = m.offsetWidth, mh = m.offsetHeight;
    m.style.left = Math.max(8, Math.min(window.innerWidth - mw - 8, r.right - mw)) + "px";
    m.style.top = (r.bottom + 4 + mh > window.innerHeight - 8 ? Math.max(8, r.top - 4 - mh) : r.bottom + 4) + "px";
}

function openMenu(btn) {
    if (menuBtn === btn) return closeMenu(true);
    closeMenu();
    const id = btn.closest("[data-cid]").dataset.cid;
    const c = memberOf(id);
    if (!c) return;
    const m = document.createElement("div");
    m.className = "rt-menu";
    m.setAttribute("role", "menu");
    m.tabIndex = -1;
    m.dataset.cmenuPop = "";
    m.dataset.mid = id;
    m.setAttribute("aria-label", t("Acciones para {name}", {name: c.username}));
    m.innerHTML = memberMenu(c);
    document.body.append(m);
    menuBtn = btn;
    placeMenu();
    btn.setAttribute("aria-expanded", "true");
    // With every item disabled the menu itself keeps the focus for Escape.
    (m.querySelector("[role=menuitem]:not(:disabled)") || m).focus();
    m.addEventListener("keydown", (e) => {
        const items = [...m.querySelectorAll("[role=menuitem]:not(:disabled)")],
            i = items.indexOf(document.activeElement);
        if (!items.length && e.key !== "Escape" && e.key !== "Tab") return;
        if (e.key === "ArrowDown") {
            e.preventDefault();
            items[(i + 1) % items.length].focus();
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            items[(i - 1 + items.length) % items.length].focus();
        } else if (e.key === "Home") {
            e.preventDefault();
            items[0].focus();
        } else if (e.key === "End") {
            e.preventDefault();
            items[items.length - 1].focus();
        } else if (e.key === "Escape") {
            e.preventDefault();
            closeMenu(true);
        } else if (e.key === "Tab") closeMenu();
    });
}

window.addEventListener("resize", placeMenu);
window.addEventListener("scroll", placeMenu, true);

const clientAction = (kind, id) => memberAction(kind, id);

const refreshRows = () => {
    closeMenu();
    const tb = $("[data-client-rows]");
    if (tb) tb.innerHTML = clientRows();
};
