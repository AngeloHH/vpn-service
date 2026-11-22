"use strict";

/* ---------- Equipos conectados reales (/api/members) ---------- */
// MEMBERS holds the page of connected members the server answered.
let MEMBERS = null, membersAsked = 0, membersBusy = false;
const PAGE_SIZES = [25, 50, 75, 100];

// Packet loss decides the bars: the tunnel has no radio signal to show.
const lossBars = (loss) => loss < 1 ? 4 : loss < 5 ? 3 : loss < 15 ? 2 : 1;
const networkLabel = (n) => n.name || t("Red {n}", {n: n.number});
const networkName = (id) => {
    const network = (NETWORKS || []).find((n) => n.id === id);
    return network ? networkLabel(network) : id;
};
const onlineTag = (on) => on ? `<span class="rt-tag" data-tone="green">${t("en línea")}</span>` : `<span class="rt-tag">${t("sin conexión")}</span>`;
const memberOf = (id) => MEMBERS && MEMBERS.rows.find((m) => m.id === id);

function membersQuery() {
    const query = new URLSearchParams({page: ui.clientPage, size: ui.clientSize});
    const q = ui.clientFilter.trim();
    if (q) query.set("q", q);
    if (/^net:/.test(ui.clientIface)) query.set("network", ui.clientIface.slice(4));
    if (ui.clientIface === "off") query.set("filter", "blocked");
    return "/api/members?" + query;
}

async function loadMembers() {
    // Only the newest answer is painted: filters may change mid-request.
    const asked = ++membersAsked;
    membersBusy = true;
    try {
        const response = await api("GET", membersQuery());
        if (response.status === 401) return showLogin();
        if (!response.ok || asked !== membersAsked) return;
        MEMBERS = await response.json();
        // A page past the end (after a kick or a filter) falls back to the last one.
        const pages = Math.max(1, Math.ceil(MEMBERS.total / MEMBERS.size));
        if (MEMBERS.page > pages) {
            ui.clientPage = pages;
            return loadMembers();
        }
        if (page === "clientes" && !menuBtn) refreshRows();
    } catch (e) {
        // A lost tunnel is shown by the status dot; the next poll retries.
    } finally {
        if (asked === membersAsked) membersBusy = false;
    }
}

function memberRows() {
    if (!MEMBERS) return `<tr><td colspan="6" class="rt-empty">${t("Cargando equipos…")}</td></tr>`;
    const muted = 'style="color:var(--anatomy-muted)"';
    return MEMBERS.rows.length ? MEMBERS.rows.map((m) => {
        const nets = m.networks.map(networkName).join(", ");
        const loss = m.online ? t("{n} % pérdida", {n: m.loss.toFixed(1)}) : "-";
        return `<tr${m.online ? "" : " data-off"} data-cid="${esc(m.id)}">
      <td class="rt-name">${esc(m.username || "-")}<br><small ${muted}>${esc(m.email || "-")}</small></td>
      <td>${esc(m.ip || "-")}<br><small ${muted}>${esc(m.id)}</small></td>
      <td data-conn title="${esc(nets)}">${sigBars(m.online ? lossBars(m.loss) : 0)}${esc(nets)} <small ${muted}>· ${loss}</small></td>
      <td><span data-rate>${m.online ? `${fmtRate(m.down)} / ${fmtRate(m.up)}` : "-"}</span><br><small ${muted}>${t("{n} en total", {n: fmtBytes(m.total / 1048576)})}</small></td>
      <td>${m.blocked ? `<span class="rt-tag" data-tone="red">${t("bloqueado")}</span>` : fmtAgo(Date.now() - m.connected_for * 1000)}</td>
      <td class="rt-act"><button class="rt-menu-btn" type="button" data-cmenu aria-haspopup="menu" aria-expanded="false" aria-label="${esc(t("Acciones para {name}", {name: m.username}))}"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 4.5h10M3 8h10M3 11.5h10"/></svg></button></td></tr>`;
    }).join("") : `<tr><td colspan="6" class="rt-empty">${t("No hay equipos que coincidan.")}</td></tr>`;
}

function memberMenu(m) {
    // Without the permission the item stays visible but cannot be used.
    return `<div class="rt-menu-head">${esc(m.username)}<small>${esc(m.ip || m.email || "")}</small></div>
    <button type="button" role="menuitem" data-mc="block"${m.blocked ? "" : " data-danger"}${m.actions.block ? "" : " disabled"}>${m.blocked ? t("Desbloquear") : t("Bloquear")}</button>
    <hr>
    <button type="button" role="menuitem" data-mc="kick" data-danger${m.actions.kick ? "" : " disabled"}>${t("Expulsar")}</button>`;
}

const WRITE_ERRORS = {
    400: tk("No puede aplicar esta acción a su propia cuenta."),
    403: tk("No tiene permiso para esta acción."),
    404: tk("El equipo ya no está conectado."),
};

async function memberWrite(path, body, done, action) {
    const response = await api("POST", path, body).catch(() => null);
    if (!response) return toast(t("No se pudo contactar con el servidor."), "bad");
    if (response.status === 401) return showLogin();
    if (!response.ok) return toast(t(WRITE_ERRORS[response.status] || tk("La acción falló.")), "bad");
    toast(done, null, action);
    loadMembers();
}

function memberAction(kind, id) {
    const m = memberOf(id);
    if (!m) return;
    const unblock = () => memberWrite("/api/members/block", {account_id: m.id, blocked: false}, t("{name} puede volver a conectarse.", {name: m.username}));
    if (kind === "block" && m.blocked) unblock();
    // Blocking ends the session and keeps it from coming back: it asks first, and can be undone.
    if (kind === "block" && !m.blocked) confirmBox(t("¿Bloquear a {name}?", {name: esc(m.username)}),
        t("Su sesión VPN termina y no podrá volver a conectarse hasta que alguien lo desbloquee. Lo encontrará en el filtro Sin conexión."), t("Bloquear"),
        () => memberWrite("/api/members/block", {account_id: m.id, blocked: true}, t("{name} bloqueado.", {name: m.username}), {label: t("Deshacer"), run: unblock}));
    if (kind === "kick") confirmBox(t("¿Expulsar a {name}?", {name: esc(m.username)}), t("Su sesión VPN termina y el cliente no se reconecta solo."), t("Expulsar"),
        () => memberWrite("/api/sessions/kick", {account_id: m.id}, t("{name} expulsado.", {name: m.username})));
}

function pager(total) {
    const pages = Math.max(1, Math.ceil(total / ui.clientSize));
    return `<button class="rt-btn" data-sm type="button" data-cpage="-1"${ui.clientPage <= 1 ? " disabled" : ""}>${t("Anterior")}</button>
    <span style="font:12px var(--anatomy-mono);color:var(--anatomy-muted)">${t("Página {page} de {pages}", {page: ui.clientPage, pages})}</span>
    <button class="rt-btn" data-sm type="button" data-cpage="1"${ui.clientPage >= pages ? " disabled" : ""}>${t("Siguiente")}</button>
    <span class="rt-gap"></span>
    <label style="display:inline-flex;align-items:center;gap:6px;font-size:11px">${t("Por página")}
      <select class="rt-in" data-csize style="width:auto;padding:3px 24px 3px 7px;font-size:11px">${PAGE_SIZES.map((n) => `<option value="${n}"${ui.clientSize === n ? " selected" : ""}>${n}</option>`).join("")}</select></label>`;
}

function forgetMembers() {
    // The next account must not see the previous one's rows, even briefly.
    MEMBERS = null;
    membersAsked++;
    membersBusy = false;
}

function filterRows() {
    // A new filter starts on the first page; the server answers it right away.
    ui.clientPage = 1;
    loadMembers();
    refreshRows();
}

function turnPage(step) {
    ui.clientPage = Math.max(1, ui.clientPage + step);
    loadMembers();
    refreshRows();
}

function paintNetworks() {
    // New network names reach the filter and the rows without a full render.
    const select = $("[data-cnet]");
    if (select && !menuBtn) select.parentElement.outerHTML = netFilter();
    if (MEMBERS && !menuBtn) refreshRows();
}

function paintPager(total) {
    const box = $("[data-client-pager]");
    if (box) box.innerHTML = pager(total);
}

// Polled every 2 s, only while the page and the tab are visible.
setInterval(() => {
    const visible = page === "clientes" && !document.hidden && !$("[data-view=app]").hidden;
    if (visible && !membersBusy) loadMembers();
}, 2000);
