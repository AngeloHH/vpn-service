"use strict";

/* ---------- Íconos ---------- */
const IC = {
    estado: '<path d="M2 13h3l2-6 3 9 2-5h4"/>',
    internet: '<circle cx="9" cy="9" r="7"/><path d="M2 9h14M9 2c2.5 2.5 2.5 11.5 0 14M9 2c-2.5 2.5-2.5 11.5 0 14"/>',
    lan: '<rect x="2" y="11" width="14" height="5"/><path d="M5 13.5h.01M8 13.5h.01M11 13.5h.01M9 11V7M5 7h8V3H5z"/>',
    wifi: '<path d="M2 7a10 10 0 0 1 14 0M4.5 9.6a6.5 6.5 0 0 1 9 0M7 12.2a3 3 0 0 1 4 0"/><circle cx="9" cy="14.8" r=".6"/>',
    clientes: '<rect x="2" y="3" width="10" height="7"/><path d="M5 13h4M7 10v3"/><rect x="12.5" y="7" width="4" height="8"/>',
    nat: '<path d="M2 6h11l-3-3M16 12H5l3 3"/>',
    seguridad: '<path d="M9 2l6 2.5v4c0 3.8-2.6 6.4-6 7.5-3.4-1.1-6-3.7-6-7.5v-4z"/><path d="M6.5 9l2 2 3-3.5"/>',
    sistema: '<circle cx="9" cy="9" r="2.5"/><path d="M9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.7 3.7l1.4 1.4M12.9 12.9l1.4 1.4M3.7 14.3l1.4-1.4M12.9 5.1l1.4-1.4"/>',
    diag: '<path d="M2 3h14v10H2zM5 7l2 2-2 2M9 11h4"/>',
};
const NAV = [
    [tk("General"), [["estado", tk("Estado")], ["clientes", tk("Equipos conectados")]]],
    [tk("Red"), [["internet", tk("Internet (WAN)")], ["lan", tk("Red local y DHCP")], ["wifi", tk("Otras redes")]]],
    [tk("Avanzado"), [["nat", tk("Acceso entre redes")], ["seguridad", tk("Seguridad")], ["diag", tk("Diagnóstico")], ["sistema", tk("Sistema")]]],
];
const TITLES = Object.fromEntries(NAV.flatMap(([, items]) => items.map(([id, label]) => [id, label])));

/* ---------- Componentes de formulario ---------- */
function field(label, inner, {hint, k, id} = {}) {
    const err = k && errors[k];
    return `<div class="rt-field"><label${id ? ` for="${id}"` : ""}>${label}</label><div class="rt-ctl">${inner}</div>${err ? `<div class="rt-err">${esc(err)}</div>` : hint ? `<div class="rt-hint">${hint}</div>` : ""}</div>`;
}

function txt(label, k, o = {}) {
    const id = "f-" + k.replace(/[.:]/g, "-");
    const v = getP(draft, k);
    return field(label, `<input class="rt-in" id="${id}" data-k="${k}" type="${o.type || "text"}" value="${esc(v)}"${o.num ? ' data-num inputmode="numeric"' : ""}${o.ph ? ` placeholder="${esc(o.ph)}"` : ""}${o.dis ? " disabled" : ""}${errors[k] ? ' aria-invalid="true"' : ""}${o.max ? ` maxlength="${o.max}"` : ""}>${o.suffix || ""}`, {
        hint: o.hint,
        k,
        id
    });
}

function sw(label, k, o = {}) {
    // o.value shows a fixed state, whatever the saved one is.
    const v = "value" in o ? !!o.value : !!getP(draft, k);
    return `<div class="rt-field"><span class="rt-lbl">${label}</span><div class="rt-ctl"><label class="rt-sw"><input type="checkbox" data-k="${k}" data-rr${v ? " checked" : ""}${o.dis ? " disabled" : ""}><span></span><em>${v ? (o.on || t("Activado")) : (o.off || t("Desactivado"))}</em><b class="rt-sr">${label}</b></label></div>${o.hint ? `<div class="rt-hint">${o.hint}</div>` : ""}</div>`;
}

const card = (title, body, extra = "") => `<section class="rt-card"><h3>${title}<span class="rt-gap"></span>${extra}</h3>${body}</section>`;
const head = (title, desc, extra = "") => `<div class="rt-head"><div><h1>${title}</h1>${desc ? `<p>${desc}</p>` : ""}</div><span class="rt-gap"></span>${extra}</div>`;
const sigBars = (n) => `<span class="rt-sig" aria-label="${t("Calidad {n} de 4", {n})}">${[1, 2, 3, 4].map((i) => `<i${i <= n ? " data-on" : ""}></i>`).join("")}</span>`;

/* ---------- Páginas ---------- */
const P = {};

P.estado = () => {
    const v = liveValues(), d = deviceValues(), [online, detail] = onlineValues();
    return head(t("Estado"), t("Resumen del equipo, la conexión a internet y la red local.")) +
        `<div class="rt-stats">
    <div class="rt-stat"><span>${t("Tiempo encendido")}</span><div class="rt-big" data-live="uptime" style="font-size:19px">${esc(v.uptime)}</div></div>
    <div class="rt-stat"><span>${t("Equipos en línea")}</span><div class="rt-big" data-live="online">${esc(online)}<small>${esc(detail)}</small></div></div>
    <div class="rt-stat"><span>CPU</span><div class="rt-big" data-live="cpu">${v.cpu.toFixed(0)}<small>%</small></div><div class="rt-bar"><i data-live-bar="cpu" style="width:${Math.min(100, v.cpu)}%"></i></div></div>
    <div class="rt-stat"><span>${t("Memoria")}</span><div class="rt-big" data-live="mem">${v.mem.toFixed(0)}<small>%</small></div><div class="rt-bar"><i data-live-bar="mem" style="width:${Math.min(100, v.mem)}%"></i></div></div>
  </div>` +
        card(t("Tráfico de la red · últimos 60 s"), `<svg class="rt-chart" viewBox="0 0 600 120" preserveAspectRatio="none" data-chart aria-hidden="true"></svg>
    <div class="rt-legend"><span><i></i>${t("Bajada")} <b data-live="down">0</b></span><span><i data-up></i>${t("Subida")} <b data-live="up">0</b></span><span>${t("Pico")} <b data-live="peak">0</b></span></div>`) +
        `<div data-ports>${backPanels()}</div>` +
        networkCards() +
        card(t("Equipo"), `<dl class="rt-kv">
    <dt>${t("Modelo")}</dt><dd data-live="model">${esc(d.model)}</dd>
    <dt>${t("Firmware")}</dt><dd data-live="fw">${esc(d.fw)}</dd>
    <dt>${t("Número de serie")}</dt><dd data-live="serial">${esc(d.serial)}</dd>
    <dt>${t("Modo")}</dt><dd data-live="mode">${esc(d.mode)}</dd>
    <dt>${t("Temperatura")}</dt><dd data-live="temp">${esc(v.temp)}</dd>
    <dt>${t("Hora")}</dt><dd data-live="clock">${esc(v.clock)}</dd></dl>`, `<button class="rt-btn" data-sm type="button" data-go="sistema">${t("Sistema")}</button>`);
};

function networkCards() {
    // One card per network of the organization the account can see.
    if (!NETWORKS || !NETWORKS.length) return "";
    return `<div class="rt-grid rt-trio">` + NETWORKS.map((n) => card(esc(networkLabel(n)), `<dl class="rt-kv">
    <dt>${t("Estado")}</dt><dd data-net-online="${esc(n.id)}">${esc(networkOnline(n))}</dd>
    <dt>${t("Rango")}</dt><dd>${esc(n.network_range)}</dd>
    <dt>${t("Máscara")}</dt><dd>${esc(n.subnet_mask)}</dd>
    <dt>${t("IP del router")}</dt><dd>${esc(n.router || "-")}</dd>
    <dt>${t("Direcciones")}</dt><dd>${t("{used} de {total} en uso", {used: n.used, total: n.capacity})}</dd>
    <dt>${t("Miembros")}</dt><dd>${n.members}</dd>
    <dt>${t("Su IP")}</dt><dd>${n.your_ip ? esc(n.your_ip) + (n.primary ? " " + t("(principal)") : "") : "-"}</dd></dl>`,
        // The primary network is "Red local y DHCP"; the others have their own page.
        `<button class="rt-btn" data-sm type="button" data-go="${n.primary ? "lan" : "net-" + esc(n.id)}">${t("Configurar")}</button>`)).join("") + `</div>`;
}

P.clientes = () => head(t("Equipos conectados"), t("Las cuentas conectadas a las redes que puede ver. Puede bloquearlas o expulsarlas.")) +
    `<div class="rt-tools">
    <input class="rt-in" type="search" placeholder="${t("Buscar por usuario, correo, IP o UUID")}" aria-label="${t("Buscar equipos")}" data-client-filter value="${esc(ui.clientFilter)}">
    ${netFilter()}
    <span class="rt-gap"></span><span style="font:12px var(--anatomy-mono);color:var(--anatomy-muted)" data-client-count></span>
  </div>
  <section class="rt-card" style="padding:8px 12px"><div class="rt-wrap"><table class="rt-table">
    <thead><tr><th>${t("Equipo")}</th><th>IP / UUID</th><th>${t("Conexión")}</th><th>${t("Bajada / subida")}</th><th>${t("Tiempo")}</th><th></th></tr></thead>
    <tbody data-client-rows></tbody></table></div>
    <div class="rt-tools" data-client-pager style="margin:8px 0 2px"></div></section>`;

function netFilter() {
    const options = (NETWORKS || []).map((n) => [n.id, networkLabel(n)]);
    if (/^net:/.test(ui.clientIface) && !options.some(([v]) => "net:" + v === ui.clientIface)) ui.clientIface = "all";
    const netOn = /^net:/.test(ui.clientIface);
    return `<div class="rt-seg" role="group" aria-label="${t("Filtrar por conexión")}">
    <button type="button" data-ciface="all" aria-pressed="${ui.clientIface === "all"}">${t("Todos")}</button>
    <select class="rt-seg-sel" data-cnet aria-label="${t("Filtrar por red")}"${netOn ? ' data-active=""' : ""}${options.length ? "" : " disabled"}>
      <option value="">${t("Red")}</option>
      ${options.map(([v, name]) => `<option value="${esc(v)}"${ui.clientIface === "net:" + v ? " selected" : ""}>${esc(name)}</option>`).join("")}
    </select>
    <button type="button" data-ciface="off" aria-pressed="${ui.clientIface === "off"}">${t("Sin conexión")}</button>
  </div>`;
}

function clientRows() {
    const cnt = $("[data-client-count]");
    if (cnt) cnt.textContent = MEMBERS ? t("{n} en total", {n: MEMBERS.total}) : "";
    paintPager(MEMBERS ? MEMBERS.total : 0);
    return memberRows();
}

P.internet = () => internetPage();
P.lan = () => networkPage(primaryNetwork(), true);
P.wifi = () => otherNetworksPage();
P.nat = () => accessPage();
P.seguridad = () => securityPage();
P.diag = () => diagPage();
P.sistema = () => systemPage();

/* ---------- Render ---------- */
// Each subsection of "Otras redes" is one of the other networks.
const navItems = () => NAV.map(([g, items]) => [g, items.map((item) => item[0] !== "wifi" ? item
    : ["wifi", item[1], otherNetworks().map((n) => ["net-" + n.id, networkLabel(n)])])]);

function renderNav() {
    // Labels are Spanish keys; network names are data and translate to themselves.
    $("[data-nav]").innerHTML = navItems().map(([g, items]) => `<h2>${t(g)}</h2>` + items.map(([id, label, kids]) => {
        const inGroup = kids && kids.some(([k]) => k === page);
        return `<button type="button" data-go="${id}"${id === page ? ' aria-current="page"' : ""}${inGroup ? " data-open" : ""}><svg viewBox="0 0 18 18" aria-hidden="true">${IC[id]}</svg>${t(label)}</button>` +
            (kids ? `<div class="rt-subnav" role="group" aria-label="${esc(t(label))}">${kids.map(([k, kt]) => `<button type="button" class="rt-sub" data-go="${k}"${k === page ? ' aria-current="page"' : ""}>${esc(kt)}</button>`).join("")}</div>` : "");
    }).join("")).join("");
}

function render() {
    closeMenu();
    renderNav();
    const m = $("[data-main]");
    const y = window.scrollY;
    m.innerHTML = (P[page] || networkView)();
    if (page === "clientes") $("[data-client-rows]").innerHTML = clientRows(), loadMembers();
    if (page === "diag" && !EVENTS) loadEvents();
    if (page === "internet") loadLimits(null), loadUsage(null);
    if (page === "sistema") loadSystem();
    if (page === "nat") loadAccess();
    if (page === "seguridad") loadSecurity();
    if (page === "estado") drawChart(), loadPorts();
    if (isNetworkPage()) afterNetworkRender();
    window.scrollTo(0, y);
    syncSavebar();
}

const knownPage = (p) => !!P[p] || !!netPageId(p);

function go(p) {
    if (p === page) return;
    const doGo = () => {
        page = p;
        draft = clone(S);
        errors = {};
        render();
        window.scrollTo(0, 0);
        $("[data-main]").focus({preventScroll: true});
        try {
            if (location.hash !== "#" + p) history.replaceState(null, "", "#" + p);
        } catch {
        }
    };
    if (dirty()) confirmBox(t("¿Descartar los cambios?"), t("Tiene cambios sin guardar en {page}.", {page: TITLES[page] ? t(TITLES[page]) : esc(networkTitle(page))}), t("Descartar"), doGo);
    else doGo();
}

function syncHeader() {
    $("[data-model]").textContent = REAL ? REAL.model : "";
    paintHeader();
}

function drawChart() {
    const svg = $("[data-chart]");
    if (!svg) return;
    const data = chartData();
    const max = Math.max(1000, ...data.down, ...data.up) * 1.15;
    const pts = (a) => a.map((v, i) => `${(i / (a.length - 1)) * 600},${120 - (v / max) * 116}`).join(" ");
    svg.innerHTML = [30, 60, 90].map((y) => `<line class="rt-grid-l" x1="0" x2="600" y1="${y}" y2="${y}"/>`).join("") +
        `<polygon class="rt-down-a" points="0,120 ${pts(data.down)} 600,120"/><polyline class="rt-down" points="${pts(data.down)}"/><polyline class="rt-up" points="${pts(data.up)}"/>`;
    const setT = (k, v) => {
        const el = $(`[data-live="${k}"]`);
        if (el) el.textContent = v;
    };
    setT("down", fmtRate(data.down.at(-1)));
    setT("up", fmtRate(data.up.at(-1)));
    setT("peak", fmtRate(Math.max(...data.down)));
}
