"use strict";

/* ---------- Estado real del servidor (Server-Sent Events) ---------- */
// REAL holds the latest server status; until it arrives the values show "-".
let REAL = null, statusEvents = null;
// ME is the session account; LINK colors the dot: ok, warn (reconnecting) or bad.
let ME = null, LINK = "warn";
// NETWORKS lists the organization's networks this account may view.
let NETWORKS = null;

function networkOnline(n) {
    const online = (REAL && REAL.online && REAL.online[n.id]) || 0;
    return t("Activa · {n} en línea", {n: online});
}
const MODES = {local: "Local", public: "Público"};
const modeName = (mode) => MODES[mode] ? t(MODES[mode]) : mode;

function liveValues() {
    if (!REAL) return {uptime: "-", cpu: 0, mem: 0, temp: "-", clock: "-"};
    return {
        uptime: REAL.uptime == null ? "-" : fmtUp(REAL.uptime * 1000),
        cpu: REAL.cpu ?? 0, mem: REAL.memory_percent ?? 0,
        temp: REAL.temperature == null ? t("No disponible") : REAL.temperature.toFixed(0) + " °C",
        clock: REAL.time,
    };
}

function deviceValues() {
    if (!REAL) return {model: "-", fw: "-", serial: "-", mode: "-"};
    return {model: REAL.model, fw: REAL.firmware, serial: REAL.serial, mode: modeName(REAL.mode)};
}

function onlineValues() {
    return [REAL ? REAL.sessions : "-", t("sesiones VPN")];
}

function chartData() {
    // The server's kbps history of the last 60 s.
    const traffic = (REAL && REAL.traffic) || {down: [], up: []};
    const pad = (a) => Array(Math.max(0, 60 - a.length)).fill(0).concat(a.slice(-60));
    return {down: pad(traffic.down), up: pad(traffic.up)};
}

function paintHeader() {
    if (!ME) return false;
    $("[data-wan-dot]").dataset.s = LINK;
    $("[data-wan-pill]").textContent = "Router " + ME.router;
    $("[data-mode-pill]").textContent = ME.email || ME.username || "-";
    return true;
}

function setLink(state) {
    LINK = state;
    paintHeader();
}

// "-0500" becomes "UTC-05:00".
const utcOffset = (offset) => offset && /^[+-]\d{4}$/.test(offset) ? `UTC${offset.slice(0, 3)}:${offset.slice(3)}` : "-";

function systemPage() {
    // The clock and its zone belong to the server's operating system: shown, not edited here.
    const zone = REAL && REAL.timezone, muted = 'style="color:var(--anatomy-muted)"';
    return head(t("Sistema"), t("Roles y permisos de la organización, la hora del servidor y las copias de seguridad.")) +
        `<div data-roles>${rolesCard()}</div><div data-role-members>${roleMembersCard()}</div>` +
        `<div class="rt-grid" style="margin-bottom:18px">` +
        card(t("Hora y región"), `<dl class="rt-kv"><dt>${t("Hora del servidor")}</dt><dd data-server-time>${esc(REAL ? REAL.time : "-")}</dd>
    <dt>${t("Zona horaria")}</dt><dd>${zone ? `${esc(utcOffset(zone.offset))}${zone.name ? " · " + esc(zone.name) : ""}` : "-"}</dd></dl>
    <p style="margin:12px 0 0;font-size:12.5px" ${muted}>${t("Se cambian en el sistema operativo del servidor. Los datos de cada mes se reinician el día 1 según esta hora.")}</p>`) +
        backupCard() +
        `</div>`;
}

function paintLive() {
    if ($("[data-view=app]").hidden) return;
    if (REAL) $("[data-model]").textContent = REAL.model;
    const clock = $("[data-server-time]");
    if (clock && REAL) clock.textContent = REAL.time;
    if (page !== "estado") return;
    const v = liveValues(), d = deviceValues(), [online, detail] = onlineValues();
    const setT = (k, value) => {
        const el = $(`[data-live="${k}"]`);
        if (el) el.textContent = value;
    };
    const setBig = (k, value, small) => {
        const el = $(`[data-live="${k}"]`);
        if (el) el.innerHTML = `${esc(value)}<small>${esc(small)}</small>`;
    };
    setT("uptime", v.uptime), setT("clock", v.clock), setT("temp", v.temp);
    setT("model", d.model), setT("fw", d.fw), setT("serial", d.serial), setT("mode", d.mode);
    setBig("cpu", v.cpu.toFixed(0), "%"), setBig("mem", v.mem.toFixed(0), "%"), setBig("online", online, detail);
    (NETWORKS || []).forEach((n) => {
        const el = $(`[data-net-online="${CSS.escape(n.id)}"]`);
        if (el) el.textContent = networkOnline(n);
    });
    $$("[data-live-bar]").forEach((b) => (b.style.width = Math.min(100, v[b.dataset.liveBar]) + "%"));
    drawChart();
}

function showLogin(message) {
    // The server ended the login: expired, logged out elsewhere or VPN reconnected.
    stopStatus();
    forgetMembers();
    PORTS = null;
    EVENTS = null;
    for (const key in LIMITS) delete LIMITS[key];
    forgetRoles();
    forgetAccess();
    forgetUsage();
    forgetSecurity();
    $("[data-view=app]").hidden = true;
    $("[data-view=login]").hidden = false;
    $("[data-login-err]").textContent = message || "";
    $("#rt-p").value = "";
    $("#rt-p").focus();
}

function startStatus() {
    if (statusEvents || document.hidden) return;
    statusEvents = new EventSource("/api/events");
    statusEvents.addEventListener("status", (m) => {
        REAL = JSON.parse(m.data);
        setLink("ok");
        paintLive();
    });
    statusEvents.addEventListener("networks", (m) => {
        // A network was created, removed or changed: rebuild the cards.
        NETWORKS = JSON.parse(m.data);
        syncNetworks();
        if ($("[data-view=app]").hidden) return;
        if (isNetworkPage()) return repaintNetworks();
        if (page === "estado") render();
        if (page === "clientes") paintNetworks();
    });
    statusEvents.onerror = () => {
        // A refused stream does not retry; ask why before giving up.
        if (!statusEvents) return;
        if (statusEvents.readyState !== EventSource.CLOSED) return setLink("warn");
        setLink("bad");
        statusEvents = null;
        api("GET", "/api/me").then((r) => (r.ok ? r.json() : null)).then((me) => {
            if (me && !me.logged_in) showLogin(t("La sesión expiró. Vuelva a iniciar sesión."));
        }).catch(() => {
        });
    };
}

function stopStatus() {
    if (statusEvents) statusEvents.close();
    statusEvents = null;
}

// Hidden tabs stop receiving; the stream resumes when the tab is visible again.
document.addEventListener("visibilitychange", () => {
    if (document.hidden) return stopStatus();
    if (!$("[data-view=app]").hidden) startStatus();
});
