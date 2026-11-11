"use strict";

/* ---------- Diagnóstico real: pruebas desde el servidor y registro ---------- */
// EVENTS holds the organization's log as the server answered it.
let EVENTS = null;
const LEVELS = {INFO: "INFO", WARN: "WARN", ERROR: "ERROR"};
const CHANGE_NAMES = {name: tk("el nombre"), network_range: tk("el rango"), max_address: tk("el límite"), router: tk("la IP del router"), dns: tk("los DNS")};

// "10.0.0.50:80 a 8.8.8.8:53", without ports when the rule takes them all.
const forwardText = (e) => t("{from} a {to}", {from: `${e.address}${e.port ? ":" + e.port : ""}`,
    to: `${e.target}${e.target_port ? ":" + e.target_port : e.port ? ":" + e.port : ""}`});

function eventText(e) {
    const who = e.by || "", net = e.network_id ? networkName(e.network_id) : "";
    const changes = (e.changes || []).filter((c) => c !== "internet").map((c) => CHANGE_NAMES[c] ? t(CHANGE_NAMES[c]) : c);
    if ((e.changes || []).includes("internet")) changes.push(e.internet ? t("abrió la salida a internet") : t("cerró la salida a internet"));
    const where = e.scope === "internet" ? t("en internet") : t("en {network}", {network: net});
    const v = {...e, who, net, where};
    const amount = (mb, down) => down ? t("{gb} GB de bajada", {gb: mb / 1000}) : t("{gb} GB de subida", {gb: mb / 1000});
    const texts = {
        connected: () => t("{username} se conectó a {net} con {ip}", v),
        panel_login: () => t("{username} entró al panel", v),
        login_failed: () => e.wait ? t("{username} escribió mal la contraseña del panel (debe esperar {wait} s)", v) : t("{username} escribió mal la contraseña del panel", v),
        member_kicked: () => t("{who} expulsó a {username}", v),
        member_blocked: () => t("{who} bloqueó a {username}", v),
        member_unblocked: () => t("{who} desbloqueó a {username}", v),
        network_created: () => t("{who} creó la red {name}", {...v, name: e.name || e.network_range}),
        network_updated: () => t("{who} cambió la red {net}: {changes}", {...v, changes: changes.join(", ") || t("sin cambios")}),
        network_deleted: () => t("{who} eliminó la red {name}; {moved} cambiaron de red y {left} salieron de la organización", {...v, name: e.name || e.network_range}),
        address_added: () => t("{who} dio la IP {ip} a {username} en {net}", v),
        address_changed: () => t("{who} cambió la IP de {username} a {ip} en {net}", v),
        address_removed: () => t("{who} quitó a {username} de {net}", v),
        internet_limit: () => t("{username} llegó al límite de conexiones a internet", v),
        limits_changed: () => e.scope === "internet" ? t("{who} cambió los límites de internet", v) : t("{who} cambió los límites de {net}", v),
        extra_granted: () => t("{who} dio un extra a {target} de {amount} {where}", {...v,
            amount: [e.down && amount(e.down, true), e.up && amount(e.up, false)].filter(Boolean).join(" + ")}),
        extra_cleared: () => t("{who} quitó el extra de {target} {where}", v),
        isolation_changed: () => e.isolated ? t("{who} aisló a los miembros de {net}", v) : t("{who} dejó que los miembros de {net} se vean entre sí", v),
        rule_added: () => e.action === "allow" ? t("{who} creó una regla para permitir en {net}", v) : t("{who} creó una regla para bloquear en {net}", v),
        rule_changed: () => t("{who} cambió una regla de {net}", v),
        rule_moved: () => t("{who} cambió el orden de las reglas de {net}", v),
        rule_removed: () => t("{who} eliminó una regla de {net}", v),
        route_added: () => t("{who} dio a {username} acceso a {net} con su IP {ip}", v),
        route_removed: () => t("{who} quitó el acceso de {username} a {net} con la IP de otra red", v),
        forward_added: () => t("{who} creó el reenvío {forward} en {net}", {...v, forward: forwardText(e)}),
        forward_changed: () => t("{who} cambió el reenvío {forward} en {net}", {...v, forward: forwardText(e)}),
        forward_removed: () => t("{who} eliminó el reenvío {forward} en {net}", {...v, forward: forwardText(e)}),
        role_created: () => t("{who} creó el rol {name}", v),
        role_updated: () => t("{who} cambió el rol {name}", v),
        role_deleted: () => t("{who} eliminó el rol {name}", v),
        role_assigned: () => e.name ? t("{who} dio el rol {name} a {username}", v) : t("{who} quitó el rol de {username}", v),
        permissions_changed: () => t("{who} cambió los permisos propios de {username}", v),
        quota_reached: () => e.direction === "down" ? t("{username} agotó sus datos de bajada del mes {where}", v) : t("{username} agotó sus datos de subida del mes {where}", v),
    };
    return (texts[e.kind] || (() => e.kind))();
}

const TCP_ERRORS = {
    not_found: (r, host) => t("No se encontró {host}.", {host}),
    not_public: (r) => t("{address} no es una dirección pública: el servidor no prueba su propia red.", {address: r.address}),
    refused: (r, host, port) => t("{address} rechazó la conexión al puerto {port}.", {address: r.address, port}),
    timeout: (r, host, port) => t("Sin respuesta de {address}:{port} en 5 s.", {address: r.address, port}),
    unreachable: (r) => t("No se pudo llegar a {address}.", {address: r.address}),
};

function diagLines(tool, host, port, r) {
    if (tool === "dns") {
        if (r.error) return [t("No se encontró {host}.", {host})];
        const lines = [t("Consulta DNS de {host} ({ms} ms)", {host, ms: r.ms}), "", ...r.addresses.map((a) => t("Dirección: {address}", {address: a}))];
        if (r.hidden) lines.push(tn(r.hidden, "{n} dirección privada oculta", "{n} direcciones privadas ocultas"));
        if (!r.addresses.length && !r.hidden) lines.push(t("Sin direcciones."));
        return lines;
    }
    if (r.error) return [(TCP_ERRORS[r.error] || (() => t("La prueba falló.")))(r, host, port)];
    return [t("Conectado a {host} ({address}) en el puerto {port}", {host, address: r.address, port}), t("Tiempo de conexión: {ms} ms", {ms: r.ms})];
}

function diagPage() {
    const muted = 'style="color:var(--anatomy-muted)"';
    const tool = ui.diagTool || "dns";
    const level = (e) => ui.logLevel === "all" || e.level === ui.logLevel;
    const items = EVENTS ? EVENTS.filter(level).slice(0, 200).map((e) => `<li><time>${fmtTime(e.time * 1000)}</time><b data-l="${e.level}">${LEVELS[e.level] || e.level}</b><span>${esc(eventText(e))}</span></li>`).join("") : "";
    return head(t("Diagnóstico"), t("Pruebe destinos de internet desde el servidor y revise lo que pasó en su organización.")) +
        card(t("Herramientas"), `<div class="rt-tools" style="margin:0">
    <select class="rt-in" style="max-width:190px" data-diag-tool aria-label="${t("Herramienta")}"><option value="dns"${tool === "dns" ? " selected" : ""}>${t("Consulta DNS")}</option><option value="tcp"${tool === "tcp" ? " selected" : ""}>${t("Prueba de conexión")}</option></select>
    <input class="rt-in" data-diag-host value="${esc(ui.diagHost || "example.com")}" aria-label="${t("Destino")}" placeholder="${t("Host o IP")}">
    <input class="rt-in" data-diag-port value="${esc(ui.diagPort ?? "443")}" aria-label="${t("Puerto")}" placeholder="${t("Puerto")}" style="max-width:90px"${tool === "tcp" ? "" : " hidden"}>
    <button class="rt-btn" data-primary type="button" data-act="diag-run"${ui.diagBusy ? " disabled" : ""}>${t("Ejecutar")}</button>
  </div><div class="rt-term" data-diag-out aria-live="polite">${ui.diagOut || `<span class="dim">${t("Elija una herramienta y pulse Ejecutar.")}</span>`}</div>
  <p style="margin:8px 0 0;font-size:12.5px" ${muted}>${t("Solo se prueban direcciones públicas. Ping y traceroute no están disponibles.")}</p>`) +
        card(t("Registro"), `<div class="rt-tools"><div class="rt-seg" role="group" aria-label="${t("Nivel")}">${[["all", tk("Todo")], ["WARN", tk("Avisos")], ["ERROR", tk("Errores")]].map(([value, label]) => `<button type="button" data-loglevel="${value}" aria-pressed="${ui.logLevel === value}">${t(label)}</button>`).join("")}</div><span class="rt-gap"></span><button class="rt-btn" data-sm type="button" data-act="log-dl"${EVENTS && EVENTS.length ? "" : " disabled"}>${t("Descargar")}</button></div>
  <ul class="rt-log" data-log>${EVENTS ? items || `<li><span ${muted}>${t("Sin entradas.")}</span></li>` : `<li><span ${muted}>${t("Cargando…")}</span></li>`}</ul>
  <p style="margin:8px 0 0;font-size:12.5px" ${muted}>${t("Se guardan los últimos 500 eventos mientras el servidor está encendido.")}</p>`);
}

async function loadEvents() {
    const response = await api("GET", "/api/logs").catch(() => null);
    if (!response || !response.ok) return;
    EVENTS = (await response.json()).events;
    // Only the list changes, so a half-typed destination is not lost.
    if (page !== "diag") return;
    const list = $("[data-log]"), download = $('[data-act="log-dl"]');
    if (!list) return;
    const fresh = document.createElement("div");
    fresh.innerHTML = diagPage();
    list.innerHTML = $("[data-log]", fresh).innerHTML;
    if (download) download.disabled = !EVENTS.length;
}

async function runServerDiag() {
    const tool = $("[data-diag-tool]").value, host = $("[data-diag-host]").value.trim() || "example.com";
    const typed = $("[data-diag-port]").value.trim(), port = /^\d+$/.test(typed) ? +typed : null;
    // What was typed stays in the field, even when it is not a valid port.
    Object.assign(ui, {diagTool: tool, diagHost: host, diagPort: typed, diagBusy: true, diagOut: `<span class="dim">${t("Probando desde el servidor…")}</span>`});
    render();
    const body = tool === "tcp" ? {tool, host, port} : {tool, host};
    const response = await api("POST", "/api/diagnostics", body).catch(() => null);
    let lines;
    if (!response) lines = [t("No se pudo contactar con el servidor.")];
    else if (response.status === 401) return showLogin();
    else if (response.status === 403) lines = [t("No tiene permiso para hacer pruebas desde el servidor.")];
    else if (response.status === 400) lines = [tool === "tcp" ? t("Destino o puerto no válido (puerto entre 1 y 65535).") : t("Destino no válido.")];
    else if (!response.ok) lines = [t("La prueba falló.")];
    else lines = diagLines(tool, host, port, await response.json());
    ui.diagBusy = false;
    ui.diagOut = lines.map(esc).join("\n");
    if (page === "diag") render();
}

function downloadEvents() {
    const lines = (EVENTS || []).slice().reverse().map((e) => `${fmtTime(e.time * 1000)} ${e.level} ${eventText(e)}`);
    download(t("registro") + ".txt", lines.join("\n"), "text/plain");
}

document.addEventListener("change", (e) => {
    if (!e.target.matches("[data-diag-tool]")) return;
    ui.diagTool = e.target.value;
    const port = $("[data-diag-port]");
    if (port) port.hidden = ui.diagTool !== "tcp";
});

// The log refreshes every 5 s, only while this page and the tab are visible.
setInterval(() => {
    if (page === "diag" && !document.hidden && !$("[data-view=app]").hidden) loadEvents();
}, 5000);
