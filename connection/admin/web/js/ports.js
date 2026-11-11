"use strict";

/* ---------- Panel trasero: un puerto por cada usuario conectado ---------- */
// PORTS: the connected members the account can see, oldest connection first,
// so each one keeps its port while it stays connected.
let PORTS = null, portsBusy = false;

/* Router and switches are equal devices of S.switchSize ports, in a chain. When the
   users do not fit, a device keeps its last port for the cable to the next one:
   with 13 users and 8 ports, the router holds 7 users plus the link and Switch 1, 6. */
function layout() {
    const rows = (PORTS && PORTS.rows) || [], size = S.switchSize, out = [];
    for (let i = 0; i < rows.length;) {
        const take = rows.length - i > size ? size - 1 : size;
        out.push(rows.slice(i, i + take));
        i += take;
    }
    return out.length ? out : [[]];
}

const deviceName = (k) => (k ? `Switch ${k}` : "Router");
const chained = (k) => k < layout().length - 1;
const parsePort = (id) => {
    const m = /^d(\d+)p(\d+)$/.exec(id || "");
    return m ? {n: +m[1], m: +m[2]} : null;
};

function portMember(id) {
    const p = parsePort(id), device = p && layout()[p.n];
    return device ? device[p.m - 1] || null : null;
}

async function loadPorts() {
    if (portsBusy) return;
    portsBusy = true;
    try {
        const response = await api("GET", "/api/members/ports");
        if (response.status === 401) return showLogin(t("La sesión expiró. Vuelva a iniciar sesión."));
        if (!response.ok) return;
        PORTS = await response.json();
        // A port that disappeared closes its detail.
        if (ui.port && /p\d+$/.test(ui.port) && !portMember(ui.port)) ui.port = null;
        paintPorts();
    } catch (e) {
        // A lost tunnel is shown by the status dot; the next poll retries.
    } finally {
        portsBusy = false;
    }
}

function paintPorts() {
    const box = $("[data-ports]");
    if (box && page === "estado") box.innerHTML = backPanels();
}

function emptyPort(label) {
    return `<button class="rt-port" type="button" data-empty disabled aria-disabled="true" title="${t("Puerto sin uso")}"><span class="rt-jack"></span><b>${label}</b><small>${t("sin uso")}</small></button>`;
}

function portBtn(id, label, member, linkTo) {
    const name = member ? member.username || member.email || "-" : "";
    const title = linkTo ? t("Enlace al {device}", {device: deviceName(linkTo)}) : name;
    return `<button class="rt-port" type="button" data-port="${id}" data-on${linkTo ? " data-link" : ""} aria-pressed="${ui.port === id}" title="${esc(title)}"><span class="rt-jack"></span><b>${label}</b><small>${linkTo ? "→ SW " + linkTo : esc(name)}</small></button>`;
}

function portDetail() {
    const p = ui.port;
    if (!p) return t("Seleccione un puerto para ver qué tiene conectado.");
    if (p === "d0wan") return t("WAN del router: la conexión del servidor VPN. Por aquí llegan todos los usuarios.");
    const size = S.switchSize, w = /^d(\d+)wan$/.exec(p);
    if (w) return t("WAN del {device}: cable que llega desde el V-CON {port} del {previous}.", {device: deviceName(+w[1]), port: size, previous: deviceName(+w[1] - 1)});
    const m = portMember(p), pp = parsePort(p);
    if (pp && pp.m === size && chained(pp.n)) return t("V-CON {port} del {device}: cable hacia el WAN del {next}. Todo lo que sigue en la cadena sale a internet por aquí.", {port: size, device: deviceName(pp.n), next: deviceName(pp.n + 1)});
    if (!m) return t("Ese puerto ya no existe.");
    const nets = m.networks.map(networkName).join(", ");
    return `<strong style="color:var(--anatomy-strong)">${esc(m.username || "-")}</strong> · ${esc(m.email || "-")} · ${deviceName(pp.n)} · V-CON ${pp.m} · ${esc(m.ip || "-")} · ${esc(nets)} · ${t("conectado hace {time}", {time: fmtAgo(Date.now() - m.connected_for * 1000)})}`;
}

function backPanels() {
    const groups = layout(), users = (PORTS && PORTS.rows.length) || 0;
    const panel = (label, wanId, wanText, ports) => `<div class="rt-back" role="group" aria-label="${esc(t("Puertos del {device}", {device: label}))}">
      <button class="rt-port" type="button" data-wan data-port="${wanId}" data-on aria-pressed="${ui.port === wanId}"><span class="rt-jack"></span><b>WAN</b><small>${wanText}</small></button>
      <span class="rt-sep"></span>
      <div class="rt-lans">${ports.join("")}</div>
      <div class="rt-power"><i></i><small style="font:10px var(--anatomy-mono);color:var(--anatomy-muted)">12V</small></div>
    </div>`;
    const size = S.switchSize, switches = groups.length - 1;
    const devices = groups.map((g, k) => {
        const name = deviceName(k);
        // The last port of a chained device carries the cable to the next one.
        const ports = Array.from({length: size}, (_, i) => chained(k) && i === size - 1 ? portBtn(`d${k}p${size}`, "V-CON " + size, null, k + 1) :
            g[i] ? portBtn(`d${k}p${i + 1}`, "V-CON " + (i + 1), g[i]) : emptyPort("V-CON " + (i + 1)));
        return (k ? `<div class="rt-swlink" aria-hidden="true"><i></i>${t("cable desde V-CON {port} del {device}", {port: size, device: deviceName(k - 1)})}</div>` : "") +
            `<div class="rt-swhead"><b>${name}</b><span>${t("{n} puertos", {n: size})} · ${tn(g.length, "{n} usuario", "{n} usuarios")}</span></div>` +
            panel(name, `d${k}wan`, t("enlace"), ports);
    }).join("");
    const loading = PORTS ? "" : `<p style="margin:0 0 10px;font-size:13px;color:var(--anatomy-muted)">${t("Cargando…")}</p>`;
    return card(switches ? t("Panel trasero y switches") : t("Panel trasero"), loading + devices +
        `<p style="margin:12px 0 0;font-size:13px" data-port-detail>${portDetail()}</p>
     <p style="margin:6px 0 0;font:11.5px var(--anatomy-mono);color:var(--anatomy-muted)">${tn(users, "{n} usuario conectado", "{n} usuarios conectados")} · ${tn(switches, "{n} switch", "{n} switches")}</p>`,
        `<label style="display:inline-flex;align-items:center;gap:6px;text-transform:none;letter-spacing:0;font-size:11px">${t("Cantidad máxima de puertos")}
      <select class="rt-in" data-swsize style="width:auto;padding:3px 24px 3px 7px;font-size:11px">${[4, 5, 8, 16, 24, 48].map((n) => `<option value="${n}"${S.switchSize === n ? " selected" : ""}>${n}</option>`).join("")}</select></label>`);
}

document.addEventListener("click", (e) => {
    const port = e.target.closest("[data-port]");
    if (!port || port.disabled) return;
    ui.port = ui.port === port.dataset.port ? null : port.dataset.port;
    paintPorts();
});

document.addEventListener("change", (e) => {
    if (!e.target.matches("[data-swsize]")) return;
    S.switchSize = +e.target.value;
    draft.switchSize = S.switchSize;
    try { localStorage.setItem("panel-switch-size", String(S.switchSize)); } catch { }
    ui.port = null;
    paintPorts();
});

// Polled every 5 s, only while Estado and the tab are visible.
setInterval(() => {
    if (page === "estado" && !document.hidden && !$("[data-view=app]").hidden) loadPorts();
}, 5000);
