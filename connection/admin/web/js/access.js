"use strict";

/* ---------- Acceso entre redes ---------- */
// ACCESS[network id]: its routes and forwarding rules, as the server sent them.
const ACCESS = {};
const accessUi = {network: null};
const PROTOCOL_NAMES = {both: "TCP+UDP", tcp: "TCP", udp: "UDP"};

Object.assign(NETWORK_ERRORS, {
    invalid_source: () => t("Esa cuenta no tiene IP propia en la red de origen."),
    invalid_port: () => t("Puerto no válido: de 1 a 65535. Sin puerto de entrada, el destino tampoco lleva puerto."),
    invalid_target: () => t("El destino debe ser una IP de un miembro de las redes de la organización o una dirección pública de internet. No puede ser un panel ni otro reenvío."),
    forward_conflict: () => t("Esa IP ya reenvía ese puerto y protocolo."),
    forward_limit: (f) => t("Una red admite hasta {maximum} reenvíos.", {maximum: f.maximum}),
    forward_not_found: () => t("Ese reenvío ya no existe."),
    forwards_outside: () => t("Hay reenvíos con IPs fuera del rango nuevo. Cámbielos o elimínelos primero en Acceso entre redes."),
});

function forgetAccess() {
    for (const key in ACCESS) delete ACCESS[key];
    accessUi.network = null;
}

function accessNetwork() {
    const nets = NETWORKS || [];
    return nets.find((n) => n.id === accessUi.network) || primaryNetwork() || nets[0] || null;
}

function accessPage() {
    const muted = 'style="color:var(--anatomy-muted)"';
    const title = t("Acceso entre redes");
    const desc = t("Cómo se llega a una red desde otra: miembros que entran con la IP que ya tienen en otra red, y direcciones de la red que llevan a otro destino.");
    if (!NETWORKS) return head(title, desc) + card(t("Red"), `<p class="rt-empty">${t("Cargando…")}</p>`);
    const n = accessNetwork();
    if (!n) return head(title, desc) + `<div class="rt-note">${t("No tiene permiso para ver ninguna red.")}</div>`;
    const choose = `<div class="rt-tools" style="margin:0 0 14px"><label style="display:inline-flex;align-items:center;gap:8px;font-size:13px">${t("Red")}
      <select class="rt-in" data-access-network style="width:auto;min-width:220px">${NETWORKS.map((x) => `<option value="${esc(x.id)}"${x.id === n.id ? " selected" : ""}>${esc(networkLabel(x))} · ${esc(x.network_range)}</option>`).join("")}</select></label></div>`;
    const data = ACCESS[n.id];
    if (data && data.forbidden) return head(title, desc) + choose + `<div class="rt-note">${t("No tiene permiso para ver el acceso a esta red.")}</div>`;
    const can = (data && data.can) || {};
    const addRoute = can["addresses:add"] ? `<button class="rt-btn" data-sm type="button" data-route-add>${t("+ Agregar ruta")}</button>` : "";
    const addForward = can["forwards:add"] ? `<button class="rt-btn" data-sm type="button" data-forward-add>${t("+ Nuevo reenvío")}</button>` : "";
    const routes = data && data.routes === null ? `<p style="margin:0;font-size:13px" ${muted}>${t("No tiene permiso para ver las rutas de esta red.")}</p>` : routeTable(n, data);
    const forwards = data && data.forwards === null ? `<p style="margin:0;font-size:13px" ${muted}>${t("No tiene permiso para ver los reenvíos de esta red.")}</p>` : forwardTable(n, data);
    return head(title, desc) + choose +
        card(t("Con su IP de otra red"), routes, data && data.routes ? addRoute : "") +
        card(t("Reenvíos"), forwards, data && data.forwards ? addForward : "");
}

function sourceLabel(r) {
    // Unnamed networks are numbered by the panel; one the viewer cannot see shows its range.
    if (!r.source_range) return "-";
    const known = (NETWORKS || []).find((x) => x.id === r.source_id);
    const name = known ? networkLabel(known) : r.source_name;
    return name ? `${esc(name)} <small style="color:var(--anatomy-muted)">${esc(r.source_range)}</small>` : esc(r.source_range);
}

function routeTable(n, data) {
    const muted = 'style="color:var(--anatomy-muted)"';
    const intro = `<p style="margin:0 0 10px;font-size:13px">${t("Miembros que entran a {network} con la IP que ya tienen en otra red, sin una IP nueva. Vale mientras están conectados a esa red de origen.", {network: esc(networkLabel(n))})}</p>`;
    const body = !data ? `<tr><td colspan="5" class="rt-empty">${t("Cargando…")}</td></tr>` : data.routes.length ? data.routes.map((r) => `<tr data-route="${esc(r.account_id)}">
      <td class="rt-name">${esc(r.username || "-")}<br><small ${muted}>${esc(r.email || "-")}</small></td>
      <td>${esc(r.ip)}</td><td>${sourceLabel(r)}</td>
      <td>${onlineTag(r.online)}</td>
      <td class="rt-act"><button class="rt-btn" data-sm data-danger type="button" data-route-del${r.actions.delete ? "" : " disabled"}>${t("Quitar")}</button></td></tr>`).join("")
        : `<tr><td colspan="5" class="rt-empty">${t("Nadie entra con la IP de otra red.")}</td></tr>`;
    return intro + `<div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Cuenta")}</th><th>IP</th><th>${t("Red de origen")}</th><th>${t("Estado")}</th><th></th></tr></thead><tbody>${body}</tbody></table></div>`;
}

const STATE_TAGS = {
    no_internet: () => `<span class="rt-tag" data-tone="red" title="${t("La red o el servidor no permiten salida a internet")}">${t("sin internet")}</span>`,
    no_target: () => `<span class="rt-tag" data-tone="red" title="${t("Ninguna red de la organización tiene ya esa IP")}">${t("destino no disponible")}</span>`,
};

function forwardTable(n, data) {
    const muted = 'style="color:var(--anatomy-muted)"';
    const intro = `<p style="margin:0 0 10px;font-size:13px">${t("Una IP de {network} que lleva a otra dirección: un miembro de otra red de la organización o un servidor de internet. Sin puerto, se reenvían todos.", {network: esc(networkLabel(n))})}</p>`;
    const edit = data && data.can && data.can["forwards:modify"], remove = data && data.can && data.can["forwards:delete"];
    const body = !data ? `<tr><td colspan="6" class="rt-empty">${t("Cargando…")}</td></tr>` : data.forwards.length ? data.forwards.map((r) => `<tr data-forward="${esc(r.id)}"${r.enabled ? "" : " data-off"}>
      <td><label class="rt-sw" style="padding:0"><input type="checkbox" data-forward-on${r.enabled ? " checked" : ""}${edit ? "" : " disabled"}><span></span><b class="rt-sr">${t("Activar el reenvío de {address}", {address: esc(r.address)})}</b></label></td>
      <td class="rt-name">${esc(r.address)}${r.port ? ":" + r.port : ` <small ${muted}>${t("todos los puertos")}</small>`}${r.name ? `<br><small ${muted}>${esc(r.name)}</small>` : ""}</td>
      <td>${PROTOCOL_NAMES[r.protocol]}</td>
      <td>${esc(r.target)}${r.target_port ? ":" + r.target_port : r.port ? ":" + r.port : ""}</td>
      <td>${STATE_TAGS[r.state] ? STATE_TAGS[r.state]() : ""}</td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-forward-edit${edit ? "" : " disabled"}>${t("Editar")}</button><button class="rt-btn" data-sm data-danger type="button" data-forward-del${remove ? "" : " disabled"}>${t("Eliminar")}</button></td></tr>`).join("")
        : `<tr><td colspan="6" class="rt-empty">${t("No hay reenvíos.")}</td></tr>`;
    return intro + `<div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Activo")}</th><th>${t("Entrada")}</th><th>${t("Protocolo")}</th><th>${t("Destino")}</th><th></th><th></th></tr></thead><tbody>${body}</tbody></table></div>`;
}

async function loadAccess() {
    const n = accessNetwork();
    if (!n) return;
    const response = await api("GET", "/api/access?network=" + encodeURIComponent(n.id)).catch(() => null);
    if (!response) return;
    if (response.status === 401) return showLogin();
    if (response.status === 403) ACCESS[n.id] = {forbidden: true};
    else if (response.ok) ACCESS[n.id] = await response.json();
    else return;
    // Only repainted if the person still looks at that network.
    const current = accessNetwork();
    if (page === "nat" && current && current.id === n.id) $("[data-main]").innerHTML = accessPage();
}

async function accessWrite(path, body, done) {
    const result = await networkPost(path, body);
    if (result.message) return result.message;
    toast(done);
    loadAccess();
    refreshNetworks();
    return null;
}

/* ---------- Ventanas ---------- */
function routeModal(n) {
    const sources = (NETWORKS || []).filter((x) => x.id !== n.id).map((x) => [x.id, networkLabel(x) + " · " + x.network_range]);
    if (!sources.length) return toast(t("No hay otra red de la que traer una IP."), "bad");
    const body = mfield(t("Correo"), "email", "", {type: "email", ph: t("persona@empresa.com"), hint: t("Un miembro de la organización con IP propia en la red de origen.")}) +
        mfield(t("Red de origen"), "source", sources[0][0], {options: sources, hint: t("Entra con la IP que tiene allí. Si está conectado a esa red, se reconecta para recibir la ruta.")});
    serverModal(t("Agregar ruta a {network}", {network: esc(networkLabel(n))}), body, t("Agregar"), (f) =>
        accessWrite("/api/routes/add", {network_id: n.id, email: fv(f, "email"), source_id: fv(f, "source")}, t("Ruta agregada.")));
}

const portValue = (text) => text === "" ? null : /^\d+$/.test(text) ? Number(text) : text;

function forwardModal(n, rule) {
    const r = rule || {name: "", address: "", port: null, protocol: "both", target: "", target_port: null, enabled: true};
    const body = mfield(t("Nombre"), "name", r.name || "", {ph: t("Opcional, por ejemplo Cámara")}) +
        mfield(t("IP en esta red"), "address", r.address, {ph: t("Por ejemplo {ip}", {ip: n.network_range.split("/")[0].replace(/\d+$/, "50")}), hint: t("Una IP libre de {range}. Los miembros llegan al destino a través de ella.", {range: esc(n.network_range)})}) +
        mfield(t("Puerto"), "port", r.port || "", {ph: t("Todos"), hint: t("Vacío: se reenvían todos los puertos.")}) +
        mfield(t("Protocolo"), "protocol", r.protocol, {options: Object.entries(PROTOCOL_NAMES)}) +
        mfield(t("Destino"), "target", r.target, {ph: t("IP de un miembro o de internet"), hint: t("La IP de un miembro en cualquier red de la organización, o una dirección pública de internet. Para internet, la red debe tener salida permitida.")}) +
        mfield(t("Puerto de destino"), "target_port", r.target_port || "", {ph: t("El mismo"), hint: t("Vacío: el mismo puerto de entrada.")});
    serverModal(rule ? t("Editar reenvío") : t("Nuevo reenvío"), body, rule ? t("Guardar") : t("Crear"), (f) => {
        const payload = {network_id: n.id, name: fv(f, "name"), address: fv(f, "address"), port: portValue(fv(f, "port")),
            protocol: fv(f, "protocol"), target: fv(f, "target"), target_port: portValue(fv(f, "target_port")), enabled: r.enabled};
        if (rule) payload.id = rule.id;
        return accessWrite(rule ? "/api/forwards/update" : "/api/forwards/add", payload, rule ? t("Reenvío guardado.") : t("Reenvío creado."));
    });
}

function ruleBody(n, r, changes) {
    return {network_id: n.id, id: r.id, name: r.name || "", address: r.address, port: r.port, protocol: r.protocol,
        target: r.target, target_port: r.target_port, enabled: r.enabled, ...changes};
}

/* ---------- Eventos ---------- */
const accessRule = (el) => {
    const n = accessNetwork(), data = n && ACCESS[n.id];
    const id = el.closest("[data-forward]").dataset.forward;
    return data && data.forwards && data.forwards.find((r) => r.id === id);
};

document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-route-add],[data-route-del],[data-forward-add],[data-forward-edit],[data-forward-del]");
    if (!b || b.disabled) return;
    const n = accessNetwork();
    if (!n) return;
    if (b.hasAttribute("data-route-add")) return routeModal(n);
    if (b.hasAttribute("data-forward-add")) return forwardModal(n, null);
    if (b.hasAttribute("data-route-del")) {
        const id = b.closest("[data-route]").dataset.route;
        const row = ACCESS[n.id].routes.find((r) => r.account_id === id);
        return confirmBox(t("¿Quitar la ruta de {name}?", {name: esc(row.username)}), t("Deja de entrar a {network} con {ip}. Si está conectado a su red de origen, se reconecta.", {network: esc(networkLabel(n)), ip: esc(row.ip)}), t("Quitar"), () =>
            accessWrite("/api/routes/delete", {network_id: n.id, account_id: id}, t("Ruta quitada.")).then((m) => m && toast(m, "bad")));
    }
    const rule = accessRule(b);
    if (!rule) return;
    if (b.hasAttribute("data-forward-edit")) return forwardModal(n, rule);
    confirmBox(t("¿Eliminar el reenvío de {address}?", {address: esc(rule.address)}), t("Las conexiones abiertas a través de él se cortan."), t("Eliminar"), () =>
        accessWrite("/api/forwards/delete", {network_id: n.id, id: rule.id}, t("Reenvío eliminado.")).then((m) => m && toast(m, "bad")));
});

document.addEventListener("change", (e) => {
    if (e.target.matches("[data-access-network]")) {
        accessUi.network = e.target.value;
        $("[data-main]").innerHTML = accessPage();
        return loadAccess();
    }
    if (!e.target.matches("[data-forward-on]")) return;
    const n = accessNetwork(), rule = accessRule(e.target), on = e.target.checked;
    e.target.disabled = true;
    accessWrite("/api/forwards/update", ruleBody(n, rule, {enabled: on}), on ? t("Reenvío activado.") : t("Reenvío desactivado.")).then((message) => {
        if (!message) return;
        toast(message, "bad");
        e.target.checked = !on;
        e.target.disabled = false;
    });
});
