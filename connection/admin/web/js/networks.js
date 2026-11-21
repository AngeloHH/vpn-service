"use strict";

/* ---------- Redes reales: red primaria, otras redes y asignaciones ---------- */
// ASSIGNMENTS keeps the loaded rows and the total of each network, page by page.
const ASSIGNMENTS = {};
const ASSIGNMENT_PAGE = 25;

const NETWORK_ERRORS = {
    invalid_range: () => t("Rango no válido. Use el formato 10.1.0.0/24, hasta /30."),
    range_overlap: (f) => t("El rango se superpone con {name}.", {name: f.name || f.network_range}),
    invalid_limit: (f) => t("El límite debe estar entre 1 y {maximum}.", {maximum: f.maximum}),
    limit_in_use: (f) => t("Hay {used} direcciones en uso; el límite no puede ser menor.", {used: f.used}),
    invalid_address: () => t("Esa IP no es válida para esta red o queda fuera del límite."),
    address_in_use: () => t("Esa IP ya está en uso."),
    exhausted: () => t("No quedan direcciones libres en esta red."),
    last_network: () => t("La organización necesita al menos una red."),
    unknown_account: () => t("No existe una cuenta con ese correo."),
    already_assigned: () => t("Esa cuenta ya tiene IP en esta red."),
    invalid_name: () => t("El nombre admite hasta 40 caracteres."),
    internet_disabled: () => t("El servidor no permite salida a internet: se habilita al arrancarlo con --internet."),
    invalid_dns: () => t("Escriba hasta dos direcciones IPv4 separadas por coma, por ejemplo 1.1.1.1, 8.8.8.8."),
    network_not_found: () => t("La red ya no existe."),
    account_not_found: () => t("Esa cuenta ya no está en esta red."),
    invalid_request: () => t("Datos no válidos."),
    changed: () => t("Otra persona cambió estos datos mientras usted los editaba. Se cargaron los valores nuevos; revise y vuelva a guardar."),
};
// The field each refusal belongs to when the network form is saved.
const ERROR_FIELDS = {
    invalid_range: "range", range_overlap: "range", exhausted: "range", invalid_limit: "max",
    limit_in_use: "max", invalid_name: "name", invalid_dns: "dns", invalid_address: "router", address_in_use: "router",
};

const netPageId = (p) => /^net-/.test(p) ? p.slice(4) : null;
const primaryNetwork = () => (NETWORKS || []).find((n) => n.primary);
const otherNetworks = () => (NETWORKS || []).filter((n) => !n.primary);
const sliceOf = (n) => "net:" + n.id;
// The form shows the DNS servers as one line; the server keeps a list.
const dnsList = (text) => text.split(/[\s,]+/).filter(Boolean);
const isNetworkPage = (p = page) => p === "lan" || p === "wifi" || !!netPageId(p);
const networkTitle = (p) => {
    const n = networkOfPage(p);
    return n ? networkLabel(n) : t("esta red");
};
const networkView = () => networkPage(networkOfPage(), false);

function networkOfPage(p = page) {
    if (p === "lan") return primaryNetwork();
    const id = netPageId(p);
    return id ? (NETWORKS || []).find((n) => n.id === id) : null;
}

function syncNetworks() {
    // Server values become the saved state; a form being edited keeps its draft.
    for (const n of NETWORKS || []) {
        const k = sliceOf(n), value = {name: n.name || "", range: n.network_range, max: n.max_address, router: n.router || "", internet: n.internet, dns: (n.dns || []).join(", ")};
        const edited = draft[k] && S[k] && JSON.stringify(draft[k]) !== JSON.stringify(S[k]);
        S[k] = value;
        if (!edited) draft[k] = clone(value);
        SLICES["net-" + n.id] = [k];
    }
    const primary = primaryNetwork();
    if (primary) SLICES.lan = [sliceOf(primary)];
}

function repaintNetworks() {
    // A form with changes or focus is not rebuilt under the person typing.
    const typing = document.activeElement && document.activeElement.closest("[data-main] input, [data-main] select");
    if (isNetworkPage() && !dirty() && !typing) render();
    else renderNav();
}

async function refreshNetworks() {
    const response = await api("GET", "/api/networks").catch(() => null);
    if (!response || !response.ok) return;
    NETWORKS = (await response.json()).networks;
    syncNetworks();
    repaintNetworks();
}

async function refreshMe() {
    // The login adds the permissions; they decide which buttons are offered.
    const response = await api("GET", "/api/me").catch(() => null);
    if (!response || !response.ok) return;
    ME = await response.json();
    paintHeader();
    if (page === "wifi") repaintNetworks();
}

async function networkPost(path, body) {
    const response = await api("POST", path, body).catch(() => null);
    if (!response) return {status: 0, message: t("No se pudo contactar con el servidor.")};
    if (response.status === 401) {
        showLogin();
        return {status: 401, message: t("La sesión expiró.")};
    }
    const data = await response.json().catch(() => ({}));
    const message = response.ok ? null : response.status === 403 ? t("No tiene permiso para esta acción.")
        : (NETWORK_ERRORS[data.code] || (() => t("La acción falló.")))(data);
    return {status: response.status, data, message};
}

function serverModal(title, body, okText, send, options) {
    // The dialog stays open until the server answers, so a refusal can be fixed.
    modal(title, body, okText, (f) => {
        const button = $("[type=submit]", f);
        button.disabled = true;
        send(f).then((message) => {
            if (!document.contains(f)) return;
            button.disabled = false;
            if (message) $("[data-md-err]", f).textContent = message;
            else $("[data-md-cancel]", f).click();
        });
        return t("Enviando…");
    }, options);
}

/* ---------- Páginas ---------- */
function networkPage(n, primary) {
    const title = primary ? t("Red local y DHCP") : n ? networkLabel(n) : t("Red");
    if (!NETWORKS) return head(title, "") + card(t("Red"), `<p class="rt-empty">${t("Cargando…")}</p>`);
    if (!n) return head(title, "") + `<div class="rt-note">${primary ? t("No tiene permiso para ver su red primaria.") : t("Esta red ya no existe o no tiene permiso para verla.")}</div>`;
    const k = sliceOf(n), dis = !n.can.modify;
    // The server's own switch comes first: without it no network can open the internet.
    const serverInternet = !!(ME && ME.internet);
    const desc = primary ? t("Su red principal en esta organización: su rango, el panel y quién tiene IP en ella.") : t("Rango, panel y direcciones de esta red.");
    const remove = n.can.delete ? `<button class="rt-btn" data-danger type="button" data-act="net-delete">${t("Eliminar red")}</button>` : "";
    const add = n.can.add_address ? `<button class="rt-btn" data-sm type="button" data-act="assign-add">${t("+ Agregar")}</button>` : "";
    return head(title, desc, remove) +
        card(t("Red"), txt(t("Nombre"), k + ".name", {dis, max: 40, ph: t("Red {n}", {n: n.number})}) +
            txt(t("Rango"), k + ".range", {dis, hint: t("Formato 10.0.0.0/24. Al cambiarlo, todas las IPs se reasignan desde el inicio del rango y los miembros se reconectan.")}) +
            field(t("Máscara de subred"), `<input class="rt-in" value="${esc(n.subnet_mask)}" disabled>`, {hint: t("Sale del rango.")}) +
            txt(t("Límite de direcciones"), k + ".max", {num: true, dis, hint: t("Cuántas IPs puede repartir esta red. Hoy hay {n} en uso.", {n: n.assigned})}) +
            txt(t("IP del router"), k + ".router", {dis, hint: t("Es la dirección del panel en esta red. Si la cambia, deberá entrar con la nueva.")}) +
            txt(t("Servidores DNS"), k + ".dns", {dis, ph: t("Los de cada equipo"), hint: t("Hasta dos, separados por coma. Los miembros los usan mientras están conectados a esta red; vacío, cada equipo sigue con su DNS.")}) +
            sw(t("Salida a internet"), k + ".internet", {
                dis: dis || !serverInternet, on: t("Permitida"), off: t("Solo la red"),
                // Closed by the server: shown off, even if the network kept it on.
                ...(serverInternet ? {} : {value: false}),
                hint: serverInternet
                ? t("Los miembros navegan por internet a través del servidor, con su IP pública. Al cambiarla se reconectan.")
                : t("El servidor no permite salida a internet. Se habilita al arrancarlo con --internet; mientras tanto, ninguna red sale a internet.")})) +
        card(t("Asignaciones"), `<div data-asg>${assignmentTable(n)}</div>`, add) +
        `<div data-limits="${esc(n.id)}">${limitsCard(n.id)}</div>` +
        `<div data-usage="${esc(n.id)}">${usageCard(n.id)}</div>` +
        card(t("Estado actual"), `<dl class="rt-kv"><dt>${t("IP del router")}</dt><dd>${esc(n.router || "-")}</dd><dt>${t("Máscara")}</dt><dd>${esc(n.subnet_mask)}</dd>
    <dt>${t("Direcciones")}</dt><dd>${t("{used} de {total} en uso", {used: n.assigned, total: n.max_address})}</dd><dt>${t("Miembros")}</dt><dd>${n.members}</dd><dt>${t("Su IP")}</dt><dd>${esc(n.your_ip || "-")}</dd></dl>`);
}

function otherNetworksPage() {
    const nets = otherNetworks(), perms = (ME && ME.permissions) || {};
    const canAdd = !!ME && (ME.administrator || perms["networks:add"] === "all");
    const muted = 'style="color:var(--anatomy-muted)"';
    const rows = nets.map((n) => `<tr><td class="rt-name">${esc(networkLabel(n))}</td><td>${esc(n.network_range)}</td><td>${esc(n.router || "-")}</td>
      <td>${t("{used} de {total}", {used: n.assigned, total: n.max_address})}</td><td>${n.members}</td><td>${esc(n.your_ip || "-")}</td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-go="net-${esc(n.id)}">${t("Abrir")}</button></td></tr>`).join("");
    return head(t("Otras redes"), t("Las demás redes de la organización que puede ver. Cada una tiene su sección en el menú."),
            canAdd ? `<button class="rt-btn" type="button" data-act="net-add">${t("+ Nueva red")}</button>` : "") +
        card(t("Redes"), !NETWORKS ? `<p class="rt-empty">${t("Cargando…")}</p>` : nets.length ? `<div class="rt-wrap"><table class="rt-table">
    <thead><tr><th>${t("Red")}</th><th>${t("Rango")}</th><th>${t("IP del router")}</th><th>${t("Direcciones")}</th><th>${t("Miembros")}</th><th>${t("Su IP")}</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>` : `<p style="margin:0;font-size:13px" ${muted}>${t("No hay otras redes.")}</p>`);
}

function assignmentTable(n) {
    if (!n.can.view_addresses) return `<p style="margin:0;font-size:13px;color:var(--anatomy-muted)">${t("No tiene permiso para ver las asignaciones de esta red.")}</p>`;
    const loaded = ASSIGNMENTS[n.id], rows = loaded && loaded.rows, muted = 'style="color:var(--anatomy-muted)"';
    const body = !rows ? `<tr><td colspan="4" class="rt-empty">${t("Cargando…")}</td></tr>` : rows.length ? rows.map((r) => `<tr data-asg-id="${esc(r.account_id)}">
      <td class="rt-name">${esc(r.username || "-")}<br><small ${muted}>${esc(r.email || "-")}</small></td>
      <td>${esc(r.ip)}${r.primary ? ` <span class="rt-tag" title="${t("Es la red primaria de esta cuenta")}">${t("primaria")}</span>` : ""}</td>
      <td>${onlineTag(r.online)}</td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-asg-ip${r.actions.modify ? "" : " disabled"}>${t("Cambiar IP")}</button><button class="rt-btn" data-sm data-danger type="button" data-asg-del${r.actions.delete ? "" : " disabled"}>${t("Quitar")}</button></td></tr>`).join("")
        : `<tr><td colspan="4" class="rt-empty">${t("Nadie tiene IP en esta red.")}</td></tr>`;
    // The rest of the accounts arrive on demand, below the ones already shown.
    const more = rows && rows.length < loaded.total ? `<div class="rt-tools" style="margin:8px 0 2px">
    <button class="rt-btn" data-sm type="button" data-asg-more>${t("Cargar más")}</button>
    <span style="font:12px var(--anatomy-mono);color:var(--anatomy-muted)">${t("{used} de {total}", {used: rows.length, total: loaded.total})}</span></div>` : "";
    return `<p style="margin:0 0 10px;font-size:13px">${t("Cada cuenta conserva siempre la misma IP en esta red.")}</p><div class="rt-wrap"><table class="rt-table">
    <thead><tr><th>${t("Cuenta")}</th><th>IP</th><th>${t("Estado")}</th><th></th></tr></thead><tbody>${body}</tbody></table></div>${more}`;
}

async function loadAssignments(n, more = false) {
    // A refresh keeps as many rows as were shown; "Cargar más" asks for the next page.
    if (!n.can.view_addresses) return;
    const shown = ASSIGNMENTS[n.id] ? ASSIGNMENTS[n.id].rows.length : 0;
    const offset = more ? shown : 0, limit = more ? ASSIGNMENT_PAGE : Math.max(ASSIGNMENT_PAGE, shown);
    const path = `/api/assignments?network=${encodeURIComponent(n.id)}&offset=${offset}&limit=${limit}`;
    const response = await api("GET", path).catch(() => null);
    if (!response || !response.ok) return;
    const loaded = await response.json();
    if (more && ASSIGNMENTS[n.id]) loaded.rows = ASSIGNMENTS[n.id].rows.concat(loaded.rows);
    ASSIGNMENTS[n.id] = loaded;
    const box = $("[data-asg]"), current = networkOfPage();
    if (box && current && current.id === n.id) box.innerHTML = assignmentTable(current);
}

function afterNetworkRender() {
    const n = networkOfPage();
    if (n) loadAssignments(n), loadLimits(n.id), loadUsage(n.id);
}

/* ---------- Guardar y acciones ---------- */
function saveNetwork() {
    const n = networkOfPage(), k = sliceOf(n), d = draft[k], s = S[k];
    // The saved values travel too: the server refuses if someone changed them since.
    const body = {network_id: n.id, expected: {name: s.name, network_range: s.range, max_address: s.max, router: s.router, internet: s.internet, dns: dnsList(s.dns)}};
    if (d.name !== s.name) body.name = d.name;
    if (d.range !== s.range) body.network_range = d.range;
    if (d.max !== s.max) body.max_address = d.max === "" ? null : d.max;
    if (d.router !== s.router) body.router = d.router;
    if (d.internet !== s.internet) body.internet = d.internet;
    if (dnsList(d.dns).join() !== dnsList(s.dns).join()) body.dns = dnsList(d.dns);
    const here = ME && ME.router === s.router;
    const send = async () => {
        const result = await networkPost("/api/networks/update", body);
        if (result.data && result.data.code === "changed") {
            errors = {};
            delete draft[k];
            await refreshNetworks();
            draft[k] = clone(S[k]);
            render();
            return toast(result.message, "bad");
        }
        if (result.message) {
            const name = ERROR_FIELDS[result.data && result.data.code];
            errors = name ? {[k + "." + name]: result.message} : {};
            render();
            return toast(result.message, "bad");
        }
        errors = {};
        const router = result.data.router;
        S[k] = {...d, name: d.name.trim(), range: result.data.network_range, router, dns: dnsList(d.dns).join(", ")};
        draft[k] = clone(S[k]);
        // Saved at once on screen; the refresh below may fail while members reconnect.
        render();
        // The panel of this very page moved: the old address stops answering.
        if (here && router !== s.router) return modal(t("El panel cambió de dirección"),
            `<p style="margin:0;font-size:14px">${t("Cuando su VPN se reconecte, abra {url}.", {url: `<strong>http://${esc(router)}/</strong>`})}</p>`, t("Abrir"), () => {
                location.href = `http://${router}/`;
            });
        toast(t("Cambios guardados."));
        refreshNetworks();
    };
    if (body.network_range == null && body.router == null && body.internet == null && body.dns == null) return send();
    confirmBox(t("¿Aplicar el cambio?"), body.network_range != null
        ? t("Todas las IPs se reasignan desde el inicio del rango y los miembros de esta red se reconectan.")
        : body.router != null ? t("El panel pasa a la nueva IP del router y los miembros de esta red se reconectan.")
        : t("Los miembros de esta red se reconectan para aplicar el cambio."), t("Aplicar"), send);
}

function deleteNetwork(n, confirm) {
    networkPost("/api/networks/delete", {network_id: n.id, confirm}).then(async (result) => {
        if (result.status === 409) {
            const list = result.data.accounts.map((a) => `<li>${esc(a.username || "-")} <small style="color:var(--anatomy-muted)">${esc(a.email || "")}</small></li>`).join("");
            return modal(t("Estas cuentas saldrán de la organización"), `<p style="margin:0;font-size:14px">${t("No tienen otra red en esta organización:")}</p><ul style="font-size:14px">${list}</ul>`,
                t("Eliminar igual"), () => deleteNetwork(n, true), {danger: true});
        }
        if (result.message) return toast(result.message, "bad");
        toast(t("{name} eliminada.", {name: networkLabel(n)}));
        go(n.primary ? "estado" : "wifi");
        refreshNetworks();
    });
}

// A free 10.x.0.0/24 to suggest; the server still checks every range.
function freeRange() {
    const ranges = (NETWORKS || []).map((n) => {
        const [ip, bits] = n.network_range.split("/");
        const size = 2 ** (32 - +bits);
        return [ipToInt(ip), ipToInt(ip) + size - 1];
    });
    for (let x = 0; x < 256; x++) {
        const start = ipToInt(`10.${x}.0.0`), end = start + 255;
        if (!ranges.some(([a, b]) => start <= b && a <= end)) return `10.${x}.0.0/24`;
    }
    return "";
}

Object.assign(ACT, {
    "net-add"() {
        serverModal(t("Nueva red"), mfield(t("Nombre"), "name", "", {ph: t("Opcional")}) + mfield(t("Rango"), "range", freeRange(), {ph: "10.1.0.0/24"}) +
            mfield(t("Límite de direcciones"), "max", "", {ph: t("Automático"), hint: t("Vacío: todas las del rango menos la del router.")}), t("Crear"), async (f) => {
            const max = fv(f, "max");
            if (max && !/^\d+$/.test(max)) return t("El límite debe ser un número.");
            const result = await networkPost("/api/networks/create", {name: fv(f, "name") || null, network_range: fv(f, "range"), max_address: max ? +max : null});
            if (result.message) return result.message;
            toast(t("Red creada. Su panel queda en la última IP del rango."));
            await refreshNetworks();
            go("net-" + result.data.network_id);
        });
    },
    "net-delete"() {
        const n = networkOfPage();
        if (n) confirmBox(t("¿Eliminar {name}?", {name: esc(networkLabel(n))}), t("Sus miembros pasan a otra red que tengan en esta organización y se reconectan."), t("Eliminar"), () => deleteNetwork(n, false));
    },
    "assign-add"() {
        const n = networkOfPage();
        if (!n) return;
        serverModal(t("Agregar a {name}", {name: esc(networkLabel(n))}), mfield(t("Correo"), "email", "", {type: "email", ph: t("persona@empresa.com"), hint: t("La cuenta debe existir. Recibe la primera IP libre.")}), t("Agregar"), async (f) => {
            const result = await networkPost("/api/assignments/add", {network_id: n.id, email: fv(f, "email")});
            if (result.message) return result.message;
            toast(t("IP {ip} asignada.", {ip: result.data.ip}));
            loadAssignments(n);
            refreshNetworks();
        });
    },
});

document.addEventListener("click", (e) => {
    const n = networkOfPage();
    if (e.target.closest("[data-asg-more]")) return n && loadAssignments(n, true);
    const b = e.target.closest("[data-asg-ip],[data-asg-del]");
    if (!b || b.disabled) return;
    const id = b.closest("[data-asg-id]").dataset.asgId;
    const row = n && ASSIGNMENTS[n.id] && ASSIGNMENTS[n.id].rows.find((r) => r.account_id === id);
    if (!row) return;
    const done = (message) => {
        toast(message);
        loadAssignments(n);
        refreshNetworks();
    };
    if (b.hasAttribute("data-asg-ip")) return serverModal(t("Cambiar IP de {name}", {name: esc(row.username)}), mfield("IP", "ip", row.ip, {hint: t("Dentro de {range} y del límite. {name} se reconecta con ella.", {range: esc(n.network_range), name: esc(row.username)})}), t("Guardar"), async (f) => {
        const result = await networkPost("/api/assignments/update", {network_id: n.id, account_id: id, ip: fv(f, "ip"), expected: row.ip});
        if (result.data && result.data.code === "changed") loadAssignments(n);
        if (result.message) return result.message;
        done(t("{name} ahora tiene {ip}.", {name: row.username, ip: result.data.ip}));
    });
    const removeMember = (confirm) => networkPost("/api/assignments/delete", {network_id: n.id, account_id: id, confirm}).then((result) => {
        // Its only network here: removing it takes the account out of the organization.
        if (result.status === 409) return modal(t("{name} saldrá de la organización", {name: esc(row.username)}),
            `<p style="margin:0;font-size:14px">${t("No tiene otra red en esta organización: se desconecta y pierde el acceso hasta que lo vuelvan a añadir.")}</p>`,
            t("Quitar igual"), () => {
                removeMember(true);
            }, {danger: true});
        if (result.message) return toast(result.message, "bad");
        done(result.data && result.data.left ? t("{name} salió de la organización.", {name: row.username}) : t("{name} ya no está en esta red.", {name: row.username}));
    });
    confirmBox(t("¿Quitar a {name} de esta red?", {name: esc(row.username)}), row.primary ? t("Es su red primaria: pasa a otra red que tenga en esta organización.") : t("Pierde su IP en esta red y se reconecta."), t("Quitar"), () => removeMember(false));
});
