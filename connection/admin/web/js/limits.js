"use strict";

/* ---------- Límites de velocidad: por red y de internet ---------- */
// LIMITS[key] holds the table being edited; key is a network id or "internet".
const LIMITS = {};
const MAX_MBPS = 10000, MAX_GB = 1000000;
// Speeds travel in kbps and data in MB; the panel shows Mbps and GB.
const SPEEDS = ["down", "up"], QUOTAS = ["quota_down", "quota_up"];

const limitsKey = (networkId) => networkId || "internet";
const fromThousands = (value) => value == null ? "" : String(value / 1000);
// "" means no limit; anything else must be a positive number below the maximum.
const toThousands = (text, maximum) => {
    const value = String(text).trim().replace(",", ".");
    if (!value) return null;
    const number = Number(value);
    return Number.isFinite(number) && number > 0 && number <= maximum ? Math.max(1, Math.round(number * 1000)) : NaN;
};

function limitsCard(networkId) {
    const key = limitsKey(networkId), data = LIMITS[key], muted = 'style="color:var(--anatomy-muted)"';
    const title = networkId ? t("Límites de velocidad") : t("Límites de internet");
    const intro = networkId
        ? t("Aplican a todo el tráfico de cada persona en esta red, también el que sale a internet. El panel nunca se limita.")
        : t("Aplican solo a lo que sale a internet, además de los de la red: vale el más estricto.");
    if (!data) return card(title, `<p style="margin:0;font-size:13px" ${muted}>${t("Cargando…")}</p>`);
    if (data.forbidden) return card(title, `<p style="margin:0;font-size:13px" ${muted}>${t("No tiene permiso para ver estos límites.")}</p>`);
    const dis = data.can_edit ? "" : " disabled";
    const LABELS = {down: tk("Velocidad de bajada de {name}"), up: tk("Velocidad de subida de {name}"), quota_down: tk("Datos de bajada de {name}"), quota_up: tk("Datos de subida de {name}")};
    const input = (owner, field, value, name) =>
        `<input class="rt-in" inputmode="decimal" style="width:116px" data-limit="${esc(key)}" data-owner="${esc(owner)}" data-dir="${field}" value="${esc(value)}" placeholder="${t("Sin límite")}" aria-label="${esc(t(LABELS[field], {name}))}"${dis}>`;
    const cells = (owner, row, name) => [...SPEEDS, ...QUOTAS].map((field) => `<td>${input(owner, field, row[field], name)}</td>`).join("");
    const heads = `<th>${t("Bajada")}<br><small ${muted}>Mbps</small></th><th>${t("Subida")}<br><small ${muted}>Mbps</small></th><th>${t("Datos de bajada")}<br><small ${muted}>${t("GB al mes")}</small></th><th>${t("Datos de subida")}<br><small ${muted}>${t("GB al mes")}</small></th>`;
    const roles = data.roles.map((r) => `<tr><td class="rt-name">${esc(r.name)}</td>${cells("role:" + r.role_id, r, r.name)}<td></td></tr>`).join("");
    const people = data.members.map((m) => `<tr><td class="rt-name">${esc(m.username || "-")}<br><small ${muted}>${esc(m.email || "")}</small></td>
      ${cells("member:" + m.account_id, m, m.username)}
      <td class="rt-act"><button class="rt-btn" data-sm data-danger type="button" data-limit-drop="${esc(key)}" data-owner="${esc(m.account_id)}"${dis}>${t("Quitar")}</button></td></tr>`).join("");
    const actions = data.can_edit ? `<button class="rt-btn" data-sm type="button" data-limit-add="${esc(key)}">${t("+ Persona")}</button>
      <button class="rt-btn" data-sm data-primary type="button" data-limit-save="${esc(key)}"${data.changed ? "" : " disabled"}>${t("Guardar límites")}</button>` : "";
    const extras = (data.extras || []).map((x) => `<tr><td class="rt-name">${x.kind === "role" ? t("Rol {name}", {name: esc(x.name || "-")}) : esc(x.name || "-")}${x.email ? `<br><small ${muted}>${esc(x.email)}</small>` : ""}</td>
      <td>${x.down ? "+" + fromThousands(x.down) + " GB" : "-"}</td><td>${x.up ? "+" + fromThousands(x.up) + " GB" : "-"}</td>
      <td class="rt-act"><button class="rt-btn" data-sm data-danger type="button" data-extra-clear="${esc(key)}" data-kind="${x.kind}" data-owner="${esc(x.id)}"${dis}>${t("Quitar")}</button></td></tr>`).join("");
    const extraButton = data.can_edit ? `<button class="rt-btn" data-sm type="button" data-extra-add="${esc(key)}" style="margin-top:8px">${t("+ Extra del mes")}</button>` : "";
    return card(title, `<p style="margin:0 0 10px;font-size:13px">${intro} ${t("Los datos se reinician el día 1 de cada mes y, al agotarse, se corta. Vacío es sin límite.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Rol")}</th>${heads}<th></th></tr></thead><tbody>${roles}</tbody></table></div>
    <p style="margin:14px 0 8px;font-size:13px">${t("Personas con su propio límite: reemplaza al de su rol, también cuando se deja vacío.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Persona")}</th>${heads}<th></th></tr></thead>
    <tbody>${people || `<tr><td colspan="6" class="rt-empty">${t("Nadie tiene un límite propio.")}</td></tr>`}</tbody></table></div>
    <p style="margin:14px 0 8px;font-size:13px">${t("Extras de este mes: se suman al tope de datos hasta el día 1 y luego desaparecen solos.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Para")}</th><th>${t("Datos de bajada")}</th><th>${t("Datos de subida")}</th><th></th></tr></thead>
    <tbody>${extras || `<tr><td colspan="4" class="rt-empty">${t("No hay extras este mes.")}</td></tr>`}</tbody></table></div>${extraButton}`, actions);
}

async function loadLimits(networkId) {
    const key = limitsKey(networkId);
    const query = networkId ? "?network=" + encodeURIComponent(networkId) : "";
    const response = await api("GET", "/api/limits" + query).catch(() => null);
    if (!response) return;
    if (response.status === 401) return showLogin();
    // Edits not saved yet are kept when the page repaints; the month's extras always update.
    if (LIMITS[key] && LIMITS[key].changed) {
        if (response.ok) LIMITS[key].extras = (await response.json()).extras;
        return paintLimits(key);
    }
    LIMITS[key] = response.status === 403 ? {forbidden: true} : response.ok ? await response.json() : LIMITS[key];
    if (!LIMITS[key]) return;
    for (const row of [...(LIMITS[key].roles || []), ...(LIMITS[key].members || [])]) {
        for (const field of [...SPEEDS, ...QUOTAS]) row[field] = fromThousands(row[field]);
    }
    paintLimits(key);
}

function paintLimits(key) {
    const box = $(`[data-limits="${key}"]`);
    if (box) box.innerHTML = limitsCard(key === "internet" ? null : key);
}

function limitRow(key, owner) {
    const [kind, id] = owner.split(":"), data = LIMITS[key];
    return kind === "role" ? data.roles.find((r) => r.role_id === id) : data.members.find((m) => m.account_id === id);
}

async function saveLimits(key) {
    const data = LIMITS[key], limits = {roles: {}, members: {}};
    for (const [group, rows, id] of [["roles", data.roles, "role_id"], ["members", data.members, "account_id"]]) {
        for (const row of rows) {
            const entry = {};
            for (const field of SPEEDS) entry[field] = toThousands(row[field], MAX_MBPS);
            for (const field of QUOTAS) entry[field] = toThousands(row[field], MAX_GB);
            if (Object.values(entry).some(Number.isNaN)) return toast(t("Valores no válidos en {name}: use números positivos, o déjelo vacío.", {name: row.name || row.username}), "bad");
            limits[group][row[id]] = entry;
        }
    }
    const result = await networkPost("/api/limits", {network_id: key === "internet" ? null : key, limits});
    if (result.message) return toast(result.data && result.data.code === "invalid_limits" ? t("Revise los valores de los límites.") : result.message, "bad");
    data.changed = false;
    toast(t("Límites guardados. Ya se aplican a quienes están conectados."));
    loadLimits(key === "internet" ? null : key);
}

document.addEventListener("input", (e) => {
    if (!e.target.matches("[data-limit]")) return;
    const key = e.target.dataset.limit, row = limitRow(key, e.target.dataset.owner);
    row[e.target.dataset.dir] = e.target.value;
    LIMITS[key].changed = true;
    const save = $(`[data-limit-save="${key}"]`);
    if (save) save.disabled = false;
});

document.addEventListener("click", (e) => {
    const save = e.target.closest("[data-limit-save]"), add = e.target.closest("[data-limit-add]");
    const drop = e.target.closest("[data-limit-drop]");
    if (save && !save.disabled) return saveLimits(save.dataset.limitSave);
    if (drop && !drop.disabled) {
        const key = drop.dataset.limitDrop, data = LIMITS[key];
        data.members = data.members.filter((m) => m.account_id !== drop.dataset.owner);
        data.changed = true;
        return paintLimits(key);
    }
    if (!add) return;
    const key = add.dataset.limitAdd, data = LIMITS[key];
    serverModal(t("Límite propio para una persona"), mfield(t("Correo"), "email", "", {type: "email", ph: t("persona@empresa.com"), hint: t("Debe ser miembro de la organización.")}), t("Agregar"), async (f) => {
        const query = (key === "internet" ? "?" : `?network=${encodeURIComponent(key)}&`) + "email=" + encodeURIComponent(fv(f, "email"));
        const response = await api("GET", "/api/limits/member" + query).catch(() => null);
        if (!response) return t("No se pudo contactar con el servidor.");
        if (response.status === 404) return t("No hay ningún miembro con ese correo.");
        if (!response.ok) return t("No tiene permiso para cambiar estos límites.");
        const person = await response.json();
        if (data.members.some((m) => m.account_id === person.account_id)) return t("Esa persona ya tiene un límite propio.");
        data.members.push({...person, down: "", up: "", quota_down: "", quota_up: ""});
        data.changed = true;
        paintLimits(key);
    });
});

async function extraFor(key, f) {
    // The role is chosen in the list; a person is found by email.
    const target = fv(f, "target"), network_id = key === "internet" ? null : key;
    const down = toThousands(fv(f, "down"), MAX_GB), up = toThousands(fv(f, "up"), MAX_GB);
    if (Number.isNaN(down) || Number.isNaN(up)) return t("Use un número positivo de GB, o déjelo vacío.");
    if (!down && !up) return t("Escriba los GB de bajada, de subida o ambos.");
    let body = {network_id, kind: "role", id: target.slice(5), down: down || 0, up: up || 0};
    if (target === "account") {
        const query = (network_id ? `?network=${encodeURIComponent(network_id)}&` : "?") + "email=" + encodeURIComponent(fv(f, "email"));
        const response = await api("GET", "/api/limits/member" + query).catch(() => null);
        if (!response) return t("No se pudo contactar con el servidor.");
        if (response.status === 404) return t("No hay ningún miembro con ese correo.");
        if (!response.ok) return t("No tiene permiso para dar extras aquí.");
        body = {...body, kind: "account", id: (await response.json()).account_id};
    }
    const result = await networkPost("/api/limits/extra", body);
    if (result.message) return result.message;
    toast(t("Extra agregado hasta el día 1. Ya se aplica."));
    loadLimits(network_id);
}

document.addEventListener("click", (e) => {
    const add = e.target.closest("[data-extra-add]"), clear = e.target.closest("[data-extra-clear]");
    if (clear && !clear.disabled) {
        const key = clear.dataset.extraClear, network_id = key === "internet" ? null : key;
        return confirmBox(t("¿Quitar este extra?"), t("El tope vuelve a su valor normal desde ahora."), t("Quitar"), () => {
            networkPost("/api/limits/extra", {network_id, kind: clear.dataset.kind, id: clear.dataset.owner, clear: true}).then((result) => {
                if (result.message) return toast(result.message, "bad");
                toast(t("Extra quitado."));
                loadLimits(network_id);
            });
        });
    }
    if (!add) return;
    const key = add.dataset.extraAdd, data = LIMITS[key];
    const targets = [...data.roles.map((r) => ["role:" + r.role_id, t("Rol {name}", {name: r.name})]), ["account", t("Una persona (por correo)")]];
    serverModal(t("Extra de datos hasta el día 1"),
        mfield(t("Para"), "target", targets[0][0], {options: targets}) +
        mfield(t("Correo"), "email", "", {type: "email", ph: t("persona@empresa.com"), hint: t("Solo si es para una persona.")}) +
        mfield(t("GB de bajada"), "down", "", {ph: "0"}) + mfield(t("GB de subida"), "up", "", {ph: "0"}),
        t("Agregar"), (f) => extraFor(key, f));
});

/* ---------- Internet (WAN) con servidor ---------- */
function internetPage() {
    const open = !!(ME && ME.internet), muted = 'style="color:var(--anatomy-muted)"';
    const nets = (NETWORKS || []).filter((n) => n.internet).map((n) => esc(networkLabel(n))).join(", ");
    return head(t("Internet (WAN)"), t("La salida a internet a través del servidor y sus límites.")) +
        card(t("Estado"), `<dl class="rt-kv"><dt>${t("Salida a internet")}</dt><dd>${open ? t("Habilitada en el servidor") : t("Deshabilitada: el servidor arrancó sin --internet")}</dd>
    <dt>${t("Redes que la usan")}</dt><dd>${open ? nets || t("Ninguna; se activa en la página de cada red") : "-"}</dd></dl>
    <p style="margin:10px 0 0;font-size:12.5px" ${muted}>${t("Solo se alcanzan direcciones públicas, con la IP pública del servidor.")}</p>`) +
        `<div data-limits="internet">${limitsCard(null)}</div>` +
        `<div data-usage="internet">${usageCard(null)}</div>`;
}
