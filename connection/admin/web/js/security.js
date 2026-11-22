"use strict";

/* ---------- Seguridad: reglas entre miembros ---------- */
// SECURITY[network id]: isolation, rules in order and the roles to choose from.
const SECURITY = {};
const securityUi = {network: null};
const TRAFFIC_NAMES = {any: tk("Todo"), tcp: "TCP", udp: "UDP"};

Object.assign(NETWORK_ERRORS, {
    invalid_rule: () => t("La regla no es válida."),
    port_needs_protocol: () => t("Para indicar un puerto, elija TCP o UDP."),
    rule_limit: (f) => t("Una red admite hasta {maximum} reglas.", {maximum: f.maximum}),
    rule_not_found: () => t("Esa regla ya no existe."),
});

function forgetSecurity() {
    for (const key in SECURITY) delete SECURITY[key];
    securityUi.network = null;
}

function securityNetwork() {
    const nets = NETWORKS || [];
    return nets.find((n) => n.id === securityUi.network) || primaryNetwork() || nets[0] || null;
}

function sideText(side) {
    if (side.kind === "any") return t("Cualquiera");
    if (!side.name) return `<span style="color:var(--anatomy-muted)">${t("(ya no existe)")}</span>`;
    if (side.kind === "role") return t("Rol {name}", {name: esc(roleLabel(side.name))});
    return `${esc(side.name)}<br><small style="color:var(--anatomy-muted)">${esc(side.email || "")}</small>`;
}

function securityPage() {
    const title = t("Seguridad"), desc = t("Qué miembros de una red pueden llegar a cuáles. El panel, los reenvíos e internet no dependen de estas reglas.");
    if (!NETWORKS) return head(title, desc) + card(t("Red"), `<p class="rt-empty">${t("Cargando…")}</p>`);
    const n = securityNetwork();
    if (!n) return head(title, desc) + `<div class="rt-note">${t("No tiene permiso para ver ninguna red.")}</div>`;
    const choose = `<div class="rt-tools" style="margin:0 0 14px"><label style="display:inline-flex;align-items:center;gap:8px;font-size:13px">${t("Red")}
      <select class="rt-in" data-security-network style="width:auto;min-width:220px">${NETWORKS.map((x) => `<option value="${esc(x.id)}"${x.id === n.id ? " selected" : ""}>${esc(networkLabel(x))} · ${esc(x.network_range)}</option>`).join("")}</select></label></div>`;
    const data = SECURITY[n.id];
    if (data && data.forbidden) return head(title, desc) + choose + `<div class="rt-note">${t("No tiene permiso para ver las reglas de esta red.")}</div>`;
    if (!data) return head(title, desc) + choose + card(t("Entre miembros"), `<p class="rt-empty">${t("Cargando…")}</p>`);
    const edit = data.can["rules:modify"], remove = data.can["rules:delete"];
    const isolation = `<label class="rt-sw" style="padding:0"><input type="checkbox" data-security-isolated${data.isolated ? " checked" : ""}${edit ? "" : " disabled"}><span></span>
      <b style="font-weight:500;font-size:13px">${data.isolated ? t("Aislados") : t("Se ven entre sí")}</b></label>
      <p style="margin:8px 0 0;font-size:13px">${data.isolated ? t("Los miembros de esta red no se alcanzan entre sí, salvo lo que permitan las reglas.") : t("Los miembros de esta red se alcanzan entre sí (P2P), salvo lo que bloqueen las reglas.")}</p>`;
    const last = data.rules.length - 1;
    const rows = data.rules.length ? data.rules.map((r, i) => `<tr data-rule="${esc(r.id)}"${r.enabled ? "" : " data-off"}>
      <td>${i + 1}</td>
      <td>${r.action === "allow" ? `<span class="rt-tag" data-tone="green">${t("permitir")}</span>` : `<span class="rt-tag" data-tone="red">${t("bloquear")}</span>`}</td>
      <td class="rt-name">${sideText(r.source)}</td><td class="rt-name">${sideText(r.destination)}</td>
      <td>${t(TRAFFIC_NAMES[r.protocol])}${r.port ? " " + r.port : ""}</td>
      <td><label class="rt-sw" style="padding:0"><input type="checkbox" data-rule-on${r.enabled ? " checked" : ""}${edit ? "" : " disabled"}><span></span><b class="rt-sr">${t("Activar la regla {n}", {n: i + 1})}</b></label></td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-rule-move="-1" aria-label="${t("Subir")}"${edit && i > 0 ? "" : " disabled"}>↑</button><button class="rt-btn" data-sm type="button" data-rule-move="1" aria-label="${t("Bajar")}"${edit && i < last ? "" : " disabled"}>↓</button>
      <button class="rt-btn" data-sm type="button" data-security-edit${edit ? "" : " disabled"}>${t("Editar")}</button><button class="rt-btn" data-sm data-danger type="button" data-security-del${remove ? "" : " disabled"}>${t("Eliminar")}</button></td></tr>`).join("")
        : `<tr><td colspan="7" class="rt-empty">${t("No hay reglas.")}</td></tr>`;
    const add = data.can["rules:add"] ? `<button class="rt-btn" data-sm type="button" data-security-add>${t("+ Nueva regla")}</button>` : "";
    return head(title, desc) + choose + card(t("Entre miembros"), isolation) +
        card(t("Reglas"), `<p style="margin:0 0 10px;font-size:13px">${t("Se leen de arriba abajo y decide la primera que coincide; sin ninguna, decide el interruptor de arriba. Las respuestas de una conversación permitida siempre vuelven.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>#</th><th>${t("Acción")}</th><th>${t("Desde")}</th><th>${t("Hacia")}</th><th>${t("Tráfico")}</th><th>${t("Activa")}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`, add);
}

async function loadSecurity() {
    const n = securityNetwork();
    if (!n) return;
    const response = await api("GET", "/api/security?network=" + encodeURIComponent(n.id)).catch(() => null);
    if (!response) return;
    if (response.status === 401) return showLogin();
    if (response.status === 403) SECURITY[n.id] = {forbidden: true};
    else if (response.ok) SECURITY[n.id] = await response.json();
    else return;
    const current = securityNetwork();
    if (page === "seguridad" && current && current.id === n.id) $("[data-main]").innerHTML = securityPage();
}

async function securityWrite(path, body, done, action) {
    const result = await networkPost(path, body);
    if (result.message) return result.message;
    toast(done, null, action);
    loadSecurity();
    return null;
}

/* ---------- Ventana de regla ---------- */
function sideFields(prefix, label, side, roles) {
    const kind = side ? side.kind : "any";
    return mfield(label, prefix + "_kind", kind, {options: [["any", t("Cualquiera")], ["account", t("Una persona")], ["role", t("Un rol")]]}) +
        `<div data-side="${prefix}:account"${kind === "account" ? "" : " hidden"}>${mfield(t("Correo"), prefix + "_email", side && side.kind === "account" ? side.email || "" : "", {type: "email", ph: t("persona@empresa.com")})}</div>` +
        `<div data-side="${prefix}:role"${kind === "role" ? "" : " hidden"}>${mfield(t("Rol"), prefix + "_role", side && side.kind === "role" ? side.id : (roles[0] || {}).id || "", {options: roles.map((r) => [r.id, roleLabel(r.name)])})}</div>`;
}

function readSide(f, prefix) {
    const kind = fv(f, prefix + "_kind");
    if (kind === "account") return {kind, email: fv(f, prefix + "_email")};
    if (kind === "role") return {kind, id: fv(f, prefix + "_role")};
    return {kind: "any"};
}

function securityRuleModal(n, rule) {
    const data = SECURITY[n.id];
    // A new rule starts without an action: saving the defaults must not block everything.
    const actions = [["block", t("Bloquear")], ["allow", t("Permitir")]];
    const body = mfield(t("Acción"), "action", rule ? rule.action : "", {options: rule ? actions : [["", t("Elija una acción")], ...actions]}) +
        sideFields("source", t("Desde"), rule && rule.source, data.roles) + sideFields("destination", t("Hacia"), rule && rule.destination, data.roles) +
        mfield(t("Tráfico"), "protocol", rule ? rule.protocol : "any", {options: Object.entries(TRAFFIC_NAMES).map(([value, label]) => [value, t(label)])}) +
        mfield(t("Puerto"), "port", rule && rule.port ? rule.port : "", {ph: t("Todos"), hint: t("Solo con TCP o UDP: el puerto de destino. Vacío, todos.")});
    serverModal(rule ? t("Editar regla") : t("Nueva regla"), body, rule ? t("Guardar") : t("Crear"), async (f) => {
        if (!fv(f, "action")) return t("Elija si la regla permite o bloquea.");
        const port = fv(f, "port");
        const payload = {network_id: n.id, action: fv(f, "action"), source: readSide(f, "source"), destination: readSide(f, "destination"),
            protocol: fv(f, "protocol"), port: port === "" ? null : /^\d+$/.test(port) ? Number(port) : port, enabled: rule ? rule.enabled : true};
        if (rule) payload.id = rule.id;
        return securityWrite(rule ? "/api/security/rules/update" : "/api/security/rules/add", payload, rule ? t("Regla guardada.") : t("Regla creada."));
    });
}

// A rule as the server needs it back: people by id, unchanged.
function securityRuleBody(n, r, changes) {
    const side = (s) => s.kind === "any" ? {kind: "any"} : {kind: s.kind, id: s.id};
    return {network_id: n.id, id: r.id, action: r.action, source: side(r.source), destination: side(r.destination),
        protocol: r.protocol, port: r.port, enabled: r.enabled, ...changes};
}

/* ---------- Eventos ---------- */
const securityRule = (el) => {
    const n = securityNetwork(), data = n && SECURITY[n.id];
    const id = el.closest("[data-rule]").dataset.rule;
    return data && data.rules && data.rules.find((r) => r.id === id);
};

document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-security-add],[data-security-edit],[data-security-del],[data-rule-move]");
    if (!b || b.disabled) return;
    const n = securityNetwork();
    if (!n) return;
    if (b.hasAttribute("data-security-add")) return securityRuleModal(n, null);
    const rule = securityRule(b);
    if (!rule) return;
    if (b.hasAttribute("data-security-edit")) return securityRuleModal(n, rule);
    if (b.dataset.ruleMove) return securityWrite("/api/security/rules/move", {network_id: n.id, id: rule.id, step: Number(b.dataset.ruleMove)}, t("Orden cambiado.")).then((m) => m && toast(m, "bad"));
    confirmBox(t("¿Eliminar la regla?"), t("Las conversaciones que permitía o bloqueaba pasan a decidirse por las demás reglas."), t("Eliminar"), () =>
        securityWrite("/api/security/rules/delete", {network_id: n.id, id: rule.id}, t("Regla eliminada.")).then((m) => m && toast(m, "bad")));
});

document.addEventListener("change", (e) => {
    const el = e.target;
    if (el.matches("[data-security-network]")) {
        securityUi.network = el.value;
        $("[data-main]").innerHTML = securityPage();
        return loadSecurity();
    }
    // The modal shows the email or the role only for the kind chosen.
    const side = el.name && /^(source|destination)_kind$/.exec(el.name);
    if (side && el.closest("[data-modal]")) {
        const prefix = side[1];
        for (const box of $$(`[data-modal] [data-side^="${prefix}:"]`)) box.hidden = box.dataset.side !== `${prefix}:${el.value}`;
        return;
    }
    const n = securityNetwork();
    if (!n) return;
    const done = (on) => (message) => {
        if (!message) return;
        toast(message, "bad");
        el.checked = !on;
        el.disabled = false;
    };
    if (el.matches("[data-security-isolated]")) {
        // It changes the whole network at once, so it can be undone from the notice.
        const isolate = (on) => securityWrite("/api/security/isolated", {network_id: n.id, isolated: on},
            on ? t("Miembros aislados.") : t("Los miembros vuelven a verse entre sí."),
            {label: t("Deshacer"), run: () => isolate(!on).then((message) => message && toast(message, "bad"))});
        el.disabled = true;
        return isolate(el.checked).then(done(el.checked));
    }
    if (el.matches("[data-rule-on]")) {
        const rule = securityRule(el);
        el.disabled = true;
        securityWrite("/api/security/rules/update", securityRuleBody(n, rule, {enabled: el.checked}), el.checked ? t("Regla activada.") : t("Regla desactivada.")).then(done(el.checked));
    }
});
