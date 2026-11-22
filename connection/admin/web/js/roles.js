"use strict";

/* ---------- Roles y permisos de la organización (Sistema) ---------- */
// ROLES: roles, catalog and what the viewer may do; ROLE_MEMBERS: the page of members shown.
let ROLES = null, ROLE_MEMBERS = null, roleMembersAsked = 0;
const roleUi = {page: 1, size: 25, filter: ""};

const RESOURCE_NAMES = {
    status: tk("Estado"), sessions: tk("Sesiones"), members: tk("Miembros"), addresses: tk("Direcciones"), networks: tk("Redes"),
    rules: tk("Reglas"), forwards: tk("Reenvíos"), roles: tk("Roles"), permissions: tk("Permisos"), organization: tk("Organización"),
};
const ACTION_NAMES = {view: tk("Ver"), add: tk("Agregar"), modify: tk("Modificar"), delete: tk("Eliminar")};
const SCOPE_NAMES = {"": tk("No"), primary: tk("Solo su red"), all: tk("Todas")};

Object.assign(NETWORK_ERRORS, {
    invalid_role_name: () => t("El nombre es obligatorio y admite hasta 40 caracteres."),
    role_name_taken: () => t("Ya existe un rol con ese nombre."),
    invalid_permissions: () => t("Hay permisos no válidos."),
    role_locked: () => t("El rol Administrador no se puede cambiar."),
    role_not_found: () => t("El rol ya no existe."),
    last_administrator: () => t("La organización necesita al menos un administrador."),
});

function forgetRoles() {
    ROLES = ROLE_MEMBERS = null;
    roleMembersAsked++;
}

// What the viewer could give: the same rule the server applies.
function grantable(name, scope, targetPrimary) {
    if (!ME || ME.administrator) return !!ME;
    const own = (ME.permissions || {})[name];
    if (scope === "all") return own === "all";
    return own === "all" || (own === "primary" && targetPrimary != null && targetPrimary === ME.primary);
}

function permissionCount(permissions) {
    return tn(Object.keys(permissions || {}).length, "{n} permiso", "{n} permisos");
}

/* ---------- Matriz de permisos ---------- */
// rules: {current, targetPrimary, canAdd, canRemove}; a choice the viewer cannot make stays disabled.
function permissionMatrix(current, rules) {
    const actions = Object.keys(ACTION_NAMES), muted = 'style="color:var(--anatomy-muted)"';
    const rows = Object.entries(ROLES.catalog).map(([resource, allowedActions]) => {
        const cells = actions.map((action) => {
            if (!allowedActions.includes(action)) return `<td ${muted}>-</td>`;
            const name = `${resource}:${action}`, value = current[name] || "";
            const scopes = ROLES.network_resources.includes(resource) ? ["", "primary", "all"] : ["", "all"];
            const options = scopes.map((scope) => {
                const possible = scope === value || (scope === "" ? rules.canRemove : rules.canAdd && grantable(name, scope, rules.targetPrimary));
                return `<option value="${scope}"${scope === value ? " selected" : ""}${possible ? "" : " disabled"}>${t(SCOPE_NAMES[scope])}</option>`;
            }).join("");
            return `<td><select class="rt-in" name="perm:${name}" aria-label="${esc(t(ACTION_NAMES[action]) + " · " + t(RESOURCE_NAMES[resource]))}" style="width:auto;min-width:112px;padding:4px 24px 4px 8px;font-size:12px">${options}</select></td>`;
        }).join("");
        return `<tr><td class="rt-name">${RESOURCE_NAMES[resource] ? t(RESOURCE_NAMES[resource]) : esc(resource)}</td>${cells}</tr>`;
    }).join("");
    return `<p style="margin:4px 0 8px;font-size:12.5px" ${muted}>${t("\"Solo su red\" vale únicamente en la red primaria de cada persona.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Recurso")}</th>${actions.map((a) => `<th>${t(ACTION_NAMES[a])}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

function readMatrix(f) {
    const permissions = {};
    for (const el of f.elements) {
        if (el.name && el.name.startsWith("perm:") && el.value) permissions[el.name.slice(5)] = el.value;
    }
    return permissions;
}

function wideModal(title, body, okText, send) {
    serverModal(title, body, okText, send);
    const form = $("[data-modal] form");
    if (form) form.dataset.wide = "";
}

/* ---------- Tarjetas ---------- */
function rolesCard() {
    const muted = 'style="color:var(--anatomy-muted)"';
    if (!ROLES) return card(t("Roles"), `<p style="margin:0;font-size:13px" ${muted}>${t("Cargando…")}</p>`);
    if (ROLES.forbidden || !ROLES.roles.some((r) => r.permissions)) return card(t("Roles"), `<p style="margin:0;font-size:13px" ${muted}>${t("No tiene permiso para ver los roles.")}</p>`);
    const rows = ROLES.roles.map((r) => {
        const tags = (r.administrator ? ` <span class="rt-tag">${t("administrador")}</span>` : "") + (r.default ? ` <span class="rt-tag">${t("por defecto")}</span>` : "");
        const summary = r.administrator ? t("Todos, siempre") : permissionCount(r.permissions);
        return `<tr data-role="${esc(r.role_id)}"><td class="rt-name">${esc(roleLabel(r.name))}${tags}</td><td>${r.members}</td><td>${summary}</td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-role-edit${r.administrator ? " disabled" : ""}>${r.actions.modify ? t("Editar") : t("Ver")}</button>
      <button class="rt-btn" data-sm data-danger type="button" data-role-delete${r.actions.delete ? "" : " disabled"}>${t("Eliminar")}</button></td></tr>`;
    }).join("");
    const add = ROLES.can_add ? `<button class="rt-btn" data-sm type="button" data-role-new>${t("+ Nuevo rol")}</button>` : "";
    return card(t("Roles"), `<p style="margin:0 0 10px;font-size:13px">${t("Valen para todas las redes de la organización. Los permisos propios de cada persona se suman a los de su rol. El rol por defecto se da a quien entra a la organización.")}</p>
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Rol")}</th><th>${t("Miembros")}</th><th>${t("Permisos")}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`, add);
}

function roleMembersCard() {
    const muted = 'style="color:var(--anatomy-muted)"';
    const title = t("Miembros y permisos");
    if (ROLES && ROLES.forbidden) return "";
    if (ROLE_MEMBERS && ROLE_MEMBERS.forbidden) return card(title, `<p style="margin:0;font-size:13px" ${muted}>${t("No tiene permiso para ver los permisos de los miembros.")}</p>`);
    const search = `<div class="rt-tools"><input class="rt-in" type="search" data-role-filter value="${esc(roleUi.filter)}" placeholder="${t("Buscar por usuario o correo")}" aria-label="${t("Buscar miembros")}"></div>`;
    return card(title, `<p style="margin:0 0 10px;font-size:13px">${t("Todas las personas de la organización, conectadas o no.")}</p>${search}
    <div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Persona")}</th><th>${t("Rol")}</th><th>${t("Permisos propios")}</th><th></th></tr></thead>
    <tbody data-role-rows>${roleMemberRows()}</tbody></table></div>
    <div class="rt-tools" data-role-pager style="margin:8px 0 2px">${roleMembersPager()}</div>`);
}

function roleMemberRows() {
    const muted = 'style="color:var(--anatomy-muted)"';
    if (!ROLE_MEMBERS || !ROLES || !ROLES.roles) return `<tr><td colspan="4" class="rt-empty">${t("Cargando…")}</td></tr>`;
    if (!ROLE_MEMBERS.rows.length) return `<tr><td colspan="4" class="rt-empty">${t("No hay miembros que coincidan.")}</td></tr>`;
    return ROLE_MEMBERS.rows.map((m) => {
        const current = m.role_id || "";
        const options = [["", t("Sin rol")], ...ROLES.roles.map((r) => [r.role_id, roleLabel(r.name)])].map(([id, name]) => {
            const possible = id === current || id === "" || m.roles.includes(id);
            return `<option value="${esc(id)}"${id === current ? " selected" : ""}${possible ? "" : " disabled"}>${esc(name)}</option>`;
        }).join("");
        const role = `<select class="rt-in" data-role-assign="${esc(m.account_id)}" aria-label="${esc(t("Rol de {name}", {name: m.username}))}" style="width:auto;min-width:150px"${m.actions.assign ? "" : " disabled"}>${options}</select>`;
        const own = Object.keys(m.permissions).length ? permissionCount(m.permissions) : `<span ${muted}>${t("Ninguno")}</span>`;
        const editable = m.actions.grant || m.actions.revoke;
        return `<tr data-rmember="${esc(m.account_id)}"><td class="rt-name">${esc(m.username || "-")}${m.me ? ` <small ${muted}>${t("(usted)")}</small>` : ""}${m.blocked ? ` <span class="rt-tag" data-tone="red">${t("bloqueado")}</span>` : ""}<br><small ${muted}>${esc(m.email || "-")}</small></td>
      <td>${role}</td><td>${own}</td>
      <td class="rt-act"><button class="rt-btn" data-sm type="button" data-member-perms="${esc(m.account_id)}">${editable ? t("Editar permisos") : t("Ver permisos")}</button></td></tr>`;
    }).join("");
}

function roleMembersPager() {
    if (!ROLE_MEMBERS || ROLE_MEMBERS.forbidden) return "";
    const pages = Math.max(1, Math.ceil(ROLE_MEMBERS.total / roleUi.size));
    return `<button class="rt-btn" data-sm type="button" data-role-page="-1"${roleUi.page <= 1 ? " disabled" : ""}>${t("Anterior")}</button>
    <span style="font:12px var(--anatomy-mono);color:var(--anatomy-muted)">${t("Página {page} de {pages}", {page: roleUi.page, pages})}</span>
    <button class="rt-btn" data-sm type="button" data-role-page="1"${roleUi.page >= pages ? " disabled" : ""}>${t("Siguiente")}</button>
    <span class="rt-gap"></span>
    <label style="display:inline-flex;align-items:center;gap:6px;font-size:11px">${t("Por página")}
      <select class="rt-in" data-role-size style="width:auto;padding:3px 24px 3px 7px;font-size:11px">${PAGE_SIZES.map((n) => `<option value="${n}"${roleUi.size === n ? " selected" : ""}>${n}</option>`).join("")}</select></label>`;
}

/* ---------- Carga ---------- */
async function loadRoles() {
    const response = await api("GET", "/api/roles").catch(() => null);
    if (!response) return;
    if (response.status === 401) return showLogin();
    ROLES = response.status === 403 ? {forbidden: true} : response.ok ? await response.json() : ROLES;
    paintRoles();
}

async function loadRoleMembers() {
    // Only the newest answer is painted: the search may change mid-request.
    const asked = ++roleMembersAsked;
    const query = new URLSearchParams({page: roleUi.page, size: roleUi.size});
    if (roleUi.filter.trim()) query.set("q", roleUi.filter.trim());
    const response = await api("GET", "/api/roles/members?" + query).catch(() => null);
    if (!response || asked !== roleMembersAsked) return;
    if (response.status === 401) return showLogin();
    ROLE_MEMBERS = response.status === 403 ? {forbidden: true} : response.ok ? await response.json() : ROLE_MEMBERS;
    const pages = ROLE_MEMBERS && !ROLE_MEMBERS.forbidden ? Math.max(1, Math.ceil(ROLE_MEMBERS.total / roleUi.size)) : 1;
    if (roleUi.page > pages) {
        roleUi.page = pages;
        return loadRoleMembers();
    }
    paintRoleMembers();
}

function loadSystem() {
    loadRoles();
    loadRoleMembers();
}

function paintRoles() {
    const box = $("[data-roles]");
    if (box) box.innerHTML = rolesCard();
    paintRoleMembers();
}

function paintRoleMembers() {
    const box = $("[data-role-members]");
    if (!box) return;
    // The search box keeps its focus while the rows change.
    const rows = $("[data-role-rows]", box);
    if (!rows || (ROLE_MEMBERS && ROLE_MEMBERS.forbidden) || (ROLES && ROLES.forbidden)) return box.innerHTML = roleMembersCard();
    rows.innerHTML = roleMemberRows();
    $("[data-role-pager]", box).innerHTML = roleMembersPager();
}

async function roleWrite(path, body, done, action) {
    const result = await networkPost(path, body);
    if (result.message) return result.message;
    toast(done, null, action);
    // Our own permissions may have changed with it.
    refreshMe();
    loadSystem();
    return null;
}

/* ---------- Acciones ---------- */
function roleModal(role) {
    const editable = !role || role.actions.modify;
    const rules = {current: role ? role.permissions : {}, targetPrimary: null, canAdd: editable, canRemove: editable};
    const body = mfield(t("Nombre"), "name", role ? role.name : "", {ph: t("Por ejemplo, Soporte")}) +
        `<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin:6px 0 10px"><input type="checkbox" name="default"${role && role.default ? " checked" : ""}${editable ? "" : " disabled"}> ${t("Rol por defecto para quien entra a la organización")}</label>` +
        permissionMatrix(rules.current, rules);
    if (!editable) {
        modal(esc(roleLabel(role.name)), body, t("Cerrar"), () => null);
        $("[data-modal] form").dataset.wide = "";
        return $$("[data-modal] form input, [data-modal] form select").forEach((el) => (el.disabled = true));
    }
    wideModal(role ? t("Editar {name}", {name: esc(role.name)}) : t("Nuevo rol"), body, role ? t("Guardar") : t("Crear"), (f) => {
        const payload = {name: fv(f, "name"), permissions: readMatrix(f), default: f.elements.default.checked};
        if (!payload.name) return Promise.resolve(t("Escriba un nombre."));
        // Unchecking the default leaves the organization without one; it is only sent when it changes.
        if (role && payload.default === role.default) delete payload.default;
        return role ? roleWrite("/api/roles/update", {role_id: role.role_id, ...payload}, t("Rol {name} guardado. Ya se aplica a sus miembros conectados.", {name: payload.name}))
            : roleWrite("/api/roles/create", payload, t("Rol {name} creado.", {name: payload.name}));
    });
}

function deleteRole(role) {
    const fallback = ROLES.roles.find((r) => r.default && r.role_id !== role.role_id);
    const role_name = fallback ? esc(roleLabel(fallback.name)) : "";
    const who = !role.members ? t("Nadie tiene este rol.")
        : fallback ? tn(role.members, "Su único miembro pasa al rol {role}.", "Sus {n} miembros pasan al rol {role}.", {role: role_name})
        : tn(role.members, "Su único miembro pasa a no tener rol.", "Sus {n} miembros pasan a no tener rol.");
    confirmBox(t("¿Eliminar el rol {name}?", {name: esc(role.name)}), who, t("Eliminar"), () => {
        roleWrite("/api/roles/delete", {role_id: role.role_id}, t("Rol {name} eliminado.", {name: role.name})).then((message) => message && toast(message, "bad"));
    });
}

function memberPermissions(member) {
    const editable = member.actions.grant || member.actions.revoke;
    const rules = {current: member.permissions, targetPrimary: member.primary, canAdd: member.actions.grant, canRemove: member.actions.revoke};
    const role = ROLES.roles.find((r) => r.role_id === member.role_id);
    const intro = `<p style="margin:0 0 6px;font-size:13px">${role ? t("Se suman a los de su rol ({role}); si coinciden, vale el más amplio.", {role: esc(roleLabel(role.name))}) : t("Se suman a los de su rol; si coinciden, vale el más amplio.")}</p>`;
    const title = t("Permisos propios de {name}", {name: esc(member.username || member.email)});
    if (!editable) {
        modal(title, intro + permissionMatrix(rules.current, rules), t("Cerrar"), () => null);
        $("[data-modal] form").dataset.wide = "";
        return $$("[data-modal] form select").forEach((el) => (el.disabled = true));
    }
    wideModal(title, intro + permissionMatrix(rules.current, rules), t("Guardar"), (f) =>
        roleWrite("/api/roles/permissions", {account_id: member.account_id, permissions: readMatrix(f)},
            t("Permisos de {name} guardados. Ya se aplican.", {name: member.username})));
}

const roleOf = (el) => ROLES && ROLES.roles.find((r) => r.role_id === el.closest("[data-role]").dataset.role);
const roleMemberOf = (id) => ROLE_MEMBERS && ROLE_MEMBERS.rows.find((m) => m.account_id === id);

document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-role-new],[data-role-edit],[data-role-delete],[data-member-perms],[data-role-page]");
    if (!b || b.disabled) return;
    if (b.hasAttribute("data-role-new")) return roleModal(null);
    if (b.hasAttribute("data-role-edit")) return roleModal(roleOf(b));
    if (b.hasAttribute("data-role-delete")) return deleteRole(roleOf(b));
    if (b.dataset.memberPerms) return memberPermissions(roleMemberOf(b.dataset.memberPerms));
    roleUi.page = Math.max(1, roleUi.page + Number(b.dataset.rolePage));
    loadRoleMembers();
});

document.addEventListener("input", (e) => {
    if (!e.target.matches("[data-role-filter]")) return;
    roleUi.filter = e.target.value;
    roleUi.page = 1;
    loadRoleMembers();
});

document.addEventListener("change", (e) => {
    if (e.target.matches("[data-role-size]")) {
        roleUi.size = Number(e.target.value);
        roleUi.page = 1;
        return loadRoleMembers();
    }
    if (!e.target.matches("[data-role-assign]")) return;
    const select = e.target, member = roleMemberOf(select.dataset.roleAssign), role_id = select.value || null;
    const role = ROLES.roles.find((r) => r.role_id === role_id), previous = member.role_id || null;
    const assign = (to, done, action) => {
        select.disabled = true;
        roleWrite("/api/roles/assign", {account_id: member.account_id, role_id: to}, done, action).then((message) => {
            if (!message) return;
            toast(message, "bad");
            paintRoleMembers();
        });
    };
    const done = role ? t("{name} ahora tiene el rol {role}.", {name: member.username, role: roleLabel(role.name)}) : t("{name} ya no tiene rol.", {name: member.username});
    const undo = {label: t("Deshacer"), run: () => assign(previous, t("Se restauró el rol de {name}.", {name: member.username}))};
    const apply = () => {
        select.value = role_id || "";
        assign(role_id, done, undo);
    };
    // Granting everything, or changing one's own access, asks first; the rest applies with Deshacer.
    if (!(role && role.administrator) && !member.me) return apply();
    select.value = previous || "";
    if (member.me) return confirmBox(t("¿Cambiar su propio rol?"), t("Puede perder permisos en este panel y no podrá devolvérselos usted mismo."), t("Cambiar"), apply);
    confirmBox(t("¿Dar el rol {role} a {name}?", {role: esc(roleLabel(role.name)), name: esc(member.username)}),
        t("Tendrá todos los permisos de la organización, también cambiar roles y eliminar redes."), t("Dar el rol"), apply);
});
