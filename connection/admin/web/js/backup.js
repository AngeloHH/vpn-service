"use strict";

/* ---------- Copia de seguridad de la configuración (Sistema) ---------- */
// The virtual HTTP server refuses bodies over 1 MB; the file is checked here first.
const BACKUP_LIMIT = 1048576;

Object.assign(NETWORK_ERRORS, {
    invalid_backup: () => t("El archivo no es una copia válida o no encaja con este servidor."),
    backup_without_you: () => t("En esa copia usted no es administrador: no puede restaurarla."),
});

const canBackup = () => !!ME && (ME.administrator || !!(ME.permissions || {})["organization:view"]);
const canRestore = () => !!ME && ME.administrator;

function backupCard() {
    const muted = 'style="color:var(--anatomy-muted)"';
    const download = canBackup() ? "" : " disabled";
    const restore = canRestore() ? "" : " disabled";
    return card(t("Copia de seguridad"), `<p style="margin:0 0 12px;font-size:13px">${t("Guarde la configuración de la organización en un archivo para restaurarla después.")}</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="rt-btn" type="button" data-act="backup-download"${download}>${t("Descargar copia")}</button>
    <button class="rt-btn" type="button" data-act="backup-restore"${restore}>${t("Restaurar desde archivo")}</button>
    <input type="file" accept="application/json,.json" data-backup-file hidden></div>
    <p style="margin:10px 0 0;font-size:12.5px" ${muted}>${t("Incluye redes, direcciones, roles, miembros, permisos, límites, reglas y reenvíos. No incluye cuentas ni contraseñas.")}</p>
    ${canRestore() ? "" : `<p style="margin:6px 0 0;font-size:12.5px" ${muted}>${t("Solo un administrador puede restaurar una copia.")}</p>`}`);
}

async function downloadBackup() {
    const response = await api("GET", "/api/backup").catch(() => null);
    if (!response) return toast(t("No se pudo contactar con el servidor."), "bad");
    if (response.status === 401) return showLogin();
    if (!response.ok) return toast(response.status === 403 ? t("No tiene permiso para esta acción.") : t("La acción falló."), "bad");
    const backup = await response.json();
    const day = (backup.created || "").slice(0, 10) || "copia";
    download(`vpn-backup-${day}.json`, JSON.stringify(backup, null, 1));
    toast(t("Copia descargada."));
}

async function restorePost(backup, confirm) {
    // Without confirm the server only checks the file and answers what would change.
    const result = await networkPost("/api/backup/restore", {backup, confirm});
    if (result.status === 413) result.message = t("El archivo es demasiado grande: el máximo es 1 MB.");
    return result;
}

function restoreSummary(summary) {
    const lines = [t("La organización quedará exactamente como en la copia: {networks}, {roles} y {members}.", {
        networks: tn(summary.networks, "{n} red", "{n} redes"),
        roles: tn(summary.roles, "{n} rol", "{n} roles"),
        members: tn(summary.members, "{n} miembro", "{n} miembros"),
    })];
    if (summary.leaving) lines.push(tn(summary.leaving, "{n} miembro que no está en la copia saldrá de la organización.",
        "{n} miembros que no están en la copia saldrán de la organización."));
    lines.push(t("Todos se desconectarán y volverán a conectarse, usted también."));
    let body = lines.map((line) => `<p style="margin:0 0 8px;font-size:14px">${esc(line)}</p>`).join("");
    const skipped = summary.skipped || [];
    if (skipped.length) {
        const names = skipped.slice(0, 20).map((person) => `<li>${esc(person.email || person.username || "-")}</li>`).join("");
        const more = skipped.length > 20 ? `<li>${esc(t("y {n} más", {n: skipped.length - 20}))}</li>` : "";
        body += `<p style="margin:4px 0 4px;font-size:13px">${esc(tn(skipped.length,
            "{n} persona de la copia no tiene cuenta en este servidor y no se agregará:",
            "{n} personas de la copia no tienen cuenta en este servidor y no se agregarán:"))}</p>
        <ul style="margin:0;padding-left:18px;font-size:13px;max-height:140px;overflow:auto">${names}${more}</ul>`;
    }
    return body;
}

async function restoreFile(file) {
    let backup;
    try {
        backup = JSON.parse(await file.text());
    } catch (error) {
        return toast(t("El archivo no es una copia válida o no encaja con este servidor."), "bad");
    }
    if (new Blob([JSON.stringify({backup, confirm: true})]).size > BACKUP_LIMIT) {
        return toast(t("El archivo es demasiado grande: el máximo es 1 MB."), "bad");
    }
    const preview = await restorePost(backup, false);
    if (preview.message) return toast(preview.message, "bad");
    serverModal(t("¿Restaurar esta copia?"), restoreSummary(preview.data), t("Restaurar"), async () => {
        const result = await restorePost(backup, true);
        if (result.message) return result.message;
        toast(t("Copia restaurada. Reconectando…"));
        return null;
    }, {danger: true});
}

Object.assign(ACT, {
    "backup-download"() {
        if (canBackup()) downloadBackup();
    },
    "backup-restore"() {
        const input = $("[data-backup-file]");
        if (!canRestore() || !input) return;
        input.value = "";
        input.onchange = () => input.files[0] && restoreFile(input.files[0]);
        input.click();
    },
});
