"use strict";

/* ---------- Consumo del mes por persona ---------- */
// USAGE["internet" | network id]: the rows shown, the total and the month.
const USAGE = {};
const USAGE_PAGE = 25;
const usageKey = (networkId) => networkId || "internet";
// Decimal units, like the quotas: 1 GB = 1000 MB.
const fmtData = (bytes) => bytes >= 1e9 ? (bytes / 1e9).toFixed(2) + " GB" : Math.round(bytes / 1e6) + " MB";

function forgetUsage() {
    for (const key in USAGE) delete USAGE[key];
}

// "1.20 GB de 5.00 GB": what was spent against the quota, extras included.
function usedOf(bytes, quotaMb, extraBytes) {
    if (quotaMb == null) return fmtData(bytes);
    const quota = quotaMb * 1e6 + extraBytes;
    return `${fmtData(bytes)} <small style="color:var(--anatomy-muted)">${t("de {total}", {total: fmtData(quota)})}</small>${bytes >= quota ? ` <span class="rt-tag" data-tone="red">${t("agotado")}</span>` : ""}`;
}

function usageCard(networkId) {
    const key = usageKey(networkId), data = USAGE[key], muted = 'style="color:var(--anatomy-muted)"';
    const title = t("Consumo del mes");
    if (data && data.forbidden) return "";
    const period = data && data.period ? ` (${esc(data.period)})` : "";
    const intro = `<p style="margin:0 0 10px;font-size:13px">${networkId
        ? t("Lo que cada persona lleva gastado en esta red desde el día 1{period}, con su cuota si tiene una. Los extras del mes ya están sumados a la cuota.", {period})
        : t("Lo que cada persona lleva gastado en internet, sumando todas las redes, desde el día 1{period}, con su cuota si tiene una. Los extras del mes ya están sumados a la cuota.", {period})}</p>`;
    const rows = !data ? `<tr><td colspan="3" class="rt-empty">${t("Cargando…")}</td></tr>` : data.rows.length ? data.rows.map((r) => `<tr>
      <td class="rt-name">${esc(r.username || "-")}<br><small ${muted}>${esc(r.email || "-")}</small></td>
      <td>${usedOf(r.down, r.quota_down, r.extra_down)}</td><td>${usedOf(r.up, r.quota_up, r.extra_up)}</td></tr>`).join("")
        : `<tr><td colspan="3" class="rt-empty">${t("No hay miembros.")}</td></tr>`;
    const more = data && data.rows.length < data.total ? `<div class="rt-tools" style="margin:8px 0 2px">
    <button class="rt-btn" data-sm type="button" data-usage-more="${esc(key)}">${t("Cargar más")}</button>
    <span style="font:12px var(--anatomy-mono);color:var(--anatomy-muted)">${t("{used} de {total}", {used: data.rows.length, total: data.total})}</span></div>` : "";
    return card(title, intro + `<div class="rt-wrap"><table class="rt-table"><thead><tr><th>${t("Persona")}</th><th>${t("Bajada")}</th><th>${t("Subida")}</th></tr></thead><tbody>${rows}</tbody></table></div>` + more,
        `<button class="rt-btn" data-sm type="button" data-usage-refresh="${esc(key)}">${t("Actualizar")}</button>`);
}

async function loadUsage(networkId, more = false) {
    // Most consumption first; a refresh keeps as many rows as were shown.
    const key = usageKey(networkId), shown = USAGE[key] && USAGE[key].rows ? USAGE[key].rows.length : 0;
    const offset = more ? shown : 0, limit = more ? USAGE_PAGE : Math.max(USAGE_PAGE, shown);
    const network = networkId ? "&network=" + encodeURIComponent(networkId) : "";
    const response = await api("GET", `/api/usage?offset=${offset}&limit=${limit}${network}`).catch(() => null);
    if (!response) return;
    if (response.status === 401) return showLogin();
    if (response.status === 403) USAGE[key] = {forbidden: true};
    else if (response.ok) {
        const loaded = await response.json();
        if (more && USAGE[key] && USAGE[key].rows) loaded.rows = USAGE[key].rows.concat(loaded.rows);
        USAGE[key] = loaded;
    } else return;
    const box = $(`[data-usage="${key}"]`);
    if (box) box.innerHTML = usageCard(networkId);
}

document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-usage-more],[data-usage-refresh]");
    if (!b) return;
    const key = b.dataset.usageMore || b.dataset.usageRefresh;
    loadUsage(key === "internet" ? null : key, !!b.dataset.usageMore);
});
