"use strict";

/* ---------- Utilidades ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const clone = (o) => JSON.parse(JSON.stringify(o));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
}[c]));
const getP = (o, p) => p.split(".").reduce((a, k) => (a == null ? a : a[k]), o);
const setP = (o, p, v) => {
    const ks = p.split(".");
    const last = ks.pop();
    ks.reduce((a, k) => a[k], o)[last] = v;
};
const pad = (n) => String(n).padStart(2, "0");
// Panel API: same-origin cookies plus the header the server requires on writes.
const api = (method, path, body) => fetch(path, {
    method,
    credentials: "same-origin",
    headers: Object.assign({"X-Requested-With": "vpn-panel"}, body ? {"Content-Type": "application/json"} : {}),
    body: body ? JSON.stringify(body) : undefined,
});
const ipToInt = (ip) => ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;

const fmtUp = (ms) => {
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    return t("{d} d", {d}) + ` ${pad(Math.floor(s / 3600) % 24)}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
};
const fmtRate = (kbps) => kbps >= 1000 ? (kbps / 1000).toFixed(1) + " Mbps" : Math.round(kbps) + " kbps";
const fmtBytes = (mb) => mb >= 1024 ? (mb / 1024).toFixed(2) + " GB" : mb.toFixed(0) + " MB";
const fmtAgo = (since) => {
    const m = Math.floor((Date.now() - since) / 60000);
    if (m < 1) return t("ahora");
    if (m < 60) return t("{m} min", {m});
    const h = Math.floor(m / 60);
    return h < 24 ? t("{h} h {m} min", {h, m: m % 60}) : t("{d} d {h} h", {d: Math.floor(h / 24), h: h % 24});
};
const fmtTime = (t) => {
    const d = new Date(t);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
