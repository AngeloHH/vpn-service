"use strict";

/* ---------- Idiomas del panel ---------- */
// Texts are written in Spanish in the code; each language maps them to its own.
const LANGUAGES = {es: "Español", en: "English", zh: "中文", ru: "Русский"};
const LOCALES = {es: "es", en: "en", zh: "zh-CN", ru: "ru"};
const I18N = {en: {}, zh: {}, ru: {}};

function detectLanguage() {
    let saved = null;
    try { saved = localStorage.getItem("panel-language"); } catch { }
    if (saved && LANGUAGES[saved]) return saved;
    // The first language of the browser that the panel knows; English otherwise.
    for (const tag of navigator.languages || [navigator.language || ""]) {
        const code = String(tag).toLowerCase().split("-")[0];
        if (LANGUAGES[code]) return code;
    }
    return "en";
}

let LANG = detectLanguage();

const currentLanguage = () => LANG;

// The administrator role is created by the server with this Spanish name, which never changes.
const roleLabel = (name) => name === "Administrador" ? t("Administrador") : name;

// tk("...") marks a text kept in a table and translated later with t(); it returns it as is.
const tk = (text) => text;

// t("Hay {n} en uso", {n: 3}): the text in the current language, with its values.
function t(text, values) {
    const language = currentLanguage();
    const translated = language !== "es" && I18N[language][text];
    let result = typeof translated === "string" ? translated : text;
    if (values) result = result.replace(/\{(\w+)\}/g, (whole, name) => name in values ? values[name] : whole);
    return result;
}

// tn(n, "{n} equipo", "{n} equipos"): Spanish picks one of the two; a translation of
// the plural text may be one string or {one, few, many, other} by the language's rules.
function tn(count, one, other, values) {
    const language = currentLanguage(), all = Object.assign({n: count}, values);
    let text = count === 1 ? one : other;
    if (language !== "es") {
        const entry = I18N[language][other];
        if (typeof entry === "string") text = entry;
        else if (entry) text = entry[new Intl.PluralRules(LOCALES[language]).select(count)] || entry.other;
    }
    return text.replace(/\{(\w+)\}/g, (whole, name) => name in all ? all[name] : whole);
}

// Static texts of the page: data-i18n holds the Spanish text of the element.
function translateStatic(root = document) {
    for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of root.querySelectorAll("[data-i18n-label]")) el.setAttribute("aria-label", t(el.dataset.i18nLabel));
    for (const el of root.querySelectorAll("[data-i18n-title]")) el.title = t(el.dataset.i18nTitle);
    document.documentElement.lang = currentLanguage() === "zh" ? "zh-CN" : currentLanguage();
    document.title = t("Panel del router");
    for (const slot of root.querySelectorAll("[data-language-slot]")) {
        slot.innerHTML = slot.dataset.languageSlot === "login" ? `<div style="margin-top:12px">${languagePicker()}</div>` : languagePicker();
    }
}

function languagePicker() {
    return `<select class="rt-in" data-language aria-label="${esc(t("Idioma"))}" style="width:auto;padding:5px 26px 5px 9px">${
        Object.entries(LANGUAGES).map(([code, name]) => `<option value="${code}"${code === LANG ? " selected" : ""}>${name}</option>`).join("")}</select>`;
}

function setLanguage(code) {
    if (!LANGUAGES[code]) return;
    LANG = code;
    try { localStorage.setItem("panel-language", code); } catch { }
    translateStatic();
    // Everything drawn from code is drawn again in the new language.
    if (!$("[data-view=app]").hidden) {
        syncHeader();
        render();
    }
}

document.addEventListener("change", (e) => {
    if (e.target.matches("[data-language]")) setLanguage(e.target.value);
});
