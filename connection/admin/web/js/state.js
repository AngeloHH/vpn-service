"use strict";

/* ---------- Estado de la vista ---------- */
// S holds the values the server saved for each form; draft, the ones being edited.
// Only the network pages have forms: their slices are "net:<id>".
let S = {switchSize: 8};
let page = "estado";
let draft = clone(S);
let errors = {};
let ui = {
    clientFilter: "",
    clientIface: "all",
    clientPage: 1,
    clientSize: 25,
    port: null,
    diagOut: "",
    diagBusy: false,
    logLevel: "all"
};

// Pages whose form slices decide whether there are unsaved changes.
const SLICES = {};

try {
    const size = Number(localStorage.getItem("panel-switch-size"));
    if ([4, 5, 8, 16, 24, 48].includes(size)) S.switchSize = size;
} catch { }

const formDirty = () => (SLICES[page] || []).some((k) => JSON.stringify(draft[k]) !== JSON.stringify(S[k]));
// The limits tables of this page: a network's own, or the internet ones on Internet (WAN).
const limitKeys = () => page === "internet" ? ["internet"] : networkOfPage() ? [networkOfPage().id] : [];
const limitsDirty = () => limitKeys().filter((key) => LIMITS[key] && LIMITS[key].changed);
// One model for everything typed into a page: the bar, Ctrl+S and the warning before leaving.
const dirty = () => formDirty() || limitsDirty().length > 0;

function syncSavebar() {
    $("[data-savebar]").toggleAttribute("data-show", dirty());
}

/* ---------- Guardar ---------- */
function save() {
    for (const key of limitsDirty()) saveLimits(key);
    if (networkOfPage() && formDirty()) return saveNetwork();
}

// Edits of the limits are thrown away with the rest of the page's changes.
function dropLimitEdits() {
    for (const key of limitsDirty()) delete LIMITS[key];
}

function discard() {
    draft = clone(S);
    errors = {};
    dropLimitEdits();
    render();
}
