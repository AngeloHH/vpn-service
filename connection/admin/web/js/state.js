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

const dirty = () => (SLICES[page] || []).some((k) => JSON.stringify(draft[k]) !== JSON.stringify(S[k]));

function syncSavebar() {
    $("[data-savebar]").toggleAttribute("data-show", dirty());
}

/* ---------- Guardar ---------- */
function save() {
    // Only network pages have something to save.
    if (networkOfPage()) return saveNetwork();
}

function discard() {
    draft = clone(S);
    errors = {};
    render();
}
