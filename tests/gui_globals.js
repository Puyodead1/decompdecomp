// The Globals tab's list (globals.js) against a stand-in page: loading, search, filter, sort, and a project-mode note.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = (file) => fs.readFileSync(path.join(__dirname, "../src/decompnet/app/static/js", file + ".js"), "utf8");

function element() {
  return { hidden: false, value: "", textContent: "", innerHTML: "", dataset: {}, listeners: {},
    addEventListener(kind, fn) { this.listeners[kind] = fn; } };
}
const elements = new Map();
const $ = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
let answer = null, asked = [];
const ctx = {
  $, S: { slug: "g", tab: "globals" },
  api: async (url) => { asked.push(url); return answer; },
  esc: (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  plural: (n, word) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`,
};
vm.createContext(ctx);
const base = read("base");
vm.runInContext(base.slice(base.indexOf("const hex8"), base.indexOf("\n", base.indexOf("const hex8"))), ctx);
vm.runInContext(read("globals"), ctx);

const keys = ["name", "address", "size", "kind", "preview", "original"];
answer = { supported: true, keys, named: 1, rows: [
  ["sDirectKey", 0x800A4DFC, 4, "data", "0x00000001", "D_800A4DFC"],
  ["D_800A4E00", 0x800A4E00, 8, "bss", "", "D_800A4E00"],
  ["<b>odd</b>", 0x800A4E10, 0, "rodata", "\"hi\"", "D_800A4E10"],
] };

(async () => {
  await ctx.loadGlobals("g");
  assert.equal(asked[0], "/api/globals?slug=g");
  let rows = $("globalsRows").innerHTML;
  assert.equal((rows.match(/<tr>/g) || []).length, 3);
  assert.ok(rows.indexOf("sDirectKey") < rows.indexOf("D_800A4E00"));          // by address first
  assert.ok(rows.includes("&lt;b&gt;odd&lt;/b&gt;") && !rows.includes("<b>odd"));  // names reach the page escaped
  assert.equal($("gTabCount").textContent, "3");
  assert.equal($("globalsNote").hidden, true);
  assert.match($("globalsFilter").innerHTML, /Named<span>2<\/span>/);
  assert.match($("globalsFilter").innerHTML, /Not named yet<span>1<\/span>/);

  // Either name finds it, and so does its address with or without 0x.
  for (const q of ["sdirect", "D_800A4DFC", "0x800a4dfc", "800A4DFC"]) {
    $("globalsSearch").value = q; $("globalsSearch").listeners.input();
    assert.equal(($("globalsRows").innerHTML.match(/<tr>/g) || []).length, 1, q);
    assert.ok($("globalsRows").innerHTML.includes("sDirectKey"), q);
  }
  $("globalsSearch").value = "nothing"; $("globalsSearch").listeners.input();
  assert.match($("globalsRows").innerHTML, /No global matches “nothing”/);
  $("globalsSearch").value = ""; $("globalsSearch").listeners.input();

  // Not named yet: the ones still called by their address.
  $("globalsFilter").listeners.click({ target: { closest: () => ({ dataset: { gfilter: "unnamed" } }) } });
  rows = $("globalsRows").innerHTML;
  assert.ok(rows.includes("D_800A4E00") && !rows.includes("sDirectKey"));
  $("globalsFilter").listeners.click({ target: { closest: () => ({ dataset: { gfilter: "all" } }) } });

  // Sort by size, then again for the other way; a missing size stays last both ways.
  const click = (k) => $("globalsHead").listeners.click({ target: { closest: () => ({ dataset: { gsort: k } }) } });
  click("size");
  rows = $("globalsRows").innerHTML;
  assert.ok(rows.indexOf("sDirectKey") < rows.indexOf("D_800A4E00") && rows.indexOf("D_800A4E00") < rows.indexOf("odd"));
  click("size");
  rows = $("globalsRows").innerHTML;
  assert.ok(rows.indexOf("D_800A4E00") < rows.indexOf("sDirectKey"));
  assert.match($("globalsHead").innerHTML, /aria-sort="descending"><button[^>]*data-gsort="size">Size ↓/);

  // A project-mode game says why its list is empty.
  answer = { supported: false, keys, rows: [], named: 0, reason: "Globals are listed for ROM projects." };
  ctx.S.slug = "fork";
  await ctx.loadGlobals("fork");
  assert.equal($("globalsNote").hidden, false);
  assert.equal($("globalsNote").textContent, "Globals are listed for ROM projects.");
  assert.equal($("gTabCount").textContent, "");
  assert.match($("globalsRows").innerHTML, /Nothing listed for this project yet/);

  // An answer for a project no longer open is dropped.
  let release; answer = new Promise((resolve) => { release = resolve; });
  const late = ctx.loadGlobals("other");
  ctx.S.slug = "fork";
  release({ supported: true, keys, rows: [["x", 1, 0, "data", "", "D_00000001"]], named: 1 });
  await late;
  assert.equal($("gTabCount").textContent, "");
  console.log("globals tab passed");
})().catch((error) => { console.error(error); process.exit(1); });
