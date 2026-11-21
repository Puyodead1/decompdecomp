/* A C++ function is named as written in the window (`zl::List<float>::allocate(int)`), never by its symbol
   (`_ZN2zl4ListIfE8allocateEi`), which stays the link and the hover title. Run: node --test tests/gui_cxx_names.js */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const base = fs.readFileSync(path.join(__dirname, "../src/decompnet/app/static/js/base.js"), "utf8");
const take = (name) => base.slice(base.indexOf(`function ${name}(`), base.indexOf("\n}\n", base.indexOf(`function ${name}(`)) + 2);
const esc = base.match(/^const esc = .*$/m)[0];

test("fnLabel names a C++ function as written and keeps its symbol as the title", () => {
  const ctx = { S: {} };
  vm.createContext(ctx);
  vm.runInContext(`${esc}\n${take("fnLabel")}\n${take("fnTitled")}\nthis.fnLabel = fnLabel; this.fnTitled = fnTitled;`, ctx);
  assert.equal(ctx.fnLabel("_ZN2zl4ListIfE8allocateEi"), "_ZN2zl4ListIfE8allocateEi");  // (no project open)
  ctx.S.map = [{ name: "_ZN2zl4ListIfE8allocateEi", cxx: "zl::List<float>::allocate(int)" }, { name: "main", cxx: null }];
  ctx.S.byName = new Map(ctx.S.map.map((f, i) => [f.name, i]));
  assert.equal(ctx.fnLabel("_ZN2zl4ListIfE8allocateEi"), "zl::List<float>::allocate(int)");
  assert.equal(ctx.fnLabel("main"), "main");
  assert.equal(ctx.fnLabel("_Zother", "other()"), "other()");  // (another project's, as the server named it)
  assert.equal(ctx.fnTitled("_ZN2zl4ListIfE8allocateEi"),
    '<span title="_ZN2zl4ListIfE8allocateEi">zl::List&lt;float&gt;::allocate(int)</span>');
  assert.equal(ctx.fnTitled("main"), "main");
});
