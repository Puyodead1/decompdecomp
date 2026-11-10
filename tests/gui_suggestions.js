// A suggestion as the Steering tab and Settings → Compiler show it (steering.js's suggestionHtml), run in node: its
// number heads it, the one range checks, agents' notes and the event log call it by ("range check #2 of suggestion
// #8"). Cards said only "suggested", and a user couldn't tell which was which.
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const source = fs.readFileSync(path.join(__dirname, "../src/decompnet/app/static/js/steering.js"), "utf8");
const start = source.indexOf("function saidHead(");
const end = source.indexOf("$(\"suggestList\").onclick");
const ctx = {
  esc: (s) => String(s), clock: () => "now", miniMarkdown: (s) => s, plural: (n, w) => `${n} ${w}s`,
  S: { st: { toolchains: [{ id: "gcc-2.95.3-linux", name: "GCC 2.95.3" }] } },
};
vm.createContext(ctx);
vm.runInContext(source.slice(start, end) + "\nthis.suggestionHtml = suggestionHtml;", ctx);

const one = ctx.suggestionHtml({ id: 7, agents: ["agent-1"], t: 1, text: "needs -fno-gcse", toolchain: "gcc-2.95.3-linux",
                                  flags: ["-O2", "-fno-gcse"], ranges: [], check: "checked: f's C matches the game" });
assert.match(one, /suggestion #7</);
const two = ctx.suggestionHtml({ id: 8, agents: ["a", "b"], t: 1, text: "x", toolchain: "gcc-2.95.3-linux",
                                  flags: ["-O2"], ranges: [[1, 2]], check: "range check #2: checking" });
assert.match(two, /suggestion #8 · 2 agents agree/);
assert.match(two, /range check #2/);
