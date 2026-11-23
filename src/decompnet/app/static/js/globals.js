/* The Globals tab: the game's data symbols, searchable by the name they have now or the D_ address name they started
   as (D_800A4DFC → sDirectKey). Read-only, like the Functions list; renames happen through the agents' rename_symbol.
   Loaded when the tab opens (setTab), so a game with thousands of globals costs nothing until someone looks. */
const GLOBAL_ROWS = 500;
const G = { slug: null, rows: [], supported: true, reason: "", q: "", filter: "all", sort: "address", dir: 1, limit: GLOBAL_ROWS, request: 0 };
const GLOBAL_COLUMNS = [["address", "Address"], ["name", "Name"], ["original", "Address name"], ["size", "Size", "r"], ["kind", "Kind"], ["preview", "Value"]];

async function loadGlobals(slug) {
  if (!slug) return;
  if (G.slug !== slug) {
    Object.assign(G, { slug, rows: [], supported: true, reason: "", q: "", filter: "all", limit: GLOBAL_ROWS });
    $("globalsSearch").value = "";
    $("gTabCount").textContent = "";
  }
  const request = ++G.request;
  $("globalsShown").textContent = "Loading globals…";
  try {
    const data = await api(`/api/globals?slug=${encodeURIComponent(slug)}`);
    if (request !== G.request || S.slug !== slug) return;  // another project, or a newer answer
    G.supported = data.supported; G.reason = data.reason || "";
    // A size of 0 is one nobody knows (shown "–"): sorted with the missing values, last.
    G.rows = data.rows.map((r) => Object.fromEntries(data.keys.map((k, i) => [k, k === "size" && !r[i] ? null : r[i]])));
    renderGlobals();
  } catch (error) {
    if (request === G.request && S.slug === slug) $("globalsShown").textContent = `Could not load globals: ${error.message}`;
  }
}

/* The rows the search and filter keep, in the chosen order. Missing values sort last in either direction. */
function globalsShown() {
  const named = (r) => r.name !== r.original;
  const q = G.q.trim().toLowerCase(), hex = q.replace(/^0x/, "");
  const rows = G.rows.filter((r) => (G.filter === "all" || (G.filter === "named") === named(r)) &&
    (!q || r.name.toLowerCase().includes(q) || r.original.toLowerCase().includes(q)
      || (hex && hex8(r.address).toLowerCase().includes(hex)) || (r.preview || "").toLowerCase().includes(q)));
  const key = (v) => typeof v === "string" ? v.toLowerCase() : v;
  const missing = (v) => v === "" || v == null;
  return rows.sort((a, b) => {
    const x = a[G.sort], y = b[G.sort];
    if (missing(x) !== missing(y)) return missing(x) ? 1 : -1;
    return (key(x) < key(y) ? -1 : key(x) > key(y) ? 1 : a.address - b.address) * G.dir;
  });
}

function renderGlobals() {
  if (S.tab !== "globals" || G.slug !== S.slug) return;
  const named = (r) => r.name !== r.original;
  const counts = { all: G.rows.length, named: G.rows.filter(named).length };
  counts.unnamed = counts.all - counts.named;
  $("globalsFilter").innerHTML = [["all", "All"], ["named", "Named"], ["unnamed", "Not named yet"]].map(([k, label]) =>
    `<button type="button" role="radio" aria-checked="${G.filter === k}" class="${G.filter === k ? "on" : ""}" data-gfilter="${k}">${label}<span>${counts[k].toLocaleString()}</span></button>`).join("");
  $("globalsNote").hidden = G.supported;
  $("globalsNote").textContent = G.reason;
  const rows = globalsShown();
  $("globalsHead").innerHTML = `<tr>${GLOBAL_COLUMNS.map(([k, label, cls]) =>
    `<th scope="col" class="${cls || ""}" aria-sort="${G.sort === k ? (G.dir > 0 ? "ascending" : "descending") : "none"}"><button type="button" class="sort-btn" data-gsort="${k}">${label}${G.sort === k ? (G.dir > 0 ? " ↑" : " ↓") : ""}</button></th>`).join("")}</tr>`;
  $("globalsRows").innerHTML = rows.slice(0, G.limit).map((r) =>
    `<tr><td class="mono dim">${hex8(r.address)}</td><td class="mono name">${esc(r.name)}</td><td class="mono dim">${named(r) ? esc(r.original) : ""}</td>
      <td class="r mono">${r.size ? r.size.toLocaleString() : `<span class="dim">–</span>`}</td><td>${esc(r.kind)}</td><td class="mono dim">${esc(r.preview || "")}</td></tr>`).join("")
    || `<tr class="none"><td colspan="6">${G.rows.length ? `No global matches${G.q.trim() ? ` “${esc(G.q.trim())}”` : ""}.` : G.supported ? "No data symbols recorded for this project." : "Nothing listed for this project yet."}</td></tr>`;
  $("globalsShown").textContent = rows.length > G.limit ? `${G.limit.toLocaleString()} of ${rows.length.toLocaleString()} shown` : plural(rows.length, "global");
  $("globalsMore").hidden = rows.length <= G.limit;
  $("gTabCount").textContent = G.rows.length ? G.rows.length.toLocaleString() : "";
}

$("globalsFilter").addEventListener("click", (e) => { const b = e.target.closest("[data-gfilter]"); if (b) { G.filter = b.dataset.gfilter; G.limit = GLOBAL_ROWS; renderGlobals(); } });
$("globalsSearch").addEventListener("input", () => { G.q = $("globalsSearch").value; G.limit = GLOBAL_ROWS; renderGlobals(); });
$("globalsMore").onclick = () => { G.limit += GLOBAL_ROWS; renderGlobals(); };
$("globalsHead").addEventListener("click", (e) => {
  const b = e.target.closest("[data-gsort]"); if (!b) return;
  if (G.sort === b.dataset.gsort) G.dir = -G.dir; else { G.sort = b.dataset.gsort; G.dir = 1; }
  renderGlobals();
});
