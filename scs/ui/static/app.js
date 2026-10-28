/* Packhound UI — vanilla JS, no dependencies. All text from scan data is escaped. */
"use strict";

// ---------------------------------------------------------------- token + API
// optional deep link next to the token: #token=…&page=findings&tab=wait
const START = { page: (location.hash.match(/[&]page=(\w+)/) || [])[1] || "home",
                tab: (location.hash.match(/[&]tab=(act|update|check|wait)\b/) || [])[1] || "act" };
const TOKEN = (() => {
  const m = location.hash.match(/token=([\w-]+)/);
  if (m) {
    try { sessionStorage.setItem("scs-token", m[1]); } catch (e) { /* storage may be unavailable */ }
    history.replaceState(null, "", location.pathname + "#/" + START.page);
    return m[1];
  }
  try { return sessionStorage.getItem("scs-token") || ""; } catch (e) { return ""; }
})();

async function api(path, body) {
  const opts = { headers: { "X-SCS-Token": TOKEN } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const when = (iso) => {
  if (!iso) return "never";
  const d = new Date(iso);
  const mins = Math.round((Date.now() - d) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  if (mins < 60 * 24) return `${Math.round(mins / 60)} h ago`;
  return d.toLocaleDateString();
};
let STATE = { status: null, findings: null, malware: null, tab: START.tab, search: "", plan: null };

// ---------------------------------------------------------------- jobs (bottom bar)
let jobTimer = null;
async function runJob(promise, onDone) {
  let job;
  try { job = await promise; } catch (e) { return toast(e.message, "bad"); }
  const bar = $("#jobbar"), log = $("#job-log"), cancel = $("#job-cancel");
  bar.classList.remove("hidden", "done", "failed", "cancelled");
  $("#job-title").textContent = job.title;
  $("#job-line").textContent = "Starting…";
  log.textContent = "";
  cancel.classList.toggle("hidden", !job.cancellable);
  cancel.disabled = false;
  cancel.textContent = "Cancel";
  cancel.onclick = async () => {
    cancel.disabled = true;
    cancel.textContent = "Cancelling…";
    try { await api(`/api/jobs/${job.id}/cancel`, {}); } catch (e) { toast(e.message, "bad"); cancel.disabled = false; }
  };
  let since = 0, lastLine = "Starting…", failures = 0;
  const fmt = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  clearInterval(jobTimer);
  jobTimer = setInterval(async () => {
    let v;
    try { v = await api(`/api/jobs/${job.id}?since=${since}`); failures = 0; }
    catch (e) {
      if (++failures >= 5) $("#job-line").textContent = `Lost contact with the scanner (${e.message}). Is the app still running?`;
      return;
    }
    since = v.log_size;
    if (v.log.length) {
      log.textContent += v.log.join("\n") + "\n";
      log.scrollTop = log.scrollHeight;
      lastLine = v.log.filter((l) => l.trim()).pop() || lastLine;
    }
    $("#job-title").textContent = `${job.title} · ${fmt(v.elapsed)}`;
    // a step can legitimately take a while (slow network); say so instead of looking frozen
    const stalled = v.idle >= 30 ? ` — still working, no news for ${fmt(v.idle)} (slow network?)` : "";
    $("#job-line").textContent = (v.cancel_requested ? "Stopping after the current step… " : "") + lastLine + stalled;
    if (v.state !== "running") {
      clearInterval(jobTimer);
      cancel.classList.add("hidden");
      bar.classList.add(v.state);
      $("#job-line").textContent = { done: "Finished", cancelled: "Cancelled", failed: `Failed: ${v.error}` }[v.state] || v.state;
      setTimeout(() => bar.classList.add("hidden"), v.state === "failed" ? 30000 : 6000);
      await refresh();
      if (onDone && v.state === "done") onDone(v);
    }
  }, 1000);
}
$("#job-toggle").addEventListener("click", () => {
  const log = $("#job-log");
  log.classList.toggle("hidden");
  $("#job-toggle").textContent = log.classList.contains("hidden") ? "Show details" : "Hide details";
});

function toast(msg, kind = "warn") {
  // fixed, always-visible stack (messages must not appear off-screen at the top of a long page)
  let box = $("#toasts");
  if (!box) {
    box = document.createElement("div");
    box.id = "toasts";
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    document.body.append(box);
  }
  const div = document.createElement("div");
  div.className = `banner ${kind}`;
  div.textContent = msg;
  box.append(div);
  setTimeout(() => div.remove(), 8000);
}

// ---------------------------------------------------------------- dialog helpers
function dialog(html, { wide = false } = {}) {
  const d = $("#dialog");
  d.className = wide ? "wide" : "";
  $("#dialog-form").innerHTML = html;
  d.showModal();
  return d;
}
function confirmBox(title, text, okLabel = "Continue", extra = "") {
  return new Promise((resolve) => {
    const d = dialog(`<h3>${esc(title)}</h3><p>${esc(text)}</p>${extra}
      <div class="actions"><button value="cancel" formnovalidate>Cancel</button><button value="ok" class="primary">${esc(okLabel)}</button></div>`);
    d.addEventListener("close", () => resolve(d.returnValue === "ok" ? d : null), { once: true });
  });
}
function openReport(which) {
  dialog(`<div class="row between"><h3>Technical report</h3><button value="close">Close</button></div>
    <iframe src="/report/${which}?token=${encodeURIComponent(TOKEN)}" title="Technical report"></iframe>`, { wide: true });
}
document.addEventListener("click", (e) => {
  const a = e.target.closest("a[data-external]");
  if (a) { e.preventDefault(); api("/api/open", { url: a.getAttribute("href") }).catch((err) => toast(err.message)); }
});

// ---------------------------------------------------------------- data
async function refresh() {
  STATE.status = await api("/api/status");
  const s = STATE.status;
  const c = s.counts || {};
  const n = (c.act || 0) + (c.update || 0) + (c.check || 0);
  $("#nav-findings").textContent = n ? n : "";
  const m = s.malware_counts || {};
  $("#nav-malware").textContent = (m.critical || 0) + (m.high || 0) || "";
  $("#side-foot").innerHTML = `${esc(s.host)}<br>Packhound ${esc(s.version)}`;
  STATE.findings = null;
  STATE.malware = null;
  render();
}

// ---------------------------------------------------------------- pages
const PAGES = { home, findings, fix, malware, settings };
function render() {
  const page = (location.hash.match(/^#\/(\w+)/) || [])[1] || "home";
  document.querySelectorAll(".side a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  (PAGES[page] || home)();
}
window.addEventListener("hashchange", render);

function home() {
  const s = STATE.status;
  if (!s) return;
  const h = s.health;
  const icon = { good: "✓", attention: "!", act: "!!", unknown: "?" }[h.level];
  const c = s.counts || {};
  const tiles = s.counts ? [["act", "Act now"], ["update", "Safe to update"], ["check", "Check before updating"], ["wait", "No automatic fix"]]
    .map(([id, t]) => `<button class="tile ${id}" data-tab="${id}"><b>${c[id] || 0}</b>${t}</button>`).join("") : "";
  const roots = s.roots.length ? s.roots.map((r) => `<code>${esc(r)}</code>`).join(", ")
    : `none yet — <a href="#/settings">choose your project folders</a> so scs can check them too`;
  $("#main").innerHTML = `
    <h1>Home</h1><p class="muted">Checks the software on this computer for known security problems and malicious packages.</p>
    <div class="card health ${h.level}"><div class="dot">${icon}</div>
      <div><h2>${esc(h.headline)}</h2><div>${esc(h.detail)}</div>
      <div class="small muted">Last scan: ${when(s.scanned)} · Last malware check: ${when(s.malware_scanned)}</div></div></div>
    ${s.integrity && s.integrity.ok === false ? `<div class="banner bad"><b>This copy of Packhound was modified after it was built.</b>
      Its results can't be trusted: reinstall it from a trusted download. <span class="small">(${esc(s.integrity.detail)})</span></div>` : ""}
    <div class="row">
      <button class="primary big" id="scan">Scan now</button>
      <button class="big" id="quick">Quick malware check</button>
      ${c.update ? `<button class="big" id="fixsafe">Fix ${c.update} safe item(s)</button>` : ""}
      ${fixableCount(c) ? `<button class="big" id="fixall">Fix everything (${fixableCount(c)})</button>` : ""}
    </div>
    ${!s.roots.length && s.scanned ? `<div class="banner warn">Only apps and system-wide tools were checked. Your code projects were not, so
      their dependencies are not included. <button id="addroots" class="link">Choose project folders</button></div>` : ""}
    <div class="tiles">${tiles}</div>
    ${s.outdated ? `<p class="muted small">${s.outdated} app(s) have ordinary updates available (no known security issue). See the Fix page.</p>` : ""}
    <h2>What is checked</h2>
    <div class="card small"><div class="kv">
      <span class="muted">Apps and tools</span><span>Homebrew, APT/Snap, winget/Chocolatey/Scoop, Python, JavaScript (npm), Rust, Go</span>
      <span class="muted">Languages</span><span>JavaScript/TypeScript, Python, Java/Kotlin/Scala, Android, Swift/iOS, Flutter/Dart,
        React Native, .NET, Go, Rust, Ruby, PHP, Elixir/Erlang, Haskell, Julia, OCaml, R, C/C++ (Conan), GitHub Actions</span>
      <span class="muted">Developer tools</span><span>runtimes (JDK, Node.js, Python, Go, PHP, Ruby, .NET, Rust, Erlang/Elixir, Deno, Bun, Perl,
        GHC, Julia), build tools (Gradle, Maven, Bazel, pnpm/yarn), global gems/Go programs/.NET tools/Composer, download
        caches, git, curl and OpenSSH</span>
      <span class="muted">Project folders</span><span>${roots}</span>
      <span class="muted">Malware checks</span><span>install scripts, startup items, browser/editor extensions, tampering, Gradle/Maven wrappers, CI workflows</span>
      <span class="muted">This app</span><span>${s.integrity ? esc({ true: "unchanged since it was built", false: "MODIFIED", null: "not checked" }[s.integrity.ok]
        + (s.integrity.ok !== null ? " (" + s.integrity.detail + ")" : "")) : ""}</span>
    </div></div>`;
  $("#scan").onclick = () => runJob(api("/api/scan", {}));
  $("#quick").onclick = () => runJob(api("/api/malware", { mode: "quick" }));
  const fs = $("#fixsafe");
  if (fs) fs.onclick = fixSafe;
  const fa = $("#fixall");
  if (fa) fa.onclick = fixAll;
  const ar = $("#addroots");
  if (ar) ar.onclick = () => { location.hash = "#/settings"; };
  document.querySelectorAll(".tile").forEach((t) => (t.onclick = () => { STATE.tab = t.dataset.tab; location.hash = "#/findings"; }));
}

async function fixSafe() {
  const c = STATE.status.counts || {};
  const ok = await confirmBox("Fix safe items",
    `scs will update ${c.update} item(s) that have a low-risk fix. Before each change it saves a copy, runs your project checks, ` +
    `and automatically undoes the change if anything breaks. Items that need a closer look are skipped.`, "Start");
  if (ok) runJob(api("/api/fix-safe", {}), (v) => { if (v.result) showFixResult(v.result.targets, v.result.left); });
}

function fixableCount(c) { return (c.update || 0) + (c.check || 0) + (c.act || 0); }

async function fixAll() {
  const c = STATE.status.counts || {};
  const d = await confirmBox("Fix everything",
    `scs will fix all ${fixableCount(c)} item(s) that have a fix, including the ones marked “Check before updating”. ` +
    `For each group it saves a copy, applies the fix, tests the affected apps and tools, and undoes the change automatically ` +
    `if a test fails. You may be asked for your password (or Windows approval) for system-wide software. ` +
    `Homebrew and Windows installer updates cannot be undone automatically.`, "Fix everything",
    `<label class="check"><input type="checkbox" id="migrate"> <span>Also move old Python environments to a newer Python when a fix
      needs one (the old environment is kept in scs's backups and can be restored).</span></label>`);
  if (!d) return;
  const migrate = d.querySelector("#migrate").checked;
  runJob(api("/api/fix-all", { migrate }), (v) => { if (v.result) showFixResult(v.result.targets, v.result.left); });
}

const STATUS_TEXT = { applied: ["good", "Updated"], partial: ["warn", "Partly updated"], rolled_back: ["warn", "Undone (a check failed)"],
  skipped: ["", "Skipped"], failed: ["bad", "Failed"], rollback_failed: ["bad", "Undo failed — see details"], interrupted: ["bad", "Interrupted"] };
function showFixResult(targets, left) {
  const rows = (targets || []).map((t) => {
    const [cls, text] = STATUS_TEXT[t.status] || ["", t.status];
    return `<tr><td>${esc(t.title)}</td><td><span class="chip ${cls}">${esc(text)}</span>${t.reason ? `<div class="small muted">${esc(t.reason)}</div>` : ""}</td></tr>`;
  }).join("");
  const updated = (targets || []).filter((t) => t.status === "applied" || t.status === "partial").length;
  dialog(`<h3>Result: ${updated} of ${(targets || []).length} group(s) updated</h3>
    <table class="result">${rows || "<tr><td>Nothing needed updating.</td></tr>"}</table>
    ${left && left.length ? `<h3>Still open after the new scan (${left.length})</h3><table class="result">${left.map((i) =>
      `<tr><td>${esc(i.headline)}</td><td class="small muted">${esc(i.why)}</td></tr>`).join("")}</table>`
      : left ? `<p class="banner good">Nothing fixable is left open.</p>` : ""}
    <p class="small muted">Anything not updated stays on the Findings page with the reason shown here.</p>
    <div class="actions"><button value="ok" class="primary">Done</button></div>`);
}

async function findings() {
  if (!STATE.findings) {
    $("#main").innerHTML = `<p class="muted">Loading…</p>`;
    STATE.findings = await api("/api/findings");
  }
  const F = STATE.findings;
  if (!F.scanned) {
    $("#main").innerHTML = `<h1>Findings</h1><div class="empty">No scan yet.<br><br><button class="primary" id="scan">Scan now</button></div>`;
    $("#scan").onclick = () => runJob(api("/api/scan", {}));
    return;
  }
  const groups = Object.values(F.groups);
  const count = (id) => F.items.filter((i) => i.group === id).length;
  if (!count(STATE.tab)) STATE.tab = (groups.find((g) => count(g.id)) || groups[0]).id;
  const g = groups.find((x) => x.id === STATE.tab);
  const q = STATE.search.toLowerCase();
  const items = F.items.filter((i) => i.group === STATE.tab && (!q || (i.name + i.headline + i.where.join(" ")).toLowerCase().includes(q)));
  $("#main").innerHTML = `
    <div class="row between"><div><h1>Findings</h1>
      <span class="muted small">Scanned ${when(F.scanned)}</span></div>
      <button id="report">Open technical report</button></div>
    <div class="tabs">${groups.map((x) => `<button data-tab="${x.id}" class="${x.id === STATE.tab ? "on" : ""}">${esc(x.title)} (${count(x.id)})</button>`).join("")}</div>
    <p class="muted">${esc(g.blurb)}</p>
    <div class="row"><input type="search" id="search" placeholder="Search by name or project…" value="${esc(STATE.search)}"></div>
    <div id="list">${items.length ? items.map(card).join("") : `<div class="empty">Nothing here.</div>`}</div>`;
  $("#report").onclick = () => openReport("scan");
  document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => { STATE.tab = b.dataset.tab; findings(); }));
  const s = $("#search");
  s.oninput = () => { STATE.search = s.value; const pos = s.selectionStart; findings().then(() => { const n = $("#search"); n.focus(); n.setSelectionRange(pos, pos); }); };
  document.querySelectorAll("[data-act]").forEach((b) => (b.onclick = () => triage(b.dataset.key, b.dataset.act)));
  document.querySelectorAll("[data-copy]").forEach((b) => (b.onclick = () =>
    navigator.clipboard.writeText(b.dataset.copy).then(() => toast("Copied.", "good"), () => toast("Couldn't copy: select the text instead."))));
}

function card(i) {
  const chips = [`<span class="chip sev-${esc(i.severity)}">${esc(i.severity)}</span>`, `<span class="chip">${esc(i.kind)}</span>`];
  if (i.malicious) chips.push(`<span class="chip bad">Malicious</span>`);
  if (i.exploited) chips.push(`<span class="chip bad">Exploited in the wild</span>`);
  if (i.new) chips.push(`<span class="chip info">New</span>`);
  if (i.decision) chips.push(`<span class="chip good">Your choice: ${esc({ patch: "update", verify: "check first", defer: "later", respond: "respond" }[i.decision.action] || i.decision.action)}${i.decision.until ? " until " + esc(i.decision.until) : ""}</span>`);
  const d = i.details;
  const adv = d.advisories.map((a) => `<li>${a.link ? `<a href="${esc(a.link)}" data-external>${esc(a.id)}</a>` : esc(a.id)}
    ${a.cves.length ? `(${esc(a.cves.join(", "))})` : ""} — ${esc(a.summary)}${a.kev ? " <b>[exploited]</b>" : ""}</li>`).join("");
  const canAct = ["update", "check"].includes(i.group);
  return `<div class="item">
    <div class="top"><div><h3>${esc(i.headline)}</h3><div class="chips">${chips.join("")}</div></div></div>
    ${i.summary ? `<div class="small">${esc(i.summary)}</div>` : ""}
    <ul class="where">${i.where.map((w) => `<li>${esc(w)}</li>`).join("")}${i.where_count > i.where.length ? `<li>…and more (${i.where_count} places)</li>` : ""}</ul>
    ${i.notes.length ? `<ul class="notes">${i.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
    <div class="small mt">${esc(i.action)}</div>
    ${(i.manual || []).length ? `<div class="manual mt"><b>How to fix it yourself</b><ol>${i.manual.map((m) => `<li>${esc(m.text)}
      ${m.link ? ` <a href="${esc(m.link)}" data-external>Open</a>` : ""}
      ${m.cmd ? `<div class="cmdline"><code>${esc(m.cmd)}</code><button class="link" data-copy="${esc(m.cmd)}">Copy</button></div>` : ""}</li>`).join("")}</ol></div>` : ""}
    <div class="actions">
      ${canAct ? `<button data-act="patch" data-key="${esc(i.key)}">Update this</button>` : ""}
      ${i.group !== "act" ? `<button data-act="defer" data-key="${esc(i.key)}">Remind me later…</button>
      <button data-act="ignore" data-key="${esc(i.key)}">Ignore…</button>` : ""}
      ${i.decision ? `<button class="link" data-act="clear" data-key="${esc(i.key)}">Clear my choice</button>` : ""}
    </div>
    <details class="tech"><summary>Technical details</summary>
      <ul>${adv}</ul>
      ${d.chains.length ? `<div><b>Pulled in by</b><pre>${esc(d.chains.join("\n"))}</pre></div>` : ""}
      ${d.commands.length ? `<div><b>Command-line fix</b><pre>${esc(d.commands.join("\n"))}</pre></div>` : ""}
    </details></div>`;
}

async function triage(key, action) {
  let body = { key, action };
  if (action === "ignore") {
    const d = await confirmBox("Ignore this item", "It will be hidden from results until the rule expires. Please say why (for your future self or your team).",
      "Ignore", `<label>Reason<br><input type="text" id="ig-reason" class="full" required></label>
      <p><label>For <select id="ig-exp"><option value="30d">30 days</option><option value="90d" selected>90 days</option><option value="180d">6 months</option></select></label></p>`);
    if (!d) return;
    body.reason = d.querySelector("#ig-reason").value;
    body.expires = d.querySelector("#ig-exp").value;
    if (!body.reason.trim()) return toast("A reason is required to ignore an item.");
  }
  if (action === "defer") {
    const d = await confirmBox("Remind me later", "The item moves out of your way and comes back when this time is up.", "Remind me",
      `<div class="row"><label>In <input type="number" id="df-n" min="1" max="365" value="2" required style="width:5em"></label>
      <select id="df-unit" aria-label="unit"><option value="1">days</option><option value="7" selected>weeks</option><option value="30">months</option></select></div>`);
    if (!d) return;
    const n = parseInt(d.querySelector("#df-n").value, 10);
    body.days = n * Number(d.querySelector("#df-unit").value);
    if (!(n >= 1) || body.days > 365) return toast("Pick a time between 1 day and 12 months.");
  }
  try {
    await api("/api/triage", body);
    STATE.findings = null;
    if (action === "patch") toast("Marked for update. Open the Fix page to apply it.", "good");
    findings();
  } catch (e) { toast(e.message, "bad"); }
}

async function fix() {
  if (!STATE.findings) STATE.findings = await api("/api/findings");
  const F = STATE.findings;
  const fixable = F.items.filter((i) => i.fix && ["update", "check", "act"].includes(i.group));
  const plan = STATE.plan;
  $("#main").innerHTML = `
    <h1>Fix</h1><p class="muted">Every change is reversible: scs saves a copy first, runs your project's checks afterwards, and undoes the change automatically if something breaks.</p>
    <div class="card"><h3>Quick fix</h3><p>“Fix safe items” updates only what is marked “Safe to update”. “Fix everything” also
      fixes the items marked “Check before updating”: each change is tested and undone automatically if a test fails.</p>
      <div class="row"><button class="primary big" id="fixsafe" ${(STATE.status.counts || {}).update ? "" : "disabled"}>Fix safe items</button>
      <button class="big" id="fixall" ${fixableCount(STATE.status.counts || {}) ? "" : "disabled"}>Fix everything</button></div></div>
    <h2>Choose what to fix</h2>
    ${fixable.length ? `<div class="card"><div class="row between"><label class="check"><input type="checkbox" id="all"> Select all</label>
      <label class="check"><input type="checkbox" id="outdated"> Also install ordinary app updates (${F.outdated ? F.outdated.length : 0})</label>
      <label class="check"><input type="checkbox" id="migrate"> Move old Python environments to a newer Python when a fix needs one</label></div>
      <table>${fixable.map((i) => `<tr><td><input type="checkbox" class="sel" value="${esc(i.key)}" aria-label="select ${esc(i.name)}"></td>
        <td><b>${esc(i.name)}</b> ${esc(i.version)} → ${esc(i.fix)}<div class="small muted">${esc(i.kind)} · ${esc(i.where[0] || "")}${i.where_count > 1 ? ` (+${i.where_count - 1})` : ""}</div></td>
        <td><span class="chip sev-${esc(i.severity)}">${esc(i.severity)}</span> ${i.group === "check" ? `<span class="chip warn">check first</span>` : ""}</td></tr>`).join("")}</table>
      <div class="actions"><button class="primary" id="build">Review changes</button></div></div>` : `<div class="empty">Nothing to fix right now.</div>`}
    <div id="plan">${plan ? planView(plan) : ""}</div>`;
  $("#fixsafe").onclick = fixSafe;
  $("#fixall").onclick = fixAll;
  const all = $("#all");
  if (all) all.onchange = () => document.querySelectorAll(".sel").forEach((c) => (c.checked = all.checked));
  const b = $("#build");
  if (b) b.onclick = async () => {
    const keys = [...document.querySelectorAll(".sel:checked")].map((c) => c.value);
    const outdated = $("#outdated").checked;
    if (!keys.length && !outdated) return toast("Select at least one item.");
    try {
      STATE.plan = await api("/api/plan", { keys, outdated, migrate: $("#migrate").checked });
      $("#plan").innerHTML = planView(STATE.plan);
      wirePlan();
      $("#plan").scrollIntoView({ behavior: "smooth" });
    } catch (e) { toast(e.message, "bad"); }
  };
  wirePlan();
}

function planView(p) {
  if (!p.targets.length) return `<div class="card">Nothing to change for the selection.</div>`;
  return `<h2>Review</h2><p class="muted">Changes are grouped by where they apply. Untick a group to leave it alone.</p>
    ${p.targets.map((t) => `<div class="target">
      <label class="check"><input type="checkbox" class="tsel" value="${t.n}" ${t.has_changes ? "checked" : "disabled"}>
        <span><b>${esc(t.title)}</b> ${t.risky ? `<span class="chip warn">needs care</span>` : `<span class="chip good">low risk</span>`}
        <div class="small muted">${t.packages.map(esc).join(", ")}</div></span></label>
      ${t.warnings.length ? `<ul class="notes">${t.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
      ${t.notes.length ? `<ul class="where">${t.notes.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
      <details class="tech"><summary>Commands</summary><pre>${esc(t.commands.join("\n") || "(manual steps only)")}</pre>
      ${t.verify.length ? `<b>Checks afterwards</b><pre>${esc(t.verify.join("\n"))}</pre>` : ""}</details></div>`).join("")}
    <label class="check"><input type="checkbox" id="risk"> <span>I have read the notes above. Apply groups marked “needs care” too.</span></label>
    <div class="actions"><button class="primary big" id="apply">Apply selected</button></div>`;
}

function wirePlan() {
  const a = $("#apply");
  if (!a) return;
  a.onclick = async () => {
    const targets = [...document.querySelectorAll(".tsel:checked")].map((c) => Number(c.value));
    if (!targets.length) return toast("Select at least one group.");
    const risky = STATE.plan.targets.some((t) => targets.includes(t.n) && t.risky);
    const accept = $("#risk").checked;
    if (risky && !accept) return toast("Some selected groups need care: tick the confirmation box, or untick them.");
    const ok = await confirmBox("Apply changes", `Update ${targets.length} group(s) now? Close other apps that use them first.`, "Apply");
    if (ok) runJob(api("/api/patch", { targets, accept_risk: accept }), (v) => { STATE.plan = null; if (v.result) showFixResult(v.result.targets, v.result.left); });
  };
}

async function malware() {
  if (!STATE.malware) {
    $("#main").innerHTML = `<p class="muted">Loading…</p>`;
    [STATE.malware, STATE.quarantine] = await Promise.all([api("/api/malware"), api("/api/quarantine")]);
  }
  const M = STATE.malware;
  const items = M.items.filter((m) => m.level !== "info");
  const exp = M.exposure || [];
  const byAction = new Set((M.actions || []).flatMap((a) => a.quarantine || []));
  const quarantined = (STATE.quarantine || []).filter((q) => !byAction.has(q.id));
  $("#main").innerHTML = `
    <div class="row between"><div><h1>Malware check</h1>
      <span class="muted small">Last check ${when(M.scanned)}</span></div>${M.scanned ? `<button id="report">Open technical report</button>` : ""}</div>
    <p class="muted">Looks for malicious install scripts, things that start automatically, risky extensions and tampered files.</p>
    <div class="row"><button class="primary" id="quick">Quick check (~1 min)</button><button id="full">Full check (~3 min)</button>
      <label class="check small"><input type="checkbox" id="rep"> Also look up file fingerprints online (needs API keys; only fingerprints are sent)</label></div>
    <h2>Results</h2>
    ${!M.scanned ? `<div class="empty">No check yet.</div>` : items.length ? items.map((m) => `<div class="item">
      <div class="chips"><span class="chip ${m.level === "critical" || m.level === "high" ? "bad" : m.level === "medium" ? "warn" : ""}">${esc(m.severity)}</span>${m.new ? `<span class="chip info">New</span>` : ""}</div>
      <h3>${esc(m.title)}</h3><div class="small muted">${esc(m.path)}</div><div class="small mt">${esc(m.advice)}</div>
      ${m.evidence.length ? `<details class="tech"><summary>Why it was flagged</summary><pre>${esc(m.evidence.join("\n"))}</pre></details>` : ""}
      ${m.done ? `<div class="banner good mt">Done: ${esc(m.done.label)} · ${esc(m.done.done_at.replace("T", " "))}
        ${m.done.note ? `<div class="small">${esc(m.done.note)}</div>` : ""}
        ${m.done.can_undo ? ` <button class="link" data-undo="${esc(m.done.id)}">Undo</button>` : ""}</div>` : ""}
      ${(m.manual || []).length ? `<div class="manual mt"><b>${m.actions.length ? "Or do it yourself" : "How to fix it yourself"}</b><ol>${m.manual.map((s) => `<li>${esc(s.text)}
        ${s.cmd ? `<div class="cmdline"><code>${esc(s.cmd)}</code><button class="link" data-copy="${esc(s.cmd)}">Copy</button></div>` : ""}</li>`).join("")}</ol></div>` : ""}
      <div class="actions">${(m.actions || []).map((a, n) => `<button class="${a.recommended ? "primary" : ""}" data-fix="${esc(m.id)}" data-n="${n}">${esc(a.label)}</button>`).join("")}
        ${m.level !== "critical" && !m.done ? `<button data-ig="${esc(m.id)}">Ignore…</button>` : ""}</div></div>`).join("")
      : `<div class="banner good">Nothing suspicious found.</div>`}
    ${(M.ignored || []).length ? `<details class="card mt"><summary><b>Ignored (${M.ignored.length})</b> <span class="small muted">items you marked as known</span></summary>
      <table>${M.ignored.map((m) => `<tr><td><b>${esc(m.title)}</b><div class="small muted">${esc(m.path)}</div>
        <div class="small">“${esc(m.reason)}” · ${m.expires ? `until ${esc(m.expires)}` : "until you undo it"}</div></td>
        <td><button data-unig="${esc(m.id)}">Stop ignoring</button></td></tr>`).join("")}</table></details>` : ""}
    ${exp.length ? `<h2>Passwords and tokens stored on this computer</h2><p class="muted small">Only locations are shown; scs never reads the values. If anything above is confirmed malicious, change these.</p>
      <table>${exp.map((e) => `<tr><td>${esc(e.label)}</td><td class="small"><code>${esc(e.path)}</code></td><td>${e.state === "UNENCRYPTED" ? `<span class="chip bad">no passphrase</span>` : esc(e.state)}</td></tr>`).join("")}</table>` : ""}
    ${(M.actions || []).length ? `<h2>Actions taken</h2><table>${M.actions.map((a) => `<tr class="${a.undone ? "muted" : ""}">
      <td><b>${esc(a.label)}</b> · ${esc(a.title)}<div class="small muted">${esc(a.path)} · ${esc(a.done_at.replace("T", " "))}${a.undone ? " · undone" : ""}</div></td>
      <td>${!a.undone && a.can_undo ? `<button data-undo="${esc(a.id)}">Undo</button>` : ""}</td></tr>`).join("")}</table>` : ""}
    ${quarantined.length ? `<h2>Quarantine</h2><p class="muted small">Moved here from the command line. Items an action moved are restored with that action's Undo.</p>
      <table>${quarantined.map((q) => `<tr><td><code>${esc(q.original_path)}</code><div class="small muted">${esc(q.reason)} · ${esc(q.quarantined_at)}</div></td>
      <td><button data-r="${esc(q.id)}">Restore</button></td></tr>`).join("")}</table>` : ""}`;
  const rep = () => $("#rep").checked;
  $("#quick").onclick = () => runJob(api("/api/malware", { mode: "quick", reputation: rep() }));
  $("#full").onclick = () => runJob(api("/api/malware", { mode: "full", reputation: rep() }));
  const r = $("#report");
  if (r) r.onclick = () => openReport("malware");
  const reload = () => { STATE.malware = null; malware(); };
  document.querySelectorAll("[data-fix]").forEach((b) => (b.onclick = async () => {
    const m = M.items.find((x) => x.id === b.dataset.fix), a = m.actions[Number(b.dataset.n)];
    const undoNote = !a.undo ? "This can't be undone." : /undo|restore/i.test(a.explain) ? "" : "You can undo it afterwards.";
    if (!(await confirmBox(a.label, `${a.explain} ${undoNote}`, a.label))) return;
    let r;
    try { r = await api("/api/malware/act", { id: m.id, action: a.id }); } catch (e) { return toast(e.message, "bad"); }
    if (r.job) return runJob(Promise.resolve(r.job), reload);
    toast(`Done: ${a.label}.`, "good");
    reload();
  }));
  document.querySelectorAll("[data-undo]").forEach((b) => (b.onclick = async () => {
    if (!(await confirmBox("Undo", "Put things back the way they were before this action?", "Undo"))) return;
    try { await api("/api/malware/undo", { id: b.dataset.undo }); toast("Undone.", "good"); reload(); } catch (e) { toast(e.message, "bad"); }
  }));
  document.querySelectorAll("#main [data-copy]").forEach((b) => (b.onclick = () =>
    navigator.clipboard.writeText(b.dataset.copy).then(() => toast("Copied.", "good"), () => toast("Couldn't copy: select the text instead."))));
  document.querySelectorAll("[data-ig]").forEach((b) => (b.onclick = () => ignoreMalware(M.items.find((m) => m.id === b.dataset.ig))));
  document.querySelectorAll("[data-unig]").forEach((b) => (b.onclick = async () => {
    if (!(await confirmBox("Stop ignoring", "Show this item in the results again?", "Show again"))) return;
    try { await api("/api/malware/unignore", { id: b.dataset.unig }); STATE.malware = null; malware(); } catch (e) { toast(e.message, "bad"); }
  }));
  document.querySelectorAll("[data-r]").forEach((b) => (b.onclick = async () => {
    if (!(await confirmBox("Restore", "Put this item back where it was?", "Restore"))) return;
    try { await api("/api/quarantine/restore", { id: b.dataset.r }); STATE.malware = null; malware(); } catch (e) { toast(e.message, "bad"); }
  }));
}

async function ignoreMalware(m) {
  const serious = m.level === "high";
  const d = await confirmBox("Ignore this item?", "Only ignore something you recognise and trust. It stays hidden while it is unchanged: "
    + "if the file or what was flagged changes, it shows up again.", "Ignore",
    `<div class="card"><b>${esc(m.title)}</b><div class="small muted">${esc(m.path)}</div></div>
    <label>Why is it safe? (required)<br><input type="text" id="mi-reason" class="full" required placeholder="e.g. my own backup script"></label>
    <p><label>Hide it for <select id="mi-exp"><option value="30d">30 days</option><option value="90d" selected>90 days</option>
      <option value="6m">6 months</option><option value="1y">1 year</option><option value="never">until I undo it</option></select></label></p>
    ${serious ? `<label class="check"><input type="checkbox" id="mi-ack" required> <span>This is rated <b>high</b>. I know what it is and I trust it.</span></label>` : ""}`);
  if (!d) return;
  const reason = d.querySelector("#mi-reason").value.trim();
  if (!reason) return toast("A reason is required to ignore an item.");
  if (serious && !d.querySelector("#mi-ack").checked) return toast("Tick the confirmation box to ignore a high-rated item.");
  try {
    await api("/api/malware/ignore", { id: m.id, reason, expires: d.querySelector("#mi-exp").value });
    toast("Ignored. You can undo it under “Ignored” at the bottom of the page.", "good");
    STATE.malware = null;
    malware();
  } catch (e) { toast(e.message, "bad"); }
}

async function settings() {
  const S = await api("/api/settings");
  const cfg = S.config;
  const roots = cfg.roots || [];
  const n = cfg.notify || {};
  $("#main").innerHTML = `
    <h1>Settings</h1>
    <h2>Project folders</h2><p class="muted small">scs also checks the code projects in these folders (their dependency files).</p>
    <div class="card">${roots.length ? `<table>${roots.map((r, i) => `<tr><td><code>${esc(r)}</code></td><td><button class="link" data-rm="${i}">Remove</button></td></tr>`).join("")}</table>` : `<p class="muted">No folders yet.</p>`}
      <div class="actions"><button id="add">Add folder…</button></div></div>
    <h2>Automatic checks</h2><div class="card"><p class="small">Status: <code>${esc(S.schedule)}</code></p>
      <div class="row"><label>Every day at <input type="time" id="time" value="09:00"></label>
      <button class="primary" id="sched">Turn on</button><button id="unsched">Turn off</button><button class="link" id="preview">What will be installed?</button></div>
      <p class="small muted">Runs a scan and a quick malware check, and notifies you only about new problems.</p></div>
    <h2>Safety</h2><div class="card">
      <label>Wait before installing new releases <input type="number" id="minage" min="0" max="90" value="${esc(cfg.fix_min_age_days ?? 7)}" style="width:5em"> days</label>
      <p class="small muted">Fixes from PyPI and npm skip versions published more recently than this, so a hijacked release can be
        found and pulled before it reaches you. Fixes for problems that are being exploited wait at most 2 days. 0 turns this off.</p>
      <div class="actions"><button class="primary" id="saveage">Save</button></div></div>
    <h2>Notifications</h2><div class="card">
      <label class="check"><input type="checkbox" id="desk" ${n.desktop ? "checked" : ""}> Show a desktop notification</label>
      <div class="kv mt">
        <label for="slack">Slack webhook</label><input type="text" id="slack" value="${esc(n.slack_webhook || "")}" placeholder="env:SCS_SLACK_WEBHOOK">
        <label for="teams">Teams webhook</label><input type="text" id="teams" value="${esc(n.teams_webhook || "")}" placeholder="env:SCS_TEAMS_WEBHOOK">
        <label for="hook">Other webhook</label><input type="text" id="hook" value="${esc(n.webhook || "")}" placeholder="env:SCS_WEBHOOK">
        <label for="sev">Notify me about</label><select id="sev">${["critical", "high", "medium"].map((v) => `<option value="${v}" ${(cfg.alert_min_severity || "high") === v ? "selected" : ""}>${v} and above</option>`).join("")}</select>
      </div>
      <p class="small muted">Tip: store webhook URLs in environment variables and enter <code>env:NAME</code> here, so secrets are not saved in the settings file.</p>
      <div class="actions"><button class="primary" id="save">Save</button><button id="test">Send test notification</button></div></div>
    <p class="small muted">Settings file: <code>${esc(S.config_path)}</code></p>`;
  const save = async (patch) => { await api("/api/settings", patch); toast("Saved.", "good"); await refresh(); location.hash = "#/settings"; };
  $("#add").onclick = async () => {
    const r = await api("/api/pick-folder", {});
    if (r.path) save({ roots: [...roots, r.path] });
    else toast("No folder chosen (or no folder picker is available on this system).");
  };
  document.querySelectorAll("[data-rm]").forEach((b) => (b.onclick = () => save({ roots: roots.filter((_, i) => i !== Number(b.dataset.rm)) })));
  $("#save").onclick = () => save({ notify: { ...n, desktop: $("#desk").checked, slack_webhook: $("#slack").value.trim() || undefined,
    teams_webhook: $("#teams").value.trim() || undefined, webhook: $("#hook").value.trim() || undefined }, alert_min_severity: $("#sev").value });
  $("#saveage").onclick = () => {
    const v = parseInt($("#minage").value, 10);
    if (!(v >= 0 && v <= 90)) return toast("Enter 0 to 90 days.");
    save({ fix_min_age_days: v });
  };
  $("#test").onclick = async () => {
    try { const r = await api("/api/notify/test", {}); toast(Object.entries(r).map(([k, v]) => `${k}: ${v}`).join(" · "), "good"); }
    catch (e) { toast(e.message, "bad"); }
  };
  $("#preview").onclick = async () => {
    const r = await api("/api/schedule", { action: "preview", daily: $("#time").value });
    dialog(`<h3>This will be installed</h3><pre>${esc(r.preview)}</pre><div class="actions"><button value="ok">Close</button></div>`);
  };
  $("#sched").onclick = async () => {
    if (!(await confirmBox("Turn on automatic checks", `scs will run every day at ${$("#time").value} in the background using your system's scheduler.`, "Turn on"))) return;
    try { await api("/api/schedule", { action: "install", daily: $("#time").value }); toast("Automatic checks are on.", "good"); settings(); }
    catch (e) { toast(e.message, "bad"); }
  };
  $("#unsched").onclick = async () => {
    try { await api("/api/schedule", { action: "remove" }); toast("Automatic checks are off.", "good"); settings(); }
    catch (e) { toast(e.message, "bad"); }
  };
}

// ---------------------------------------------------------------- start
if (!TOKEN) {
  $("#main").innerHTML = `<h1>Packhound</h1><div class="banner bad">This page must be opened from the Packhound app (missing access token). Start it with <code>scs ui</code>.</div>`;
} else {
  refresh().catch((e) => { $("#main").innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; });
}
