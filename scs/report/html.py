"""Self-contained HTML report (no external resources; all data HTML-escaped)."""
from __future__ import annotations

import json
from html import escape

from scs.analyze import BUCKET_TITLES, BUCKETS, RESPOND_CHECKLIST
from scs.report import short_path, where

CSS = """
:root{--bg:#f7f7f8;--card:#fff;--fg:#1d1d1f;--muted:#6b6b72;--line:#e3e3e8;--accent:#2f6fed;
--crit:#c4161c;--high:#e5531a;--med:#b98900;--low:#2a8bb3;--ok:#1e8e3e;--code:#f0f0f3}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121214;--card:#1c1c1f;--fg:#ececf0;
--muted:#9a9aa3;--line:#2c2c31;--accent:#6c9cff;--crit:#ff5a5f;--high:#ff8a4c;--med:#e8c14a;--low:#5cc3ea;--ok:#4cc26c;--code:#26262b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.tile.active{outline:2px solid var(--accent)}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 14px}input[type=search]{flex:1;min-width:200px;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}summary{list-style:none;cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}.score{font-variant-numeric:tabular-nums;font-weight:700;min-width:2.2em}
.sev{font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;color:#fff}.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.UNKNOWN{background:var(--muted)}
.tag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;color:var(--muted)}.tag.kev{color:var(--crit);border-color:var(--crit)}.tag.new{color:var(--accent);border-color:var(--accent)}
.body{padding:0 14px 12px;border-top:1px solid var(--line)}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
a{color:var(--accent)}.fix{color:var(--ok);font-weight:600}ol{margin:6px 0 0;padding-left:20px}.why{color:var(--med)}
.hidden{display:none}
"""

JS = """
const tiles=[...document.querySelectorAll('.tile')],items=[...document.querySelectorAll('details.f')],q=document.getElementById('q');
let bucket='';
function apply(){const t=q.value.toLowerCase();items.forEach(d=>{const ok=(!bucket||d.dataset.bucket===bucket)&&(!t||d.dataset.text.includes(t));d.classList.toggle('hidden',!ok)});
document.querySelectorAll('section[data-bucket]').forEach(s=>{s.classList.toggle('hidden',![...s.querySelectorAll('details.f')].some(d=>!d.classList.contains('hidden')))})}
tiles.forEach(t=>t.addEventListener('click',()=>{bucket=bucket===t.dataset.bucket?'':t.dataset.bucket;tiles.forEach(x=>x.classList.toggle('active',x.dataset.bucket===bucket));apply()}));
q.addEventListener('input',apply);
"""


def _e(s) -> str:
    return escape(str(s), quote=True)


def _link(url: str) -> str:
    if not url.startswith("https://"):
        return _e(url)
    return f'<a href="{_e(url)}" rel="noopener noreferrer" target="_blank">{_e(url)}</a>'


def _finding(f: dict, has_prev: bool) -> str:
    advs = f["advisories"]
    tags = []
    if any(a["kev"] for a in advs):
        tags.append('<span class="tag kev">KEV: exploited in the wild</span>')
    epss = max((a["epss"] or 0 for a in advs), default=0)
    if epss >= 0.01:
        tags.append(f'<span class="tag">EPSS {epss:.0%}</span>')
    if any(a["confidence"] == "low" for a in advs):
        tags.append('<span class="tag">low confidence</span>')
    if f["new"] and has_prev:
        tags.append('<span class="tag new">NEW</span>')
    if f.get("decision"):
        d = f["decision"]
        tags.append(f'<span class="tag new">decision: {_e(d["action"])}{" until " + _e(d["until"]) if d.get("until") else ""}'
                    f'{" · stale" if d.get("stale") else ""}</span>')
    if f["ecosystem"] == "file":
        title = f"<b>IOC file</b> <code>{_e(short_path(f['name']))}</code>"
    else:
        fix = f' → <span class="fix">{_e(f["fix_version"])}</span>' if f.get("fix_version") else ""
        title = f'<span class="muted">{_e(f["ecosystem"])}</span> <b>{_e(f["name"])}</b> {_e(f["version"])}{fix}'
    rows = []
    for a in advs:
        ids = ", ".join([a["id"]] + [x for x in a["aliases"] if x.startswith("CVE-")][:3])
        score = f'{a["cvss"]:.1f}' if a.get("cvss") is not None else ""
        fixed = ", ".join(a["fixed"][-4:])
        refs = "<br>".join(_link(r) for r in a["references"][:3])
        rows.append(f'<tr><td><span class="sev {_e(a["severity"])}">{_e(a["severity"])}</span> {score}</td>'
                    f'<td><code>{_e(ids)}</code><br>{_e(a["summary"])}<br><span class="muted">{refs}</span></td>'
                    f'<td>{_e(fixed)}</td><td>{_e(a["source"])}</td></tr>')
    def _loc(p: dict) -> str:
        paths = (p.get("meta") or {}).get("paths") or []
        chains = "".join(f"<li><code>{_e(' › '.join(x))}</code></li>" for x in paths if len(x) > 1)
        n_intro = (p.get("meta") or {}).get("introduced_by_count", 0)
        more = f"<li class='muted'>pulled in by {n_intro} direct dependencies in total</li>" if n_intro > len(paths) else ""
        return f"<li>{_e(where(p))}{f'<ul>{chains}{more}</ul>' if chains else ''}</li>"

    locs = "".join(_loc(p) for p in f["packages"][:50])
    if len(f["packages"]) > 50:
        locs += f"<li class='muted'>… {len(f['packages']) - 50} more</li>"
    reasons = "".join(f'<li class="why">{_e(r)}</li>' for r in f["reasons"])
    tc = f.get("toolchain") or {}
    if tc.get("fix_requires"):
        rts = ", ".join(sorted({f"{r['value']} ({r['source']})" for r in tc.get("runtimes", [])})[:4])
        reasons += f'<li class="muted">{_e(f.get("fix_version"))} requires {_e(tc["runtime"])} {_e(tc["fix_requires"])}' \
                   f'{"; in use: " + _e(rts) if rts else ""}</li>'
    for ig in f.get("ignored") or []:
        reasons += f'<li class="muted">ignored by policy: {_e(ig["advisory"])} — {_e(ig["reason"])} (until {_e(ig["expires"] or "never")})</li>'
    cmds = "\n".join(f["commands"])
    text = " ".join([f["name"], f["version"], f["ecosystem"]] + [a["id"] for a in advs]
                    + [x for a in advs for x in a["aliases"]] + [where(p) for p in f["packages"][:20]]).lower()
    return f"""<details class="f" data-bucket="{_e(f['bucket'])}" data-text="{_e(text)}">
<summary><span class="score">{f['score']}</span><span class="sev {_e(f['severity'])}">{_e(f['severity'])}</span>{title}
<span class="muted">{len(advs)} advisor{'y' if len(advs) == 1 else 'ies'} · {len(f['packages']) or 1} location(s)</span>{''.join(tags)}</summary>
<div class="body"><p>{_e(f['advice'])}</p>{f'<ul>{reasons}</ul>' if reasons else ''}
{f'<p><b>Suggested commands</b> (review before running)</p><pre>{_e(cmds)}</pre>' if cmds else ''}
{f'<p><b>Where it is installed / chain of effect</b></p><ul>{locs}</ul>' if locs else ''}
<p><b>Advisories</b></p><table><tr><th>Severity</th><th>Advisory</th><th>Fixed in</th><th>Source</th></tr>{''.join(rows)}</table>
</div></details>"""


def render(result: dict) -> str:
    s = result["summary"]
    has_prev = bool(result.get("has_previous"))
    tiles = "".join(
        f'<div class="tile" data-bucket="{b}"><b>{s["buckets"][b]}</b>{_e(BUCKET_TITLES[b])}</div>' for b in BUCKETS)
    sections = []
    for b in BUCKETS:
        items = [f for f in result["findings"] if f["bucket"] == b]
        if not items:
            continue
        extra = ""
        if b == "respond":
            extra = "<ol>" + "".join(f"<li>{_e(x)}</li>" for x in RESPOND_CHECKLIST) + "</ol>"
        sections.append(f'<section data-bucket="{b}"><h2>{_e(BUCKET_TITLES[b])} ({len(items)})</h2>{extra}'
                        + "".join(_finding(f, has_prev) for f in items) + "</section>")
    srcs = "".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in result["sources"].items())
    cols = "".join(f"<tr><td>{_e(k)}</td><td>{_e(v['status'])}</td><td>{v['count']}</td><td>{v['seconds']}s</td></tr>"
                   for k, v in result["collectors"].items())
    outdated = "".join(f"<tr><td>{_e(o['name'])}</td><td>{_e(o['version'])}</td><td>{_e(o['latest'])}</td><td>{_e(o['kind'])}</td></tr>"
                       for o in result.get("outdated", []))
    errors = "".join(f"<li><code>{_e(x)}</code></li>" for x in result["errors"][:200])
    ignored = "".join(
        f"<tr><td>{_e(i['ecosystem'])}</td><td>{_e(i['name'])} {_e(i['version'])}</td><td>"
        + "<br>".join(f"{_e(r['advisory'])}: {_e(r['reason'])} (until {_e(r['expires'] or 'never')})" for r in i["rules"])
        + "</td></tr>" for i in result.get("ignored") or [])
    projects = "".join(
        f"<tr><td>{_e(short_path(d))}</td><td>"
        + ", ".join(f"{_e(rt)} {_e(v['value'])} <span class='muted'>({_e(v['source'])})</span>"
                    for rt, v in info.items() if isinstance(v, dict) and "value" in v)
        + "</td></tr>" for d, info in (result.get("projects") or {}).items()
        if any(isinstance(v, dict) and "value" in v for v in info.values()))
    empty = '<p class="fix">No known vulnerable or malicious packages found.</p>' if not result["findings"] else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Supply Chain Scan</title><style>{CSS}</style></head><body><main>
<h1>Supply chain scan — {_e(result['host'])}</h1>
<div class="muted">{_e(result['started'])} · {result['duration_s']}s · {result['inventory']['total']} package instances ({result['inventory']['unique']} unique) · scs {_e(result['scs_version'])}</div>
<div class="tiles">{tiles}</div>
<div class="controls"><input id="q" type="search" placeholder="Filter by package, CVE, path…"></div>
{empty}{''.join(sections)}
<h2>Outdated packages (Homebrew, Snap, Flatpak, winget, Chocolatey, Scoop) ({len(result.get('outdated', []))})</h2>
<p class="muted">Outdated is a weak signal, not proof of a vulnerability{'' if result['config'].get('nvd') else '; run with --nvd for CPE-based CVE matching'}.</p>
<table><tr><th>Name</th><th>Installed</th><th>Latest</th><th>Kind</th></tr>{outdated}</table>
{f'<h2>Ignored by policy ({len(result.get("ignored") or [])})</h2><table><tr><th>Ecosystem</th><th>Package</th><th>Rules</th></tr>{ignored}</table>' if ignored else ''}
{f'<h2>Project toolchains</h2><p class="muted">Used to check whether a fixed version still supports the runtime you build with.</p><table><tr><th>Project</th><th>Runtime</th></tr>{projects}</table>' if projects else ''}
<h2>Data sources</h2><table>{srcs}</table>
<h2>Collectors</h2><table><tr><th>Collector</th><th>Status</th><th>Packages</th><th>Time</th></tr>{cols}</table>
{f'<h2>Errors</h2><ul>{errors}</ul>' if errors else ''}
</main><script>{JS}</script></body></html>"""


def render_json(result: dict) -> str:
    return json.dumps(result, indent=1, default=str)
