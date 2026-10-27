"""Fleet (multi-host) report: terminal summary and self-contained HTML."""
from __future__ import annotations

import sys
from html import escape

from scs.report.html import CSS
from scs.report.terminal import c, dim


KEV_TAG = '<span class="tag kev">KEV</span>'


def _e(s) -> str:
    return escape(str(s), quote=True)


def render(fleet: dict, limit: int = 15, out=sys.stdout) -> None:
    w = out.write
    t = fleet["totals"]
    w(f"\n{c('scs fleet report', '1')}  {t['hosts']} hosts · {t['unique_vulnerable_packages']} vulnerable packages · "
      f"{t['cves']} CVEs · {t['respond']} respond-now · {t['malware_items']} malware items\n\n")
    w(f"{'host':<24} {'os':<26} {'scan age':>8}  respond patch verify monitor  malware c/h  exposure\n")
    for h in fleet["hosts"]:
        b = h["buckets"]
        age = f"{h['scan_age_days']}d" if h["scan_age_days"] is not None else "?"
        mw = h["malware"] or {}
        mal = f"{mw.get('critical', 0)}/{mw.get('high', 0)}" if h["malware"] is not None else "—"
        resp = c(str(b.get("respond", 0)), "1;31") if b.get("respond") else "0"
        w(f"{h['host'][:24]:<24} {h['os'][:26]:<26} {age:>8}  {resp:>7} {b.get('patch', 0):>5} {b.get('verify', 0):>6} "
          f"{b.get('monitor', 0):>7}  {mal:>11}  {h['exposure'] if h['exposure'] is not None else '—':>8}\n")
    if fleet["respond"]:
        w(f"\n{c('Respond now (malicious / IOC)', '1;41;97')}\n")
        for r in fleet["respond"][:limit]:
            w(f"  {r['host']}: {r['ecosystem']} {r['name']} {r['version']}  {', '.join(r['advisories'][:3])}\n")
        if fleet["shared_ioc_hosts"]:
            w(c(f"  same indicator on several hosts: {', '.join(fleet['shared_ioc_hosts'])}\n", "1;31"))
    w(f"\n{c('Most widespread vulnerable packages', '1')}\n")
    for v in fleet["vulnerabilities"][:limit]:
        kev = c(" KEV", "1;35") if v["kev"] else ""
        fix = f" → {v['fix_version']}" if v.get("fix_version") else ""
        w(f"  {v['host_count']:>3} hosts  {v['severity'][:4]:<4} {v['ecosystem']} {v['name']} {v['version']}{fix}{kev}\n")
    hot = [e for e in fleet["cves"] if e["kev"]][:limit]
    if hot:
        w(f"\n{c('Known-exploited CVEs (CISA KEV) in the fleet', '1;35')}\n")
        for e in hot:
            w(f"  {e['cve']}  {e['host_count']} hosts  {', '.join(e['packages'][:3])}\n")
    if fleet["malware"]:
        w(f"\n{c('Malware / compromise checks (medium+)', '1')}\n")
        for m in fleet["malware"][:limit]:
            w(f"  {m['severity'].upper()[:4]:<4} {m['title'][:80]}  " + dim(f"[{', '.join(x['host'] for x in m['hosts'][:5])}]") + "\n")


def render_html(fleet: dict) -> str:
    t = fleet["totals"]
    tiles = "".join(f'<div class="tile"><b>{t[k]}</b>{label}</div>' for k, label in
                    (("hosts", "hosts"), ("respond", "respond now"), ("unique_vulnerable_packages", "vulnerable packages"),
                     ("cves", "CVEs"), ("malware_items", "malware items")))
    host_rows = []
    for h in fleet["hosts"]:
        b, mw = h["buckets"], h["malware"] or {}
        host_rows.append(
            f"<tr><td><b>{_e(h['host'])}</b><br><span class='muted'>{_e(h['os'])}</span></td>"
            f"<td>{_e(h['scan_age_days'])}d</td><td>{b.get('respond', 0)}</td><td>{b.get('patch', 0)}</td>"
            f"<td>{b.get('verify', 0)}</td><td>{b.get('monitor', 0)}</td><td>{h['outdated']}</td>"
            f"<td>{(str(mw.get('critical', 0)) + ' / ' + str(mw.get('high', 0))) if h['malware'] is not None else '—'}</td>"
            f"<td>{_e(h['exposure'] if h['exposure'] is not None else '—')}"
            f"{' · ' + str(h['unencrypted_ssh_keys']) + ' unencrypted SSH key(s)' if h['unencrypted_ssh_keys'] else ''}</td></tr>")
    vuln_rows = "".join(
        f"<tr><td>{v['host_count']}</td><td><span class='sev {_e(v['severity'])}'>{_e(v['severity'])}</span>"
        f"{' ' + KEV_TAG if v['kev'] else ''}</td><td>{_e(v['ecosystem'])}</td>"
        f"<td><b>{_e(v['name'])}</b> {_e(v['version'])}</td><td class='fix'>{_e(v.get('fix_version') or '')}</td>"
        f"<td class='muted'>{_e(', '.join(sorted(v['hosts'])[:8]))}{' …' if v['host_count'] > 8 else ''}</td></tr>"
        for v in fleet["vulnerabilities"][:300])
    cve_rows = "".join(
        f"<tr><td><code>{_e(e['cve'])}</code>{' ' + KEV_TAG if e['kev'] else ''}</td>"
        f"<td>{e['host_count']}</td><td><span class='sev {_e(e['severity'])}'>{_e(e['severity'])}</span></td>"
        f"<td class='muted'>{_e(', '.join(e['packages']))}</td></tr>" for e in fleet["cves"][:200])
    resp_rows = "".join(f"<tr><td>{_e(r['host'])}</td><td>{_e(r['ecosystem'])}</td><td><b>{_e(r['name'])}</b> {_e(r['version'])}</td>"
                        f"<td><code>{_e(', '.join(r['advisories']))}</code></td></tr>" for r in fleet["respond"])
    mal_rows = "".join(f"<tr><td><span class='sev {_e(m['severity'].upper())}'>{_e(m['severity'].upper())}</span></td>"
                       f"<td>{_e(m['title'])}</td><td class='muted'>{_e(', '.join(x['host'] for x in m['hosts']))}</td></tr>"
                       for m in fleet["malware"])
    shared = (f"<p class='why'><b>Same indicator on several hosts:</b> {_e(', '.join(fleet['shared_ioc_hosts']))}</p>"
              if fleet["shared_ioc_hosts"] else "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Fleet Report</title><style>{CSS} table{{font-size:13px}} .wrap{{overflow-x:auto}}</style></head><body><main>
<h1>Supply chain fleet report</h1><div class="muted">{_e(fleet['created'])} · scs {_e(fleet['scs_version'])}</div>
<div class="tiles">{tiles}</div>
<h2>Hosts</h2><div class="wrap"><table><tr><th>Host</th><th>Scan age</th><th>Respond</th><th>Patch</th><th>Verify</th>
<th>Monitor</th><th>Outdated</th><th>Malware crit / high</th><th>Exposure</th></tr>{''.join(host_rows)}</table></div>
{f'<h2>Respond now (malicious / IOC)</h2>{shared}<div class="wrap"><table><tr><th>Host</th><th>Ecosystem</th><th>Package</th><th>Indicators</th></tr>{resp_rows}</table></div>' if resp_rows else ''}
<h2>Most widespread vulnerable packages</h2><p class="muted">Ranked by hosts affected × risk score. Fixing one row fixes it everywhere it appears.</p>
<div class="wrap"><table><tr><th>Hosts</th><th>Severity</th><th>Ecosystem</th><th>Package</th><th>Fix</th><th>Where</th></tr>{vuln_rows}</table></div>
<h2>CVEs across the fleet</h2><div class="wrap"><table><tr><th>CVE</th><th>Hosts</th><th>Severity</th><th>Packages</th></tr>{cve_rows}</table></div>
{f'<h2>Malware / compromise checks (medium and above)</h2><div class="wrap"><table><tr><th>Severity</th><th>Finding</th><th>Hosts</th></tr>{mal_rows}</table></div>' if mal_rows else ''}
</main></body></html>"""
