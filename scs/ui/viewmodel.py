"""Plain-language view of scan and malware results for non-technical users.

The UI shows these simplified records; the technical detail (advisory ids,
dependency chains, commands) stays available under "Details".
"""
from __future__ import annotations

import os
import re

from scs.models import finding_key
from scs.report import short_path

ECO_LABEL = {
    "PyPI": "Python package", "npm": "JavaScript package", "Go": "Go module", "crates.io": "Rust package",
    "RubyGems": "Ruby package", "Packagist": "PHP package", "Maven": "Java library", "NuGet": ".NET package",
    "Homebrew": "Homebrew tool", "Homebrew-cask": "Mac app (Homebrew)", "Windows-app": "Windows program",
    "winget": "App (winget)", "chocolatey": "App (Chocolatey)", "scoop": "App (Scoop)", "Snap": "Snap app",
    "Flatpak": "Flatpak app", "file": "Suspicious file", "Runtime": "Language runtime", "Dev-tool": "Developer tool",
    "Pub": "Dart/Flutter package", "SwiftURL": "Swift package (iOS/macOS)", "CocoaPods": "CocoaPods pod (iOS)",
    "Hex": "Elixir package", "CRAN": "R package", "ConanCenter": "C/C++ package (Conan)", "GitHub Actions": "GitHub Action",
    "Hackage": "Haskell package", "Julia": "Julia package", "opam": "OCaml package",
}
GROUPS = {
    "respond": {"id": "act", "title": "Act now", "blurb": "Known malicious software. Remove it and change your passwords and tokens."},
    "patch": {"id": "update", "title": "Safe to update", "blurb": "A fixed version exists and updating is low-risk."},
    "verify": {"id": "check", "title": "Check before updating", "blurb": "A fix exists, but it may affect apps or projects that use it."},
    "monitor": {"id": "wait", "title": "No automatic fix", "blurb": "Packhound can't install these for you: no fixed version "
                "has been published, only the vendor (Apple, your Linux distribution, …) can ship it, or it is updated by "
                "hand (JDKs, Node.js, Python and Go installs, Java build files). Each item lists the steps."},
}
SEVERITY_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Unrated"}


def eco_label(eco: str) -> str:
    if eco.startswith(("Ubuntu:", "Debian:")):
        return f"System package ({eco.replace(':LTS', ' LTS').replace(':', ' ')})"
    return ECO_LABEL.get(eco, eco)


def where_plain(p: dict) -> str:
    meta = p.get("meta") or {}
    src = p.get("source")
    if src in ("runtime", "devtool", "gem", "go-binary", "dotnet-tool", "corepack") or (src == "lockfile" and meta.get("display")):
        return meta.get("display") or short_path(p.get("location", ""))
    if src == "java-cache":
        return "Gradle download cache" if meta.get("cache") == "gradle" else "Maven local repository (~/.m2)"
    if src == "pub-cache":
        return "Dart/Flutter download cache (pub)"
    if src == "nuget-cache":
        return "NuGet download cache (~/.nuget/packages)"
    if src == "lockfile" and meta.get("lockfile") == "workflow":
        return f"Workflow {meta.get('workflow', '')} in {os.path.basename(meta.get('project', ''))}"
    if src == "lockfile":
        proj = meta.get("project", "")
        return f"Project {os.path.basename(proj)} ({short_path(proj)})"
    if src == "pip":
        env = meta.get("env", "")
        m = re.search(r"(\d+\.\d+(\.\d+)?)", env) or re.search(r"python(\d\.\d+)", p.get("location", ""))
        ver = f" {m.group(1)}" if m else ""
        if "/.pyenv/" in env:
            return f"Python{ver} (pyenv)"
        if "venv" in env or "/.venv" in env:
            return f"Python environment in {short_path(env)}"
        return f"Python{ver} ({short_path(env)})"
    if src == "npm-global":
        return "Globally installed JavaScript tools" + (f", inside {p['chain'][0]}" if p.get("chain") else "")
    return {"brew": "Homebrew", "apt": "System packages (APT)", "cargo": "Rust tools (cargo install)",
            "winget": "winget", "choco": "Chocolatey", "scoop": "Scoop", "snap": "Snap", "flatpak": "Flatpak",
            "programs": "Installed programs"}.get(src or "", short_path(p.get("location", "")))


def _link(a: dict) -> str:
    refs = [r for r in a.get("references", []) if r.startswith("https://")]
    if a["id"].startswith(("GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "MAL-", "UBUNTU-", "DEBIAN-", "USN-", "DSA-")):
        return f"https://osv.dev/vulnerability/{a['id']}"
    return refs[0] if refs else ""


def _bundled_in(f: dict) -> str:
    """The global tool that bundles this package (e.g. npm bundles tar), if every location is such a copy."""
    tops = set()
    for p in f["packages"]:
        chain = [c for c in p.get("chain", []) if not c.startswith("(")]
        if p.get("source") != "npm-global" or not chain:
            return ""
        tops.add(chain[0])
    return tops.pop() if len(tops) == 1 else ""


def _q(s: str) -> str:
    return s if re.fullmatch(r"[\w@%+=:,./-]+", s) else "'" + s.replace("'", "'\\''") + "'"


def manual_steps(f: dict) -> list[dict]:
    """Do-it-yourself steps for an item scs can't fix itself ("No automatic fix"): [{text, cmd}]."""
    if f["bucket"] != "monitor" or f["ecosystem"] == "file":
        return []
    from scs import handfix
    from scs.analyze import OS_MANAGED_PY
    name, fix, pkgs = f["name"], f.get("fix_version"), f["packages"]
    steps: list[dict] = []
    if pkgs and all(handfix.manual_only(p) for p in pkgs):
        for p in pkgs:
            for st in handfix.steps(f["ecosystem"], name, f["version"], fix, p):
                if st not in steps:
                    steps.append(st)
        steps = steps[:8]
        for a in [a for a in f["advisories"] if _link(a)][:2]:
            steps.append({"text": f"Read {a['id']} for details.", "cmd": "", "link": _link(a)})
        return steps
    envs = [(p.get("meta") or {}).get("env", "") for p in pkgs]
    if pkgs and all(p.get("source") == "pip" and e.startswith(OS_MANAGED_PY) for p, e in zip(pkgs, envs)):
        py = (pkgs[0].get("meta") or {}).get("python") or "python3"
        if envs[0].startswith("/usr/lib/python"):
            mgr = "sudo apt update && sudo apt install --only-upgrade" if os.path.exists("/usr/bin/apt") else "sudo dnf upgrade"
            steps.append({"text": f"Install your Linux distribution's update for it (the package is usually python3-{name.lower()}).",
                          "cmd": f"{mgr} python3-{name.lower()}"})
        else:
            steps.append({"text": "Install Apple's latest Command Line Tools: System Settings › General › Software Update, "
                                  "or list the available updates here. Apple may still ship this version.",
                          "cmd": "softwareupdate --list"})
        if fix and not any(r.startswith(f"{fix} needs python") for r in f.get("reasons", [])):
            steps.append({"text": f"Or install the fixed version into your user folder, where this Python looks first. Apple's/the "
                                  f"OS's copy stays on disk and still shows here: ignore it afterwards.",
                          "cmd": f"{_q(py)} -m pip install --user {_q(f'{name}>={fix}')}"})
        steps.append({"text": "Use your own Python for your work (pyenv, Homebrew, python.org), not this one. "
                              "The first line printed here is the one your terminal uses.", "cmd": "which -a python3"})
        return steps
    seen = set()
    for p in pkgs:
        meta, src = p.get("meta") or {}, p.get("source")
        key = (src, meta.get("project") or meta.get("env") or "")
        if key in seen or len(seen) >= 2:
            continue
        seen.add(key)
        proj = _q(meta.get("project", ""))
        if src == "lockfile" and f["ecosystem"] == "Go":
            steps.append({"text": f"See which module pulls it into {short_path(meta['project'])}.",
                          "cmd": f"cd {proj} && go mod why -m {name}"})
            if len(seen) == 1:
                steps.append({"text": "Check for a newer release. If there is one, update to it in each project and run your tests.",
                              "cmd": f"cd {proj} && go list -m -u {name}  # then: go get {name}@latest && go mod tidy"})
        elif src == "lockfile" and f["ecosystem"] == "npm":
            steps.append({"text": f"See what pulls it into {short_path(meta['project'])}"
                                  + (" (only used while developing; it isn't shipped)" if p.get("dev") else "") + ".",
                          "cmd": f"cd {proj} && npm ls {name}"})
            if len(seen) == 1:
                steps.append({"text": "If a newer version exists, force it with \"overrides\" in package.json, "
                                      "then reinstall and run your tests.", "cmd": f"npm view {name} version"})
        elif src == "lockfile":
            steps.append({"text": f"Look for a newer {name} release or a maintained replacement, then update "
                                  f"{meta.get('lockfile', 'the lockfile')} in {short_path(meta.get('project', ''))}.", "cmd": ""})
        elif src == "pip":
            py = _q(meta.get("python") or "python3")
            steps.append({"text": "See whether anything needs it (\"Required-by\"). If nothing does and you don't use it, uninstall it.",
                          "cmd": f"{py} -m pip show {name}  # then: {py} -m pip uninstall {name}"})
        elif src == "npm-global":
            steps.append({"text": "See which global tool includes it. Remove the tool if you don't use it.",
                          "cmd": f"npm ls -g {name}"})
        elif src == "brew":
            steps.append({"text": "See what depends on it. If nothing does and you don't use it, uninstall it.",
                          "cmd": f"brew uses --installed {name}  # then: brew uninstall {name}"})
    links = [a for a in f["advisories"] if _link(a)][:2]
    for a in links:
        steps.append({"text": f"Read {a['id']} for a workaround or mitigation.", "cmd": "", "link": _link(a)})
    return steps


def display_name(f: dict) -> str:
    """'stdlib' is Go's standard library: name the toolchain instead."""
    if f["ecosystem"] == "Go" and f["name"] == "stdlib":
        return "Go"
    from scs.collectors.runtimes import LABELS
    return LABELS.get(f["name"], f["name"]) if f["ecosystem"] == "Runtime" else f["name"]


def plain_finding(f: dict) -> dict:
    from scs import handfix
    malicious = f["bucket"] == "respond"
    kev = any(a.get("kev") for a in f["advisories"])
    if f["ecosystem"] == "file":
        headline = f"Suspicious file found: {os.path.basename(f['name'])}"
        action = "Remove or quarantine this file and change passwords/tokens used on this computer."
    elif malicious:
        headline = f"{f['name']} {f['version']} is a known malicious version"
        action = "Remove it, reinstall a clean version, and change passwords/tokens used on this computer."
    elif f.get("fix_version") and f["bucket"] == "monitor" and not all(handfix.vendor_managed(p) for p in f["packages"]) \
            and all(handfix.manual_only(p) for p in f["packages"]):
        headline = f"Update {display_name(f)} from {f['version']} to {f['fix_version']} by hand"
        action = "Packhound can't change installers or build files for you: follow the steps below."
    elif f.get("fix_version") and f["bucket"] == "monitor":
        headline = f"{display_name(f)} {f['version']}: fixed in {f['fix_version']}, but Packhound can't install it here"
        action = "Only the vendor can replace this copy. Until then, follow the steps below."
    elif f.get("fix_version") and _bundled_in(f):
        tool = _bundled_in(f)
        headline = f"Update {f['name']} from {f['version']} to {f['fix_version']} (bundled inside {tool})"
        action = (f"It ships inside {tool}, so it is fixed by updating {tool}. “Fix safe items” picks a {tool} "
                  f"version that runs on your Node.js and includes the fix, or tells you if none exists yet.")
    elif f.get("fix_version"):
        headline = f"Update {f['name']} from {f['version']} to {f['fix_version']}"
        action = "Use “Fix safe items” or select it on the Fix page." if f["bucket"] == "patch" else \
            "Updating may affect what uses it: check the notes, then fix it from the Fix page."
    else:
        headline = f"{display_name(f)} {f['version']} has a known problem without a fix yet"
        action = "Nothing to install yet; Packhound keeps watching. Meanwhile, the steps below lower the risk."
    summary = next((a.get("summary") for a in f["advisories"] if a.get("summary")), "")
    return {
        "key": finding_key(f), "group": GROUPS[f["bucket"]]["id"], "headline": headline, "action": action,
        "name": display_name(f), "version": f["version"], "fix": f.get("fix_version"),
        "kind": "Go toolchain" if display_name(f) == "Go" and f["ecosystem"] == "Go" else eco_label(f["ecosystem"]),
        "severity": SEVERITY_LABEL.get(f["severity"], f["severity"]), "score": f["score"], "new": f.get("new", False),
        "exploited": kev, "malicious": malicious, "summary": summary,
        "where": sorted({where_plain(p) for p in f["packages"]})[:8] or [short_path(f["name"])],
        "where_count": len(f["packages"]), "notes": f.get("reasons", []), "decision": f.get("decision"),
        "manual": manual_steps(f),
        "details": {
            "ecosystem": f["ecosystem"], "advice": f.get("advice", ""), "commands": f.get("commands", [])[:6],
            "advisories": [{"id": a["id"], "cves": a.get("cves", [])[:3], "severity": a["severity"],
                            "summary": a.get("summary", ""), "link": _link(a), "kev": a.get("kev", False),
                            "epss": a.get("epss")} for a in f["advisories"][:12]],
            "chains": [" › ".join(x) for p in f["packages"][:5] for x in ((p.get("meta") or {}).get("paths") or [])[:2]],
            "toolchain": f.get("toolchain"),
        },
    }


def health(scan: dict | None, malware: dict | None) -> dict:
    if not scan:
        return {"level": "unknown", "headline": "Not scanned yet", "detail": "Run your first scan to see how this computer is doing."}
    osv_note = str((scan.get("sources") or {}).get("osv", ""))
    if osv_note.startswith(("FAILED", "INCOMPLETE")):
        return {"level": "attention", "headline": "Scan incomplete",
                "detail": "Some vulnerability data could not be downloaded, so problems may be missing. "
                          f"Check the internet connection and scan again. ({osv_note.split(':', 1)[-1].strip()[:180]})"}
    b = scan["summary"]["buckets"]
    kev = sum(1 for f in scan["findings"] if any(a.get("kev") for a in f["advisories"]))
    mal = (malware or {}).get("counts") or {}
    if b.get("respond") or mal.get("critical"):
        return {"level": "act", "headline": "Act now",
                "detail": "Malicious software or a strong sign of compromise was found. Open “Act now” first."}
    if mal.get("high") or kev or scan["summary"]["severity"].get("CRITICAL"):
        parts = []
        if kev:
            parts.append(f"{kev} issue(s) are being exploited in the wild")
        if scan["summary"]["severity"].get("CRITICAL"):
            parts.append(f"{scan['summary']['severity']['CRITICAL']} critical issue(s)")
        if mal.get("high"):
            parts.append(f"{mal['high']} suspicious item(s) in the malware check")
        return {"level": "attention", "headline": "Needs attention", "detail": "; ".join(parts) + "."}
    if b.get("patch") or b.get("verify"):
        return {"level": "attention", "headline": "Updates recommended",
                "detail": f"{b.get('patch', 0) + b.get('verify', 0)} item(s) have security updates available."}
    return {"level": "good", "headline": "Looking good", "detail": "No known vulnerable or malicious software found."}


def plain_malware(m: dict) -> dict:
    sev = m["severity"]
    return {"id": f"{m['check']}|{m['title']}|{m.get('path', '')}", "severity": sev.capitalize(), "level": sev,
            "title": m["title"], "path": short_path(m.get("path", "")), "raw_path": m.get("path", ""),
            "advice": m.get("advice", ""), "evidence": m.get("evidence", [])[:6], "check": m["check"],
            "can_quarantine": bool(m.get("quarantinable") and m.get("path") and os.path.exists(m["path"])),
            "new": m.get("new", False)}


def counts(items: list[dict]) -> dict:
    out = {g["id"]: 0 for g in GROUPS.values()}
    for i in items:
        out[i["group"]] += 1
    return out
