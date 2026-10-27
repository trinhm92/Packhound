"""Serve the Packhound UI with made-up demo data, for README screenshots.

Nothing from the real machine is shown: HOME, the data/cache folders and the host
name are replaced, and the findings are built from public advisories for a
fictional developer laptop ("demo-mac", projects under ~/code).

    python3 docs/screenshots/demo.py            # prints the URL, Ctrl+C to stop
    python3 docs/screenshots/demo.py --shoot    # also writes the PNGs with headless Chrome
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="packhound-demo-"))
os.environ.update({"HOME": str(TMP), "XDG_DATA_HOME": str(TMP / "data"), "XDG_CACHE_HOME": str(TMP / "cache"),
                   "XDG_CONFIG_HOME": str(TMP / "config")})
socket.gethostname = lambda: "demo-mac"  # shown in the sidebar
sys.path.insert(0, str(REPO))

from scs.analyze import build_findings, summarize  # noqa: E402
from scs.models import Advisory, Package  # noqa: E402

H = str(TMP)
# page -> (width, height, findings tab)
PAGES = {"home": (1280, 860, ""), "findings": (1280, 1180, "wait"), "malware": (1280, 1080, "")}


def lock(eco, name, version, project, lockfile, direct=True, dev=False):
    d = f"{H}/code/{project}"
    return Package(eco, name, version, "lockfile", f"{d}/{lockfile}", scope="project", direct=direct, dev=dev,
                   meta={"project": d, "lockfile": lockfile})


def adv(id_, sev, fixed, summary, cvss=None, malicious=False, kev=False, source="osv"):
    return Advisory(id_, summary=summary, severity=sev, fixed=fixed, cvss=cvss, malicious=malicious, kev=kev, source=source,
                    references=[f"https://osv.dev/vulnerability/{id_}"])


def demo_scan() -> dict:
    items = [
        (lock("npm", "event-stream", "3.3.6", "webshop", "package-lock.json", direct=False),
         [adv("GHSA-mh6f-8j2x-4483", "CRITICAL", [], "Critical severity vulnerability that affects event-stream and flatmap-stream",
              malicious=True)]),
        (lock("npm", "lodash", "4.17.20", "webshop", "package-lock.json"),
         [adv("GHSA-35jh-r3h4-6jhm", "HIGH", ["4.17.21"], "Command Injection in lodash", cvss=7.2)]),
        (lock("PyPI", "requests", "2.31.0", "data-api", "poetry.lock"),
         [adv("GHSA-9wx4-h78v-vm56", "MEDIUM", ["2.32.0"], "Requests `Session` object does not verify requests after making "
              "first request with verify=False", cvss=5.6)]),
        (lock("PyPI", "jinja2", "3.1.2", "data-api", "poetry.lock"),
         [adv("GHSA-h75v-3vvj-5mfj", "MEDIUM", ["3.1.4"], "Jinja vulnerable to HTML attribute injection when passing "
              "user input as keys to xmlattr filter", cvss=5.4)]),
        (lock("Go", "golang.org/x/net", "0.17.0", "gateway", "go.mod"),
         [adv("GHSA-4v7x-pqxf-cx7m", "HIGH", ["0.23.0"], "net/http, x/net/http2: close connections when receiving too "
              "many headers", cvss=7.5)]),
        (lock("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "android-app", "gradle.lockfile"),
         [adv("GHSA-jfh8-c2jp-5v3q", "CRITICAL", ["2.15.0"], "Remote code injection in Log4j", cvss=10.0, kev=True)]),
        (Package("Runtime", "node", "20.11.0", "runtime", "/opt/homebrew/Cellar/node@20/20.11.0", direct=True,
                 meta={"runtime": "node", "manager": "Homebrew", "product": "nodejs", "cycle": "20",
                       "display": "Node.js 20.11.0 (Homebrew, /opt/homebrew/Cellar/node@20/20.11.0)"}),
         [Advisory("EOL-nodejs-20", summary="Node.js 20 reached end of life on 2026-04-30: it no longer gets security "
                   "fixes. Move to Node.js 22 (latest 22.21.1).", severity="HIGH", fixed=["22.21.1"], source="eol",
                   references=["https://endoflife.date/nodejs"])]),
        (Package("Dev-tool", "curl", "8.7.1", "devtool", "/usr/bin/curl", direct=True,
                 meta={"vendor": "Apple", "vendor_managed": True, "cpe": ["haxx", "curl"],
                       "display": "curl from Apple (macOS: /usr/bin/curl)"}),
         [Advisory("CVE-2024-6197", summary="libcurl's ASN1 parser has a utf8asn1str() function used for parsing an "
                   "ASN.1 UTF-8 string. It can detect an invalid field and return error.", severity="HIGH", cvss=7.5,
                   fixed=["8.9.0"], source="nvd", confidence="low",
                   references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6197"])]),
    ]
    pkgs = [p for p, _ in items]
    findings, ignored = build_findings(pkgs, {p.key: a for p, a in items}, [])
    started = "2026-10-27T09:00:12+07:00"
    return {
        "scs_version": "0.1.0", "host": "demo-mac", "started": started, "platform": "Darwin 25.6.0 arm64",
        "duration_s": 41.3, "config": {"roots": [f"{H}/code"], "offline": False, "nvd": False, "system": True},
        "collectors": {}, "errors": [], "has_previous": True,
        "sources": {"osv": "1874 packages queried, 214 advisories", "runtimes": "9 runtimes checked"},
        "inventory": {"total": 2310, "unique": 1874, "by_ecosystem": {}},
        "summary": summarize(findings), "findings": [f.to_dict() for f in findings], "ignored": ignored,
        "policy": {"rules": 0, "expired": 0}, "projects": {}, "outdated": [], "packages": [],
    }


def demo_malware() -> dict:
    def f(check, sev, title, path, advice, evidence=(), rules=(), quarantinable=False):
        return {"check": check, "severity": sev, "title": title, "path": path, "evidence": list(evidence),
                "rules": list(rules), "advice": advice, "quarantinable": quarantinable, "new": True, "meta": {}}
    return {
        "kind": "malware", "scs_version": "0.1.0", "host": "demo-mac", "started": "2026-10-27T09:01:40+07:00",
        "duration_s": 12.4, "checks": ["packages", "buildchain", "persistence", "extensions", "exposure"],
        "has_baseline": True, "stats": {}, "ignored": [], "inventory": {}, "yara_rules": [],
        "counts": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
        "findings": [
            f("buildchain", "critical", "Gradle wrapper jar does not match any Gradle release",
              f"{H}/code/android-app/gradle/wrapper/gradle-wrapper.jar",
              "Don't run ./gradlew in this project. Check how it changed (git log -p -- gradle/wrapper/gradle-wrapper.jar), "
              "then restore it from a trusted commit or regenerate it with a Gradle you installed yourself: gradle wrapper.",
              ["sha256 9f2c1e…"], ["GRADLE_WRAPPER_MISMATCH"], True),
            f("packages", "high", "install script of flatmap-stream runs downloaded code",
              f"{H}/code/webshop/node_modules/flatmap-stream/index.min.js",
              "Install-time code runs with your user's rights. Remove the package and reinstall from a clean lockfile "
              "with --ignore-scripts, then rotate tokens listed under Exposure.",
              ["EVAL_DECODE: decodes and evaluates a payload", "SECRET_TOOLING: reads wallet / credential files"],
              ["EVAL_DECODE", "SECRET_TOOLING"], True),
            f("buildchain", "low", "workflow release.yml in webshop: 2 action(s) not pinned to a commit",
              f"{H}/code/webshop/.github/workflows/release.yml",
              "A tag or branch can be moved to new code, which then runs with your repository's secrets. Pin each action "
              "to its full commit SHA.", ["tj-actions/changed-files@v45", "actions/setup-node@v4"], ["ACTION_NOT_PINNED"]),
        ],
        "exposure": [
            {"label": "npm token", "path": f"{H}/.npmrc", "state": "token present", "mode": "0o600",
             "world_readable": False, "rotate": "npm token revoke <id>, then npm login"},
            {"label": "GitHub CLI token", "path": f"{H}/.config/gh/hosts.yml", "state": "token present", "mode": "0o600",
             "world_readable": False, "rotate": "gh auth refresh"},
        ],
    }


def main() -> int:
    from scs import history
    from scs.ui.server import serve
    from scs.util import data_dir, write_json
    (TMP / ".config" / "scs").mkdir(parents=True, exist_ok=True)
    write_json(TMP / ".config" / "scs" / "config.json", {"roots": ["~/code"]})
    history.save(demo_scan())
    (data_dir() / "malware-latest.json").write_text(json.dumps(demo_malware()), encoding="utf-8")
    httpd, _, url = serve(port=0)
    print(f"demo UI: {url}")
    if "--shoot" in sys.argv:
        chrome = shutil.which("google-chrome") or shutil.which("chromium") or \
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        for page, (w, h, tab) in PAGES.items():
            out = OUT / f"{page}.png"
            subprocess.run([chrome, "--headless=new", "--hide-scrollbars", "--force-device-scale-factor=2",
                            f"--window-size={w},{h}", "--virtual-time-budget=4000", f"--user-data-dir={TMP / 'chrome'}",
                            f"--screenshot={out}", f"{url}&page={page}" + (f"&tab={tab}" if tab else "")],
                           check=True, capture_output=True)
            print(f"wrote {out.relative_to(REPO)}")
        httpd.shutdown()
        shutil.rmtree(TMP, ignore_errors=True)
        return 0
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        httpd.shutdown()
        shutil.rmtree(TMP, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
