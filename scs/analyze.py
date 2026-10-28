"""Turn packages + advisories into scored, bucketed findings with advice."""
from __future__ import annotations

import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from scs import handfix, shell, toolchain
from scs.graph import annotate
from scs.models import SEVERITY_ORDER, Advisory, Finding, Package, normalize_name
from scs.policy import Decisions, Policy
from scs.versions import is_major_bump, lowest_fix_above, vkey

BUCKETS = ("respond", "patch", "verify", "monitor")
BUCKET_TITLES = {
    "respond": "Respond now (malicious / IOC)",
    "patch": "Patch now",
    "verify": "Verify first",
    "monitor": "No automatic fix (fix by hand, vendor-only, or none published yet)",
}

# Upgrading these tends to break builds/ABIs or many dependents: always verify first.
TOOLCHAIN = {
    "Homebrew": {"python", "node", "openssl", "llvm", "gcc", "openjdk", "go", "rust", "ruby", "perl",
                 "php", "cmake", "icu4c", "protobuf", "boost", "qt", "glib", "libffi", "readline",
                 "sqlite", "zlib", "xz", "ca-certificates", "bash", "zsh", "git"},
    "PyPI": {"numpy", "scipy", "torch", "tensorflow", "protobuf", "grpcio", "setuptools", "pip",
             "cython", "pybind11", "cryptography", "pyopenssl", "jax", "jaxlib"},
    "npm": {"node-gyp", "typescript", "webpack", "esbuild", "vite", "@angular/core", "react",
            "react-native", "electron", "next"},
    "Runtime": {"java", "node", "python"},
    "Go": {"stdlib"},
}
SEV_BASE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5, "UNKNOWN": 4.0}

RESPOND_CHECKLIST = [
    "Do not run, import or rebuild anything that depends on it until cleaned.",
    "Remove the package (or the tool/project that pulled it in) and reinstall from a lockfile pinned to a safe version.",
    "Rotate credentials reachable from this machine: npm/PyPI tokens (~/.npmrc, ~/.pypirc), GitHub/gh tokens, SSH keys, cloud credentials (~/.aws, ~/.config/gcloud, ~/.azure), .env secrets.",
    "Check for persistence: LaunchAgents/LaunchDaemons, crontab, shell rc files, unexpected .github/workflows in your repos.",
    "Search your other machines and CI runners for the same package@version.",
]


def _advisory_score(a: Advisory) -> float:
    if a.malicious:
        return 100.0
    base = a.cvss if a.cvss is not None else SEV_BASE.get(a.severity, 4.0)
    s = base * 10
    if a.kev:
        s = max(s, 90) + 5
    if a.epss:
        s += a.epss * 15
    if a.confidence == "low":
        s *= 0.7
    return s


# Debian/Ubuntu source packages whose update needs service restarts or a reboot to take effect.
DEB_SYSTEM = {"glibc", "systemd", "openssl", "openssh", "sudo", "dbus", "polkit", "pam", "gnutls28", "nss",
              "libxml2", "zlib", "xz-utils", "util-linux", "shadow", "apt", "dpkg", "grub2", "shim", "intel-microcode",
              "amd64-microcode", "linux-firmware", "python3-defaults", "perl", "bash", "coreutils", "cryptsetup"}


def _toolchain_sensitive(eco: str, name: str) -> bool:
    base = re.sub(r"@[\d.]+$", "", normalize_name(eco, name))
    if eco.startswith(("Ubuntu:", "Debian:")):
        return base in DEB_SYSTEM or base.startswith(("linux", "python3.", "gcc-", "llvm-toolchain"))
    return base in TOOLCHAIN.get(eco, set())


def _q(s: str) -> str:
    return shell.current().q(s)


def _fix_commands(p: Package, fix: str | None, malicious: bool) -> list[str]:
    n = p.name
    if not malicious and handfix.manual_only(p.to_dict()):
        return handfix.commands(p.ecosystem, n, p.version, fix, p.to_dict())
    if p.source == "apt":
        bins = " ".join(_q(b["name"]) for b in p.meta.get("binaries", [])) or _q(n)
        if malicious:
            return [f"sudo apt-get remove {bins}"]
        return [f"sudo apt-get update && sudo apt-get install --only-upgrade {bins}"]
    if p.source in ("snap", "flatpak"):
        return [f"sudo snap refresh {_q(n)}" if p.source == "snap" else f"flatpak update {_q(n)}"]
    if p.source == "brew":
        if malicious:
            return [f"brew uninstall {'--cask ' if p.ecosystem == 'Homebrew-cask' else ''}{n}"]
        return [f"brew upgrade {'--cask ' if p.ecosystem == 'Homebrew-cask' else ''}{n}"]
    if p.source == "pip":
        py = _q(p.meta.get("python", "python3"))
        if malicious:
            return [f"{py} -m pip uninstall -y {_q(n)}"]
        return [f"{py} -m pip install --upgrade {_q(f'{n}>={fix}')}"] if fix else []
    if p.source == "npm-global":
        top = next((c for c in p.chain if not c.startswith("(")), None)
        if malicious:
            return [f"npm uninstall -g {_q(top or n)}"]
        if not fix:
            return []
        if p.direct:
            return [f"npm install -g {_q(f'{n}@{fix}')}"]
        return [f"npm install -g {_q(f'{top}@latest')}   # pulls in {n} via {' > '.join(p.chain)}"] if top else []
    if p.source == "cargo":
        return [f"cargo install {_q(n)} --locked --force"]
    if p.source == "lockfile":
        lf = p.meta.get("lockfile", "")
        if malicious:
            pin = f"pin {n} to a known-good version (not {p.version}) in {lf}, delete node_modules / the venv, reinstall"
            return [shell.current().adapt(f"{shell.current().cd(p.meta.get('project', '.'))}  # {pin}")]
        if not fix:
            return []
        cmds = {
            "package-lock.json": f"npm install {_q(f'{n}@^{fix}')}" if p.direct
            else f"npm update {_q(n)}   # if still old: add \"overrides\": {{\"{n}\": \"^{fix}\"}} to package.json",
            "npm-shrinkwrap.json": f"npm update {_q(n)}",
            "yarn.lock": f"yarn up {_q(n)}   # yarn 1: yarn upgrade {n}; or add a \"resolutions\" entry",
            "pnpm-lock.yaml": f"pnpm update {_q(n)}   # or pnpm.overrides in package.json",
            "poetry.lock": f"poetry update {_q(n)}",
            "uv.lock": f"uv lock --upgrade-package {_q(n)}",
            "Pipfile.lock": f"pipenv update {_q(n)}",
            "Cargo.lock": f"cargo update -p {_q(n)} --precise {_q(fix)}",
            "go.mod": f"go get {_q(f'{n}@v{fix}' + ('+incompatible' if '+incompatible' in p.version else ''))} && go mod tidy",
            "Gemfile.lock": f"bundle update {_q(n)} --conservative",
            "composer.lock": f"composer update {_q(n)} --with-dependencies",
        }
        cmd = cmds.get(lf) or f"# edit {lf}: {n}=={fix}"
        return [shell.current().adapt(f"{shell.current().cd(p.meta.get('project', '.'))} && {cmd}")]
    return []


@dataclass
class AnalysisContext:
    """Optional inputs that refine findings; every field may be left empty (e.g. in tests)."""
    graphs: dict = field(default_factory=dict)
    policy: Optional[Policy] = None
    decisions: Optional[Decisions] = None
    projects: dict[str, dict] = field(default_factory=dict)  # project dir -> toolchain.detect_project()
    brew_versions: dict[str, str] = field(default_factory=dict)
    requirements: Optional[toolchain.Requirements] = None


def _fix_version(version: str, advs: list[Advisory], ecosystem: str = "") -> tuple[Optional[str], int]:
    fixes, unfixed = [], 0
    for a in advs:
        if a.malicious:
            continue
        lf = lowest_fix_above(version, a.fixed, ecosystem)
        if lf:
            fixes.append(lf)
        else:
            unfixed += 1
    return (max(fixes, key=lambda v: vkey(v, ecosystem)) if fixes else None), unfixed


def _prefetch_requirements(groups: dict, advisories: dict, actx: AnalysisContext) -> None:
    if not actx.requirements:
        return
    wanted = set()
    for key, advs in advisories.items():
        if key[0] in toolchain.RUNTIME_OF and groups.get(key):
            fix, _ = _fix_version(key[2], advs, key[0])
            if fix:
                wanted.add((key[0], groups[key][0].name, fix))
    if wanted:
        from scs.util import log
        log(f"checking runtime requirements of {len(wanted)} fixed versions…")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda k: actx.requirements.get(*k), wanted))
    actx.requirements.save()


OS_MANAGED_PY = ("/Library/Developer/CommandLineTools", "/Applications/Xcode", "/System/", "/usr/lib/python")


def _bundled_top(p: Package) -> Optional[str]:
    if p.source != "npm-global" or p.direct:
        return None
    return next((c for c in p.chain if not c.startswith("(")), None)


def _bundled_tool_fixes(packages: list[Package], groups: dict, advisories: dict,
                        actx: AnalysisContext) -> dict[tuple[str, str], dict]:
    """(global root, tool) -> npm_tool_update() result, for tools that bundle a vulnerable package.

    Packages bundled inside a global tool (npm bundles tar, undici, ...) can only be fixed by
    updating the tool, so whether they are "safe" depends on the tool having a compatible release.
    """
    if actx.requirements is None or getattr(actx.requirements, "offline", True):
        return {}
    tool_versions = {(p.meta.get("root"), p.name): p.version for p in packages if p.source == "npm-global" and p.direct}
    needs: dict[tuple[str, str], dict[str, str]] = {}
    for key, advs in advisories.items():
        for p in groups.get(key, []):
            top = _bundled_top(p)
            fix, _ = _fix_version(key[2], advs, key[0])
            if top and fix:
                needs.setdefault((p.meta.get("root"), top), {})[p.name] = fix
    out = {}
    for (root, tool), want in needs.items():
        installed = tool_versions.get((root, tool))
        if installed and root:
            out[(root, tool)] = toolchain.npm_tool_update(tool, installed, toolchain.node_version_for_root(root), want)
    return out


def build_findings(packages: list[Package], advisories: dict, file_hits: list[dict],
                   previous: dict[str, set[str]] | None = None,
                   actx: Optional[AnalysisContext] = None) -> tuple[list[Finding], list[dict]]:
    """Return (findings, ignored) where ignored lists findings fully suppressed by policy."""
    previous = previous or {}
    actx = actx or AnalysisContext()
    groups: dict[tuple, list[Package]] = defaultdict(list)
    for p in packages:
        groups[p.key].append(p)
    _prefetch_requirements(groups, advisories, actx)
    bundle_fix = _bundled_tool_fixes(packages, groups, advisories, actx)

    findings: list[Finding] = []
    ignored_out: list[dict] = []
    for key, advs in advisories.items():
        pkgs = groups.get(key)
        if not pkgs or not advs:
            continue
        first = pkgs[0]
        ignored: list[dict] = []
        if actx.policy:
            advs, ignored = actx.policy.filter(advs, pkgs)
            if not advs:
                ignored_out.append({"ecosystem": first.ecosystem, "name": first.name, "version": first.version,
                                    "locations": len(pkgs), "rules": ignored})
                continue
        f = Finding(ecosystem=first.ecosystem, name=first.name, version=first.version,
                    packages=pkgs, advisories=sorted(advs, key=lambda a: -_advisory_score(a)))
        malicious = any(a.malicious for a in advs)
        f.severity = max((a.severity for a in advs), key=lambda s: SEVERITY_ORDER.get(s, 0))

        exposure = 1.0
        if all(p.dev for p in pkgs):
            exposure *= 0.7
            f.reasons.append("dev-only dependency")
        if all(p.direct is False for p in pkgs):
            exposure *= 0.9
        if all(p.source in ("java-cache", "pub-cache") for p in pkgs):
            exposure *= 0.8
            cache = "Gradle/Maven" if pkgs[0].source == "java-cache" else "Dart/Flutter (pub)"
            f.reasons.append(f"only in the {cache} download cache: a build on this computer used it")
        f.score = min(100, round(max(_advisory_score(a) for a in advs) * (1 if malicious else exposure)))

        f.ignored = ignored
        f.fix_version, unfixed = _fix_version(f.version, advs, f.ecosystem)
        latest = first.meta.get("latest")
        if first.source == "brew" and latest and vkey(latest) > vkey(f.version):
            f.fix_version = f.fix_version or latest

        annotate(pkgs, actx.graphs)
        if f.fix_version and not malicious:
            req = actx.requirements.get(f.ecosystem, f.name, f.fix_version) \
                if actx.requirements and f.ecosystem in toolchain.RUNTIME_OF else None
            runtimes = []
            for p in pkgs:
                rt = toolchain.runtime_for(p, actx.projects, actx.brew_versions)
                if rt:
                    runtimes.append({**rt, "where": p.meta.get("project") or p.meta.get("env") or p.source})
                for r in toolchain.check(p, f.fix_version, rt, req, f.ecosystem):
                    if r not in f.reasons:
                        f.reasons.append(r)
                conflict = toolchain.pin_conflict(p, f.fix_version, actx.projects)
                if conflict and conflict not in f.reasons:
                    f.reasons.append(conflict)
            f.toolchain = {"runtime": toolchain.RUNTIME_OF.get(f.ecosystem), "fix_requires": req,
                           "runtimes": runtimes[:20]}

        if malicious:
            f.bucket = "respond"
            f.advice = "Known malicious version. " + RESPOND_CHECKLIST[1]
        elif not f.fix_version:
            f.bucket = "monitor"
            f.advice = "No fixed version published. Apply the advisory's workaround, limit exposure, or replace the package."
        else:
            if unfixed:
                f.reasons.append(f"{unfixed} advisory(ies) still unfixed in {f.fix_version}")
            if is_major_bump(f.version, f.fix_version, f.ecosystem):
                f.reasons.append(f"major version bump {f.version} → {f.fix_version}")
            if _toolchain_sensitive(f.ecosystem, f.name):
                if f.ecosystem.startswith(("Ubuntu:", "Debian:")):
                    f.reasons.append("kernel: reboot required" if f.name.startswith("linux")
                                     else "system component: restart affected services (or reboot) after upgrading")
                else:
                    f.reasons.append("runtime/toolchain package: dependents may need rebuild")
            if "esm" in f.fix_version:
                f.reasons.append("fixed only in Ubuntu Pro (ESM): needs `sudo pro attach` (free for personal use)")
            vendor_only = bool(pkgs) and all(p.source == "pip" and str(p.meta.get("env", "")).startswith(OS_MANAGED_PY)
                                             for p in pkgs)
            if vendor_only:
                f.reasons.append("in Apple's/the OS's own Python: only Apple (Command Line Tools / Xcode updates) or your "
                                 "OS vendor can replace these files")
            for p in pkgs:
                top = _bundled_top(p)
                pick = bundle_fix.get((p.meta.get("root"), top)) if top else None
                if not pick or pick.get("error"):
                    continue
                if pick.get("version"):
                    note = f"fixed by updating {top} to {pick['version']} (it bundles {f.name})"
                else:
                    # no usable release of the tool ships it: scs replaces the copy inside the tool and
                    # load-tests the tool (a major jump keeps its own "major version bump" reason)
                    note = f"fixed by patching {f.name} inside {top} (no {top} release includes the fix yet)"
                if note not in f.reasons:
                    f.reasons.append(note)
            if any(p.meta.get("pinned") for p in pkgs):
                f.reasons.append("pinned in Homebrew (brew pin)")
            used_by = max((len(p.meta.get("used_by", [])) for p in pkgs), default=0)
            if used_by >= 5:
                f.reasons.append(f"{used_by} installed formulae depend on it")
            if any(a.confidence == "low" for a in advs) and all(a.confidence == "low" for a in advs):
                f.reasons.append("low-confidence CPE match: confirm the CVE applies")
            blocking = [r for r in f.reasons if not r.startswith(("dev-only", f"{unfixed} advisory", "fixed by "))]
            f.bucket = "verify" if blocking else "patch"
            f.advice = f"Upgrade {f.name} {f.version} → {f.fix_version}."
            pdicts = [p.to_dict() for p in pkgs]
            if all(handfix.manual_only(p) for p in pdicts):
                # installers, IDEs and build scripts: scs gives the steps instead of running them
                f.bucket = "monitor"
                if all(handfix.vendor_managed(p) for p in pdicts):
                    vendor = pkgs[0].meta.get("vendor") or "the vendor"
                    f.advice = (f"{f.name} {f.version} ships with the operating system / developer tools; only {vendor} "
                                f"can update this copy. {f.fix_version} has the fix.")
                else:
                    f.advice += " Update it by hand: scs can't change installers or build files for you (see the steps)."
            if vendor_only:
                f.bucket = "monitor"
                f.advice = (f"{f.name} {f.version} is part of the Python that ships with the operating system / Apple's "
                            "Command Line Tools. It cannot be changed safely in place; install vendor updates when they "
                            "appear (macOS: System Settings › General › Software Update). Avoid running untrusted code "
                            "with that Python meanwhile.")
            intro = sorted({i for p in pkgs if not p.direct for i in p.meta.get("introduced_by", [])})
            if intro and all(p.direct is False for p in pkgs):
                shown = ", ".join(intro[:3]) + (f" (+{len(intro) - 3})" if len(intro) > 3 else "")
                f.advice += f" It is transitive, pulled in by {shown}: update those, or force the version with an override."
            if f.bucket == "verify":
                f.advice += " Test builds/apps that use it before rolling out."

        seen_cmds: list[str] = []
        for p in pkgs:
            for c in _fix_commands(p, f.fix_version, malicious):
                if c not in seen_cmds:
                    seen_cmds.append(c)
        f.commands = seen_cmds
        ids = {a.id for a in advs}
        prev = previous.get(f.key)
        f.new = prev is None or bool(ids - prev)
        if actx.decisions:
            f.decision = actx.decisions.get(f.key, ids)
        findings.append(f)

    for hit in file_hits:
        adv = Advisory(id=f"IOC:{hit['pack']}", summary=hit["name"], severity="CRITICAL",
                       malicious=True, source="ioc", references=hit.get("references", []))
        f = Finding(ecosystem="file", name=hit["path"], version="", packages=[], advisories=[adv],
                    score=100, severity="CRITICAL", bucket="respond",
                    advice="IOC file found. Inspect it (do not execute), remove it, and follow the incident checklist.")
        prev = previous.get(f.key)
        f.new = prev is None
        if actx.decisions:
            f.decision = actx.decisions.get(f.key, {adv.id})
        findings.append(f)

    findings.sort(key=lambda f: (BUCKETS.index(f.bucket), -f.score, f.name))
    return findings, ignored_out


def summarize(findings: list[Finding]) -> dict:
    s = {b: 0 for b in BUCKETS}
    sev = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        s[f.bucket] += 1
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {"buckets": s, "severity": sev, "total": len(findings), "new": sum(f.new for f in findings)}
