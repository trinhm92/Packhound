"""Do-it-yourself update steps for what scs can't change itself.

Runtimes (JDKs, Node.js, Python, Go), OS-bundled tools (Apple's git, curl,
ssh), the Maven/Gradle download caches and Java/.NET build files are updated
by installers, IDEs or by editing build scripts, so scs gives the steps
instead of running them. Each step is {"text", "cmd", "link"?}.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

MANUAL_SOURCES = {"runtime", "devtool", "java-cache"}
MANUAL_LOCKFILES = {"pom.xml", "gradle.lockfile", "libs.versions.toml", "packages.lock.json"}

JDK_DOWNLOADS = {
    "eclipse-temurin": "https://adoptium.net/temurin/releases/?version={cycle}",
    "amazon-corretto": "https://aws.amazon.com/corretto/",
    "azul-zulu": "https://www.azul.com/downloads/?version=java-{cycle}-lts&package=jdk",
    "oracle-jdk": "https://www.oracle.com/java/technologies/downloads/",
    "microsoft-build-of-openjdk": "https://learn.microsoft.com/java/openjdk/download",
}


def _q(s: str) -> str:
    return s if re.fullmatch(r"[\w@%+=:,./-]+", s) else "'" + s.replace("'", "'\\''") + "'"


def manual_only(p: dict) -> bool:
    meta = p.get("meta") or {}
    return p.get("source") in MANUAL_SOURCES or (p.get("source") == "lockfile" and meta.get("lockfile") in MANUAL_LOCKFILES)


def vendor_managed(p: dict) -> bool:
    return bool((p.get("meta") or {}).get("vendor_managed"))


def _formula(location: str) -> str:
    m = re.search(r"/Cellar/([^/]+)/", location)
    return m.group(1) if m else ""


def _cycle_of(fix: str, runtime: str) -> str:
    parts = fix.split(".")
    return ".".join(parts[:2]) if runtime in ("python", "go") else parts[0]


def _gradle_root(project: str) -> str:
    d = Path(project)
    for cand in [d, *d.parents]:
        if (cand / "gradlew").exists() or (cand / "settings.gradle").exists() or (cand / "settings.gradle.kts").exists():
            return str(cand)
    return project


def _runtime_steps(name: str, version: str, fix: str, p: dict) -> list[dict]:
    meta, loc = p.get("meta") or {}, p.get("location", "")
    rt, mgr, cycle = meta.get("runtime"), meta.get("manager", ""), str(meta.get("cycle", ""))
    new_cycle = _cycle_of(fix, rt) if fix else cycle
    moving = new_cycle != cycle
    label = {"java": "JDK", "node": "Node.js", "python": "Python", "go": "Go"}.get(rt, name)
    steps: list[dict] = []
    if moving:
        steps.append({"text": f"{label} {cycle} no longer gets security fixes. Install {label} {new_cycle} "
                              f"and move your projects to it (test them: it is a new release line).", "cmd": ""})
    formula = _formula(loc)
    if mgr == "Homebrew" and formula:
        # unversioned formulae (go, node, openjdk) follow the newest line; python@3.10 / openjdk@17 stay on theirs
        cmd = f"brew install {formula.split('@')[0]}@{new_cycle}" if moving and "@" in formula else f"brew upgrade {formula}"
        steps.append({"text": "Update it with Homebrew.", "cmd": cmd})
    elif rt == "java":
        if mgr == "SDKMAN":
            steps.append({"text": f"Install the latest {new_cycle} build of the same vendor with SDKMAN and make it the default.",
                          "cmd": f"sdk list java | grep ' {new_cycle}\\.'   # then: sdk install java <identifier> && sdk default java <identifier>"})
        elif mgr == "Android Studio" or "IntelliJ IDEA" in loc:
            steps.append({"text": "This JDK is bundled with the IDE: update the IDE (Help › Check for Updates).", "cmd": ""})
        elif mgr == "Gradle toolchains":
            steps.append({"text": "Gradle downloaded this JDK for a toolchain. Delete it; Gradle fetches a current one "
                                  "the next time a build needs it.", "cmd": f"rm -rf {_q(loc)}"})
        else:
            url = JDK_DOWNLOADS.get(meta.get("product", ""), JDK_DOWNLOADS["eclipse-temurin"]).format(cycle=new_cycle)
            bundle = loc.split(".jdk/")[0] + ".jdk" if ".jdk/" in loc else loc
            steps.append({"text": f"Download and install the latest {label} {new_cycle} from {meta.get('vendor') or 'the vendor'}.",
                          "cmd": "", "link": url})
            steps.append({"text": "Then remove the old one (after checking nothing points to it, e.g. JAVA_HOME).",
                          "cmd": f"sudo rm -rf {_q(bundle)}" if bundle.startswith("/Library/Java/") else ""})
    elif rt == "node":
        cmd = {"nvm": f"nvm install {new_cycle} && nvm alias default {new_cycle}", "Volta": f"volta install node@{new_cycle}",
               "fnm": f"fnm install {new_cycle} && fnm default {new_cycle}", "asdf": f"asdf install nodejs latest:{new_cycle}",
               "mise": f"mise use -g node@{new_cycle}"}.get(mgr)
        steps.append({"text": f"Install the latest Node.js {new_cycle}.x.", "cmd": cmd or "",
                      **({} if cmd else {"link": "https://nodejs.org/en/download"})})
    elif rt == "python":
        if mgr == "Apple Command Line Tools":
            steps.append({"text": "This is Apple's Python. Install Apple's Command Line Tools updates; use your own Python "
                                  "(pyenv, Homebrew, python.org) for your work.", "cmd": "softwareupdate --list"})
        else:
            cmd = {"pyenv": f"pyenv install {fix}   # then point projects at it: pyenv local {fix}",
                   "uv": f"uv python install {fix}", "asdf": f"asdf install python {fix}", "mise": f"mise install python@{fix}"}.get(mgr)
            steps.append({"text": f"Install Python {fix}. Virtual environments made from {version} keep the old one: "
                                  "recreate them.", "cmd": cmd or "",
                          **({} if cmd else {"link": "https://www.python.org/downloads/"})})
    elif rt == "go":
        if mgr == "Go toolchain cache":
            steps.append({"text": f"A go.mod asks for this toolchain. Raise it in each project; Go downloads the new one itself.",
                          "cmd": f"go get toolchain@go{fix}"})
        elif "/sdk/" in loc:
            steps.append({"text": f"Install Go {fix} next to it.", "cmd": f"go install golang.org/dl/go{fix}@latest && go{fix} download"})
        else:
            steps.append({"text": f"Download Go {fix} and install it over this one.", "cmd": "", "link": "https://go.dev/dl/"})
    return steps


def steps(ecosystem: str, name: str, version: str, fix: str | None, p: dict) -> list[dict]:
    meta, src = p.get("meta") or {}, p.get("source")
    fix = fix or ""
    if src == "runtime":
        return _runtime_steps(name, version, fix, p)
    if src == "devtool":
        bin_ = "ssh" if name == "openssh" else name
        if meta.get("vendor") == "Microsoft":
            return [{"text": "Windows ships this copy: install Windows updates (Settings › Windows Update).", "cmd": ""}]
        return [{"text": f"Apple ships this {name}: install the Command Line Tools / Xcode / macOS updates.",
                 "cmd": "softwareupdate --list"},
                {"text": f"Or install {name} from Homebrew and make sure its folder comes first in PATH.",
                 "cmd": f"brew install {name}   # then check: which -a {bin_}"}]
    if src == "java-cache":
        artifact = name.split(":")[-1]
        cache = "Gradle" if meta.get("cache") == "gradle" else "Maven"
        return [{"text": f"A {cache} build on this computer downloaded it. Update the projects that still use it "
                         f"(search them for \"{artifact}\"), then delete the old copy from the cache.",
                 "cmd": f"rm -rf {_q(p.get('location', ''))}"}]
    lf, proj = meta.get("lockfile"), meta.get("project", "")
    to = f" to {fix}" if fix else ""
    if lf == "pom.xml":
        return [{"text": f"Set {name}'s version{to} in pom.xml (in <dependencyManagement> if it comes in through "
                         "another library), then rebuild.", "cmd": f"cd {_q(proj)} && mvn dependency:tree -Dincludes={name}"}]
    if lf in ("libs.versions.toml", "gradle.lockfile"):
        root = _gradle_root(proj)
        where = "gradle/libs.versions.toml" if lf == "libs.versions.toml" else \
            "the build (version catalog, or a dependency constraint if another library pulls it in)"
        out = [{"text": f"Change {name}{to} in {where}, then rebuild.",
                "cmd": f"cd {_q(root)} && ./gradlew dependencyInsight --dependency {name}"}]
        if lf == "gradle.lockfile":
            out.append({"text": "Refresh the lockfiles afterwards.", "cmd": f"cd {_q(root)} && ./gradlew dependencies --write-locks"})
        return out
    if lf == "packages.lock.json":
        cmd = f"dotnet add package {name}" + (f" --version {fix}" if fix else "") if p.get("direct") else \
            "dotnet list package --include-transitive --vulnerable"
        return [{"text": f"Update {name}{to} in the project, then restore.", "cmd": f"cd {_q(proj)} && {cmd}"}]
    return []


def commands(ecosystem: str, name: str, version: str, fix: str | None, p: dict) -> list[str]:
    return [s["cmd"] for s in steps(ecosystem, name, version, fix, p) if s.get("cmd")]
