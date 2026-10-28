"""Do-it-yourself update steps for what scs can't change itself.

Runtimes (JDKs, Node.js, Python, Go), OS-bundled tools (Apple's git, curl,
ssh), the Maven/Gradle/pub download caches, and the build files of Android,
iOS, Flutter, .NET and other ecosystems are updated by installers, IDEs or
by editing build scripts, so scs gives the steps instead of running them. Each step is {"text", "cmd", "link"?}.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

MANUAL_SOURCES = {"runtime", "devtool", "java-cache", "pub-cache", "nuget-cache", "gem", "go-binary", "dotnet-tool",
                  "corepack"}
MANUAL_LOCKFILES = {"pom.xml", "gradle.lockfile", "libs.versions.toml", "packages.lock.json", "build.gradle",
                    "build.gradle.kts", "pubspec.lock", "Package.resolved", "Cartfile.resolved", "Podfile.lock",
                    "bun.lock", "deno.lock", "mix.lock", "renv.lock", "conan.lock", "Directory.Packages.props", "workflow",
                    "pdm.lock", "pylock.toml", "cabal.project.freeze", "stack.yaml.lock", "Manifest.toml",
                    "JuliaManifest.toml", "rebar.lock", "paket.lock", "package.json"}
MSBUILD = (".csproj", ".fsproj", ".vbproj")

JDK_DOWNLOADS = {
    "eclipse-temurin": "https://adoptium.net/temurin/releases/?version={cycle}",
    "amazon-corretto": "https://aws.amazon.com/corretto/",
    "azul-zulu": "https://www.azul.com/downloads/?version=java-{cycle}-lts&package=jdk",
    "oracle-jdk": "https://www.oracle.com/java/technologies/downloads/",
    "microsoft-build-of-openjdk": "https://learn.microsoft.com/java/openjdk/download",
}


def _q(s: str) -> str:
    return s if re.fullmatch(r"[\w@%+=:,./-]+", s) else "'" + s.replace("'", "'\\''") + "'"


def _qp(path: str) -> str:
    """A quoted path, written as ~/… under the home folder (shorter, and no user name when shared)."""
    home = os.path.expanduser("~")
    if os.name != "nt" and path.startswith(home + os.sep):
        return "~/" + _q(path[len(home) + 1:])
    return _q(path)


def manual_only(p: dict) -> bool:
    meta = p.get("meta") or {}
    lf = meta.get("lockfile") or ""
    return p.get("source") in MANUAL_SOURCES or (p.get("source") == "lockfile" and (
        lf in MANUAL_LOCKFILES or lf.endswith(MSBUILD + (".opam.locked",)) or lf.startswith(("pylock.", "Manifest-v"))))


def vendor_managed(p: dict) -> bool:
    return bool((p.get("meta") or {}).get("vendor_managed"))


def _formula(location: str) -> str:
    m = re.search(r"/Cellar/([^/]+)/", location)
    return m.group(1) if m else ""


# runtimes whose release lines are "major.minor" (the others are numbered by major version)
TWO_PART_LINES = {"python", "go", "php", "ruby", "elixir", "perl", "ghc", "julia", "rust", "deno", "maven"}


def _cycle_of(version: str, runtime: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2]) if runtime in TWO_PART_LINES else parts[0]


def _gradle_root(project: str) -> str:
    d = Path(project)
    for cand in [d, *d.parents]:
        if (cand / "gradlew").exists() or (cand / "settings.gradle").exists() or (cand / "settings.gradle.kts").exists():
            return str(cand)
    return project


def _runtime_steps(name: str, version: str, fix: str, p: dict) -> list[dict]:
    meta, loc = p.get("meta") or {}, p.get("location", "")
    rt, mgr = meta.get("runtime"), meta.get("manager", "")
    cycle = _cycle_of(version, rt) if rt not in ("java", "node") else str(meta.get("cycle", ""))
    new_cycle = _cycle_of(fix, rt) if fix else cycle
    moving = new_cycle != cycle
    from scs.collectors.runtimes import LABELS
    label = {"java": "JDK"}.get(rt) or LABELS.get(rt, name)
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
                                  "the next time a build needs it.", "cmd": f"rm -rf {_qp(loc)}"})
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
        elif "/sdk/" in loc.replace("\\", "/"):
            steps.append({"text": f"Install Go {fix} next to it.", "cmd": f"go install golang.org/dl/go{fix}@latest && go{fix} download"})
        else:
            steps.append({"text": f"Download Go {fix} and install it over this one.", "cmd": "", "link": "https://go.dev/dl/"})
    elif rt in OTHER_RUNTIMES:
        steps += _other_runtime_steps(rt, mgr, fix, new_cycle, loc)
    return steps


OTHER_RUNTIMES = {"php", "ruby", "dotnet", "erlang", "elixir", "rust", "deno", "bun", "perl", "ghc", "julia", "gradle",
                  "maven", "bazel"}
ASDF_PLUGIN = {"php": "php", "ruby": "ruby", "erlang": "erlang", "elixir": "elixir", "rust": "rust", "deno": "deno",
               "bun": "bun", "perl": "perl", "ghc": "haskell", "julia": "julia", "gradle": "gradle", "maven": "maven"}
DOWNLOADS = {
    "php": "https://www.php.net/downloads.php", "ruby": "https://www.ruby-lang.org/en/downloads/",
    "dotnet": "https://dotnet.microsoft.com/download/dotnet/{cycle}", "erlang": "https://www.erlang.org/downloads",
    "elixir": "https://elixir-lang.org/install.html", "perl": "https://www.perl.org/get.html",
    "julia": "https://julialang.org/downloads/", "bazel": "https://github.com/bazelbuild/bazel/releases",
}


def _other_runtime_steps(rt: str, mgr: str, fix: str, cycle: str, loc: str) -> list[dict]:
    by_manager = {
        "phpenv": f"phpenv install {fix}", "rbenv": f"rbenv install {fix}", "rvm": f"rvm install {fix}",
        "chruby": f"ruby-install ruby {fix}", "rustup": "rustup update stable", "ghcup": f"ghcup install ghc {fix}",
        "juliaup": "juliaup update", "perlbrew": f"perlbrew install perl-{fix}", "plenv": f"plenv install {fix}",
        "Deno installer": "deno upgrade", "Bun installer": "bun upgrade", "SDKMAN": f"sdk install {rt} {fix}",
        "dotnet-install": f"./dotnet-install.sh --channel {cycle}   # from https://dot.net/v1/dotnet-install.sh",
        "asdf": f"asdf install {ASDF_PLUGIN.get(rt, rt)} {fix}", "mise": f"mise use -g {ASDF_PLUGIN.get(rt, rt)}@{fix}",
    }
    if mgr == "macOS":
        return [{"text": "This is the Ruby that comes with macOS. Apple no longer updates it: install your own Ruby "
                         "(Homebrew or rbenv) and use that for your work.", "cmd": "brew install ruby"}]
    if mgr == "Gradle wrapper":
        return [{"text": f"Projects whose wrapper uses this Gradle should move to {fix}: run this in each of them "
                         "(it updates gradle/wrapper/), then add the new distributionSha256Sum.",
                 "cmd": f"./gradlew wrapper --gradle-version {fix}"}]
    if mgr == "Maven wrapper":
        return [{"text": f"Projects whose wrapper uses this Maven should move to {fix}: run this in each of them.",
                 "cmd": f"./mvnw wrapper:wrapper -Dmaven={fix}"}]
    if mgr == "Bazelisk":
        return [{"text": f"Projects that pin this Bazel should move to {fix}: change .bazelversion in each of them.",
                 "cmd": f"echo {fix} > .bazelversion"}]
    if mgr in ("MAMP", "XAMPP", "Laravel Herd", "Laragon"):
        return [{"text": f"This PHP comes with {mgr}: update {mgr}, or switch its PHP version to {cycle} in its settings.",
                 "cmd": ""}]
    if mgr == "Stack":
        return [{"text": f"Stack installed this GHC for a resolver: move the projects to a resolver that uses GHC {cycle}.",
                 "cmd": "stack config set resolver lts"}]
    if mgr in by_manager:
        return [{"text": f"Install {fix}.", "cmd": by_manager[mgr]}]
    link = DOWNLOADS.get(rt, "").format(cycle=cycle)
    return [{"text": f"Download and install {fix}, then remove the old version.", "cmd": "", **({"link": link} if link else {})}]


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
    if src == "gem":
        if meta.get("vendor_managed"):
            return [{"text": "This gem comes with macOS's own Ruby; only Apple updates it. Use your own Ruby (Homebrew, "
                             "rbenv) for your work.", "cmd": "brew install ruby"}]
        gem = _qp(meta.get("gem") or "gem")
        return [{"text": f"Update the gem{' to ' + fix if fix else ''}, then remove the old version.",
                 "cmd": f"{gem} install {name}" + (f" -v {fix}" if fix else "") + f" && {gem} uninstall {name} -v {version}"}]
    if src == "go-binary":
        main, binary = meta.get("main", ""), os.path.basename(p.get("location", ""))
        what = f"Go {fix}" if name == "stdlib" else f"{name} {fix}" if fix else name
        return [{"text": f"{binary} was built with {name} {version}. Rebuild it so it uses {what}: reinstall the latest "
                         f"release (built with a current Go), or remove it if you don't use it.",
                 "cmd": f"go install {main}@latest" if main else ""}]
    if src == "dotnet-tool":
        return [{"text": f"Update the .NET tool{' to ' + fix if fix else ''}.",
                 "cmd": f"dotnet tool update -g {name}" + (f" --version {fix}" if fix else "")}]
    if src == "corepack":
        return [{"text": f"Corepack downloaded {name} {version}. Projects that pin it in package.json "
                         f"(\"packageManager\") should move to {fix or 'a fixed version'}; run this in each of them.",
                 "cmd": f"corepack use {name}@{fix or 'latest'}"}]
    if src in ("java-cache", "pub-cache", "nuget-cache"):
        artifact = name.split(":")[-1]
        cache = {"gradle": "Gradle", "maven": "Maven", "coursier": "Coursier (sbt/Scala)", "pub": "Dart/Flutter",
                 "nuget": "NuGet (.NET)"}.get(meta.get("cache"), "build")
        return [{"text": f"A {cache} build on this computer downloaded it. Update the projects that still use it "
                         f"(search them for \"{artifact}\"), then delete the old copy from the cache.",
                 "cmd": f"rm -rf {_qp(p.get('location', ''))}"}]
    lf, proj = meta.get("lockfile"), meta.get("project", "")
    to = f" to {fix}" if fix else ""
    if lf == "pom.xml":
        return [{"text": f"Set {name}'s version{to} in pom.xml (in <dependencyManagement> if it comes in through "
                         "another library), then rebuild.", "cmd": f"cd {_qp(proj)} && mvn dependency:tree -Dincludes={name}"}]
    if lf in ("libs.versions.toml", "gradle.lockfile", "build.gradle", "build.gradle.kts"):
        root = _gradle_root(proj)
        where = {"libs.versions.toml": "gradle/libs.versions.toml", "gradle.lockfile":
                 "the build (version catalog, or a dependency constraint if another library pulls it in)"}.get(lf, lf)
        out = [{"text": f"Change {name}{to} in {where}, then rebuild.",
                "cmd": f"cd {_qp(root)} && ./gradlew dependencyInsight --dependency {name}"}]
        if lf == "gradle.lockfile":
            out.append({"text": "Refresh the lockfiles afterwards.", "cmd": f"cd {_qp(root)} && ./gradlew dependencies --write-locks"})
        return out
    if lf == "packages.lock.json":
        cmd = f"dotnet add package {name}" + (f" --version {fix}" if fix else "") if p.get("direct") else \
            "dotnet list package --include-transitive --vulnerable"
        return [{"text": f"Update {name}{to} in the project, then restore.", "cmd": f"cd {_qp(proj)} && {cmd}"}]
    if lf.endswith(MSBUILD) or lf == "Directory.Packages.props":
        where = f"the PackageVersion entry in {lf}" if lf == "Directory.Packages.props" else lf
        return [{"text": f"Update {name}{to} in {where}, then restore and rebuild.",
                 "cmd": f"cd {_qp(proj)} && dotnet add package {name}" + (f" --version {fix}" if fix else "")
                 if lf != "Directory.Packages.props" else f"cd {_qp(proj)} && dotnet list package --vulnerable"}]
    simple = {  # lockfile -> (what to tell, command run in the project)
        "pubspec.lock": ("Upgrade it in the Flutter/Dart project (add --major-versions if the fix is a new major), "
                         "then run the app's tests.", f"flutter pub upgrade {name}   # Dart-only project: dart pub upgrade {name}"),
        "Package.resolved": ("Update the Swift package: in Xcode, File › Packages › Update to Latest Package Versions; "
                             "if the fix is outside the allowed range, raise the version rule in the project first.",
                             f"swift package update {name.rsplit('/', 1)[-1]}"),
        "Cartfile.resolved": ("Update it with Carthage (raise the version in the Cartfile if needed), then rebuild.",
                              f"carthage update {name.rsplit('/', 1)[-1]} --use-xcframeworks"),
        "Podfile.lock": ("Update the pod (raise its version in the Podfile if needed), then rebuild the iOS app.",
                         f"pod update {name}"),
        "bun.lock": (f"Update it with Bun{to}, then run your tests.", f"bun update {name}"),
        "deno.lock": (f"Update the npm package{to} in deno.json, then refresh the lockfile.", f"deno outdated --update {name}"),
        "mix.lock": (f"Update the Elixir dependency{to} (raise its requirement in mix.exs if needed).", f"mix deps.update {name}"),
        "renv.lock": (f"Update the R package{to} and record it in renv.lock.",
                      f"Rscript -e 'renv::update(\"{name}\"); renv::snapshot()'"),
        "conan.lock": (f"Raise {name}{to} in conanfile, then recreate the lockfile.", "conan lock create . --update"),
        "pdm.lock": (f"Update {name}{to} with PDM, then run your tests.", f"pdm update {name}"),
        "cabal.project.freeze": (f"Raise {name}{to} in the .cabal file, then refresh the freeze file.", "cabal freeze"),
        "stack.yaml.lock": (f"Move the project to a Stack resolver (or extra-deps entry) with {name}{to}.",
                            f"stack ls dependencies | grep {name}"),
        "rebar.lock": (f"Upgrade the Erlang dependency{to}.", f"rebar3 upgrade {name}"),
        "paket.lock": (f"Update the package{to} with Paket.", f"dotnet paket update {name}"),
        "package.json": (f"The project pins {name} {version} as its package manager; move it to {fix or 'a fixed version'}.",
                         f"corepack use {name}@{fix or 'latest'}"),
    }
    for julia in ("Manifest.toml", "JuliaManifest.toml"):
        simple[julia] = (f"Update the Julia package{to}.", f"julia --project=. -e 'using Pkg; Pkg.update(\"{name}\")'")
    if lf.startswith("Manifest-v"):
        lf = "Manifest.toml"
    if lf.endswith(".opam.locked"):
        return [{"text": f"Raise {name}{to} in the .opam file, then regenerate the lock file.", "cmd": f"cd {_qp(proj)} && opam lock ."}]
    if lf.startswith("pylock."):
        return [{"text": f"Update {name}{to} with the tool that wrote {lf} (pip, uv or PDM), then regenerate it.", "cmd": ""}]
    if lf in simple:
        text, cmd = simple[lf]
        return [{"text": text, "cmd": f"cd {_qp(proj)} && {cmd}"}]
    if lf == "workflow":
        return [{"text": f"In .github/workflows/{meta.get('workflow', '')}, change `uses: {name}@{meta.get('ref', '')}` to "
                         f"{fix or 'a fixed release'}, pinned to that release's full commit SHA "
                         f"(uses: {name}@<sha> # v{fix or 'x.y.z'}).", "cmd": "",
                 "link": f"https://github.com/{name}/releases"}]
    return []


def commands(ecosystem: str, name: str, version: str, fix: str | None, p: dict) -> list[str]:
    return [s["cmd"] for s in steps(ecosystem, name, version, fix, p) if s.get("cmd")]
