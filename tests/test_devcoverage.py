import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs.analyze import build_findings
from scs.collectors import java, lockfiles, runtimes
from scs.enrich import runtimes as rt_enrich
from scs.malware import buildchain
from scs.models import Advisory, Package


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp())


def write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(text, bytes) else path.write_text)(text)
    return path


class JavaLockfileTests(unittest.TestCase):
    def test_pom(self):
        pom = write(tmpdir() / "pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <version>2.0</version>
  <properties><jackson.version>2.15.0</jackson.version></properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.1</version><scope>test</scope></dependency>
    <dependency><groupId>a</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
    <dependency><groupId>a</groupId><artifactId>managed</artifactId></dependency>
  </dependencies>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.33</version></dependency>
    <dependency><groupId>x</groupId><artifactId>bom</artifactId><version>1</version><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>""")
        pkgs, _ = lockfiles.parser_for("pom.xml")(pom)
        got = {(p.name, p.version, p.dev) for p in pkgs}
        self.assertEqual(got, {("com.fasterxml.jackson.core:jackson-databind", "2.15.0", False),
                               ("junit:junit", "4.13.1", True), ("org.yaml:snakeyaml", "1.33", False)})
        self.assertTrue(all(p.ecosystem == "Maven" and p.direct for p in pkgs))
        write(pom, '<!DOCTYPE p [<!ENTITY a "x">]><project/>')
        with self.assertRaises(ValueError):
            lockfiles.parse_pom(pom)

    def test_gradle_lockfile_and_catalog(self):
        d = tmpdir()
        lock = write(d / "app" / "gradle.lockfile", "# comment\n"
                     "com.squareup.okhttp3:okhttp:4.9.0=debugRuntimeClasspath,releaseRuntimeClasspath\n"
                     "junit:junit:4.12=debugUnitTestRuntimeClasspath,testRuntimeClasspath\nempty=annotationProcessor\n")
        pkgs, _ = lockfiles.parse_gradle_lockfile(lock)
        self.assertEqual({(p.name, p.version, p.dev) for p in pkgs},
                         {("com.squareup.okhttp3:okhttp", "4.9.0", False), ("junit:junit", "4.12", True)})
        cat = write(d / "gradle" / "libs.versions.toml", """[versions]
okhttp = "4.12.0"
strict = { strictly = "1.2.3" }
[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
gson = { group = "com.google.code.gson", name = "gson", version = "2.10.1" }
s = { module = "a:b", version.ref = "strict" }
short = "c:d:3.0"
nover = { module = "e:f" }
[plugins]
android = { id = "com.android.application", version = "8.0.0" }
""")
        pkgs, _ = lockfiles.parser_for("libs.versions.toml")(cat)
        self.assertEqual({(p.name, p.version) for p in pkgs},
                         {("com.squareup.okhttp3:okhttp", "4.12.0"), ("com.google.code.gson:gson", "2.10.1"),
                          ("a:b", "1.2.3"), ("c:d", "3.0")})
        self.assertEqual(pkgs[0].meta["project"], str(d))  # the project, not its gradle/ folder

    def test_nuget(self):
        lock = write(tmpdir() / "packages.lock.json", '{"version": 1, "dependencies": {"net8.0": {'
                     '"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"},'
                     '"System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},'
                     '"MyLib": {"type": "Project"}}, "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}}}}')
        pkgs, _ = lockfiles.parser_for("packages.lock.json")(lock)
        self.assertEqual({(p.ecosystem, p.name, p.version, p.direct) for p in pkgs},
                         {("NuGet", "Newtonsoft.Json", "12.0.1", True), ("NuGet", "System.Text.Json", "8.0.0", False)})


class JavaCacheTests(unittest.TestCase):
    def test_gradle_and_maven_caches(self):
        g = tmpdir()
        base = g / "caches" / "modules-2" / "files-2.1"
        write(base / "org.yaml" / "snakeyaml" / "1.33" / "abc" / "snakeyaml-1.33.jar", b"jar")
        write(base / "org.yaml" / "snakeyaml" / "1.30" / "def" / "snakeyaml-1.30.pom", "pom only: lost conflict resolution")
        write(base / "com.x" / "lib" / "2.0" / "fff" / "lib-2.0-sources.jar", b"sources only")
        pkgs = java.gradle_cache(g)
        self.assertEqual([(p.name, p.version) for p in pkgs], [("org.yaml:snakeyaml", "1.33")])
        m = tmpdir()
        write(m / "org" / "apache" / "logging" / "log4j" / "log4j-core" / "2.14.1" / "log4j-core-2.14.1.jar", b"jar")
        write(m / "org" / "apache" / "logging" / "log4j" / "log4j-core" / "2.17.1" / "log4j-core-2.17.1.pom", "pom")
        pkgs = java.maven_cache(m)
        self.assertEqual([(p.name, p.version, p.source) for p in pkgs],
                         [("org.apache.logging.log4j:log4j-core", "2.14.1", "java-cache")])


class RuntimeCollectorTests(unittest.TestCase):
    def test_jdk_release_files(self):
        d = tmpdir()
        write(d / "temurin" / "release", 'JAVA_VERSION="17.0.9"\nIMPLEMENTOR="Eclipse Adoptium"\n')
        write(d / "old" / "release", 'JAVA_VERSION="1.8.0_392"\nIMPLEMENTOR="Amazon.com Inc."\n')
        write(d / "jbr" / "release", 'JAVA_VERSION="21.0.10"\nIMPLEMENTOR="JetBrains s.r.o."\n')
        with mock.patch.object(runtimes, "jdk_homes", return_value=[str(d / x) for x in ("temurin", "old", "jbr")]):
            got = {(p.version, p.meta["product"], p.meta["cycle"]) for p in runtimes.jdks()}
        self.assertEqual(got, {("17.0.9", "eclipse-temurin", "17"), ("8.0.392", "amazon-corretto", "8"),
                               ("21.0.10", "eclipse-temurin", "21")})  # JetBrains: OpenJDK's own update line

    def test_go_toolchain_cache_only_when_requested(self):
        from scs.collectors import Context
        from scs.config import Config
        gopath = tmpdir()
        for v in ("1.25.1", "1.26.4"):
            write(gopath / "pkg" / "mod" / "golang.org" / f"toolchain@v0.0.1-go{v}.darwin-arm64" / "VERSION", f"go{v}\ntime x\n")
        proj = tmpdir()
        gomod = write(proj / "go.mod", "module x\n\ngo 1.24\n\ntoolchain go1.26.4\n")
        ctx = Context(Config())
        ctx.lockfiles = [gomod]
        with mock.patch.dict(os.environ, {"GOPATH": str(gopath)}), mock.patch.object(runtimes, "BREW_PREFIXES", ()), \
                mock.patch.object(runtimes, "_globs", side_effect=lambda *pats: sorted(
                    p for pat in pats for p in __import__("glob").glob(pat) if str(gopath) in p)):
            pkgs = runtimes.gos(ctx)
        self.assertEqual([(p.ecosystem, p.name, p.version) for p in pkgs], [("Go", "stdlib", "1.26.4")])


TODAY = "2026-10-27"
JAVA_CYCLES = [{"cycle": "21", "lts": True, "eol": "2029-12-31", "latest": "21.0.13+9"},
               {"cycle": "17", "lts": True, "eol": "2027-10-31", "latest": "17.0.21+9"},
               {"cycle": "11", "lts": True, "eol": "2024-10-31", "latest": "11.0.25+9"},
               {"cycle": "8", "lts": True, "eol": "2030-12-31", "latest": "8u462-b08"}]


def rt(name, version, product, cycle, **meta):
    eco, pkg = ("Go", "stdlib") if name == "go" else ("Runtime", name)
    return Package(eco, pkg, version, "runtime", "/x", meta={"runtime": name, "product": product, "cycle": cycle,
                                                                "manager": "installer", **meta})


class RuntimeAdvisoryTests(unittest.TestCase):
    def test_java(self):
        behind = rt_enrich.advisories_for(rt("java", "17.0.9", "eclipse-temurin", "17"), JAVA_CYCLES, today=TODAY)
        self.assertEqual([(a.id, a.fixed, a.severity) for a in behind], [("UPDATE-eclipse-temurin-17.0.21", ["17.0.21"], "MEDIUM")])
        self.assertEqual(rt_enrich.advisories_for(rt("java", "17.0.21", "eclipse-temurin", "17"), JAVA_CYCLES, today=TODAY), [])
        eol = rt_enrich.advisories_for(rt("java", "11.0.25", "eclipse-temurin", "11"), JAVA_CYCLES, today=TODAY)
        self.assertEqual((eol[0].id, eol[0].fixed, eol[0].severity), ("EOL-eclipse-temurin-11", ["17.0.21"], "HIGH"))
        java8 = rt_enrich.advisories_for(rt("java", "8.0.392", "eclipse-temurin", "8"), JAVA_CYCLES, today=TODAY)
        self.assertEqual(java8[0].fixed, ["8.0.462"])
        self.assertEqual(rt_enrich.norm("17.0.21.0.10", "java"), "17.0.21")  # Corretto

    def test_node_only_security_releases_count(self):
        cycles = [{"cycle": "22", "lts": "2024-10-29", "eol": "2027-04-30", "latest": "22.12.0"}]
        index = [{"version": "v22.12.0", "security": False}, {"version": "v22.11.0", "security": True},
                 {"version": "v22.10.0", "security": False}]
        p = rt("node", "22.10.0", "nodejs", "22")
        advs = rt_enrich.advisories_for(p, cycles, index, today=TODAY)
        self.assertEqual((advs[0].severity, advs[0].fixed), ("HIGH", ["22.12.0"]))
        self.assertIn("v22.11.0", advs[0].summary)
        self.assertEqual(rt_enrich.advisories_for(rt("node", "22.11.0", "nodejs", "22"), cycles, index, today=TODAY), [])

    def test_python_eol_and_go(self):
        cycles = [{"cycle": "3.13", "eol": "2029-10-31", "latest": "3.13.18"}, {"cycle": "3.11", "eol": "2027-10-31", "latest": "3.11.15"},
                  {"cycle": "3.10", "eol": "2026-10-01", "latest": "3.10.22"}]
        advs = rt_enrich.advisories_for(rt("python", "3.10.20", "python", "3.10"), cycles, today=TODAY)
        self.assertEqual((advs[0].id, advs[0].fixed), ("EOL-python-3.10", ["3.11.15"]))
        go = [{"cycle": "1.26", "eol": False, "latest": "1.26.7"}]
        self.assertEqual(rt_enrich.advisories_for(rt("go", "1.26.4", "go", "1.26"), go, today=TODAY), [])  # CVEs come from OSV


class ManualFixTests(unittest.TestCase):
    def test_runtime_and_vendor_tools_go_to_no_automatic_fix(self):
        from scs.ui import viewmodel
        jdk = rt("java", "17.0.9", "eclipse-temurin", "17", vendor="Eclipse Adoptium", display="JDK 17.0.9")
        jdk.location = "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"
        git = Package("Dev-tool", "git", "2.39.0", "devtool", "/usr/bin/git",
                      meta={"vendor": "Apple", "vendor_managed": True, "cpe": ["git-scm", "git"]})
        advs = {jdk.key: [Advisory("UPDATE-eclipse-temurin-17.0.21", severity="MEDIUM", fixed=["17.0.21"], source="eol")],
                git.key: [Advisory("CVE-2024-32002", severity="CRITICAL", fixed=["2.45.1"], source="nvd", confidence="low")]}
        findings, _ = build_findings([jdk, git], advs, [])
        by = {f.name: f for f in findings}
        self.assertEqual(by["java"].bucket, "monitor")
        self.assertEqual(by["git"].bucket, "monitor")
        pj = viewmodel.plain_finding(by["java"].to_dict())
        self.assertEqual(pj["headline"], "Update Java (JDK) from 17.0.9 to 17.0.21 by hand")
        self.assertTrue(any("adoptium.net" in (s.get("link") or "") for s in pj["manual"]))
        pg = viewmodel.plain_finding(by["git"].to_dict())
        self.assertIn("Packhound can't install it here", pg["headline"])
        self.assertTrue(any(s["cmd"] == "softwareupdate --list" for s in pg["manual"]))

    def test_homebrew_commands(self):
        from scs import handfix
        def cmds(loc, version, fix, cycle, name="go"):
            p = rt(name, version, "x", cycle, manager="Homebrew")
            p.location = loc
            return handfix.commands("Runtime", name, version, fix, p.to_dict())
        self.assertEqual(cmds("/opt/homebrew/Cellar/go/1.25.7_1/libexec", "1.25.7", "1.26.10", "1.25"), ["brew upgrade go"])
        self.assertEqual(cmds("/opt/homebrew/Cellar/python@3.10/3.10.20", "3.10.20", "3.11.18", "3.10", "python"),
                         ["brew install python@3.11"])
        self.assertEqual(cmds("/opt/homebrew/Cellar/python@3.12/3.12.13", "3.12.13", "3.12.16", "3.12", "python"),
                         ["brew upgrade python@3.12"])

    def test_cache_only_and_build_file_items(self):
        from scs import plan
        from scs.policy import Decisions
        cached = Package("Maven", "org.yaml:snakeyaml", "1.33", "java-cache", "/c/snakeyaml/1.33", meta={"cache": "gradle"})
        d = tmpdir()
        pom = Package("Maven", "org.yaml:snakeyaml", "1.33", "lockfile", str(d / "pom.xml"), scope="project", direct=True,
                      meta={"project": str(d), "lockfile": "pom.xml"})
        advs = {cached.key: [Advisory("GHSA-mjmj-j48q-9wg2", severity="HIGH", fixed=["2.0"])]}
        f = build_findings([cached], advs, [])[0][0]
        self.assertEqual(f.bucket, "monitor")
        self.assertTrue(any("download cache" in r for r in f.reasons))
        f2 = build_findings([cached, pom], advs, [])[0][0]
        self.assertEqual(len(f2.packages), 2)
        self.assertTrue(any("mvn dependency:tree" in c for c in f2.commands))
        result = {"host": "h", "started": "s", "findings": [f2.to_dict()]}
        dec = mock.Mock()
        dec.get.return_value = {"action": "verify"}
        pl = plan.build(result, dec, min_age=0)
        kinds = {t["kind"]: t for t in pl["targets"]}
        self.assertEqual(kinds["manual"]["change"], [])
        self.assertTrue(any("rm -rf" in m for m in kinds["manual"]["manual"]))
        self.assertTrue(any("pom.xml" in m for m in kinds["project"]["manual"]))


class BuildChainTests(unittest.TestCase):
    def test_gradle_wrapper(self):
        d = tmpdir() / "gradle" / "wrapper"
        jar = write(d / "gradle-wrapper.jar", b"official")
        write(d / "gradle-wrapper.properties", "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-bin.zip\n"
              "distributionSha256Sum=abc\n")
        good = {buildchain._sha(jar)}
        self.assertEqual(buildchain.check_gradle(d, good, offline=True), [])
        jar.write_bytes(b"tampered")
        with mock.patch.object(buildchain, "gradle_wrapper_sums", return_value=good) as refresh:
            out = buildchain.check_gradle(d, good, offline=False)
        refresh.assert_called_once_with(refresh=True)  # a newer release could be missing from the cached list
        self.assertEqual([(f.severity, f.rules) for f in out], [("critical", ["GRADLE_WRAPPER_MISMATCH"])])
        self.assertTrue(out[0].quarantinable)
        write(d / "gradle-wrapper.properties", "distributionUrl=http\\://evil.example/gradle.zip\n")
        rules = {r for f in buildchain.check_gradle(d, {buildchain._sha(jar)}, True) for r in f.rules}
        self.assertEqual(rules, {"WRAPPER_HTTP", "WRAPPER_NO_CHECKSUM"})

    def test_maven_wrapper(self):
        d = tmpdir() / ".mvn" / "wrapper"
        jar = write(d / "maven-wrapper.jar", b"jar")
        write(d / "maven-wrapper.properties", "wrapperVersion=3.3.2\ndistributionUrl=https://repo.maven.apache.org/x.zip\n"
              "distributionSha256Sum=1\n")
        with mock.patch.object(buildchain, "_central_sha1", return_value=buildchain._sha(jar, "sha1")):
            self.assertEqual(buildchain.check_maven(d, offline=False), [])
        with mock.patch.object(buildchain, "_central_sha1", return_value="0" * 40):
            self.assertEqual(buildchain.check_maven(d, offline=False)[0].rules, ["MAVEN_WRAPPER_MISMATCH"])

    def test_github_and_gitlab(self):
        repo = tmpdir()
        wf = write(repo / ".github" / "workflows" / "ci.yml", """on: [pull_request_target]
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v45
      - uses: docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee
      - uses: ./local-action
""")
        out = buildchain.check_github_workflow(wf)
        self.assertEqual([(f.severity, f.rules[0]) for f in out], [("low", "ACTION_NOT_PINNED"), ("high", "PR_TARGET_CHECKOUT")])
        self.assertEqual(out[0].evidence, ["tj-actions/changed-files@v45", "actions/checkout@v4"])
        gl = write(repo / ".gitlab-ci.yml", """include:
  - remote: 'https://example.com/ci.yml'
  - project: 'group/templates'
    ref: main
  - project: 'group/pinned'
    ref: 0123456789abcdef0123456789abcdef01234567
""")
        out = buildchain.check_gitlab_ci(gl)
        self.assertEqual([(f.severity, f.evidence) for f in out],
                         [("medium", ["https://example.com/ci.yml"]), ("info", ["group/templates@main"])])
        findings, stats = buildchain.scan([wf, gl], [repo], offline=True)
        self.assertEqual(stats["ci_files"], 2)  # the workflow is not counted twice


if __name__ == "__main__":
    unittest.main()
