"""Issues that stay after a manual fix: old copies left next to the fixed version, and moved project folders."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import handfix
from scs.analyze import AnalysisContext, build_findings
from scs.collectors import runtimes
from scs.models import Advisory, Package
from scs.ui import viewmodel


def cached(name, version, cache="gradle", location=None):
    return Package("Maven", name, version, "java-cache", location or f"/c/{name}/{version}", meta={"cache": cache})


ADV = {"fixed": ["2.18.11"]}


def advs(*pkgs, fixed="2.18.11"):
    return {p.key: [Advisory("GHSA-x", severity="HIGH", fixed=[fixed])] for p in pkgs}


class CacheLeftoverTests(unittest.TestCase):
    def test_old_cache_copy_next_to_a_fixed_one_is_not_an_issue(self):
        old, new = cached("com.fasterxml.jackson.core:jackson-databind", "2.12.7"), \
            cached("com.fasterxml.jackson.core:jackson-databind", "2.20.1")
        actx = AnalysisContext()
        findings, _ = build_findings([old, new], advs(old), [], actx=actx)
        self.assertEqual(findings, [])
        self.assertEqual([(l["version"], l["newer"]) for l in actx.leftovers], [("2.12.7", "2.20.1")])

    def test_still_an_issue_when_no_fixed_copy_or_a_project_uses_it(self):
        lone = cached("org.x:lib", "1.0")
        actx = AnalysisContext()
        self.assertEqual(len(build_findings([lone], advs(lone, fixed="1.1"), [], actx=actx)[0]), 1)
        self.assertEqual(actx.leftovers, [])
        old, new = cached("org.y:lib", "1.0"), cached("org.y:lib", "1.2")
        proj = Package("Maven", "org.y:lib", "1.0", "lockfile", "/p/gradle.lockfile", scope="project",
                       meta={"project": "/p", "lockfile": "gradle.lockfile"})
        findings, _ = build_findings([old, new, proj], advs(old, fixed="1.1"), [], actx=AnalysisContext())
        self.assertEqual(len(findings), 1)  # the project still locks the old version
        other_cache = cached("org.z:lib", "1.0", cache="maven")
        fixed_elsewhere = cached("org.z:lib", "2.0", cache="gradle")
        self.assertEqual(len(build_findings([other_cache, fixed_elsewhere], advs(other_cache, fixed="1.1"), [])[0]), 1)

    def test_leftovers_view_and_cleanup_command(self):
        d = Path(tempfile.mkdtemp())
        loc = d / "jackson-core" / "2.10.0"
        loc.mkdir(parents=True)
        view = viewmodel.leftovers([{"name": "jackson-core", "version": "2.10.0", "newer": "2.20.1", "severity": "HIGH",
                                     "cache": "gradle", "locations": [str(loc)]},
                                    {"name": "gone", "version": "1", "newer": "2", "severity": "LOW", "cache": "gradle",
                                     "locations": [str(d / "deleted")]}])
        self.assertEqual([i["name"] for i in view["items"]], ["jackson-core"])  # already deleted: not listed
        self.assertIn(str(loc.name), view["cmd"])
        self.assertEqual(viewmodel.leftovers([])["cmd"], "")


class NewerInstalledTests(unittest.TestCase):
    def test_old_runtime_next_to_a_fixed_one(self):
        old = runtimes._runtime("python", "3.10.20", os.path.expanduser("~/.pyenv/versions/3.10.20"), "pyenv", "python", "3.10")
        new = runtimes._runtime("python", "3.13.17", "/Library/Frameworks/Python.framework/Versions/3.13",
                                "python.org installer", "python", "3.13")
        a = {old.key: [Advisory("EOL-python-3.10", severity="HIGH", fixed=["3.11.18"], source="eol")]}
        f = build_findings([old, new], a, [])[0][0]
        self.assertTrue(any("you also have 3.13.17 installed" in r for r in f.reasons))
        steps = handfix.steps("Runtime", "python", "3.10.20", "3.11.18", f.packages[0].to_dict())
        self.assertEqual([s["cmd"] for s in steps], ["pyenv uninstall -f 3.10.20"])

    def test_another_release_line_does_not_replace_an_lts_jdk(self):
        jdk17 = runtimes._runtime("java", "17.0.18", "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
                                  "installer", "eclipse-temurin", "17")
        jdk25 = runtimes._runtime("java", "25.0.2", "/opt/homebrew/Cellar/openjdk/25.0.2/libexec", "Homebrew",
                                  "eclipse-temurin", "25")
        a = {jdk17.key: [Advisory("UPDATE-eclipse-temurin-17.0.21", severity="MEDIUM", fixed=["17.0.21"], source="eol")]}
        f = build_findings([jdk17, jdk25], a, [])[0][0]
        self.assertFalse(any("also have" in r for r in f.reasons))
        jdk17b = runtimes._runtime("java", "17.0.21", "/opt/homebrew/Cellar/openjdk@17/17.0.21/libexec", "Homebrew",
                                   "eclipse-temurin", "17")
        f = build_findings([jdk17, jdk17b], a, [])[0][0]
        self.assertTrue(any("you also have 17.0.21 installed" in r for r in f.reasons))

    def test_remove_commands_per_install_method(self):
        def cmd(mgr, version, loc, newer, rt="python"):
            return handfix._remove_old(rt, mgr, version, loc, newer, "X")["cmd"]
        self.assertEqual(cmd("Homebrew", "3.10.4", "/opt/homebrew/Cellar/python@3.10/3.10.4", "3.13.1"), "brew uninstall python@3.10")
        self.assertEqual(cmd("Homebrew", "25.0.1", "/opt/homebrew/Cellar/openjdk/25.0.1/libexec", "25.0.2", "java"),
                         "brew cleanup openjdk")
        self.assertEqual(cmd("SDKMAN", "21.0.9", os.path.expanduser("~/.sdkman/candidates/java/21.0.9-tem"), "21.0.13", "java"),
                         "sdk uninstall java 21.0.9-tem")
        self.assertEqual(cmd("installer", "17.0.9", "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
                             "17.0.21", "java"), "sudo rm -rf /Library/Java/JavaVirtualMachines/temurin-17.jdk")
        self.assertEqual(cmd("somewhere", "1", "/x", "2"), "")  # unknown: told to use its own uninstaller

    def test_gems(self):
        home = "/r/lib/ruby/gems/3.3.0"
        old = Package("RubyGems", "rack", "2.2.3", "gem", f"{home}/specifications/rack-2.2.3.gemspec",
                      meta={"gem": "/r/bin/gem", "gem_home": home})
        new = Package("RubyGems", "rack", "2.2.9", "gem", f"{home}/specifications/rack-2.2.9.gemspec",
                      meta={"gem": "/r/bin/gem", "gem_home": home})
        f = build_findings([old, new], {old.key: [Advisory("GHSA-r", severity="HIGH", fixed=["2.2.8"])]}, [])[0][0]
        self.assertEqual(handfix.commands("RubyGems", "rack", "2.2.3", "2.2.8", f.packages[0].to_dict()),
                         ["/r/bin/gem uninstall rack -v 2.2.3"])
        bundled = Package("RubyGems", "bundler", "1.17.2", "gem", f"{home}/specifications/default/bundler-1.17.2.gemspec",
                          meta={"gem": "/r/bin/gem", "gem_home": home, "default": True})
        fixed = Package("RubyGems", "bundler", "2.2.33", "gem", f"{home}/specifications/bundler-2.2.33.gemspec",
                        meta={"gem": "/r/bin/gem", "gem_home": home})
        actx = AnalysisContext()
        self.assertEqual(build_findings([bundled, fixed], {bundled.key: [Advisory("GHSA-b", severity="HIGH", fixed=["2.2.33"])]},
                                        [], actx=actx)[0], [])  # the manual fix worked: Ruby loads 2.2.33
        self.assertEqual(viewmodel.leftovers(actx.leftovers)["cmd"], "")  # but it's part of Ruby: never offered for deletion
        self.assertEqual(viewmodel.plain_finding(f.to_dict())["headline"], "Remove the old rack 2.2.3: 2.2.9 is installed already")
        default = dict(old.to_dict(), meta={"gem": "/r/bin/gem", "gem_home": home, "default": True},
                       location="/opt/homebrew/Cellar/ruby/4.0.1/lib/ruby/gems/4.0.0/specifications/default/erb-6.0.1.gemspec")
        self.assertIn("brew upgrade ruby", handfix.commands("RubyGems", "erb", "6.0.1", "6.0.1.1", default)[0])


class MissingRootTests(unittest.TestCase):
    def test_scan_records_and_health_warns(self):
        from scs.cli import perform_scan
        from scs.config import Config
        gone = str(Path(tempfile.mkdtemp()) / "renamed-away")
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": tempfile.mkdtemp(), "XDG_CACHE_HOME": tempfile.mkdtemp()}):
            r = perform_scan(Config(roots=[gone], collectors=["lockfile"], offline=True), save=False)
        self.assertEqual(r["missing_roots"], [gone])
        self.assertEqual(viewmodel.health(r, None)["headline"], "Project folder not found")


if __name__ == "__main__":
    unittest.main()
