import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from datetime import date, timedelta
from pathlib import Path

from scs import miniyaml, plan, toolchain, triage
from scs.analyze import AnalysisContext, build_findings
from scs.minitoml import _Parser
from scs.models import Advisory, Package
from scs.policy import Decisions, Policy, parse_expiry


def pkg(name, ver, eco="npm", project="/p", lockfile="package-lock.json", **kw):
    return Package(eco, name, ver, "lockfile", f"{project}/{lockfile}",
                   meta={"project": project, "lockfile": lockfile}, **kw)


class FakeReqs:
    def __init__(self, table):
        self.table = table

    def get(self, eco, name, version):
        return self.table.get((eco, name, version))

    def save(self):
        pass


def setUpModule():
    """Command strings in these tests are asserted in POSIX sh syntax, on every OS."""
    global _shell_patch, _orig_sh
    from scs import plan as _plan
    from scs import shell as _shell
    _shell_patch = mock.patch.object(_shell, "current", lambda: _shell.Posix())
    _shell_patch.start()
    _orig_sh, _plan.SH = _plan.SH, _shell.Posix()


def tearDownModule():
    from scs import plan as _plan
    _shell_patch.stop()
    _plan.SH = _orig_sh


class ParserTests(unittest.TestCase):
    def test_minitoml_subset(self):
        d = _Parser('[[package]]\nname = "a"\ndependencies = [\n "b 1.0",\n]\n[package.extras]\nx = ["y (>=1)"]\n'
                    '[[package]]\nname = "b"\nsource = { registry = "https://x" }\n').parse()
        self.assertEqual([p["name"] for p in d["package"]], ["a", "b"])
        self.assertEqual(d["package"][0]["extras"]["x"], ["y (>=1)"])
        self.assertEqual(d["package"][1]["source"]["registry"], "https://x")

    def test_miniyaml(self):
        d = miniyaml.loads("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@a/b':\n"
                           "        specifier: ^1\n        version: 1.0.0(x@2)\n  # comment\n")
        self.assertEqual(d["lockfileVersion"], "9.0")
        self.assertEqual(d["importers"]["."]["dependencies"]["@a/b"]["version"], "1.0.0(x@2)")


class ToolchainTests(unittest.TestCase):
    def test_detect_project(self):
        d = Path(tempfile.mkdtemp())
        (d / ".nvmrc").write_text("v18.19.0\n")
        (d / "package.json").write_text(json.dumps({"engines": {"node": ">=20"}, "dependencies": {"qs": "6.5.2"},
                                                    "scripts": {"test": "jest"}}))
        (d / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.9"\ndependencies = ["requests>=2,<3"]\n')
        info = toolchain.detect_project(d)
        self.assertEqual(info["node"], {"value": "18.19.0", "source": ".nvmrc"})  # exact pin wins over engines
        self.assertEqual(info["python"]["value"], "3.9")
        self.assertEqual(info["pins"]["npm"]["qs"], "6.5.2")
        self.assertEqual(info["pins"]["PyPI"]["requests"], ">=2,<3")
        self.assertEqual(info["scripts"], ["test"])

    def test_findings_get_toolchain_and_pin_reasons(self):
        p1 = pkg("qs", "6.5.2", direct=True)
        p2 = Package("PyPI", "pillow", "10.4.0", "pip", "/env/lib/python3.10/site-packages",
                     meta={"env": "/env", "python": "/env/bin/python", "runtime": "3.10"})
        advs = {p1.key: [Advisory("GHSA-1", severity="HIGH", fixed=["6.5.3"])],
                p2.key: [Advisory("GHSA-2", severity="HIGH", fixed=["12.2.0"])]}
        actx = AnalysisContext(projects={"/p": {"pins": {"npm": {"qs": "6.5.2"}}}},
                               requirements=FakeReqs({("PyPI", "pillow", "12.2.0"): ">=3.11"}))
        f = {x.name: x for x in build_findings([p1, p2], advs, [], None, actx)[0]}
        self.assertEqual(f["qs"].bucket, "verify")
        self.assertIn("excludes 6.5.3", " ".join(f["qs"].reasons))
        self.assertEqual(f["pillow"].bucket, "verify")
        self.assertIn("needs python >=3.11", " ".join(f["pillow"].reasons))
        self.assertEqual(f["pillow"].toolchain["fix_requires"], ">=3.11")


class PolicyDecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.policy_file = self.tmp / "policy.json"

    def test_ignore_rules(self):
        Policy.add({"advisory": "CVE-1", "package": "npm:qs", "reason": "dev only", "expires": parse_expiry("30d")},
                   self.policy_file)
        Policy.add({"advisory": "GHSA-old", "reason": "x", "expires": "2000-01-01"}, self.policy_file)
        Policy.add({"advisory": "MAL-1", "reason": "nope"}, self.policy_file)
        pol = Policy([self.policy_file])
        p = pkg("qs", "6.5.2")
        advs = [Advisory("GHSA-a", aliases=["CVE-1"]), Advisory("GHSA-old"), Advisory("MAL-1", malicious=True)]
        kept, ignored = pol.filter(advs, [p])
        self.assertEqual([a.id for a in kept], ["GHSA-old", "MAL-1"])  # expired + malicious not hidden
        self.assertEqual(ignored[0]["reason"], "dev only")
        findings, hidden = build_findings([p], {p.key: [Advisory("GHSA-a", aliases=["CVE-1"])]}, [], None,
                                          AnalysisContext(policy=pol))
        self.assertEqual((findings, len(hidden)), ([], 1))
        self.assertEqual(Policy.prune(self.policy_file), 1)

    def test_path_rule_needs_all_locations(self):
        Policy.add({"advisory": "GHSA-a", "path": "/legacy/*", "reason": "r"}, self.policy_file)
        pol = Policy([self.policy_file])
        a = Advisory("GHSA-a")
        self.assertEqual(len(pol.filter([a], [pkg("x", "1", project="/legacy/app")])[0]), 0)
        self.assertEqual(len(pol.filter([a], [pkg("x", "1", project="/legacy/app"), pkg("x", "1", project="/new")])[0]), 1)

    def test_decisions(self):
        d = Decisions(self.tmp / "decisions.json")
        d.set("k1", "patch", ["A"])
        d.set("k2", "defer", ["B"], until=(date.today() - timedelta(days=1)).isoformat())
        d.save()
        d = Decisions(self.tmp / "decisions.json")
        self.assertFalse(d.get("k1", {"A"})["stale"])
        self.assertTrue(d.get("k1", {"A", "C"})["stale"])
        self.assertIsNone(d.get("k2", {"B"}))  # deferral expired


def _result(findings):
    return {"host": "h", "started": "2026-10-26T10:00:00", "findings": [f.to_dict() for f in findings]}


class TriagePlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "app"
        self.proj.mkdir()
        (self.proj / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0.0"},
                                                            "scripts": {"test": "jest"}}))
        pk = [pkg("express", "4.17.1", project=str(self.proj), direct=True),
              pkg("qs", "6.5.2", project=str(self.proj), direct=False),
              pkg("left-pad", "1.0.0", project=str(self.proj), direct=False),
              Package("PyPI", "requests", "2.19.0", "pip", "/env/lib/python3.10/site-packages",
                      meta={"env": "/env", "python": "/env/bin/python"})]
        pk[1].meta["introduced_by"] = ["express@4.17.1"]
        advs = {pk[0].key: [Advisory("GHSA-e", severity="HIGH", fixed=["4.19.2"])],
                pk[1].key: [Advisory("GHSA-q", severity="HIGH", fixed=["6.5.3"])],
                pk[2].key: [Advisory("GHSA-l", severity="LOW")],
                pk[3].key: [Advisory("GHSA-r", severity="MEDIUM", fixed=["2.20.0"])]}
        self.findings, _ = build_findings(pk, advs, [])
        self.decisions = Decisions(self.tmp / "d.json")

    def test_scripted_triage_then_plan(self):
        answers = iter(["", "", "i", "not reachable", "30d", "", "d", ""])
        out: list[str] = []
        stats = triage.run(_result(self.findings), self.decisions, ask=lambda _: next(answers),
                           out=out.append, policy_path=self.tmp / "pol.json")
        self.assertEqual(stats["patch"], 2)
        self.assertEqual(stats["ignore"], 1)
        self.assertEqual(stats["defer"], 1)
        rules = json.loads((self.tmp / "pol.json").read_text())["ignore"]
        self.assertEqual(rules[0]["reason"], "not reachable")

        p = plan.build(_result(self.findings), self.decisions, min_age=0)
        # order is by bucket then score: express(patch), qs(patch), requests(ignored), left-pad(deferred)
        changes = "\n".join(c for t in p["targets"] for c in t["change"])
        self.assertIn("express", changes)
        self.assertNotIn("requests", changes)
        self.assertNotIn("left-pad", changes)
        script = plan.to_script(p)
        self.assertIn('SCS_CONFIRM', script)
        self.assertIn("set -euo pipefail", script)

    def test_plan_commands(self):
        triage.run(_result(self.findings), self.decisions, auto=True, out=lambda _: None)
        p = plan.build(_result(self.findings), self.decisions, min_age=0)
        proj = next(t for t in p["targets"] if t["kind"] == "project")
        cmds = "\n".join(proj["change"])
        self.assertIn("npm update express", cmds)
        self.assertIn("npm update qs", cmds)  # transitive: update within ranges first
        self.assertIn("npm pkg set 'overrides.qs=^6.5.3'", "\n".join(proj["manual"]))  # override only as fallback
        self.assertIn("npm ls qs", "\n".join(proj["verify"]))
        self.assertIn("npm run test", "\n".join(proj["verify"]))
        self.assertNotIn("left-pad", cmds)  # monitor bucket: auto never patches without a fix
        pip_t = next(t for t in p["targets"] if t["kind"] == "pip")
        self.assertIn("/env/bin/python -m pip install --upgrade 'requests>=2.20.0'", pip_t["change"][0])
        self.assertIn("pip install -r", pip_t["rollback"][0])
        md = plan.to_markdown(p)
        self.assertIn("dry run", md)
        if os.name != "nt":
            script = self.tmp / "plan.sh"
            script.write_text(plan.to_script(p))
            self.assertEqual(subprocess.run(["bash", "-n", str(script)]).returncode, 0)
            guarded = subprocess.run(["bash", str(script), "target_1"], capture_output=True, text=True)
            self.assertEqual(guarded.returncode, 1)  # refuses to run without SCS_CONFIRM=1


if __name__ == "__main__":
    unittest.main()


class BundledAndManagedTests(unittest.TestCase):
    def test_tool_bundled_items_are_patched_in_place_and_os_managed_wait_for_vendor(self):
        root = "/opt/homebrew/lib/node_modules"
        npm = Package("npm", "npm", "11.21.1", "npm-global", f"{root}/npm", direct=True, meta={"root": root})
        undici = Package("npm", "undici", "6.21.0", "npm-global", f"{root}/npm/node_modules/undici", direct=False,
                         chain=["npm"], meta={"root": root})
        tar = Package("npm", "tar", "7.5.11", "npm-global", f"{root}/npm/node_modules/tar", direct=False,
                      chain=["npm"], meta={"root": root})
        fut = Package("PyPI", "future", "0.18.2", "pip", "/Library/Developer/CommandLineTools/x/site-packages",
                      meta={"env": "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9"})
        advs = {undici.key: [Advisory("GHSA-u", severity="HIGH", fixed=["6.24.0"])],
                tar.key: [Advisory("GHSA-t", severity="HIGH", fixed=["7.5.21"])],
                fut.key: [Advisory("GHSA-f", severity="HIGH", fixed=["0.18.3"])]}

        def fake_update(tool, installed, node, needs):
            if "undici" in needs:
                return {"version": None, "latest": "12.2.1", "latest_runs_here": False,
                        "latest_engines": "^22.22.2 || ^24.15.0 || >=26.0.0"}
            return {"version": "11.22.0", "latest": "12.2.1", "latest_runs_here": False, "latest_engines": ""}

        class Reqs(FakeReqs):
            offline = False
        actx = AnalysisContext(requirements=Reqs({}))
        with mock.patch.object(toolchain, "npm_tool_update", side_effect=fake_update), \
                mock.patch.object(toolchain, "node_version_for_root", return_value="25.9.0"):
            f = {x.name: x for x in build_findings([npm, undici, tar, fut], advs, [], None, actx)[0]}
        # no npm release that runs here ships the fix: same-major copy replaced inside npm, so still "safe"
        self.assertEqual(f["undici"].bucket, "patch")
        self.assertIn("fixed by patching undici inside npm", " ".join(f["undici"].reasons))
        # Apple's own Python: nothing the user can install, so it waits for the vendor instead of nagging
        self.assertEqual(f["future"].bucket, "monitor")
        self.assertIn("Apple", " ".join(f["future"].reasons))
        self.assertTrue(any(r.startswith("fixed by ") for r in f["tar"].reasons))
