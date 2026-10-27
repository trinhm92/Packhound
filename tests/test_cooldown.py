import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scs import cooldown, fixers, plan
from scs.analyze import build_findings
from scs.models import Advisory, Package
from scs.policy import Decisions

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


class PickTests(unittest.TestCase):
    def test_newest_old_enough_fixed_release(self):
        times = {"2.31.0": ago(400), "2.32.0": ago(30), "2.32.1": ago(10), "2.33.0": ago(1), "2.34.0rc1": ago(20)}
        with mock.patch.object(cooldown, "pypi_times", return_value=times):
            self.assertEqual(cooldown.pick("PyPI", "requests", "2.32.0", 7, now=NOW)["version"], "2.32.1")
            self.assertEqual(cooldown.pick("PyPI", "requests", "2.32.0", 0, now=NOW)["version"], "2.32.0")
            held = cooldown.pick("PyPI", "requests", "2.33.0", 7, now=NOW)
        self.assertIsNone(held["version"])
        self.assertEqual(held["wait_until"], "2026-11-02")
        with mock.patch.object(cooldown, "pypi_times", return_value=None):  # offline: the installers' own cutoff still applies
            self.assertTrue(cooldown.pick("PyPI", "requests", "2.33.0", 7, now=NOW)["unknown"])

    def test_exploited_items_wait_less(self):
        kev = [{"advisories": [{"kev": True}]}]
        self.assertEqual(cooldown.days_for(kev, 7), 2)
        self.assertEqual(cooldown.days_for([{"advisories": [{}]}], 7), 7)
        self.assertEqual(cooldown.days_for(kev, 0), 0)

    def test_too_new(self):
        with mock.patch.object(cooldown, "pypi_times", side_effect=lambda n: None if n == "gone" else
                               {"1.0": ago(100), "1.1": ago(2)}):
            bad, unknown = cooldown.too_new({"a": "1.0", "b": "1.1", "gone": "3"}, 7, now=NOW)
        self.assertEqual([b.split(" ")[0] for b in bad], ["b"])
        self.assertEqual(unknown, ["gone 3"])


class PlanCooldownTests(unittest.TestCase):
    def build(self, pkgs_advs, days=7):
        pkgs = [p for p, _ in pkgs_advs]
        findings, _ = build_findings(pkgs, {p.key: a for p, a in pkgs_advs}, [])
        result = {"host": "h", "started": "s", "findings": [f.to_dict() for f in findings]}
        return plan.build(result, Decisions(Path(os.devnull)), suggested=True, min_age=days)

    def pip_pkg(self, name, version):
        d = tempfile.mkdtemp()
        return Package("PyPI", name, version, "pip", f"{d}/lib/python3.12/site-packages", direct=True,
                       meta={"env": d, "python": sys.executable})

    def test_pip_holds_new_releases_and_checks_dependencies(self):
        times = {"1.0": ago(500), "1.1": ago(20), "1.2": ago(1)}
        p, q = self.pip_pkg("aaa", "1.0"), self.pip_pkg("bbb", "1.0")
        q.location = p.location
        q.meta = p.meta
        with mock.patch.object(cooldown, "pypi_times", side_effect=lambda n: times), \
                mock.patch.object(cooldown, "cutoff", lambda d, now=None: NOW - timedelta(days=d)), \
                mock.patch.object(plan, "_pip_cutoff_flag", return_value=""):  # an older pip: pin instead
            pl = self.build([(p, [Advisory("GHSA-a", severity="HIGH", fixed=["1.1"])]),
                             (q, [Advisory("GHSA-b", severity="HIGH", fixed=["1.2"])])])
        t = pl["targets"][0]
        self.assertIn("aaa==1.1", t["change"][0])
        self.assertNotIn("bbb", t["change"][0])  # its only fix is a day old
        self.assertTrue(any("bbb 1.2 was published on" in m and "2026-11-02" in m for m in t["manual"]))
        self.assertTrue(any("fixer age-check" in v and "--min-age 7" in v for v in t["verify"]))

    def test_pip_cutoff_flag_used_when_supported(self):
        p = self.pip_pkg("aaa", "1.0")
        with mock.patch.object(cooldown, "pypi_times", return_value={"1.1": ago(400)}), \
                mock.patch.object(plan, "_pip_cutoff_flag", return_value=" --uploaded-prior-to P7D"):
            t = self.build([(p, [Advisory("GHSA-a", severity="HIGH", fixed=["1.1"])])])["targets"][0]
        self.assertIn("--uploaded-prior-to P7D", t["change"][0])
        self.assertIn(plan.q("aaa>=1.1"), t["change"][0])

    def test_npm_global_uses_before_and_old_enough_version(self):
        d = Path(tempfile.mkdtemp())
        p = Package("npm", "tool", "1.0.0", "npm-global", str(d / "tool"), direct=True, meta={"root": str(d)})
        with mock.patch.object(cooldown, "npm_times", return_value={"1.0.1": ago(30), "1.0.2": ago(1), "2.0.0": ago(40)}):
            t = self.build([(p, [Advisory("GHSA-n", severity="HIGH", fixed=["1.0.1"])])])["targets"][0]
        install = next(c for c in t["change"] if "install -g" in c)
        self.assertIn("--before ", install)
        self.assertIn("tool@1.0.1", install)  # 1.0.2 is too new, 2.0.0 is another major

    def test_off(self):
        p = self.pip_pkg("aaa", "1.0")
        with mock.patch.object(cooldown, "pypi_times", side_effect=AssertionError("no lookups when off")):
            t = self.build([(p, [Advisory("GHSA-a", severity="HIGH", fixed=["1.1"])])], days=0)["targets"][0]
        self.assertIn(plan.q("aaa>=1.1"), t["change"][0])
        self.assertFalse(any("age-check" in v for v in t["verify"]))


class AgeCheckTests(unittest.TestCase):
    def test_rejects_new_dependency(self):
        snap = Path(tempfile.mkdtemp()) / "freeze.txt"
        self.assertEqual(fixers.age_check(sys.executable, str(snap), 7, out=lambda s: None), 0)  # baseline: no snapshot yet
        snap.write_text("aaa==1.0\nbbb==2.0\n")
        frozen = mock.Mock(returncode=0, stdout="aaa==1.1\nbbb==2.0\nccc==0.1\n", stderr="")
        times = {"aaa": {"1.1": ago(30)}, "ccc": {"0.1": ago(1)}}
        msgs = []
        with mock.patch.object(fixers.subprocess, "run", return_value=frozen), \
                mock.patch.object(cooldown, "pypi_times", side_effect=lambda n: times[n]), \
                mock.patch.object(cooldown, "cutoff", lambda d, now=None: NOW - timedelta(days=d)):
            self.assertEqual(fixers.age_check(sys.executable, str(snap), 7, out=msgs.append), 1)
        self.assertEqual(len(msgs), 1)
        self.assertIn("ccc 0.1", msgs[0])


class SelfCheckTests(unittest.TestCase):
    def test_manifest_detects_changed_and_added_files(self):
        from scs import selfcheck
        d = Path(tempfile.mkdtemp())
        (d / "app.exe").write_bytes(b"MZ original")
        (d / "_internal").mkdir()
        (d / "_internal" / "lib.dll").write_bytes(b"lib")
        with mock.patch("builtins.print"):
            selfcheck.write_manifest(str(d))
        self.assertEqual(selfcheck._check_manifest(d)[0], True)
        (d / "_internal" / "lib.dll").write_bytes(b"patched")
        ok, detail = selfcheck._check_manifest(d)
        self.assertFalse(ok)
        self.assertIn("_internal/lib.dll", detail)
        (d / "_internal" / "lib.dll").write_bytes(b"lib")
        (d / "_internal" / "evil.pth").write_text("import os")
        ok, detail = selfcheck._check_manifest(d)
        self.assertFalse(ok)
        self.assertIn("added: _internal/evil.pth", detail)
        (d / selfcheck.MANIFEST).unlink()
        self.assertFalse(selfcheck._check_manifest(d)[0])

    def test_source_tree_is_not_checked(self):
        from scs import selfcheck
        self.assertIsNone(selfcheck.verify()["ok"])


class BuildCheckTests(unittest.TestCase):
    def test_fails_on_malicious_or_vulnerable(self):
        from scs.enrich import osv
        from scs.models import Advisory
        site = Path(tempfile.mkdtemp())
        pkgs = [Package("PyPI", "good", "1.0", "pip", str(site)), Package("PyPI", "bad", "2.0", "pip", str(site))]
        run = mock.Mock(returncode=0, stdout=str(site) + "\n", stderr="")
        msgs = []
        with mock.patch.object(fixers.subprocess, "run", return_value=run), \
                mock.patch("scs.collectors.python.scan_site", return_value=pkgs), \
                mock.patch.object(osv, "LAST_RUN", {"failed": 0}):
            with mock.patch.object(osv, "lookup", return_value={("PyPI", "bad", "2.0"): [Advisory("MAL-1", malicious=True)]}):
                self.assertEqual(fixers.build_check("py", out=msgs.append), 1)
                self.assertEqual(fixers.build_check("py", allow_vulnerable=True, out=msgs.append), 1)  # malicious: always
            vuln = {("PyPI", "bad", "2.0"): [Advisory("GHSA-1", severity="HIGH", fixed=["2.1"])]}
            with mock.patch.object(osv, "lookup", return_value=vuln):
                self.assertEqual(fixers.build_check("py", out=msgs.append), 1)
                self.assertEqual(fixers.build_check("py", allow_vulnerable=True, out=msgs.append), 0)
            with mock.patch.object(osv, "lookup", return_value={}):
                self.assertEqual(fixers.build_check("py", out=msgs.append), 0)
        self.assertTrue(any(m.startswith("MALICIOUS  bad 2.0") for m in msgs))


if __name__ == "__main__":
    unittest.main()
