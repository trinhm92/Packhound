import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scs.analyze import build_findings
from scs.collectors import Context
from scs.collectors import lockfiles as lf
from scs.collectors.node import walk_node_modules
from scs.collectors.python import scan_site
from scs.config import Config
from scs.cvss import cvss3_base_score
from scs.enrich import ioc, nvd, osv
from scs.graph import annotate, finalize
from scs.models import Advisory, Package
from scs.report import html as html_report
from scs.versions import is_major_bump, lowest_fix_above, vkey


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


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(vkey("1.2.3"), vkey("1.10.0"))
        self.assertLess(vkey("1.0.0rc1"), vkey("1.0.0"))
        self.assertLess(vkey("1.0.0-beta.2"), vkey("1.0.0"))
        self.assertEqual(vkey("v1.2"), vkey("1.2.0"))

    def test_fix_and_major(self):
        self.assertEqual(lowest_fix_above("2.19.0", ["2.20.0", "2.31.0", "1.0"]), "2.20.0")
        self.assertIsNone(lowest_fix_above("3.0", ["2.0"]))
        self.assertTrue(is_major_bump("4.17.1", "5.0.0"))
        self.assertTrue(is_major_bump("0.3.1", "0.4.0"))
        self.assertFalse(is_major_bump("1.2.3", "1.9.0"))
        self.assertFalse(is_major_bump("2020.12.5", "2026.10.19"))
        self.assertFalse(is_major_bump("0.46.0", "0.56.0", "Go"))


class CvssTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"), 5.3)
        self.assertIsNone(cvss3_base_score("CVSS:4.0/AV:N"))


class LockfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def write(self, name, text):
        p = self.tmp / name
        p.write_text(text)
        return p

    def parsed(self, fn, p):
        """Parse, finalize the graph and annotate chains like the scanner does."""
        pkgs, g = fn(p)
        if g is not None:
            finalize(g, pkgs, str(p))
            annotate(pkgs, {str(p): g})
        out = {}
        for x in pkgs:
            out.setdefault(x.name, x)  # first occurrence (top-level copy)
        return out

    def test_package_lock_v3_chain(self):
        # qs is hoisted to the top level but only reachable through express > body-parser
        p = self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
            "node_modules/express": {"version": "4.17.1", "dependencies": {"body-parser": "1"}},
            "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"qs": "6"}},
            "node_modules/qs": {"version": "6.5.2"},
            "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"qs": "6"}},
            "node_modules/jest/node_modules/qs": {"version": "6.11.0", "dev": True},
        }}))
        pkgs = self.parsed(lf.parse_package_lock, p)
        self.assertTrue(pkgs["express"].direct)
        self.assertFalse(pkgs["qs"].direct)
        self.assertFalse(pkgs["qs"].dev)
        self.assertEqual(pkgs["qs"].meta["paths"][0], ["express@4.17.1", "body-parser@1.19.0", "qs@6.5.2"])
        self.assertEqual(pkgs["qs"].meta["introduced_by"], ["express@4.17.1"])
        self.assertTrue(pkgs["jest"].dev)

    def test_yarn_v1_and_berry(self):
        p = self.write("yarn.lock", '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n  dependencies:\n'
                       '    lodash "^4"\n    "@babel/types" "^7.0.0"\n\nlodash@^4:\n  version "4.17.20"\n\n'
                       '"@babel/types@^7.0.0":\n  version "7.22.0"\n')
        (self.tmp / "package.json").write_text(json.dumps({"devDependencies": {"@babel/core": "^7.0.0"}}))
        pkgs = self.parsed(lf.parse_yarn_lock, p)
        self.assertEqual({(x.name, x.version) for x in pkgs.values()},
                         {("@babel/core", "7.22.5"), ("lodash", "4.17.20"), ("@babel/types", "7.22.0")})
        self.assertEqual(pkgs["lodash"].chain, ["@babel/core@7.22.5"])
        self.assertTrue(pkgs["lodash"].dev)
        p = self.write("yarn.lock", '__metadata:\n  version: 6\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n'
                       '  dependencies:\n    lodash: "npm:^4.17.0"\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n')
        (self.tmp / "package.json").unlink()
        pkgs = self.parsed(lf.parse_yarn_lock, p)
        self.assertEqual([(x.name, x.version) for x in pkgs.values()], [("lodash", "4.17.21")])
        self.assertTrue(pkgs["lodash"].direct)

    def test_pnpm_v9_and_v6(self):
        p = self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n"
                       "      b:\n        specifier: ^2.0.0\n        version: 2.0.0(react@18.0.0)\n\n"
                       "packages:\n\n  '@scope/a@1.0.0':\n    resolution: {integrity: sha512-x}\n\n"
                       "  b@2.0.0:\n    resolution: {integrity: sha512-y}\n\n"
                       "snapshots:\n\n  '@scope/a@1.0.0': {}\n\n  b@2.0.0(react@18.0.0):\n    dependencies:\n"
                       "      '@scope/a': 1.0.0\n")
        pkgs = self.parsed(lf.parse_pnpm_lock, p)
        self.assertEqual({(x.name, x.version) for x in pkgs.values()}, {("@scope/a", "1.0.0"), ("b", "2.0.0")})
        self.assertTrue(pkgs["b"].direct)
        self.assertEqual(pkgs["@scope/a"].chain, ["b@2.0.0"])
        p = self.write("pnpm-lock.yaml", "lockfileVersion: '6.0'\n\ndevDependencies:\n  c:\n    specifier: ^3\n"
                       "    version: 3.0.0\n\npackages:\n\n  /c@3.0.0:\n    resolution: {integrity: x}\n    dev: true\n")
        pkgs = self.parsed(lf.parse_pnpm_lock, p)
        self.assertTrue(pkgs["c"].dev and pkgs["c"].direct)

    def test_cargo_and_gem_graphs(self):
        p = self.write("Cargo.lock", 'version = 4\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "hyper",\n]\n\n'
                       '[[package]]\nname = "hyper"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                       'dependencies = [\n "h2 0.4.1",\n]\n\n[[package]]\nname = "h2"\nversion = "0.4.1"\n'
                       'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        pkgs = self.parsed(lf.parse_cargo_lock, p)
        self.assertEqual(set(pkgs), {"hyper", "h2"})
        self.assertEqual(pkgs["h2"].meta["paths"][0], ["hyper@1.0.0", "h2@0.4.1"])
        p = self.write("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    cocoapods (1.16.1)\n"
                       "      addressable (~> 2.8)\n    addressable (2.8.7)\n\nDEPENDENCIES\n  cocoapods (~> 1.16)\n")
        pkgs = self.parsed(lf.parse_gemfile_lock, p)
        self.assertEqual(pkgs["addressable"].chain, ["cocoapods@1.16.1"])

    def test_python_locks(self):
        p = self.write("poetry.lock", '[[package]]\nname = "requests"\nversion = "2.19.0"\n\n[package.dependencies]\nidna = "*"\n')
        self.assertEqual([(x.name, x.version) for x in lf.parse_poetry_lock(p)[0]], [("requests", "2.19.0")])
        p = self.write("uv.lock", '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n'
                       '[[package]]\nname = "urllib3"\nversion = "1.26.0"\nsource = { registry = "https://pypi.org/simple" }\n')
        self.assertEqual([x.name for x in lf.parse_uv_lock(p)[0]], ["urllib3"])
        p = self.write("requirements-dev.txt", "Django==3.2.0  # pinned\nflask>=2\npyyaml[extra]==5.3 ; python_version<'3.12'\n")
        got = lf.parse_requirements(p)[0]
        self.assertEqual({(x.name, x.version) for x in got}, {("Django", "3.2.0"), ("pyyaml", "5.3")})
        self.assertTrue(all(x.dev for x in got))

    def test_other_locks(self):
        p = self.write("go.mod", "module x\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/a/b v1.0.0 // indirect\n"
                       "\tgithub.com/local/mod v0.0.0-00010101000000-000000000000\n\tgithub.com/old/x v1.0.0\n)\n"
                       "require github.com/c/d v2.0.0+incompatible\n\n"
                       "replace github.com/local/mod => ../mod\nreplace (\n\tgithub.com/old/x => github.com/fork/x v1.2.0\n)\n")
        got = {x.name: x for x in lf.parse_go_mod(p)[0]}
        self.assertEqual(got["golang.org/x/net"].version, "0.7.0")
        self.assertFalse(got["github.com/a/b"].direct)
        self.assertNotIn("github.com/local/mod", got)
        self.assertEqual(got["github.com/fork/x"].version, "1.2.0")
        self.assertEqual(got["github.com/c/d"].version, "2.0.0+incompatible")
        p = self.write("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.4-arm64-darwin)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n")
        self.assertEqual({(x.name, x.version) for x in lf.parse_gemfile_lock(p)[0]}, {("nokogiri", "1.15.4"), ("rack", "2.2.3")})
        p = self.write("Cargo.lock", '[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.assertEqual([x.name for x in lf.parse_cargo_lock(p)[0]], ["time"])

    def test_discover_finds_venvs_and_repos(self):
        (self.tmp / "proj" / ".git").mkdir(parents=True)
        (self.tmp / "proj" / ".venv").mkdir()
        (self.tmp / "proj" / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
        (self.tmp / "proj" / "node_modules" / "x").mkdir(parents=True)
        (self.tmp / "proj" / "node_modules" / "x" / "package-lock.json").write_text("{}")
        (self.tmp / "proj" / "package-lock.json").write_text("{}")
        ctx = Context(Config(roots=[str(self.tmp)]))
        lf.discover(ctx)
        self.assertEqual([p.name for p in ctx.venvs], [".venv"])
        self.assertEqual(len(ctx.lockfiles), 1)  # node_modules is pruned
        self.assertEqual([p.name for p in ctx.repos], ["proj"])


class InstalledTreeTests(unittest.TestCase):
    def test_site_packages_and_node_modules(self):
        tmp = Path(tempfile.mkdtemp())
        site = tmp / "env" / "lib" / "python3.11" / "site-packages"
        (site / "Requests-2.19.0.dist-info").mkdir(parents=True)
        (site / "Requests-2.19.0.dist-info" / "METADATA").write_text("Metadata-Version: 2.1\nName: requests\nVersion: 2.19.0\n\nVersion: 9\n")
        got = scan_site(site, "global")
        self.assertEqual([(p.name, p.version) for p in got], [("requests", "2.19.0")])
        self.assertEqual(Path(got[0].meta["python"]).parts[-3:], ("env", "bin", "python"))

        nm = tmp / "node_modules"
        for d, name, ver in [(nm / "tool", "tool", "1.0.0"), (nm / "tool" / "node_modules" / "chalk", "chalk", "5.6.1"),
                             (nm / "@s" / "x", "@s/x", "2.0.0")]:
            d.mkdir(parents=True)
            (d / "package.json").write_text(json.dumps({"name": name, "version": ver}))
        out: list = []
        walk_node_modules(nm, str(nm), [], set(), out)
        by = {p.name: p for p in out}
        self.assertEqual(by["chalk"].chain, ["tool"])
        self.assertTrue(by["@s/x"].direct)


class EnrichAnalyzeTests(unittest.TestCase):
    def test_osv_advisory_and_dedupe(self):
        ghsa = {"id": "GHSA-x", "aliases": ["CVE-2018-1", "PYSEC-1"], "summary": "bad",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}
        pysec = {"id": "PYSEC-1", "aliases": ["CVE-2018-1"], "affected": []}
        mal = {"id": "GHSA-m", "database_specific": {"cwe_ids": ["CWE-506"]}, "affected": []}
        a = osv.to_advisory(ghsa, "PyPI", "requests")
        self.assertEqual((a.cvss, a.severity, a.fixed), (9.8, "CRITICAL", ["2.20.0"]))
        self.assertTrue(osv.to_advisory(mal, "npm", "x").malicious)
        merged = osv.dedupe([osv.to_advisory(pysec, "PyPI", "requests"), a])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].id, "GHSA-x")

    def test_buckets(self):
        def pkg(name, ver, eco="npm", **kw):
            return Package(eco, name, ver, "lockfile", "/p/package-lock.json",
                           meta={"project": "/p", "lockfile": "package-lock.json"}, **kw)
        pkgs = [pkg("chalk", "5.6.1"), pkg("qs", "6.5.2", direct=True), pkg("lodash", "3.0.0", direct=True),
                pkg("left", "1.0.0")]
        advs = {
            pkgs[0].key: [Advisory("MAL-1", malicious=True, severity="CRITICAL")],
            pkgs[1].key: [Advisory("GHSA-a", severity="HIGH", fixed=["6.5.3"], kev=True)],
            pkgs[2].key: [Advisory("GHSA-b", severity="MEDIUM", fixed=["4.17.21"])],
            pkgs[3].key: [Advisory("GHSA-c", severity="LOW")],
        }
        f = {x.name: x for x in build_findings(pkgs, advs, [])[0]}
        self.assertEqual(f["chalk"].bucket, "respond")
        self.assertEqual(f["chalk"].score, 100)
        self.assertEqual(f["qs"].bucket, "patch")
        self.assertGreaterEqual(f["qs"].score, 90)
        self.assertEqual(f["lodash"].bucket, "verify")
        self.assertEqual(f["left"].bucket, "monitor")
        self.assertIn("npm install 'qs@^6.5.3'", f["qs"].commands[0])

    def test_ioc_packs_and_nvd_range(self):
        packs = ioc.load_packs([])
        self.assertTrue(any(p["id"] == "xz-backdoor-2024" for p in packs))
        hit = ioc.match_packages(packs, [Package("Homebrew", "xz", "5.6.1", "brew", "/x")])
        self.assertTrue(next(iter(hit.values()))[0].malicious)
        m = {"criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*", "versionEndExcluding": "8.4.0"}
        self.assertTrue(nvd._in_range("8.1.0", m))
        self.assertFalse(nvd._in_range("8.4.0", m))
        self.assertFalse(nvd._in_range("1.0", {"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}))

    def test_html_escapes_untrusted_names(self):
        p = Package("npm", "<script>alert(1)</script>", "1.0.0", "lockfile", "/p/package-lock.json",
                    meta={"project": "/p", "lockfile": "package-lock.json"})
        f = build_findings([p], {p.key: [Advisory("MAL-9", malicious=True, summary="<img src=x onerror=1>")]}, [])[0]
        result = {"host": "h", "started": "now", "duration_s": 1, "scs_version": "t", "summary": {"buckets": {
            "respond": 1, "patch": 0, "verify": 0, "monitor": 0}}, "findings": [x.to_dict() for x in f],
            "inventory": {"total": 1, "unique": 1}, "sources": {}, "collectors": {}, "errors": [], "config": {}}
        out = html_report.render(result)
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<img src=x", out)


if __name__ == "__main__":
    unittest.main()
