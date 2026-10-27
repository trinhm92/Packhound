import base64
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import executor, fixers, plan, shell, toolchain
from scs.analyze import build_findings
from scs.models import Advisory, Package
from scs.policy import Decisions


def tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"package/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeRegistry:
    """Serves version docs and tarballs for NestedPatcher without the network."""

    def __init__(self):
        self.pkgs: dict[tuple[str, str], tuple[dict, bytes]] = {}

    def add(self, name, version, deps=None, body="module.exports = {ok: true};", corrupt=False):
        pkg = {"name": name, "version": version, "main": "index.js", "dependencies": deps or {}}
        data = tarball({"package.json": json.dumps(pkg), "index.js": body})
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(b"x" if corrupt else data).digest()).decode()
        doc = {**pkg, "dist": {"tarball": f"https://registry.example/{name}-{version}.tgz", "integrity": integrity}}
        self.pkgs[(name, version)] = (doc, data)

    def doc(self, name, version):
        return self.pkgs[(name, version)][0]

    def packument(self, name):
        return {"dist-tags": {}, "versions": {v: {"engines": {}, "deps": {}} for (n, v) in self.pkgs if n == name}}

    def urlopen(self, req, timeout=0):
        url = req.full_url
        data = next(d for (doc, d) in self.pkgs.values() if doc["dist"]["tarball"] == url)
        return io.BytesIO(data)


def write_pkg(d: Path, name: str, version: str, deps=None, body="module.exports = {ok: true};"):
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": name, "version": version, "main": "index.js",
                                                "dependencies": deps or {}}))
    (d / "index.js").write_text(body)


@unittest.skipUnless(shutil.which("node"), "needs Node.js for the load test")
class NestedPatchTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()) / "lib" / "node_modules"
        tool = self.root / "tool"
        write_pkg(tool, "tool", "1.0.0", {"undici": "^6.0.0"}, "require('undici'); module.exports = 1;")
        write_pkg(tool / "node_modules" / "undici", "undici", "6.21.0")
        self.reg = FakeRegistry()
        self.patches = [mock.patch.object(fixers, "_registry_doc", self.reg.doc),
                        mock.patch.object(toolchain, "npm_packument", self.reg.packument),
                        mock.patch.object(fixers, "urlopen", self.reg.urlopen)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def version(self, *parts):
        return json.loads((self.root.joinpath(*parts) / "package.json").read_text())["version"]

    def test_replaces_bundled_copy_with_newest_same_major_and_missing_deps(self):
        self.reg.add("undici", "6.24.0")
        self.reg.add("undici", "6.25.1", deps={"tiny": "^2.0.0"})
        self.reg.add("tiny", "2.3.0")
        out = []
        rc = fixers.npm_nested(str(self.root), "tool", {"undici": "6.24.0"}, out=out.append)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.version("tool", "node_modules", "undici"), "6.25.1")
        self.assertEqual(self.version("tool", "node_modules", "undici", "node_modules", "tiny"), "2.3.0")
        marker = json.loads((self.root / "tool" / ".scs-patched.json").read_text())
        self.assertEqual(marker["undici"]["from"], "6.21.0")
        self.assertFalse(list((self.root / "tool" / "node_modules").glob("undici.scs-*")))

    def test_bad_integrity_or_broken_tool_leaves_original(self):
        self.reg.add("undici", "6.24.0", corrupt=True)
        out = []
        self.assertEqual(fixers.npm_nested(str(self.root), "tool", {"undici": "6.24.0"}, out=out.append), 1)
        self.assertIn("sha512", "\n".join(out))
        self.assertEqual(self.version("tool", "node_modules", "undici"), "6.21.0")
        # a release that breaks the tool on load is undone
        self.reg = FakeRegistry()
        self.reg.add("undici", "6.24.0", body="throw new Error('boom')")
        with mock.patch.object(fixers, "_registry_doc", self.reg.doc), \
                mock.patch.object(toolchain, "npm_packument", self.reg.packument), \
                mock.patch.object(fixers, "urlopen", self.reg.urlopen):
            out = []
            self.assertEqual(fixers.npm_nested(str(self.root), "tool", {"undici": "6.24.0"}, out=out.append), 1)
        self.assertIn("can no longer load", "\n".join(out))
        self.assertEqual(self.version("tool", "node_modules", "undici"), "6.21.0")

    def test_only_flagged_versions_are_replaced(self):
        write_pkg(self.root / "tool" / "node_modules" / "other" / "node_modules" / "undici", "undici", "6.20.0")
        self.reg.add("undici", "6.24.0")
        out = []
        rc = fixers.npm_nested(str(self.root), "tool", {"undici": "6.24.0"}, out=out.append, only={"undici": {"6.21.0"}})
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.version("tool", "node_modules", "undici"), "6.24.0")
        self.assertEqual(self.version("tool", "node_modules", "other", "node_modules", "undici"), "6.20.0")

    def test_major_jump_needs_permission(self):
        self.reg.add("undici", "7.1.0")
        out = []
        self.assertEqual(fixers.npm_nested(str(self.root), "tool", {"undici": "7.1.0"}, out=out.append), 3)
        self.assertEqual(self.version("tool", "node_modules", "undici"), "6.21.0")
        self.assertEqual(fixers.npm_nested(str(self.root), "tool", {"undici": "7.1.0"}, allow_major=True,
                                           out=out.append), 0)
        self.assertEqual(self.version("tool", "node_modules", "undici"), "7.1.0")

    def test_tarball_cannot_escape(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("package/../../evil.js")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
        dest = Path(tempfile.mkdtemp()) / "x"
        fixers._extract(buf.getvalue(), dest)
        self.assertFalse((dest.parent / "evil.js").exists())


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.sh = mock.patch.object(plan, "SH", shell.Posix())
        self.sh.start()

    def tearDown(self):
        self.sh.stop()

    def build(self, pkgs_advs, **kw):
        pkgs = [p for p, _ in pkgs_advs]
        findings, _ = build_findings(pkgs, {p.key: a for p, a in pkgs_advs}, [])
        result = {"host": "h", "started": "s", "findings": [f.to_dict() for f in findings]}
        return plan.build(result, Decisions(Path(os.devnull)), suggested=True, **kw, min_age=0)

    def test_bundled_without_release_uses_nested_fixer(self):
        root = tempfile.mkdtemp() + "/lib/node_modules"
        write_pkg(Path(root) / "firebase-tools", "firebase-tools", "15.34.1")
        p = Package("npm", "re2", "1.24.1", "npm-global", f"{root}/firebase-tools/node_modules/re2", direct=False,
                    chain=["firebase-tools"], meta={"root": root})
        with mock.patch.object(toolchain, "npm_tool_update", return_value={"version": None, "latest": "15.34.1",
                                                                           "latest_runs_here": True, "latest_engines": ""}):
            pl = self.build([(p, [Advisory("GHSA-r", severity="MEDIUM", fixed=["1.26.1"])])])
        t = pl["targets"][0]
        cmd = next(c for c in t["change"] if "fixer npm-nested" in c)
        self.assertIn("--tool firebase-tools --set re2@1.26.1 --from re2@1.24.1", cmd)
        self.assertNotIn("--allow-major", cmd)
        self.assertFalse(t["warnings"])  # same major: low risk

    def test_pip_python_blocked_items_need_migration(self):
        env = "/Users/me/.pyenv/versions/3.10.3"
        site = env + "/lib/python3.10/site-packages"
        pil = Package("PyPI", "pillow", "10.4.0", "pip", site, direct=True,
                      meta={"env": env, "python": env + "/bin/python", "runtime": "3.10"})
        req = Package("PyPI", "requests", "2.31.0", "pip", site, direct=True,
                      meta={"env": env, "python": env + "/bin/python", "runtime": "3.10"})
        pairs = [(pil, [Advisory("GHSA-p", severity="HIGH", fixed=["13.0.0"])]),
                 (req, [Advisory("GHSA-q", severity="HIGH", fixed=["2.32.0"])])]
        pkgs = [p for p, _ in pairs]
        findings, _ = build_findings(pkgs, {p.key: a for p, a in pairs}, [])
        fs = [f.to_dict() for f in findings]
        for f in fs:
            if f["name"] == "pillow":
                f["reasons"].append(f"13.0.0 needs python >=3.11, but env {env} uses python 3.10 (its interpreter)")
        result = {"host": "h", "started": "s", "findings": fs}
        pl = plan.build(result, Decisions(Path(os.devnull)), suggested=True, min_age=0)
        pip_t = pl["targets"][0]
        self.assertIn("'requests>=2.32.0'", pip_t["change"][0])
        self.assertNotIn("pillow", pip_t["change"][0])  # would make the whole pip command fail
        self.assertTrue(any("needs Python 3.11+" in m for m in pip_t["manual"]))
        with mock.patch.object(fixers, "pyenv_exe", return_value="/usr/local/bin/pyenv"):
            pl = plan.build(result, Decisions(Path(os.devnull)), suggested=True, migrate=True, min_age=0)
        mig = next(t for t in pl["targets"] if t["kind"] == "py-migrate")
        self.assertIn(f"fixer py-migrate --env {env} --to 3.11", mig["change"][0])
        self.assertIn("--want 'pillow>=13.0.0'", mig["change"][0])
        self.assertIn('"$BACKUP/retired"', mig["change"][0])
        self.assertTrue(mig["warnings"])  # changes which Python runs: needs care

    def test_pip_homebrew_root_and_parent_fallback(self):
        d = Path(tempfile.mkdtemp())
        site = d / "lib" / "python3.12" / "site-packages"
        site.mkdir(parents=True)
        (site.parent / "EXTERNALLY-MANAGED").write_text("[externally-managed]")
        p = Package("PyPI", "sqlparse", "0.5.5", "pip", str(site), direct=False, chain=["objection@1.12.4", "litecli@1.17.1"],
                    meta={"env": str(d), "python": str(d / "bin" / "python3.12"), "introduced_by": ["objection@1.12.4"]})
        with mock.patch.object(plan, "needs_root", return_value=True):
            pl = self.build([(p, [Advisory("GHSA-s", severity="HIGH", fixed=["0.6.0"])])])
        c = pl["targets"][0]["change"][0]
        self.assertTrue(c.startswith("sudo "))
        self.assertIn("--break-system-packages", c)
        self.assertIn("pip check ||", c)
        self.assertIn("litecli", c.split("||")[1])  # parent upgraded only if the plain upgrade conflicts
        self.assertTrue(any("py_smoke.py" in v and "objection" in v for v in pl["targets"][0]["verify"]))

    def test_pip_without_record_is_installed_over(self):
        d = Path(tempfile.mkdtemp())
        site = d / "lib" / "python3.12" / "site-packages"
        (site / "pip-26.0.dist-info").mkdir(parents=True)
        p = Package("PyPI", "pip", "26.0", "pip", str(site), direct=True,
                    meta={"env": str(d), "python": str(d / "bin" / "python3.12")})
        pl = self.build([(p, [Advisory("GHSA-p", severity="MEDIUM", fixed=["26.2"])])])
        c = pl["targets"][0]["change"]
        self.assertEqual(len(c), 1)
        self.assertIn("--ignore-installed --no-deps 'pip>=26.2'", c[0])
        self.assertIn("pip-26.0.dist-info", c[0])

    def test_root_owned_npm_prefix_uses_sudo_for_fixer(self):
        root = tempfile.mkdtemp() + "/lib/node_modules"
        write_pkg(Path(root) / "npm", "npm", "12.2.1")
        p = Package("npm", "undici", "6.29.0", "npm-global", f"{root}/npm/node_modules/undici", direct=False,
                    chain=["npm"], meta={"root": root})
        with mock.patch.object(toolchain, "npm_tool_update", return_value={"version": None, "latest": "12.2.1",
                                                                           "latest_runs_here": True, "latest_engines": ""}), \
                mock.patch.object(plan, "needs_root", return_value=True):
            pl = self.build([(p, [Advisory("GHSA-u", severity="HIGH", fixed=["6.29.1"])])])
        cmd = next(c for c in pl["targets"][0]["change"] if "npm-nested" in c)
        self.assertTrue(cmd.startswith("sudo "), cmd)

    def test_windows_npm_prefix_layout(self):
        self.assertEqual(plan.npm_prefix(Path("C:/Users/me/AppData/Roaming/npm/node_modules")),
                         Path("C:/Users/me/AppData/Roaming/npm"))
        self.assertEqual(plan.npm_prefix(Path("/opt/homebrew/lib/node_modules")), Path("/opt/homebrew"))


class MigrateTests(unittest.TestCase):
    def test_migrate_switches_global_retires_and_undo_restores(self):
        home = Path(tempfile.mkdtemp())
        versions = home / ".pyenv" / "versions"
        old = versions / "3.10.3"
        (old / "bin").mkdir(parents=True)
        (old / "bin" / "python").write_text("")
        calls, glob_ver = [], ["3.10.3"]

        def fake_run(cmd, out, timeout=0):
            calls.append(cmd)
            if cmd[1:] == ["global"]:
                return "\n".join(glob_ver)
            if cmd[1] == "global":
                glob_ver[:] = cmd[2:]
                return ""
            if cmd[1:3] == ["install", "--list"]:
                return "  3.12.1\n  3.12.10\n  3.13.0\n"
            if cmd[1:3] == ["install", "-s"]:
                (versions / cmd[3] / "bin").mkdir(parents=True)
                (versions / cmd[3] / "bin" / "python").write_text("")
                return ""
            if cmd[1:4] == ["-m", "pip", "list"]:
                return '[{"name": "mitmproxy", "version": "11.0.2"}, {"name": "pip", "version": "22"}]'
            return ""
        retire = home / "backup" / "retired"
        with mock.patch.object(fixers, "_run", fake_run), mock.patch.object(fixers, "pyenv_exe", return_value="pyenv"), \
                mock.patch.object(fixers, "_pip_problems", return_value=set()):
            rc = fixers.py_migrate(str(old), "3.12", str(retire), ["mitmproxy>=12.2.2"], out=lambda m: None)
            self.assertEqual(rc, 0)
            self.assertEqual(glob_ver, ["3.12.10"])
            self.assertFalse(old.exists())
            install = next(c for c in calls if c[1:4] == ["-m", "pip", "install"] and "pip" not in c[4:])
            self.assertIn("mitmproxy", install)
            self.assertIn("mitmproxy>=12.2.2", install)
            notes = fixers.undo_migrate(retire)
        self.assertTrue(old.is_dir())
        self.assertEqual(glob_ver, ["3.10.3"])
        self.assertTrue(any("put" in n for n in notes))


class ConflictKeyTests(unittest.TestCase):
    def test_keys_ignore_versions(self):
        old = {"docx-translator 0.2.1 has requirement streamlit<1.29.0,>=1.24.0, but you have streamlit 1.65.0."}
        new = {"docx_translator 0.2.1 has requirement streamlit<1.29.0,>=1.24.0, but you have streamlit 1.66.1."}
        self.assertEqual(fixers.conflict_keys(old), fixers.conflict_keys(new))
        self.assertEqual(fixers.conflict_keys({"foo 1.0 requires bar, which is not installed."}), set())


class PyenvRepairTests(unittest.TestCase):
    def test_install_succeeds_when_only_rehash_hits_a_stale_lock(self):
        root = Path(tempfile.mkdtemp())
        (root / "shims").mkdir()
        lock = root / "shims" / ".pyenv-shim"
        lock.write_text("x")
        os.utime(lock, (0, 0))  # left behind long ago
        (root / "versions" / "3.12.13").mkdir(parents=True)

        def fake_run(cmd, out, timeout=0):
            if cmd[1] == "root":
                return str(root)
            if lock.exists() and cmd[1] in ("install", "rehash"):
                raise fixers.FixError("pyenv failed: Installed Python-3.12.13 | pyenv: cannot rehash: couldn't acquire lock")
            return ""
        with mock.patch.object(fixers, "_run", fake_run):
            fixers._pyenv_install("pyenv", "3.12.13", root / "versions", lambda m: None)
        self.assertFalse(lock.exists())


class NewProblemTests(unittest.TestCase):
    def test_only_new_pip_check_lines_are_regressions(self):
        d = Path(tempfile.mkdtemp())
        (d / "a.log").write_text("$ py -m pip check\nmitmproxy has requirement h2<=4.1.0, but you have h2 4.4.1.\n")
        (d / "b.log").write_text("$ py -m pip check\nmitmproxy has requirement h2<=4.1.0, but you have h2 4.4.1.\n"
                                 "mitmproxy has requirement pyOpenSSL<=24.3.0, but you have pyopenssl 26.4.0.\n")
        new = executor._new_problems(str(d / "a.log"), str(d / "b.log"), "py -m pip check")
        self.assertEqual(new, ["mitmproxy has requirement pyOpenSSL<=24.3.0, but you have pyopenssl 26.4.0."])
        self.assertEqual(executor._new_problems(str(d / "a.log"), str(d / "b.log"), "make test"), [])

    def test_pip_timeouts_count_as_network_errors(self):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text("WARNING: Retrying after connection broken by 'ConnectTimeoutError(<x>, "
                       "'Connection to pypi.org timed out. (connect timeout=15)')': /simple/gitpython/\n")
        self.assertIn("pypi.org", executor._network_error(str(log)))


class ElevationTests(unittest.TestCase):
    def test_uac_wrapper(self):
        with mock.patch.dict("os.environ", {"XDG_DATA_HOME": tempfile.mkdtemp()}):
            r = executor.Runner({"targets": [], "shell": "cmd"}, "p", executor.Options(yes=True))
            log = r.run.dir / "logs" / "t1-apply-0.log"
            cmd = r._elevated("choco upgrade git -y", log, Path("C:/b"))
        self.assertTrue(cmd.startswith("powershell "))
        self.assertIn("-Verb RunAs", cmd)
        bat = log.with_suffix(".cmd").read_text()
        self.assertIn("(choco upgrade git -y) >", bat)
        self.assertIn('set "BACKUP=', bat)


if __name__ == "__main__":
    unittest.main()
