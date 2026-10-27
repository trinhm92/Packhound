import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import executor, plan
from scs.analyze import build_findings
from scs.collectors import dpkg
from scs.collectors.snap import parse_snap_list
from scs.enrich import osv
from scs.graph import annotate
from scs.malware import integrity, persistence
from scs.models import Advisory, osv_supported
from scs.osinfo import deb_ecosystem, os_release
from scs.policy import Decisions

STATUS = """Package: libssl3t64
Status: install ok installed
Priority: optional
Architecture: amd64
Source: openssl
Version: 3.0.13-0ubuntu3.4
Depends: libc6 (>= 2.34)

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.13-0ubuntu3.4
Depends: libc6 (>= 2.34), libssl3t64 (>= 3.0.13)

Package: curl
Status: install ok installed
Architecture: amd64
Version: 8.5.0-2ubuntu10.6
Depends: libc6 (>= 2.34), libcurl4t64 (= 8.5.0-2ubuntu10.6)

Package: libcurl4t64
Status: install ok installed
Architecture: amd64
Source: curl
Version: 8.5.0-2ubuntu10.6
Depends: libssl3t64 (>= 3.0.0) | libssl1.1

Package: libc6
Status: install ok installed
Priority: required
Architecture: amd64
Source: glibc
Version: 2.39-0ubuntu8.3

Package: zlib1g
Status: install ok installed
Architecture: amd64
Source: zlib (1:1.3.dfsg-3.1ubuntu2)
Version: 1:1.3.dfsg-3.1ubuntu2.1

Package: oldthing
Status: deinstall ok config-files
Version: 1.0
"""


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


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


class OsInfoTests(unittest.TestCase):
    def rel(self, text):
        return os_release(write(Path(tempfile.mkdtemp()) / "os-release", text))

    def test_ecosystems(self):
        self.assertEqual(deb_ecosystem(self.rel('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n')),
                         "Ubuntu:24.04:LTS")
        self.assertEqual(deb_ecosystem(self.rel('ID=ubuntu\nVERSION_ID="24.10"\nVERSION="24.10 (Oracular)"\n')), "Ubuntu:24.10")
        self.assertEqual(deb_ecosystem(self.rel('ID=debian\nVERSION_ID="12"\n')), "Debian:12")
        self.assertEqual(deb_ecosystem(self.rel('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\nUBUNTU_CODENAME=noble\n')),
                         "Ubuntu:24.04:LTS")
        self.assertIsNone(deb_ecosystem(self.rel('ID=fedora\nVERSION_ID=40\n')))
        self.assertTrue(osv_supported("Ubuntu:24.04:LTS") and osv_supported("Debian:12"))


class DpkgCollectorTests(unittest.TestCase):
    def test_groups_by_source_and_builds_graph(self):
        pkgs, g = dpkg.collect_status(None, STATUS, "Ubuntu:24.04:LTS")
        by = {p.name: p for p in pkgs}
        self.assertEqual(set(by), {"openssl", "curl", "glibc", "zlib"})  # deinstalled package ignored
        self.assertEqual(sorted(b["name"] for b in by["openssl"].meta["binaries"]), ["libssl3t64", "openssl"])
        self.assertEqual(by["zlib"].version, "1:1.3.dfsg-3.1ubuntu2")  # source version from "Source: x (ver)"
        self.assertTrue(by["glibc"].meta["essential"])
        g.add_root("curl@8.5.0-2ubuntu10.6")
        annotate([by["openssl"]], {"dpkg": g})
        by["openssl"].meta["graph"] = "dpkg"
        annotate([by["openssl"]], {"dpkg": g})
        self.assertEqual(by["openssl"].meta["paths"][0], ["curl@8.5.0-2ubuntu10.6", "openssl@3.0.13-0ubuntu3.4"])


class OsvDistroTests(unittest.TestCase):
    def test_release_specific_fixes_and_pro_fallback(self):
        vuln = {"id": "UBUNTU-CVE-2024-1", "affected": [
            {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.18"}]}]},
            {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.5"}]}]}]}
        self.assertEqual(osv.to_advisory(vuln, "Ubuntu:24.04:LTS", "openssl").fixed, ["3.0.13-0ubuntu3.5"])
        pro_only = {"id": "UBUNTU-CVE-2024-2", "affected": [
            {"package": {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": "nodejs"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.19.0~dfsg-3ubuntu1.6+esm1"}]}]}]}
        self.assertEqual(osv.to_advisory(pro_only, "Ubuntu:20.04:LTS", "nodejs").fixed, ["10.19.0~dfsg-3ubuntu1.6+esm1"])


class AptAnalysisPlanTests(unittest.TestCase):
    def setUp(self):
        self.pkgs, _ = dpkg.collect_status(None, STATUS, "Ubuntu:24.04:LTS")
        self.by = {p.name: p for p in self.pkgs}
        advs = {self.by["openssl"].key: [Advisory("UBUNTU-CVE-1", severity="HIGH", fixed=["3.0.13-0ubuntu3.5"])],
                self.by["curl"].key: [Advisory("UBUNTU-CVE-2", severity="MEDIUM", fixed=["8.5.0-2ubuntu10.10"])],
                self.by["zlib"].key: [Advisory("UBUNTU-CVE-3", severity="MEDIUM", fixed=["1:1.3.dfsg-3.1ubuntu2.1+esm1"])]}
        self.findings, _ = build_findings(self.pkgs, advs, [])

    def test_buckets_reasons_commands(self):
        f = {x.name: x for x in self.findings}
        self.assertEqual(f["openssl"].bucket, "verify")
        self.assertIn("restart affected services", " ".join(f["openssl"].reasons))
        self.assertEqual(f["curl"].bucket, "patch")
        self.assertEqual(f["curl"].fix_version, "8.5.0-2ubuntu10.10")  # dpkg ordering: 10.10 > 10.6
        self.assertIn("sudo apt-get install --only-upgrade curl libcurl4t64", f["curl"].commands[0])
        self.assertIn("Ubuntu Pro", " ".join(f["zlib"].reasons))

    def test_plan_and_executor_gate(self):
        result = {"host": "h", "started": "s", "findings": [x.to_dict() for x in self.findings]}
        d = Decisions(Path(tempfile.mkdtemp()) / "d.json")
        p = plan.build(result, d, suggested=True, min_age=0)
        apt = next(t for t in p["targets"] if t["kind"] == "apt")
        self.assertEqual(apt["title"], "APT packages (Ubuntu 24.04 LTS)")
        self.assertIn("sudo apt-get install --only-upgrade -y", apt["change"][1])
        self.assertTrue(any("--allow-downgrades" in r and "libcurl4t64=8.5.0-2ubuntu10.6" in r for r in apt["rollback"]))
        self.assertTrue(any("Ubuntu Pro" in m for m in apt["manual"]))
        status = write(Path(tempfile.mkdtemp()) / "status", STATUS)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": tempfile.mkdtemp()}), \
                mock.patch.object(dpkg, "DPKG_STATUS", status):
            out: list[str] = []
            rec = executor.Runner({"targets": [apt]}, "p", executor.Options(yes=True, out=out.append)).execute([1])
        self.assertEqual(rec["targets"][0]["status"], "skipped")
        self.assertTrue(any("--allow-sudo" in o for o in out), out)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": tempfile.mkdtemp()}), \
                mock.patch.object(dpkg, "DPKG_STATUS", Path("/nonexistent/status")):
            out = []
            executor.Runner({"targets": [apt]}, "p", executor.Options(yes=True, out=out.append)).execute([1])
        self.assertTrue(any("not a dpkg-based system" in o for o in out))

    def test_sudo_rewrite(self):
        self.assertEqual(executor.SUDO_RE.sub(r"\1sudo -n ", "sudo apt-get update && sudo apt-get install -y x"),
                         "sudo -n apt-get update && sudo -n apt-get install -y x")
        self.assertEqual(executor.SUDO_RE.sub(r"\1sudo -n ", "sudo -n true"), "sudo -n true")
        self.assertEqual(executor.missing_tools(["sudo -n definitely-missing-tool x"]), ["definitely-missing-tool"])


class LinuxMalwareTests(unittest.TestCase):
    def test_dpkg_verify_parsing(self):
        out = ("??5??????   /usr/bin/sudo\n??5?????? c /etc/ssh/sshd_config\n??5??????   /usr/share/doc/x/README\n"
               "missing     /usr/share/man/man1/foo.1.gz\nmissing   c /etc/foo.conf\n")
        f, st = integrity.dpkg_verify(out)
        sev = {x.rules[0]: x for x in f}
        self.assertEqual(sev["DPKG_MODIFIED_SYSTEM"].evidence, ["/usr/bin/sudo"])
        self.assertEqual(sev["DPKG_MODIFIED"].evidence, ["/usr/share/doc/x/README"])
        self.assertEqual(st, {"dpkg_files_differing": 2, "dpkg_files_missing": 1})  # conffiles ignored

    @unittest.skipIf(os.name == "nt", "setuid is a POSIX concept")
    def test_ld_preload_keys_suid(self):
        tmp = Path(tempfile.mkdtemp())
        self.assertEqual(persistence.ld_preload(str(write(tmp / "preload", "# none\n"))), [])
        self.assertEqual(persistence.ld_preload(str(write(tmp / "preload2", "/usr/lib/libx.so\n")))[0].severity, "critical")
        keys = {"/h/.ssh/authorized_keys": ["ssh-ed25519 AAAA1 me@laptop", "ssh-ed25519 AAAA2 attacker@x"]}
        prev = {"/h/.ssh/authorized_keys": [persistence._h("ssh-ed25519 AAAA1 me@laptop")]}
        f = persistence.audit_authorized_keys(keys, prev)
        self.assertEqual([x.title for x in f], ["SSH authorized key attacker@x"])
        self.assertEqual(persistence.audit_authorized_keys(keys, None), [])  # first run: baseline only
        b = write(tmp / "sub" / "rootme", "#!/bin/sh\n")
        b.chmod(0o4755)
        self.assertEqual([x.path for x in persistence.suid_files([str(tmp)])], [str(b)])

    def test_snap_list_parsing(self):
        out = ("Name      Version    Rev    Tracking       Publisher   Notes\n"
               "core22    20240111   1122   latest/stable  canonical**  base\n"
               "code      1.95.3     177    latest/stable  vscode*      classic\n")
        rows = parse_snap_list(out)
        self.assertEqual([(r["name"], r["publisher"], r["notes"]) for r in rows],
                         [("core22", "canonical**", "base"), ("code", "vscode*", "classic")])


if __name__ == "__main__":
    unittest.main()
