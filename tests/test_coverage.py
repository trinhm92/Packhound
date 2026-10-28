"""Languages, global tools, runtimes and build tools added by the coverage audit."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import handfix
from scs.collectors import globaltools, java, lockfiles, runtimes
from scs.enrich import runtimes as rt_enrich


def write(path: Path, text="", binary: bytes | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(binary) if binary is not None else path.write_text(text, encoding="utf-8")
    return path


def got(pkgs) -> set:
    return {(p.ecosystem, p.name, p.version) for p in pkgs}


class LockfileTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def parse(self, name, text):
        path = write(self.d / name, text)
        return lockfiles.parser_for(name, path.parent)(path)[0]

    def test_python_pdm_and_pylock(self):
        self.assertEqual(got(self.parse("pdm.lock", '[[package]]\nname = "requests"\nversion = "2.31.0"\n')),
                         {("PyPI", "requests", "2.31.0")})
        self.assertEqual(got(self.parse("pylock.toml", '[[packages]]\nname = "urllib3"\nversion = "2.0.7"\n')),
                         {("PyPI", "urllib3", "2.0.7")})
        self.assertEqual(got(self.parse("pylock.dev.toml", '[[packages]]\nname = "pytest"\nversion = "8.0.0"\n')),
                         {("PyPI", "pytest", "8.0.0")})

    def test_haskell(self):
        self.assertEqual(got(self.parse("cabal.project.freeze", "active-repositories: hackage.haskell.org:merge\n"
                                        "constraints: any.aeson ==2.1.2.1,\n             any.base ==4.17.0.0,\n"
                                        "             aeson +ordered-keymap,\n")),
                         {("Hackage", "aeson", "2.1.2.1"), ("Hackage", "base", "4.17.0.0")})
        self.assertEqual(got(self.parse("stack.yaml.lock", "packages:\n- completed:\n    hackage: warp-3.3.25@sha256:abc,123\n"
                                        "  original:\n    hackage: warp-3.3.25\n")), {("Hackage", "warp", "3.3.25")})

    def test_julia_v1_and_v2(self):
        v2 = self.parse("Manifest.toml", 'julia_version = "1.10.0"\nmanifest_format = "2.0"\n\n[[deps.HTTP]]\n'
                        'uuid = "cd3eb016"\nversion = "1.10.0"\n\n[[deps.LinearAlgebra]]\nuuid = "37e2e46d"\n')
        self.assertEqual(got(v2), {("Julia", "HTTP", "1.10.0")})
        v1 = self.parse("JuliaManifest.toml", '[[JSON]]\nuuid = "682c06a0"\nversion = "0.21.4"\n')
        self.assertEqual(got(v1), {("Julia", "JSON", "0.21.4")})

    def test_ocaml_erlang_paket(self):
        self.assertEqual(got(self.parse("app.opam.locked", 'opam-version: "2.0"\ndepends: [\n  "cohttp" {= "5.1.0"}\n'
                                        '  "ocaml" {= "5.1.1" & with-test}\n]\n')),
                         {("opam", "cohttp", "5.1.0"), ("opam", "ocaml", "5.1.1")})
        self.assertEqual(got(self.parse("rebar.lock", '{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>},0}]}.\n')),
                         {("Hex", "cowboy", "2.9.0")})
        self.assertEqual(got(self.parse("paket.lock", "NUGET\n  remote: https://api.nuget.org/v3/index.json\n"
                                        "    Newtonsoft.Json (12.0.1)\n      Other (>= 1.0)\nGITHUB\n  remote: x/y\n"
                                        "    src/File.fs (abc)\n")), {("NuGet", "Newtonsoft.Json", "12.0.1")})

    def test_gems_locked_and_package_manager(self):
        self.assertEqual(got(self.parse("gems.locked", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n\n")),
                         {("RubyGems", "rack", "2.2.3")})
        proj = self.d / "web"
        write(proj / "package.json", '{"name": "web", "packageManager": "pnpm@8.6.0+sha512.abc"}')
        write(proj / "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
        from scs.collectors import Context
        from scs.config import Config
        ctx = Context(Config(roots=[str(self.d)]))
        pkgs = lockfiles._collect(ctx)
        pm = [p for p in pkgs if p.meta.get("lockfile") == "package.json"]
        self.assertEqual(got(pm), {("npm", "pnpm", "8.6.0")})
        self.assertTrue(handfix.manual_only(pm[0].to_dict()))
        self.assertIn("corepack use pnpm@", handfix.commands("npm", "pnpm", "8.6.0", "8.6.2", pm[0].to_dict())[0])


def go_binary(version: str, modinfo: str) -> bytes:
    def uvarint(n: int) -> bytes:
        out = b""
        while n >= 0x80:
            out += bytes([n & 0x7F | 0x80])
            n >>= 7
        return out + bytes([n])
    sentinel = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
    mod = sentinel + modinfo.encode() + sentinel
    header = globaltools.BUILDINFO_MAGIC + bytes([8, 2]) + b"\0" * 16
    return b"\x7fELF junk" * 50 + header + uvarint(len(version)) + version.encode() + uvarint(len(mod)) + mod + b"\0" * 64


class GlobalToolTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def test_go_binary_buildinfo(self):
        text = ("path\texample.com/tool/cmd/tool\nmod\texample.com/tool\tv1.4.0\th1:x=\n"
                "dep\tgolang.org/x/net\tv0.17.0\th1:y=\ndep\tgithub.com/old/lib\tv1.0.0\th1:z=\n"
                "=>\tgithub.com/fork/lib\tv1.0.1\th1:w=\nbuild\t-compiler=gc\n")
        b = write(self.d / "bin" / "tool", binary=go_binary("go1.21.3", text))
        pkgs = globaltools.go_binary_packages(b)
        self.assertEqual(got(pkgs), {("Go", "stdlib", "1.21.3"), ("Go", "example.com/tool", "1.4.0"),
                                     ("Go", "golang.org/x/net", "0.17.0"), ("Go", "github.com/fork/lib", "1.0.1")})
        self.assertEqual({p.meta["main"] for p in pkgs}, {"example.com/tool/cmd/tool"})
        self.assertEqual(globaltools.go_binary_packages(write(self.d / "bin" / "script.sh", "#!/bin/sh\n")), [])
        step = handfix.steps("Go", "golang.org/x/net", "0.17.0", "0.23.0", pkgs[2].to_dict())[0]
        self.assertEqual(step["cmd"], "go install example.com/tool/cmd/tool@latest")

    def test_gems(self):
        spec = self.d / "rbenv" / "versions" / "3.2.2" / "lib" / "ruby" / "gems" / "3.2.0" / "specifications"
        write(spec / "rack-2.2.3.gemspec")
        write(spec / "nokogiri-1.15.4-arm64-darwin.gemspec")
        write(spec / "default" / "json-2.6.3.gemspec")
        write(self.d / "rbenv" / "versions" / "3.2.2" / "bin" / "gem", "#!/bin/sh\n")
        with mock.patch.object(globaltools, "GEM_SPEC_DIRS", [str(self.d / "rbenv/versions/*/lib/ruby/gems/*/specifications")]):
            pkgs = globaltools.gems()
        self.assertEqual(got(pkgs), {("RubyGems", "rack", "2.2.3"), ("RubyGems", "nokogiri", "1.15.4"),
                                     ("RubyGems", "json", "2.6.3")})
        rack = next(p for p in pkgs if p.name == "rack").to_dict()
        cmd = handfix.commands("RubyGems", "rack", "2.2.3", "2.2.8", rack)[0]
        self.assertTrue(cmd.startswith(handfix._qp(str(self.d / "rbenv" / "versions" / "3.2.2" / "bin" / "gem"))), cmd)
        self.assertIn(" install rack -v 2.2.8 && ", cmd)

    def test_quoting_follows_the_shell(self):
        with mock.patch.object(handfix.os, "name", "nt"):
            self.assertEqual(handfix._q(r"C:\Ruby33\bin\gem.cmd"), r"C:\Ruby33\bin\gem.cmd")
            self.assertEqual(handfix._q(r"C:\Program Files\Ruby\gem"), r'"C:\Program Files\Ruby\gem"')
        with mock.patch.object(handfix.os, "name", "posix"):
            self.assertEqual(handfix._q("/opt/my ruby/gem"), "'/opt/my ruby/gem'")

    def test_dotnet_tools_nuget_cache_corepack(self):
        tool = self.d / ".dotnet" / "tools" / ".store" / "dotnet-ef" / "7.0.0" / "dotnet-ef" / "7.0.0"
        write(tool / "dotnet-ef.nuspec", "<package><metadata><id>dotnet-ef</id></metadata></package>")
        cache = self.d / "nuget"
        write(cache / "newtonsoft.json" / "12.0.1" / "newtonsoft.json.12.0.1.nupkg", "x")
        write(cache / "newtonsoft.json" / "12.0.1" / "newtonsoft.json.nuspec", "<id>Newtonsoft.Json</id>")
        write(cache / "half" / "1.0.0" / "half.nuspec", "<id>Half</id>")  # not fully extracted
        write(self.d / ".cache" / "node" / "corepack" / "v1" / "pnpm" / "8.6.0" / "package.json", "{}")
        with mock.patch.object(globaltools, "HOME", str(self.d)), mock.patch.dict(os.environ, {"NUGET_PACKAGES": str(cache)}), \
                mock.patch.object(globaltools, "COREPACK_ROOTS", [str(self.d / ".cache/node/corepack")]):
            self.assertEqual(got(globaltools.dotnet_tools()), {("NuGet", "dotnet-ef", "7.0.0")})
            self.assertEqual(got(globaltools.nuget_cache()), {("NuGet", "Newtonsoft.Json", "12.0.1")})
            self.assertEqual(got(globaltools.corepack()), {("npm", "pnpm", "8.6.0")})

    def test_composer_global(self):
        home = self.d / ".composer"
        write(home / "composer.lock", '{"packages": [{"name": "laravel/installer", "version": "v4.5.0", "require": {}}]}')
        write(home / "composer.json", '{"require": {"laravel/installer": "^4.5"}}')
        from scs.collectors import Context
        from scs.config import Config
        with mock.patch.dict(os.environ, {"COMPOSER_HOME": str(home)}):
            pkgs = globaltools.composer_global(Context(Config()))
        self.assertEqual(got(pkgs), {("Packagist", "laravel/installer", "4.5.0")})
        self.assertEqual(pkgs[0].meta["project"], str(home))  # the plan runs composer update there

    def test_coursier_cache(self):
        repo = self.d / "Coursier" / "v1" / "https" / "repo1.maven.org" / "maven2"
        write(repo / "org" / "typelevel" / "cats-core_3" / "2.9.0" / "cats-core_3-2.9.0.jar", "x")
        with mock.patch.dict(os.environ, {"COURSIER_CACHE": str(self.d / "Coursier" / "v1")}):
            self.assertIn(repo, java.coursier_repos())
            pkgs = [p for r in java.coursier_repos() for p in java.maven_cache(r)]
        self.assertEqual(got(pkgs), {("Maven", "org.typelevel:cats-core_3", "2.9.0")})


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def scan(self, runtime, *rel, **kw):
        return runtimes._scan(runtime, [str(self.d / r) for r in rel], **kw)

    def test_versions_from_folders_and_files(self):
        for rel in ("Cellar/php/8.3.12_1", "Cellar/php@8.1/8.1.30", ".rbenv/versions/3.2.2", ".rvm/rubies/ruby-3.1.4",
                    "dotnet/shared/Microsoft.NETCore.App/8.0.10", ".gradle/wrapper/dists/gradle-8.13-bin/abc/gradle-8.13",
                    ".asdf/installs/elixir/1.17.3-otp-27", ".julia/juliaup/julia-1.10.4+0.aarch64.apple.darwin14"):
            (self.d / rel).mkdir(parents=True)
        write(self.d / ".rustup" / "toolchains" / "stable-aarch64-apple-darwin" / "lib" / "rustlib" /
              "multirust-channel-manifest.toml", '[pkg.cargo]\nversion = "1.79.0 (x)"\n[pkg.rustc]\nversion = "1.80.1 (3f5fd8dd4 2024-08-06)"\n')
        self.assertEqual({p.version for p in self.scan("php", "Cellar/php*/*")}, {"8.3.12", "8.1.30"})
        self.assertEqual({p.version for p in self.scan("ruby", ".rbenv/versions/*", ".rvm/rubies/ruby-*")}, {"3.2.2", "3.1.4"})
        self.assertEqual([p.version for p in self.scan("dotnet", "dotnet/shared/Microsoft.NETCore.App/[0-9]*")], ["8.0.10"])
        self.assertEqual([p.version for p in self.scan("gradle", ".gradle/wrapper/dists/gradle-*/*/gradle-*")], ["8.13"])
        self.assertEqual([p.version for p in self.scan("elixir", ".asdf/installs/elixir/*")], ["1.17.3"])
        self.assertEqual([p.version for p in self.scan("julia", ".julia/juliaup/julia-*")], ["1.10.4"])
        rust = self.scan("rust", ".rustup/toolchains/*", from_name=False, version_file=runtimes._rustup_version)
        self.assertEqual([p.version for p in rust], ["1.80.1"])
        self.assertEqual(rust[0].meta["manager"], "rustup")
        self.assertEqual(self.scan("php", ".rbenv/versions/*", from_name=False), [])  # no version anywhere: skipped

    def test_release_lines_and_advisories(self):
        dotnet = [{"cycle": "10", "eol": "2028-11-14", "latest": "10.0.13", "lts": True},
                  {"cycle": "8", "eol": "2026-11-10", "latest": "8.0.32", "lts": True},
                  {"cycle": "7", "eol": "2024-05-14", "latest": "7.0.20", "lts": False}]
        p = runtimes._runtime("dotnet", "8.0.10", "/x", "installer", "dotnet", "8.0.10")
        a = rt_enrich.advisories_for(p, dotnet, today="2026-10-28")
        self.assertEqual((a[0].id, a[0].fixed), ("UPDATE-dotnet-8.0.32", ["8.0.32"]))
        old = runtimes._runtime("dotnet", "7.0.5", "/x", "installer", "dotnet", "7.0.5")
        self.assertEqual(rt_enrich.advisories_for(old, dotnet, today="2026-10-28")[0].id, "EOL-dotnet-7")
        gradle = [{"cycle": "9", "eol": False, "latest": "9.8.2"}, {"cycle": "7", "eol": "2025-07-31", "latest": "7.6.6"}]
        g = runtimes._runtime("gradle", "7.6.1", "/x", "Gradle wrapper", "gradle", "7.6.1")
        adv = rt_enrich.advisories_for(g, gradle, today="2026-10-28")
        self.assertEqual((adv[0].id, adv[0].fixed), ("EOL-gradle-7", ["9.8.2"]))
        steps = handfix.steps("Runtime", "gradle", "7.6.1", "9.8.2", g.to_dict())
        self.assertIn("./gradlew wrapper --gradle-version 9.8.2", [s["cmd"] for s in steps])
        self.assertIn("no longer gets security fixes", steps[0]["text"])
        newer = runtimes._runtime("gradle", "9.1.0", "/x", "Gradle wrapper", "gradle", "9.1.0")
        self.assertEqual(rt_enrich.advisories_for(newer, gradle, today="2026-10-28"), [])  # behind, but supported

    def test_manager_specific_steps(self):
        rb = runtimes._runtime("ruby", "3.2.2", str(self.d / ".rbenv/versions/3.2.2"), "rbenv", "ruby", "3.2.2")
        self.assertEqual(handfix.commands("Runtime", "ruby", "3.2.2", "3.2.9", rb.to_dict()), ["rbenv install 3.2.9"])
        apple = runtimes._runtime("ruby", "2.6", "/System/Library/Frameworks/Ruby.framework/Versions/2.6", "macOS", "ruby",
                                  "2.6", vendor_managed=True, vendor="Apple")
        self.assertTrue(handfix.vendor_managed(apple.to_dict()))
        self.assertIn("brew install ruby", handfix.commands("Runtime", "ruby", "2.6", "3.3.13", apple.to_dict()))
        rust = runtimes._runtime("rust", "1.80.1", "/x", "rustup", "rust", "1.80.1")
        self.assertIn("rustup update stable", handfix.commands("Runtime", "rust", "1.80.1", "1.99.1", rust.to_dict()))


if __name__ == "__main__":
    unittest.main()
