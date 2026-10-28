import tempfile
import unittest
from pathlib import Path

from scs.collectors import lockfiles, pub
from scs.enrich.osv import affects


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def got(pkgs) -> set:
    return {(p.ecosystem, p.name, p.version) for p in pkgs}


class MobileTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def parse(self, name: str, text: str, sub: str = ""):
        path = write(self.d / sub / name, text)
        return lockfiles.parser_for(name, path.parent)(path)[0]

    def test_pubspec_lock(self):
        pkgs = self.parse("pubspec.lock", """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "0.12.0"
  mocktail:
    dependency: "direct dev"
    source: hosted
    version: "1.0.4"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  mylib:
    dependency: "direct main"
    description:
      path: "../mylib"
    source: path
    version: "1.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
""")
        self.assertEqual(got(pkgs), {("Pub", "http", "0.12.0"), ("Pub", "mocktail", "1.0.4")})
        self.assertTrue(next(p for p in pkgs if p.name == "mocktail").dev)

    def test_swift_package_resolved_v1_and_v2(self):
        v2 = self.parse("Package.resolved", '{"pins": [{"identity": "swift-nio", "kind": "remoteSourceControl", '
                        '"location": "https://github.com/apple/swift-nio.git", "state": {"revision": "x", "version": "2.29.0"}},'
                        '{"identity": "local", "kind": "localSourceControl", "location": "/tmp/x", "state": {"version": "1.0.0"}}],'
                        '"version": 2}')
        self.assertEqual(got(v2), {("SwiftURL", "github.com/apple/swift-nio", "2.29.0")})
        v1 = self.parse("Package.resolved", '{"object": {"pins": [{"package": "Alamofire", "repositoryURL": '
                        '"git@github.com:Alamofire/Alamofire.git", "state": {"version": "5.4.0"}}]}, "version": 1}', "v1")
        self.assertEqual(got(v1), {("SwiftURL", "github.com/Alamofire/Alamofire", "5.4.0")})

    def test_podfile_and_cartfile(self):
        pods = self.parse("Podfile.lock", """PODS:
  - Firebase/Core (10.20.0):
    - FirebaseCore (= 10.20.0)
  - Firebase/Messaging (10.20.0)
  - Flutter (1.0.0)
  - "GoogleUtilities/Environment (7.12.0)"

DEPENDENCIES:
  - Firebase/Core
  - Flutter (from `Flutter`)

EXTERNAL SOURCES:
  Flutter:
    :path: Flutter
""")
        self.assertEqual(got(pods), {("CocoaPods", "Firebase", "10.20.0"), ("CocoaPods", "GoogleUtilities", "7.12.0")})
        carts = self.parse("Cartfile.resolved", 'github "ReactiveX/RxSwift" "6.5.0"\nbinary "https://x/y.json" "1.0"\n'
                           'git "https://gitlab.com/a/b.git" "v2.1.0"\n')
        self.assertEqual(got(carts), {("SwiftURL", "github.com/ReactiveX/RxSwift", "6.5.0"),
                                      ("SwiftURL", "gitlab.com/a/b", "2.1.0")})

    def test_gradle_build_scripts(self):
        write(self.d / "gradle.properties", "okhttpVersion=4.9.0\n")
        pkgs = self.parse("build.gradle.kts", """plugins {
    id("com.android.application") version "8.1.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.0"
}
val retrofit = "2.9.0"
dependencies {
    implementation("com.squareup.retrofit2:retrofit:$retrofit")
    implementation("com.squareup.okhttp3:okhttp:${okhttpVersion}")
    testImplementation("junit:junit:4.13.2")
    // implementation("commented:out:1.0")
    implementation("com.example:dynamic:1.+")
    implementation(platform("com.google.firebase:firebase-bom:32.0.0"))
}
""", "app")
        self.assertEqual(got(pkgs), {("Maven", "com.squareup.retrofit2:retrofit", "2.9.0"),
                                     ("Maven", "com.squareup.okhttp3:okhttp", "4.9.0"), ("Maven", "junit:junit", "4.13.2"),
                                     ("Maven", "com.google.firebase:firebase-bom", "32.0.0"),
                                     ("Maven", "com.android.tools.build:gradle", "8.1.0"),
                                     ("Maven", "org.jetbrains.kotlin:kotlin-gradle-plugin", "1.9.0")})
        self.assertTrue(next(p for p in pkgs if p.name == "junit:junit").dev)

    def test_pub_cache(self):
        for d in ("http-0.13.6", "path_provider_android-2.2.4", "not-a-package"):
            (self.d / "hosted" / "pub.dev" / d).mkdir(parents=True)
        pkgs = pub.cached_packages(self.d)
        self.assertEqual(got(pkgs), {("Pub", "http", "0.13.6"), ("Pub", "path_provider_android", "2.2.4")})
        self.assertEqual({p.source for p in pkgs}, {"pub-cache"})


class OtherEcosystemTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def parse(self, name: str, text: str):
        path = write(self.d / name, text)
        return lockfiles.parser_for(name, path.parent)(path)[0]

    def test_bun_and_deno(self):
        bun = self.parse("bun.lock", '{"lockfileVersion": 1, "workspaces": {"": {"dependencies": {"lodash": "^4"},},},'
                         '"packages": {"lodash": ["lodash@4.17.20", "", {}, "sha512-x"], "@scope/x": ["@scope/x@1.2.3", "", {}, "s"],},}')
        self.assertEqual(got(bun), {("npm", "lodash", "4.17.20"), ("npm", "@scope/x", "1.2.3")})
        self.assertTrue(next(p for p in bun if p.name == "lodash").direct)
        deno = self.parse("deno.lock", '{"version": "4", "npm": {"chalk@5.3.0": {}, "@types/node@20.1.0_x@1": {}}, '
                          '"jsr": {"@std/path@1.0.0": {}}}')
        self.assertEqual(got(deno), {("npm", "chalk", "5.3.0"), ("npm", "@types/node", "20.1.0")})

    def test_mix_renv_conan(self):
        mix = self.parse("mix.lock", '%{\n  "plug": {:hex, :plug, "1.14.0", "abc", [:mix], [], "hexpm", "def"},\n'
                         '  "local": {:git, "https://x", "abc", []},\n}\n')
        self.assertEqual(got(mix), {("Hex", "plug", "1.14.0")})
        renv = self.parse("renv.lock", '{"Packages": {"readxl": {"Package": "readxl", "Version": "1.3.1", '
                          '"Source": "Repository", "Repository": "CRAN"}, "dev": {"Package": "dev", "Version": "0.1", "Source": "GitHub"}}}')
        self.assertEqual(got(renv), {("CRAN", "readxl", "1.3.1")})
        conan = self.parse("conan.lock", '{"version": "0.5", "requires": ["zlib/1.2.13#abc%1", "openssl/3.0.8"], '
                           '"build_requires": ["cmake/3.27.0"]}')
        self.assertEqual(got(conan), {("ConanCenter", "zlib", "1.2.13"), ("ConanCenter", "openssl", "3.0.8"),
                                      ("ConanCenter", "cmake", "3.27.0")})

    def test_msbuild(self):
        csproj = self.parse("App.csproj", '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                            '<PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>'
                            '<PackageReference Include="Floating" Version="1.*" /></ItemGroup></Project>')
        self.assertEqual(got(csproj), {("NuGet", "Newtonsoft.Json", "12.0.1"), ("NuGet", "Serilog", "2.10.0")})
        props = self.parse("Directory.Packages.props", '<Project><ItemGroup><PackageVersion Include="xunit" Version="2.4.1" />'
                           '</ItemGroup></Project>')
        self.assertEqual(got(props), {("NuGet", "xunit", "2.4.1")})

    def test_github_actions(self):
        wf = write(self.d / "repo" / ".github" / "workflows" / "ci.yml", """jobs:
  b:
    steps:
      - uses: tj-actions/changed-files@v45.0.7
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: docker/login-action@main
      - uses: github/codeql-action/init@v3
      - uses: ./local
""")
        self.assertIs(lockfiles.parser_for("ci.yml", wf.parent), lockfiles.parse_workflow)
        self.assertIsNone(lockfiles.parser_for("ci.yml", self.d))
        pkgs, _ = lockfiles.parse_workflow(wf)
        self.assertEqual(got(pkgs), {("GitHub Actions", "tj-actions/changed-files", "45.0.7"),
                                     ("GitHub Actions", "actions/checkout", "4.2.2"),
                                     ("GitHub Actions", "github/codeql-action", "3")})
        self.assertEqual(pkgs[0].meta["project"], str(self.d / "repo"))

    def test_client_side_ranges(self):
        vuln = {"affected": [{"package": {"ecosystem": "GitHub Actions", "name": "tj-actions/changed-files"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "46.0.1"}]}]},
                             {"package": {"ecosystem": "GitHub Actions", "name": "x/y"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1"}, {"fixed": "2"},
                                                                           {"introduced": "3"}, {"last_affected": "3.5"}]}]}]}
        self.assertTrue(affects(vuln, "GitHub Actions", "tj-actions/changed-files", "45.0.7"))
        self.assertFalse(affects(vuln, "GitHub Actions", "tj-actions/changed-files", "46.0.1"))
        self.assertEqual([affects(vuln, "GitHub Actions", "x/y", v) for v in ("0.5", "1.5", "2.5", "3.5", "3.6")],
                         [False, True, False, True, False])


class DiscoveryTests(unittest.TestCase):
    def test_new_files_are_found_and_pods_folder_skipped(self):
        from scs.collectors import Context
        from scs.config import Config
        d = Path(tempfile.mkdtemp())
        for rel in ("app/pubspec.lock", "app/ios/Podfile.lock", "app/ios/Pods/Manifest.lock", "app/android/app/build.gradle",
                    "app/ios/App.xcworkspace/xcshareddata/swiftpm/Package.resolved", "app/.github/workflows/ci.yml"):
            write(d / rel, "{}" if rel.endswith(".resolved") else "")
        ctx = Context(Config(roots=[str(d)]))
        lockfiles.discover(ctx)
        names = sorted(p.name for p in ctx.lockfiles)
        self.assertEqual(names, ["Package.resolved", "Podfile.lock", "build.gradle", "ci.yml", "pubspec.lock"])
        self.assertTrue(any(p.as_posix().endswith("app/.github/workflows/ci.yml") for p in ctx.build_files))


if __name__ == "__main__":
    unittest.main()
