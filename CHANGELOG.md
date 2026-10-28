# Changelog

## 0.2.0

**Malware check that acts.** Every finding now comes with a fix you confirm, a backup and an Undo:
disable a start-up item, remove a malicious line from a shell file or crontab, remove an unknown SSH key,
restore a tampered file from git, replace a tampered Gradle or Maven wrapper with a verified official one,
add the Gradle download checksum, pin GitHub Actions to commits, reinstall a tampered Python package or
`node_modules`, or quarantine files, extensions and apps. Changes that need administrator rights come with
copy-paste steps.

**Many more languages and tools**, read from what is already installed (nothing is installed to scan):
- Android (Gradle build scripts and plugins), iOS/macOS (Swift Package Manager, Carthage, CocoaPods inventory),
  Flutter/Dart, React Native, Bun, Deno, Elixir/Erlang, Haskell, Julia, OCaml, R, C/C++ (Conan), .NET project
  files and Paket, Python PDM and pylock.toml, and the GitHub Actions your workflows use.
- Tools installed globally: Ruby gems of every Ruby, Go programs (the modules and Go version inside each
  binary), .NET global tools, Composer global packages, Corepack's pnpm/yarn.
- Download caches: Maven, Gradle, Coursier (sbt/Scala), pub (Flutter) and NuGet.
- Runtimes and build tools, checked for end of life and missed security updates: JDK, Node.js, Python, Go,
  PHP, Ruby, .NET, Erlang, Elixir, Rust, Deno, Bun, Perl, GHC, Julia, Gradle, Maven, Bazel.
- git, curl and OpenSSH bundled with macOS or Windows.
- Build-chain integrity: Gradle/Maven wrapper jars against published checksums, unpinned or risky CI.

**Also**
- `packhound` command (`scs` still works); `pipx install git+https://github.com/trinhm92/Packhound.git`.
- Signed build provenance for every release file: `gh attestation verify <file> --repo trinhm92/Packhound`.
- Fix-it-yourself steps for everything Packhound can't change itself ("No automatic fix"), quoted for your shell.
- Windows fixes found by the first CI runs on Windows.

The installers are not code-signed: see [verifying a download](SECURITY.md#verifying-a-download).

## 0.1.0

First public version: vulnerability and malicious-package scanning for macOS, Ubuntu and Windows, a desktop
app, safe fixes with snapshot and rollback, malware/persistence checks, scheduled monitoring and a merged
report for several machines.
