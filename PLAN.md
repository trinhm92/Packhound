# scs — Packhound: Plan

## Principles
- **Read-only by default.** `scan` never changes the system. Patching is a separate, explicit step with a shown plan, dry-run default, snapshot and rollback.
- **Low-risk tool.** Core is Python 3.10+ standard library only. Optional extras (yara-python, ClamAV, GuardDog) are detected, never required.
- **Never execute what we scan.** Collectors read metadata from disk (dist-info, package.json, receipts) instead of starting interpreters, so a malicious `.pth`/install hook cannot run during a scan.
- **Beyond CVEs.** Known-malicious packages (OSV `MAL-*`), IOC packs for campaigns, heuristics.
- **Confidence on every finding.** Exact (lockfile/ecosystem match) vs. low (CPE/NVD match for Homebrew and apps).

## Pipeline
`Collect → Normalize (PURL) → Enrich → Analyze → Report → Triage → Patch → Verify`

| Stage | Output |
|---|---|
| Collect | Per-ecosystem plugins list installed packages, versions, location |
| Normalize | PURL ids, stored per scan in SQLite for diffing |
| Enrich | OSV (CVE/GHSA/MAL), CISA KEV, FIRST EPSS, NVD (opt-in, low confidence), IOC packs |
| Analyze | Dependency chain / blast radius, risk score, bucket |
| Report | Terminal, self-contained HTML, JSON |
| Triage | Respond now / Patch now / Verify first / Defer / Ignore (reason + expiry) |
| Patch | Per-item snapshot → upgrade → check → rollback on failure; sudo always prompted |
| Verify | Project build/test commands, app launch checks |

## Coverage
| Platform | System | Language / dev |
|---|---|---|
| macOS | Homebrew formulae + casks, /Applications | pip (all interpreters, venvs, conda, pipx), npm/pnpm/yarn/bun globals, cargo installs, go binaries, gems, VS Code extensions |
| Ubuntu | dpkg/apt, snap, flatpak | same |
| Windows | winget, choco, scoop, registry Uninstall keys | same |
| Projects | — | Lockfiles under configured roots: package-lock, yarn.lock, pnpm-lock, poetry.lock, uv.lock, Pipfile.lock, requirements*.txt, Cargo.lock, go.sum, Gemfile.lock, maven/gradle |

## Risk & buckets
- Score = severity (CVSS/advisory) × KEV boost × EPSS × exposure (runtime > dev, direct > transitive, global > project). Malicious/IOC ⇒ Critical.
- **Respond now:** malicious package or IOC hit → incident checklist.
- **Verify first:** fix crosses a toolchain constraint (`.python-version`, `requires-python`, `.nvmrc`, `engines`, `rust-toolchain.toml`, `go` directive, Xcode/SDK), is a runtime/compiler (python, node, openssl, llvm, gcc, jdk…), is pinned/held, is a major bump, or has many reverse deps.
- **Patch now:** fix available and none of the above.
- **Monitor:** no fix published yet.

## Malware scan (`scs malware`)
| Check | Method |
|---|---|
| Known-malicious packages | OSV `MAL-*`, OpenSSF malicious-packages, IOC packs (package@version, file paths, hashes, domains) |
| Install-time behaviour | Static rules over setup.py / postinstall / build.rs / .pth (optional GuardDog) |
| Signatures | YARA (YARA Forge, Elastic) over package dirs, Downloads, Applications; optional ClamAV |
| Integrity | pip RECORD hashes, npm lockfile integrity, `dpkg --verify`, brew bottle sha256, codesign/spctl, Authenticode |
| Persistence | LaunchAgents/Daemons, login items, cron, systemd, Run keys, scheduled tasks, shell rc, git hooks, editor/browser extensions, unexpected `.github/workflows` |
| Hash reputation (opt-in) | MalwareBazaar / VirusTotal — hashes only, never files |
| Exposure | Lists credential *locations* (never values) to rotate after a hit |

Response: quarantine (move + manifest, restorable — never delete), remove persistence, reinstall from clean lockfile, rotate credentials, sweep other hosts for the same IOCs.

Limits: not an EDR / real-time protection; novel, well-obfuscated malware with no IOC or rule can still pass.

## Phases
| Phase | Scope |
|---|---|
| **1 – MVP (macOS)** ✅ | CLI, collectors (brew, pip, npm globals, cargo, lockfiles), OSV + KEV + EPSS (+ opt-in NVD), IOC packs + MAL matching, terminal/HTML/JSON report, scan history & "new since last scan" |
| **2** ✅ | Full dependency chains, toolchain constraints, interactive triage, policy/ignore file, dry-run patch plan |
| **3** ✅ | Malware scan: behaviour rules, YARA, integrity/signatures, persistence audit, exposure, quarantine |
| **4** ✅ | Patch execution with snapshot/rollback, verify runner |
| **5** ✅ | Ubuntu (dpkg/snap/USN, `dpkg --verify`, systemd persistence) |
| **6** ✅ | Windows (winget/choco/scoop/registry, Authenticode, Run keys), multi-host merged report |
| **7** ✅ | Hash reputation, scheduled scans, alerts on new findings |
