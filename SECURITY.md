# Security policy

Packhound runs package managers with administrator rights and decides what is safe on a developer machine, so a flaw in it matters. Thank you for helping keep it trustworthy.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub instead:
[**Report a vulnerability**](https://github.com/trinhm92/Packhound/security/advisories/new) (Security tab › *Report a vulnerability*).

Include what you can of:
- the affected version (`packhound --version`) and platform;
- what an attacker can do, and what they need first (a malicious package on the machine, a crafted lockfile, network position…);
- steps or a proof of concept.

What to expect:
- an acknowledgement within **3 working days**;
- an assessment and a planned fix date within **10 working days**;
- a fixed release and a published GitHub security advisory, crediting you unless you prefer otherwise.

## In scope

- Code execution, privilege escalation or file writes triggered by data Packhound reads (lockfiles, package metadata, scan results, advisory data).
- The local desktop app's server: anything that lets another site or local user call its API, bypass the token, or inject script.
- The fixer and patch engine: changes outside what the plan showed, broken rollback, or a cooldown bypass that installs a too-new release.
- Missing or wrong detection of a **known-malicious** package or IOC that Packhound claims to cover.
- The release pipeline: anything that lets a published installer differ from this repository's code.

Out of scope: findings that only repeat an upstream advisory's data (report those to [OSV.dev](https://osv.dev) or the advisory source), and attacks that already need administrator access to the machine.

## Supported versions

Security fixes go into the latest release. Please update before reporting.

| Version | Supported |
|---|---|
| latest 0.x release | ✅ |
| older releases | ❌ |

## Verifying a download

Every release is built by GitHub Actions from a tagged commit, with hash-locked build dependencies.

The installers are **not code-signed** (no Apple Developer ID or Windows Authenticode certificate yet), so macOS and Windows warn on first launch. That makes the two checks below the way to know a download is genuine. Each installer comes with:

1. **Checksums.** Download `SHA256SUMS` from the same release, then:
   ```bash
   shasum -a 256 -c SHA256SUMS --ignore-missing     # macOS
   sha256sum -c SHA256SUMS --ignore-missing         # Linux
   ```
   On Windows (PowerShell): `Get-FileHash .\Packhound-*-setup.exe` and compare with the line in `SHA256SUMS`.
2. **Build provenance.** A signed attestation (Sigstore) proves the file was built by this repository's CI workflow, from which commit:
   ```bash
   gh attestation verify Packhound-0.2.0-universal2.dmg --repo trinhm92/Packhound
   ```
   You can also see the attestations on the repository's [Attestations page](https://github.com/trinhm92/Packhound/attestations).

If either check fails, don't install the file, and please report it as above.

## How Packhound protects itself

The safeguards against attacks on Packhound itself (release-age cooldown, hash-locked builds, build-environment checks, self-check of the installed app) are described in the README under [Security of scs itself](README.md#security-of-scs-itself).
