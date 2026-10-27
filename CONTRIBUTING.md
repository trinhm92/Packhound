# Contributing to Packhound

Thanks for helping! Bug reports, false positives, new ecosystems and documentation fixes are all welcome.

**Security problems:** please report them privately, as described in [SECURITY.md](SECURITY.md), not in an issue.

## Ground rules

These keep a security tool trustworthy. Pull requests that break them can't be merged:

- **Standard library only.** The engine (`scs/`) imports nothing outside Python's standard library. The desktop window's `pywebview` is the one optional extra, and only for the app.
- **Never run what is being scanned.** Collectors read metadata files; they don't import packages or start interpreters that would load them (`.pth` files, install hooks). The few allowed version calls are listed in the README.
- **Read before you change.** `scan` and `malware` never modify the system. Anything that changes a machine goes through `plan` → `patch`, with a snapshot, verification and rollback.
- **Send as little as possible.** Network lookups send package names and versions, or file hashes when the user opts in; never paths, file contents or credentials.
- **Plain language in the app.** Text for the desktop app is written for non-specialists: say what happened and what to do.

## Development setup

You need Python 3.10 or newer and git. Nothing else to install for the engine and tests.

```bash
git clone https://github.com/trinhm92/Packhound.git
cd Packhound
python3 -m unittest discover -s tests       # all tests; no network access needed
python3 -m packhound scan --root ~/code     # try it on your machine (read-only)
python3 -m packhound ui --browser           # the app in your browser
```

Optional: `pip install -r requirements-gui.txt` for the native app window. Installer builds are described in the README under "Building installers".

## Making a change

1. **Open an issue first** for anything bigger than a small fix, so we can agree on the approach.
2. **Branch from `main`.** `main` is protected: every change goes through a pull request with passing CI.
3. **Add tests.** Tests live in `tests/` and must run offline: mock network calls (`scs.util.http_json`, `osv.lookup`) and build fixtures in temporary folders. CI runs them on macOS, Ubuntu and Windows with Python 3.10 and 3.13, so keep paths and quoting OS-neutral.
4. **Match the surrounding code:** same naming, comment density and style. Keep functions small and comments about *why*.
5. **Update the docs** (README, the app's wording) when behaviour changes.
6. **Write a clear commit message:** a short summary line, then what changed and why.

### Adding an ecosystem or collector

- A collector returns `Package` records (`scs/models.py`) and is registered in `scs/collectors/__init__.py`. Mark it `system=True` if it reads machine-wide installs.
- Use the [OSV ecosystem name](https://ossf.github.io/osv-schema/#affectedpackage-field) when one exists, so advisories match without extra code.
- If Packhound can't fix it automatically, give the hand steps in `scs/handfix.py` so the app shows them under *No automatic fix*.

### Screenshots

`python3 docs/screenshots/demo.py --shoot` regenerates the README screenshots from made-up demo data (it needs Google Chrome). Never take screenshots of a real machine: they show user names, paths and project names.

## Reporting a false positive or a missed finding

Use the **False positive / missed finding** issue template. Include the package, version and ecosystem, the advisory id, and where Packhound found it. Remove private paths and project names first.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the license of this project.
