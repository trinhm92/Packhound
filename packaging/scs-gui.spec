# PyInstaller spec for the Packhound desktop app (macOS .app / Windows .exe).
# Build with packaging/build_macos.sh or packaging/build_windows.ps1, not directly.
import os
import sys

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
NAME = "Packhound"
with open(os.path.join(SPECPATH, "..", "scs", "__init__.py"), encoding="utf-8") as _f:  # one version, set in scs/__init__.py
    VERSION = next(line.split('"')[1] for line in _f if line.startswith("__version__"))
ICON_MAC = os.environ.get("SCS_ICON_MAC") or os.path.join(SPECPATH, "icon.icns")
ICON_WIN = os.path.join(SPECPATH, "icon.ico")

datas = [
    (os.path.join(ROOT, "scs", "ui", "static"), os.path.join("scs", "ui", "static")),
    (os.path.join(ROOT, "scs", "iocs"), os.path.join("scs", "iocs")),
    (os.path.join(ROOT, "scs", "rules"), os.path.join("scs", "rules")),
]

a = Analysis(
    [os.path.join(SPECPATH, "scs_gui.py")],
    pathex=[ROOT],
    datas=datas,
    hiddenimports=["scs.cli", "scs.collectors.windows", "scs.collectors.dpkg", "scs.collectors.snap",
                   "scs.malware.windows_persistence", "scs.malware.reputation"],
    excludes=["tkinter", "unittest", "pydoc"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name=NAME,
    console=False,  # GUI app: no terminal window
    icon=ICON_WIN if sys.platform == "win32" and os.path.exists(ICON_WIN) else None,
    codesign_identity=os.environ.get("CODESIGN_IDENTITY") or None,
    # macOS: "universal2" (Intel + Apple Silicon in one app) needs a universal2 Python, e.g. python.org's installer
    target_arch=os.environ.get("SCS_TARGET_ARCH") or None,
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, name=NAME)

if sys.platform == "darwin":
    app = BUNDLE(
        coll, name=f"{NAME}.app", icon=ICON_MAC if os.path.exists(ICON_MAC) else None,
        bundle_identifier="io.github.trinhm92.packhound",
        info_plist={
            "CFBundleShortVersionString": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            "LSArchitecturePriority": ["arm64", "x86_64"],
            "NSHumanReadableCopyright": "Packhound",
        },
    )
