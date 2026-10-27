#!/usr/bin/env bash
# Build "Packhound.app" and a .dmg.
# Optional signing/notarization (needs an Apple Developer account):
#   CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#   NOTARY_PROFILE=<name created with `xcrun notarytool store-credentials`>
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
BUILD="$ROOT/build/macos"
NAME="Packhound"
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' scs/__init__.py)

# Universal2 (Intel + Apple Silicon) by default; needs a universal2 interpreter such as python.org's.
ARCH="${SCS_TARGET_ARCH:-universal2}"
PY="${PYTHON:-/Library/Frameworks/Python.framework/Versions/3.13/bin/python3}"
[ -x "$PY" ] || { echo "error: $PY not found. Install Python 3.13 from python.org (universal2) or set PYTHON=..." >&2; exit 1; }
PY_ARCHS=$(lipo -archs "$("$PY" -c 'import sys,os;print(os.path.realpath(sys.executable))')")
if [ "$ARCH" = "universal2" ] && ! { [[ "$PY_ARCHS" == *x86_64* ]] && [[ "$PY_ARCHS" == *arm64* ]]; }; then
  echo "error: $PY is '$PY_ARCHS', not universal2. Use python.org's macOS installer, or SCS_TARGET_ARCH=arm64|x86_64." >&2
  exit 1
fi
export SCS_TARGET_ARCH="$ARCH"
echo "== building $ARCH with $PY ($PY_ARCHS)"

rm -rf "$BUILD" && mkdir -p "$BUILD"
"$PY" -m venv "$BUILD/venv"
VPY="$BUILD/venv/bin/python"
# Hash-locked: pip may install only the exact files recorded in packaging/locks (made by
# packaging/lock_build_deps.py with a release-age cooldown), and nothing else (--no-deps).
"$VPY" -m pip install --quiet --require-hashes --no-deps --only-binary=:all: -r packaging/locks/build-macos.txt
# source-only packages, built with the locked setuptools instead of one fetched for the build
"$VPY" -m pip install --quiet --require-hashes --no-deps --no-build-isolation -r packaging/locks/build-macos-sdist.txt
"$VPY" -m pip check
"$VPY" -m pip freeze > "$BUILD/build-requirements.lock.txt"   # record exactly what was bundled
echo "== checking the build environment (known-malicious/vulnerable packages, startup hooks)"
PYTHONPATH="$ROOT" "$PY" -m scs fixer build-check --python "$VPY" ${SCS_ALLOW_VULNERABLE:+--allow-vulnerable}

# app icon from the SVG, with built-in tools only (qlmanage renders SVG; iconutil makes the .icns)
ICONSET="$BUILD/scs.iconset" && mkdir -p "$ICONSET"
if qlmanage -t -s 1024 -o "$BUILD" scs/ui/static/icon.svg >/dev/null 2>&1 && [ -f "$BUILD/icon.svg.png" ]; then
  for sz in 16 32 128 256 512; do
    sips -z $sz $sz "$BUILD/icon.svg.png" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null
    sips -z $((sz*2)) $((sz*2)) "$BUILD/icon.svg.png" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$BUILD/scs.icns" && export SCS_ICON_MAC="$BUILD/scs.icns"
fi

"$BUILD/venv/bin/pyinstaller" --noconfirm --clean --distpath "$BUILD/dist" --workpath "$BUILD/work" packaging/scs-gui.spec
APP="$BUILD/dist/$NAME.app"

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  echo "== signing"
  codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
fi

echo "== architectures in the bundle"
BIN="$APP/Contents/MacOS/$NAME"
echo "main executable: $(lipo -archs "$BIN")"
# every Mach-O file must contain both slices, or the app crashes on one of the two CPU types
BAD=0
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q "Mach-O"; then
    a=$(lipo -archs "$f" 2>/dev/null || echo "?")
    if [ "$ARCH" = "universal2" ] && ! { [[ "$a" == *x86_64* ]] && [[ "$a" == *arm64* ]]; }; then
      echo "  single-arch: ${f#$APP/} ($a)"; BAD=1
    fi
  fi
done < <(find "$APP/Contents" -type f -print0)
[ "$BAD" = 0 ] || { echo "error: some binaries are not universal2 (see above)" >&2; exit 1; }
echo "all Mach-O files contain: $ARCH"

DMG="$BUILD/Packhound-$VERSION-$ARCH.dmg"
echo "== creating $DMG"
STAGE="$BUILD/dmg" && rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/" && ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --sign "$CODESIGN_IDENTITY" --timestamp "$DMG"
fi
if [ -n "${NOTARY_PROFILE:-}" ]; then
  echo "== notarizing (this takes a few minutes)"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG"
fi

shasum -a 256 "$DMG" | tee "$DMG.sha256"

# Optional: sign the checksum with an SSH key (SCS_SIGN_KEY=~/.ssh/id_ed25519), so users can check the
# download against a public key published somewhere other than the download page:
#   ssh-keygen -Y verify -f allowed_signers -I <you> -n scs-release -s FILE.sha256.sig < FILE.sha256
if [ -n "${SCS_SIGN_KEY:-}" ]; then
  ssh-keygen -Y sign -f "$SCS_SIGN_KEY" -n scs-release "$DMG.sha256" && echo "signed: $DMG.sha256.sig"
fi
echo "built: $APP"
echo "       $DMG"
[ -z "${CODESIGN_IDENTITY:-}" ] && echo "note: not notarized — on first launch macOS blocks it; users open System Settings › Privacy & Security › \"Open Anyway\" (macOS 15+), or right-click › Open on older macOS."
exit 0
