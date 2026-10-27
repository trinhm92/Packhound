#!/usr/bin/env bash
# Build a .deb for Ubuntu/Debian: scs installed under /opt/scs, run by the system Python 3.10+,
# with a desktop entry. The native window uses the distro's GTK WebKit + pywebview when present;
# otherwise the app opens in the default browser (same UI). No Python packages are bundled.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=$(python3 -c "import scs; print(scs.__version__)")
PKG="$ROOT/build/linux/scs_${VERSION}_all"
rm -rf "$PKG" && mkdir -p "$PKG/DEBIAN" "$PKG/opt/scs" "$PKG/usr/bin" "$PKG/usr/share/applications" \
  "$PKG/usr/share/icons/hicolor/scalable/apps"

cp -R scs "$PKG/opt/scs/"
find "$PKG/opt/scs" -name __pycache__ -prune -exec rm -rf {} +
cp README.md PLAN.md "$PKG/opt/scs/"
cp scs/ui/static/icon.svg "$PKG/usr/share/icons/hicolor/scalable/apps/scs.svg"

cat > "$PKG/usr/bin/scs" <<'EOS'
#!/bin/sh
PYTHONPATH=/opt/scs exec python3 -m scs "$@"
EOS
cat > "$PKG/usr/bin/scs-gui" <<'EOS'
#!/bin/sh
PYTHONPATH=/opt/scs exec python3 -c 'from scs.ui.app import main_gui; main_gui()'
EOS
chmod 755 "$PKG/usr/bin/scs" "$PKG/usr/bin/scs-gui"

cat > "$PKG/usr/share/applications/scs.desktop" <<EOS
[Desktop Entry]
Type=Application
Name=Packhound
GenericName=Supply chain security scanner
Comment=Find vulnerable and malicious software on this computer
Exec=scs-gui
Icon=scs
Terminal=false
Categories=System;Security;
EOS

cat > "$PKG/DEBIAN/control" <<EOS
Package: scs
Version: $VERSION
Architecture: all
Maintainer: Packhound <noreply@example.com>
Depends: python3 (>= 3.10)
Recommends: python3-gi, gir1.2-webkit2-4.1, zenity
Suggests: yara, clamav
Section: utils
Priority: optional
Description: Packhound, a supply chain security scanner with a desktop UI
 Inventories installed packages and projects, finds known-vulnerable and
 malicious packages, checks for persistence and tampering, and applies fixes
 with snapshot and automatic rollback.
EOS

# checksums of every installed file: `dpkg --verify scs` (and `scs self-check`) detect later changes
(cd "$PKG" && find opt usr -type f | LC_ALL=C sort | while IFS= read -r f; do md5sum "$f"; done) > "$PKG/DEBIAN/md5sums"
dpkg-deb --build --root-owner-group "$PKG" >/dev/null
sha256sum "$PKG.deb" | tee "$PKG.deb.sha256"

# Optional: sign the checksum with an SSH key (SCS_SIGN_KEY=~/.ssh/id_ed25519), so users can check the
# download against a public key published somewhere other than the download page:
#   ssh-keygen -Y verify -f allowed_signers -I <you> -n scs-release -s FILE.sha256.sig < FILE.sha256
if [ -n "${SCS_SIGN_KEY:-}" ]; then
  ssh-keygen -Y sign -f "$SCS_SIGN_KEY" -n scs-release "$PKG.deb.sha256" && echo "signed: $PKG.deb.sha256.sig"
fi
echo "built: $PKG.deb"
echo "install: sudo apt install ./$(basename "$PKG").deb"
echo "native window (optional): pip install --user pywebview==6.2.1   # uses the GTK WebKit from Recommends"
