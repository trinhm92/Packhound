#!/usr/bin/env bash
# Regenerate packaging/icon.ico (Windows app + installer icon) from the SVG icons. Needs macOS
# (qlmanage renders SVG, sips resizes). 16-48 px use the bold small-size artwork, 64-256 px the
# detailed one; both full-bleed, as Windows icons usually are. Commit the result.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
sed 's|viewBox="0 0 1024 1024"|viewBox="100 100 824 824"|' scs/ui/static/icon.svg > "$TMP/large.svg"
cp scs/ui/static/icon-small.svg "$TMP/small.svg"
for f in small large; do qlmanage -t -s 1024 -o "$TMP" "$TMP/$f.svg" >/dev/null 2>&1; done
for sz in 16 24 32 48; do sips -z $sz $sz "$TMP/small.svg.png" --out "$TMP/$sz.png" >/dev/null; done
for sz in 64 128 256; do sips -z $sz $sz "$TMP/large.svg.png" --out "$TMP/$sz.png" >/dev/null; done
python3 - "$TMP" packaging/icon.ico <<'EOF'
import struct, sys
from pathlib import Path
tmp, out = Path(sys.argv[1]), Path(sys.argv[2])
sizes = [16, 24, 32, 48, 64, 128, 256]
pngs = [(tmp / f"{s}.png").read_bytes() for s in sizes]  # ICO entries may hold PNG data (Vista+)
head = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries = b""
for s, data in zip(sizes, pngs):
    entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
out.write_bytes(head + entries + b"".join(pngs))
print(f"wrote {out} ({', '.join(map(str, sizes))} px)")
EOF
