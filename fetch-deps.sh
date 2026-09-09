#!/usr/bin/env bash
# fetch-deps.sh — provision the vendored .deps tree for a target arch.
#
# Downloads the Ubuntu dev debs TkTox needs (tcl, tk, xft, sodium,
# opus, vpx, alsa), extracts them into .deps/<pkg>/usr/..., and patches the
# pkg-config files so the build resolves against the vendored tree.
#
# Usage:
#   bash fetch-deps.sh [arch] [triplet]
#     arch    arm64 (default) | amd64 | riscv64
#     triplet aarch64-linux-gnu (default) | x86_64-linux-gnu | riscv64-linux-gnu
#
# The mirror is chosen by arch: arm64/riscv64 use ports.ubuntu.com
# (ubuntu-ports), amd64 uses archive.ubuntu.com (ubuntu). The triplet is
# derived from arch if not given.
set -eu

ARCH="${1:-arm64}"
TRIPLET="${2:-}"

case "$ARCH" in
    arm64)   TRIPLET="${TRIPLET:-aarch64-linux-gnu}"; MIRROR="http://ports.ubuntu.com/ubuntu-ports" ;;
    amd64)   TRIPLET="${TRIPLET:-x86_64-linux-gnu}";  MIRROR="http://archive.ubuntu.com/ubuntu" ;;
    riscv64) TRIPLET="${TRIPLET:-riscv64-linux-gnu}"; MIRROR="http://ports.ubuntu.com/ubuntu-ports" ;;
    *) echo "unsupported arch: $ARCH (use arm64|amd64|riscv64)" >&2; exit 1 ;;
esac

ROOT=$(cd "$(dirname "$0")" && pwd)
DEPS="$ROOT/vendor/.deps"
mkdir -p "$DEPS"
cd "$DEPS"

# Package -> deb name (version pinned to what the current tree uses).
# libsodium-dev is a plain download (no version in the filename).
declare -A DEBS=(
  [tcl8.6]="tcl8.6_8.6.18+dfsg-1_${ARCH}.deb"
  [tcl8.6-dev]="tcl8.6-dev_8.6.18+dfsg-1_${ARCH}.deb"
  [libtcl8.6]="libtcl8.6_8.6.18+dfsg-1_${ARCH}.deb"
  [tk8.6]="tk8.6_8.6.18-1_${ARCH}.deb"
  [tk8.6-dev]="tk8.6-dev_8.6.18-1_${ARCH}.deb"
  [libtk8.6]="libtk8.6_8.6.18-1_${ARCH}.deb"
  [libxft2]="libxft2_2.3.6-1build2_${ARCH}.deb"
  [libxft-dev]="libxft-dev_2.3.6-1build2_${ARCH}.deb"
  [libopus-dev]="libopus-dev_1.6.1-1_${ARCH}.deb"
  [libvpx-dev]="libvpx-dev_1.16.0-3_${ARCH}.deb"
  [libasound2-dev]="libasound2-dev_1.2.15.3-1ubuntu1.1_${ARCH}.deb"
)

# libsodium-dev has no arch in the filename; fetch the arch-specific one.
SODIUM_DEB="libsodium-dev.deb"
SODIUM_POOL="pool/main/libs/libsodium"

# Map deb -> extraction dir (the pkg name under .deps/).
declare -A DIR=(
  [tcl8.6]=tcl [tcl8.6-dev]=tcl [libtcl8.6]=tcl
  [tk8.6]=tk [tk8.6-dev]=tk [libtk8.6]=tk
  [libxft2]=xft [libxft-dev]=xft
  [libopus-dev]=opus
  [libvpx-dev]=vpx
  [libasound2-dev]=alsa
)

fetch() { # url outfile
    local url="$1" out="$2"
    if [ -f "$out" ]; then
        echo "have $out"
        return 0
    fi
    echo "fetch $url"
    curl -fsSL -o "$out" "$url" || { echo "download failed: $url" >&2; return 1; }
}

extract() { # deb dir
    local deb="$1" dir="$2"
    echo "extract $deb -> $dir"
    mkdir -p "$dir"
    dpkg-deb -x "$deb" "$dir"
}

# libsodium-dev: fetch + extract.
fetch "$MIRROR/$SODIUM_POOL/$SODIUM_DEB" "$SODIUM_DEB" || true
if [ -f "$SODIUM_DEB" ]; then extract "$SODIUM_DEB" sodium; fi

# The rest: fetch + extract into their dirs.
for pkg in "${!DEBS[@]}"; do
    deb="${DEBS[$pkg]}"
    dir="${DIR[$pkg]}"
    # pool path: derive from the package name's first letter(s).
    # tcl8.6 -> pool/main/t/tcl8.6 ; libxft2 -> pool/main/libx/libxft2 ; etc.
    case "$pkg" in
        lib*) pool="pool/main/lib${pkg:3:1}/${pkg}" ;;
        *)    pool="pool/main/${pkg:0:1}/${pkg}" ;;
    esac
    fetch "$MIRROR/$pool/$deb" "$deb" || continue
    extract "$deb" "$dir"
done

# Patch pkg-config files to point at the vendored tree (tcl/tk/opus/vpx/sodium).
# alsa and xft keep prefix=/usr (system libs); only their libdir triplet matters.
for pkg in tcl tk opus vpx sodium; do
    pc="$DEPS/$pkg/usr/lib/$TRIPLET/pkgconfig"
    [ -d "$pc" ] || continue
    for f in "$pc"/*.pc; do
        [ -f "$f" ] || continue
        # Rewrite prefix to the vendored location for this tree.
        sed -i "s|^prefix=.*|prefix=$DEPS/$pkg/usr|" "$f"
        # The deb .pc files use absolute /usr paths; make them ${prefix}-relative
        # so they resolve against the vendored tree. Preserve any subdir under
        # /usr/include (e.g. tcl8.6) and /usr/lib/<triplet>.
        sed -i "s|^exec_prefix=.*|exec_prefix=\${prefix}|" "$f"
        sed -i "s|^libdir=.*|libdir=\${prefix}/lib/$TRIPLET|" "$f"
        sed -i "s|^includedir=/usr/include/\(.*\)|includedir=\${prefix}/include/\1|" "$f"
        sed -i "s|^includedir=/usr/include$|includedir=\${prefix}/include|" "$f"
        # Any remaining hardcoded triplet path (e.g. a bare /usr/lib/<triplet>)
        # is rewritten to the vendored libdir.
        sed -i "s|/usr/lib/[a-z0-9-]*linux-gnu|\${prefix}/lib/$TRIPLET|g" "$f"
        # The deb tk.pc requires "tcl" but the vendored file is tcl8.6.pc.
        sed -i "s|^Requires: tcl >=|Requires: tcl8.6 >=|" "$f"
        echo "patched $f"
    done
done

echo "done: .deps provisioned for $ARCH ($TRIPLET)"
