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
    arm64)   TRIPLET="${TRIPLET:-aarch64-linux-gnu}"; MIRROR="https://ports.ubuntu.com/ubuntu-ports" ;;
    amd64)   TRIPLET="${TRIPLET:-x86_64-linux-gnu}";  MIRROR="https://archive.ubuntu.com/ubuntu" ;;
    riscv64) TRIPLET="${TRIPLET:-riscv64-linux-gnu}"; MIRROR="https://ports.ubuntu.com/ubuntu-ports" ;;
    *) echo "unsupported arch: $ARCH (use arm64|amd64|riscv64)" >&2; exit 1 ;;
esac

# TLS gives integrity against a network MITM but NOT against a compromised
# mirror. For pinned-reprovisionable deps this is the practical trade-off;
# prefer a local apt mirror / aptly snapshot for hardened deployments
# (apt's Release signatures verify what plain curl cannot).

ROOT=$(cd "$(dirname "$0")" && pwd)
DEPS="$ROOT/vendor/.deps"
mkdir -p "$DEPS"
cd "$DEPS"

# Pinned debs as "source_pkg|deb_filename|extraction_dir".
# Versions pinned to what the current tree was verified with. The pool path
# is the SOURCE package (Ubuntu lays pools out by source, not binary name:
# libopus-dev lives in pool/main/o/opus, not libo/libopus-dev), so it is
# explicit per entry instead of derived from the binary name.
DEBS=(
  "tcl8.6|tcl8.6_8.6.18+dfsg-1_${ARCH}.deb|tcl"
  "tcl8.6|tcl8.6-dev_8.6.18+dfsg-1_${ARCH}.deb|tcl"
  "tcl8.6|libtcl8.6_8.6.18+dfsg-1_${ARCH}.deb|tcl"
  "tk8.6|tk8.6_8.6.18-1_${ARCH}.deb|tk"
  "tk8.6|tk8.6-dev_8.6.18-1_${ARCH}.deb|tk"
  "tk8.6|libtk8.6_8.6.18-1_${ARCH}.deb|tk"
  "xft|libxft2_2.3.6-1build2_${ARCH}.deb|xft"
  "xft|libxft-dev_2.3.6-1build2_${ARCH}.deb|xft"
  "opus|libopus-dev_1.6.1-1_${ARCH}.deb|opus"
  "libvpx|libvpx-dev_1.16.0-3_${ARCH}.deb|vpx"
  "alsa-lib|libasound2-dev_1.2.15.3-1ubuntu1.1_${ARCH}.deb|alsa"
  "libsodium|libsodium-dev_1.0.18-2_${ARCH}.deb|sodium"
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

# Fetch + extract each pinned deb; a single download failure is fatal so a
# broken URL cannot masquerade as a provisioned tree.
for entry in "${DEBS[@]}"; do
    IFS='|' read -r src deb dir <<<"$entry"
    case "$src" in
        lib*) prefix="${src:0:4}" ;;   # Ubuntu pool: lib* -> first 4 chars (libvpx -> libv)
        *)    prefix="${src:0:1}" ;;
    esac
    fetch "$MIRROR/pool/main/$prefix/$src/$deb" "$deb"
    extract "$deb" "$dir"
done

# Host -dev set: what xft.pc's Requires.private pulls in (fontconfig,
# freetype2) plus their own transitive .pc needs (png, brotli, bz2). On a
# normal desktop these are the BUILD.md §3b apt packages; this provisioner
# extracts them into vendor/.host-devs/ so hosts without the -dev packages
# can still configure the build. env.sh adds the tree to PKG_CONFIG_PATH.
HOST_DEBS=(
  "fontconfig|libfontconfig-dev_2.17.1-3ubuntu1_${ARCH}.deb"
  "freetype|libfreetype-dev_2.14.2+dfsg-1ubuntu0.1_${ARCH}.deb"
  "libpng1.6|libpng-dev_1.6.58-1_${ARCH}.deb"
  "brotli|libbrotli-dev_1.2.0-3build1_${ARCH}.deb"
  "bzip2|libbz2-dev_1.0.8-6ubuntu0.1_${ARCH}.deb"
)
HOST_DEVS="$ROOT/vendor/.host-devs"
mkdir -p "$HOST_DEVS"
cd "$HOST_DEVS"

for entry in "${HOST_DEBS[@]}"; do
    IFS='|' read -r src deb <<<"$entry"
    case "$src" in
        lib*) prefix="${src:0:4}" ;;
        *)    prefix="${src:0:1}" ;;
    esac
    fetch "$MIRROR/pool/main/$prefix/$src/$deb" "$deb"
    dpkg-deb -x "$deb" "$HOST_DEVS"
done

cd "$DEPS"

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
