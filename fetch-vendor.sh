#!/usr/bin/env bash
# fetch-vendor.sh — provision the ENTIRE vendor/ tree from a fresh clone.
#
# vendor/ is gitignored (third-party code), so a fresh clone has none of it.
# The build hard-requires:
#   vendor/c-toxcore     TokTok/c-toxcore, pinned commit + cmp submodule
#   vendor/sntrup761     SNTRUP761 KEM (public domain, fetched from supercop)
#   vendor/.deps         Linux debs        (via fetch-deps.sh <arch>)
#   vendor/.host-devs    host -dev set     (via fetch-deps.sh; xft.pc needs
#                        fontconfig/freetype2 .pc files on PKG_CONFIG_PATH)
#   vendor/.deps-win     mingw PE deps     (via fetch-deps-win.sh, needs the
#                        mingw-w64 cross toolchain + build tools)
#
# Usage:
#   bash fetch-vendor.sh              # everything for the host arch (Linux)
#   bash fetch-vendor.sh linux [arch] # just fetch-deps.sh for arch
#   bash fetch-vendor.sh win          # sources + .deps-win (mingw build path)
#   bash fetch-vendor.sh sources      # just c-toxcore + sntrup761
#   bash fetch-vendor.sh check        # report what is present / missing
#   bash fetch-vendor.sh clean        # remove the whole vendor/ tree
#   --force re-provisions components that already exist (clean re-fetch).
#
# Requirements: git, curl; for the Linux debs also dpkg-deb; for `win` also
# the mingw-w64 cross toolchain (see BUILD.md §5) and the host build tools
# fetch-deps-win.sh needs (cc, make, perl, pkg-config, tar, unzip, zstd).
set -eu

ROOT=$(cd "$(dirname "$0")" && pwd)
VENDOR="$ROOT/vendor"

# --- pins ------------------------------------------------------------------
# c-toxcore: the commit the current build was verified against.
TOXCORE_REPO="https://github.com/TokTok/c-toxcore.git"
TOXCORE_PIN="2a0b2cb382f4ab0e9b5f23c813d2ee54e0fe2f61"

# sntrup761: the merged single-file variant this build compiles is public-
# domain supercop-derived code (super cop-20201130 comments in-file). supercop
# itself only ships the multi-file ref/ layout, and no public mirror carries
# the exact merged file — so the 4 files (~24 KB) are TRACKED in the repo at
# vendor-sntrup761/ and simply restored into the gitignored vendor/ layout.
# sha512.c is NOT compiled by the build (crypto_hash_sha512 resolves to
# libsodium's); it ships for completeness with the pair.

FORCE=0
host_arch() { # -> arm64|amd64|riscv64 (the fetch-deps.sh names)
    case "$(uname -m)" in
        aarch64|arm64) echo arm64 ;;
        x86_64|amd64)  echo amd64 ;;
        riscv64)       echo riscv64 ;;
        *) echo "unsupported host arch: $(uname -m)" >&2; return 1 ;;
    esac
}

have_sources() {
    [ -f "$VENDOR/c-toxcore/toxcore/tox.h" ] && [ -f "$VENDOR/sntrup761/sntrup761.c" ]
}

c_toxcore_ok() { # clone present AND pinned to the verified commit
    [ -d "$VENDOR/c-toxcore/.git" ] || return 1
    [ "$FORCE" = 1 ] && return 1
    git -C "$VENDOR/c-toxcore" rev-parse HEAD 2>/dev/null | grep -q "$TOXCORE_PIN"
}

# ---------------- sources: c-toxcore --------------------------------------
do_c_toxcore() {
    if c_toxcore_ok; then
        echo "have c-toxcore (pinned $TOXCORE_PIN)"
        ensure_c_toxcore_submodule
        return 0
    fi
    if [ -d "$VENDOR/c-toxcore/.git" ]; then
        echo "c-toxcore: wrong commit, re-checking out $TOXCORE_PIN"
        git -C "$VENDOR/c-toxcore" fetch --depth 1 origin "$TOXCORE_PIN" || true
        git -C "$VENDOR/c-toxcore" checkout --detach "$TOXCORE_PIN"
        ensure_c_toxcore_submodule
        return 0
    fi
    echo "clone c-toxcore at $TOXCORE_PIN"
    # depth-1 at the exact commit: small, pinned, no history surprises.
    if ! git clone --depth 1 --branch "$TOXCORE_PIN" "$TOXCORE_REPO" \
            "$VENDOR/c-toxcore" 2>/dev/null; then
        # some servers refuse --branch <sha>; fall back to fetch-after-clone
        git clone --depth 1 "$TOXCORE_REPO" "$VENDOR/c-toxcore"
        git -C "$VENDOR/c-toxcore" fetch --depth 1 origin "$TOXCORE_PIN"
        git -C "$VENDOR/c-toxcore" checkout --detach "$TOXCORE_PIN"
    fi
    ensure_c_toxcore_submodule
}

# c-toxcore compiles third_party/cmp (a submodule); a shallow clone does not
# include it, so bring the pinned submodule in explicitly (idempotent).
ensure_c_toxcore_submodule() {
    if [ ! -f "$VENDOR/c-toxcore/third_party/cmp/cmp.c" ]; then
        git -C "$VENDOR/c-toxcore" submodule update --init --depth 1 third_party/cmp
    fi
}

# --- sntrup761 -------------------------------------------------------------
# Restore the tracked snapshot into the (gitignored) vendor/ layout.
do_sntrup761() {
    if [ -f "$VENDOR/sntrup761/sntrup761.c" ] && [ "$FORCE" != 1 ]; then
        echo "have sntrup761"
        return 0
    fi
    local src="$ROOT/vendor-sntrup761"
    if [ ! -f "$src/sntrup761.c" ]; then
        echo "missing tracked snapshot: $src/sntrup761.c" >&2
        return 1
    fi
    mkdir -p "$VENDOR/sntrup761"
    cp "$src"/sntrup761.c "$src"/sntrup761.h "$src"/sha512.c "$src"/sha512.h \
       "$VENDOR/sntrup761/"
    echo "sntrup761: restored from the tracked snapshot (vendor-sntrup761/)"
}

# --- orchestrators ----------------------------------------------------------
do_sources() {
    mkdir -p "$VENDOR"
    do_c_toxcore
    do_sntrup761
}

do_linux() { # arch -> fetch-deps.sh
    local arch="${1:-$(host_arch)}"
    bash "$ROOT/fetch-deps.sh" "$arch"
}

do_win() {
    do_sources
    bash "$ROOT/fetch-deps-win.sh"
}

do_check() {
    local rc=0
    echo "vendor/ contents:"
    if c_toxcore_ok; then
        echo "  [ok]   c-toxcore pinned at $TOXCORE_PIN"
    elif [ -d "$VENDOR/c-toxcore" ]; then
        echo "  [WARN] c-toxcore present but NOT at pin $TOXCORE_PIN:"
        echo "         $(git -C "$VENDOR/c-toxcore" rev-parse HEAD 2>/dev/null || echo '?')"
        rc=1
    else
        echo "  [MISS] c-toxcore (run: git clone ...)"; rc=1
    fi
    if [ -f "$VENDOR/sntrup761/sntrup761.c" ]; then
        echo "  [ok]   sntrup761"
    else
        echo "  [MISS] sntrup761"; rc=1
    fi
    if [ -d "$VENDOR/.deps/sodium/usr/lib" ]; then
        echo "  [ok]   .deps (Linux debs: $(ls "$VENDOR/.deps" | grep -v '\.log$\|\.deb$' | tr '\n' ' '))"
    else
        echo "  [MISS] .deps — run: bash fetch-vendor.sh (the Linux build needs it)"
        rc=1
    fi
    if ls "$VENDOR"/.host-devs/usr/lib/*/pkgconfig/fontconfig.pc >/dev/null 2>&1; then
        echo "  [ok]   .host-devs (host -dev set: fontconfig, freetype, png, brotli, bz2)"
    else
        echo "  [MISS] .host-devs — run: bash fetch-vendor.sh (xft.pc needs these .pc files)"
        rc=1
    fi
    if [ -d "$VENDOR/.deps-win/sodium/lib" ]; then
        echo "  [ok]   .deps-win (mingw static deps + runtime DLLs)"
    else
        echo "  [note] .deps-win absent — only needed for the Windows build"
    fi
    echo "rc=$rc (0 = everything the current build needs is present)"
    return $rc
}

# --- arg parsing ------------------------------------------------------------
args=()
for a in "$@"; do
    case "$a" in
        --force) FORCE=1 ;;
        *) args+=("$a") ;;
    esac
done
cmd="${args[0]:-all}"

case "$cmd" in
    all|linux|sources|win|check|clean) ;;
    *) echo "usage: $0 [all|linux [arch]|win|sources|check|clean] [--force]" >&2; exit 1 ;;
esac

case "$cmd" in
    all)     do_linux; do_sources ;;
    linux)   do_linux "${args[1]:-}" ;;
    win)     do_win ;;
    sources) do_sources ;;
    check)   do_check ;;
    clean)
        echo "removing $VENDOR (all of it is regenerable via this script)"
        rm -rf "$VENDOR"
        ;;
esac