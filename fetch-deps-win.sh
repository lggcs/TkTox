#!/usr/bin/env bash
# fetch-deps-win.sh — provision the vendored .deps-win tree for the Windows
# (mingw-w64 PE) build of TkTox.
#
# Builds the dependencies TkTox links that are not in the mingw sysroot:
#   tcl 8.6, tk 8.6, libsodium
# opus and vpx are installed from the MSYS2 mingw64 repo as static-ready
# packages (their .pc files and .a archives are shipped by those packages).
#
# Usage:
#   bash fetch-deps-win.sh
# Requires: mingw-w64 cross toolchain, pkg-config, curl, tar, make, perl,
# unzip, and a host C compiler. Downloads are TLS-protected (same trust
# trade-off as fetch-deps.sh; pin a local mirror for hardened builds).
#
# Layout produced (mirrors vendor/.deps, Windows-style):
#   vendor/.deps-win/tcl/{lib/libtcl8.6.a,include/tcl.h,lib/tcl8.6/*}
#   vendor/.deps-win/tk/{lib/libtk8.6.a,include/tk.h,lib/tk8.6/*}
#   vendor/.deps-win/sodium/{lib/libsodium.a,include/sodium.h,lib/pkgconfig/*.pc}
#   vendor/.deps-win/opus/{lib/libopus.a,include/opus.h,lib/pkgconfig/*.pc}
#   vendor/.deps-win/vpx/{lib/libvpx.a,include/vpx.h,lib/pkgconfig/*.pc}
# plus vendor/.deps-win/bin/{libwinpthread-1.dll,...} staged runtime DLLs.

set -eu

ROOT=$(cd "$(dirname "$0")" && pwd)
DEPS="$ROOT/vendor/.deps-win"
STAMP="$DEPS/.provisioned"
mkdir -p "$DEPS"

# The stamp short-circuits only the full provisioning run; the per-component
# subcommands (tcl/tk/dlls/...) must stay usable for incremental repair.
if [ -f "$STAMP" ] && [ "${1:-all}" = "all" ]; then
    echo "deps-win already provisioned ($STAMP exists)"
    exit 0
fi

HOSTCC=${HOSTCC:-cc}
TRIPLET=${TT_MINGW_TRIPLET:-x86_64-w64-mingw32}
JOBS=$(nproc 2>/dev/null || echo 4)
MSYS2=https://repo.msys2.org/mingw

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
echo "workdir: $work"

fetch() { # url out
    local url="$1" out="$2"
    if [ -f "$out" ]; then echo "have $out"; return 0; fi
    echo "fetch $url"
    curl -fsSL -o "$out" "$url" || { echo "download failed: $url" >&2; return 1; }
}

# ---------------- opus + vpx from the MSYS2 mingw64 repo ----------------
# The -doc/-debug packages are skipped; the base package carries both the
# import lib and the static lib (mingw-w64 ships .a and .dll.a together).
fetch_opus_vpx() {
    local idx="$work/msys2idx.html"
    fetch "https://repo.msys2.org/mingw/mingw64/" "$idx" >/dev/null
    local pkg url tar
    for pkg in mingw-w64-x86_64-opus mingw-w64-x86_64-libvpx; do
        # newest version wins (index lists newest last); the -[^0-9] guard
        # keeps subpackages (-docs/-tools) out of the match
        url=$(grep -o "href=\"$pkg-[0-9][^\"]*any.pkg.tar.zst\"" "$idx" | tail -1 | sed 's/href="//;s/"//')
        [ -n "$url" ] || { echo "no msys2 package for $pkg" >&2; return 1; }
        fetch "https://repo.msys2.org/mingw/mingw64/$url" "$work/$url" >/dev/null
        mkdir -p "$work/$pkg"
        tar -xf "$work/$url" -C "$work/$pkg" 2>/dev/null || {
            # zstd tar may need the zstd binary on older hosts
            zstd -dc "$work/$url" | tar -xf - -C "$work/$pkg"
        }
        echo "staged $pkg"
    done
    # copy content into the vendored tree (package -> tree name)
    local srcp
    for pair in opus:opus libvpx:vpx; do
        local pkgname=${pair%%:*} name=${pair##*:}
        srcp="$work/mingw-w64-x86_64-$pkgname"
        [ -d "$srcp" ] || return 1
        mkdir -p "$DEPS/$name"
        cp -r "$srcp/mingw64/include" "$DEPS/$name/" 2>/dev/null || true
        cp -r "$srcp/mingw64/lib" "$DEPS/$name/"
        # keep only the static archives; drop the DLL import libs to force
        # static resolution (the .pc files stay for pkg-config)
        ls "$srcp/mingw64/bin" 2>/dev/null | grep -E '\.dll$' | while read -r dll; do
            mkdir -p "$DEPS/bin"
            cp "$srcp/mingw64/bin/$dll" "$DEPS/bin/" || true
        done
    done
    # rewrite the pc prefix to the vendored tree and drop -lfoo that resolve
    # to the DLLs (they are also shipped as .a, pkg-config --static works)
    for name in opus vpx; do
        for f in "$DEPS/$name/lib/pkgconfig"/*.pc; do
            [ -f "$f" ] || continue
            sed -i "s|^prefix=.*|prefix=$DEPS/$name|" "$f"
            sed -i "s|^includedir=.*|includedir=\${prefix}/include|" "$f"
            sed -i "s|^libdir=.*|libdir=\${prefix}/lib|" "$f"
            # strip msys2-only private libs the static link cannot use
            sed -i "s/ -lssp //g" "$f"
        done
    done
}

# ---------------- libsodium from source ----------------
build_sodium() {
    local ver=1.0.20
    fetch "https://download.libsodium.org/libsodium/releases/libsodium-$ver.tar.gz" \
          "$work/sodium.tar.gz" >/dev/null
    tar -xzf "$work/sodium.tar.gz" -C "$work"
    local srctree="$work/libsodium-$ver"
    (
      cd "$srctree"
      # clean-room cross build: host cc builds the "dlopen" test progs, the
      # target triplet builds the library itself.
      ./configure --host="$TRIPLET" --prefix="$DEPS/sodium" \
                  --disable-shared --enable-static \
                  CC="$TRIPLET-gcc" AR="$TRIPLET-ar" RANLIB="$TRIPLET-ranlib"
      make -j"$JOBS"
      make install
    )
    echo "built libsodium $ver (static)"
}

# ---------------- Tcl/Tk from source ----------------
# 8.6.x with --enable-threads; static archives + the script library trees.
build_tcl() {
    local ver=${TT_TCL_VERSION:-8.6.16}
    local v1
    v1=${ver%.*}
    fetch "https://prdownloads.sourceforge.net/tcl/tcl$ver-src.tar.gz" \
          "$work/tcl.tar.gz" >/dev/null
    tar -xzf "$work/tcl.tar.gz" -C "$work"
    (
      cd "$work/tcl$ver/win"
      ./configure --host="$TRIPLET" --prefix="$DEPS/tcl" \
                  --enable-threads --disable-shared \
                  CC="$TRIPLET-gcc" AR="$TRIPLET-ar" RANLIB="$TRIPLET-ranlib"
      # libtclstub86.a is what Tk links against (its win build uses
      # -DUSE_TCL_STUBS); the "make binaries" target builds the shim archives.
      make -j"$JOBS" libtcl86.a libtclstub86.a 2>/dev/null \
        || make -j"$JOBS" libtcl8.6.a tcl8.6.lib tclsh8.6 2>/dev/null \
        || make -j"$JOBS" libtcl86.a
      # install manually: mingw tcl 'make install' wants an MSYS shell env;
      # only the pieces TkTox needs are copied. The mingw build names the
      # static archive libtcl86.a (no dot before 8.6).
      # Script tree goes to the conventional tcl$v1 (tcl8.6), which is what
      # TCL_LIBRARY points at — not tcl$ver.
      mkdir -p "$DEPS/tcl/lib" "$DEPS/tcl/include" "$DEPS/tcl/lib/tcl$v1"
      cp libtcl86.a "$DEPS/tcl/lib/"
      cp libtclstub86.a "$DEPS/tcl/lib/" 2>/dev/null || true
      cp -r ../generic/*.h "$DEPS/tcl/include/" 2>/dev/null || true
      cp tclConfig.h "$DEPS/tcl/include/" 2>/dev/null || true
      # tk's win/ configure --with-tcl expects tclConfig.sh next to the lib
      cp tclConfig.sh "$DEPS/tcl/lib/" 2>/dev/null || true
      cp -r ../library/* "$DEPS/tcl/lib/tcl$v1/"
      cp ../library/tclIndex "$DEPS/tcl/lib/tcl$v1/" 2>/dev/null || true
    )
    echo "built tcl $ver (static)"
}

build_tk() {
    local ver=${TT_TK_VERSION:-8.6.16}
    local v1
    v1=${ver%.*}
    fetch "https://prdownloads.sourceforge.net/tcl/tk$ver-src.tar.gz" \
          "$work/tk.tar.gz" >/dev/null
    tar -xzf "$work/tk.tar.gz" -C "$work"
    (
      cd "$work/tk$ver/win"
      ./configure --host="$TRIPLET" --prefix="$DEPS/tk" \
                  --enable-threads --disable-shared \
                  --with-tcl="$DEPS/tcl/lib" \
                  CC="$TRIPLET-gcc" AR="$TRIPLET-ar" RANLIB="$TRIPLET-ranlib"
      make -j"$JOBS" libtk86.a
      mkdir -p "$DEPS/tk/lib" "$DEPS/tk/include" "$DEPS/tk/lib/tk$v1"
      cp libtk86.a "$DEPS/tk/lib/"
      cp -r ../generic/*.h "$DEPS/tk/include/" 2>/dev/null || true
      cp tkConfig.h "$DEPS/tk/include/" 2>/dev/null || true
      cp -r ../library/* "$DEPS/tk/lib/tk$v1/"
      cp ../library/tk.tcl "$DEPS/tk/lib/tk$v1/" 2>/dev/null || true
      # Tk's Windows build installs the X11 compatibility headers (xlib/X11)
      # and the win/ private headers next to tk.h; tk.h includes X11/Xlib.h
      # unconditionally unless an Xlib guard is already set.
      mkdir -p "$DEPS/tk/include/X11"
      cp ../xlib/X11/*.h "$DEPS/tk/include/X11/" 2>/dev/null || true
      cp tkWin.h tkWinPort.h tkWinInt.h tkWinDefault.h tkWinSendCom.h \
         "$DEPS/tk/include/" 2>/dev/null || true
    )
    echo "built tk $ver (static)"
}

# ---------------- pkg-config .pc files for pkg_check_modules ----------------
write_pc() {
    # tcl/tk ship no .pc on Windows: write minimal ones pkg_check_modules can
    # consume (tk requires tcl; the Cflags/Libs are consumed by CMakeLists).
    mkdir -p "$DEPS/tcl/lib/pkgconfig" "$DEPS/tk/lib/pkgconfig" \
             "$DEPS/sodium/lib/pkgconfig" "$DEPS/opus/lib/pkgconfig" \
             "$DEPS/vpx/lib/pkgconfig"
    cat > "$DEPS/tcl/lib/pkgconfig/tcl86.pc" <<EOF
prefix=$DEPS/tcl
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: tcl8.6
Description: Tcl 8.6 (vendored static mingw build)
Version: ${TT_TCL_VERSION:-8.6.16}
# Libs.private is upstream's TCL_LIBS for mingw (win/configure); pkg-config
# --static surfaces it, so static consumers link the right system libs.
Libs: -L\${libdir} -ltcl86
Libs.private: -lnetapi32 -lkernel32 -luser32 -ladvapi32 -luserenv -lws2_32
Cflags: -I\${includedir}
EOF
    cat > "$DEPS/tk/lib/pkgconfig/tk86.pc" <<EOF
prefix=$DEPS/tk
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include
Requires: tcl86

Name: tk8.6
Description: Tk 8.6 (vendored static mingw build)
Version: ${TT_TK_VERSION:-8.6.16}
# Tk's win build compiles against the Tcl *stub* library, so consumers must
# link it too (it supplies Tcl_InitStubs/tclStubsPtr). The trailing -l list
# is upstream's LIBS + LIBS_GUI for mingw (win/configure).
Libs: -L\${libdir} -ltk86 -L$DEPS/tcl/lib -ltclstub86
Libs.private: -lnetapi32 -lkernel32 -luser32 -ladvapi32 -luserenv -lws2_32 -lgdi32 -lcomdlg32 -limm32 -lcomctl32 -lshell32 -luuid -lole32 -loleaut32
Cflags: -I\${includedir}
EOF
    # sodium: upstream installs a .pc already; ensure prefix correctness
    for f in "$DEPS/sodium/lib/pkgconfig"/libsodium.pc; do
        [ -f "$f" ] || continue
        sed -i "s|^prefix=.*|prefix=$DEPS/sodium|" "$f"
    done
}

# ---------------- runtime DLLs ----------------
# TkTox.exe imports the mingw pthread DLL plus the opus/vpx DLLs that ship
# with their MSYS2 packages; all three must sit next to the exe at run time
# (or on PATH) for wine/the real OS to load it.
stage_runtime_dlls() {
    mkdir -p "$DEPS/bin"
    local pthread
    pthread=$(ls /usr/"$TRIPLET"/lib/libwinpthread-1.dll \
                 /usr/lib/gcc/"$TRIPLET"/*/libwinpthread-1.dll 2>/dev/null | head -1)
    if [ -n "$pthread" ]; then
        cp "$pthread" "$DEPS/bin/"
        echo "staged libwinpthread-1.dll"
    else
        echo "warning: libwinpthread-1.dll not found in the mingw sysroot" >&2
    fi
}

case "${1:-all}" in
    all)
        fetch_opus_vpx
        build_sodium
        build_tcl
        build_tk
        write_pc
        stage_runtime_dlls
        touch "$STAMP"
        echo "done: .deps-win provisioned"
        ;;
    sodium) build_sodium && write_pc ;;
    tcl)    build_tcl && write_pc ;;
    tk)     build_tk && write_pc ;;
    opus)   fetch_opus_vpx ;;
    dlls)   stage_runtime_dlls ;;
    clean)  rm -rf "$DEPS" ;;
    *) echo "usage: $0 [all|sodium|tcl|tk|opus|dlls|clean]" >&2; exit 1 ;;
esac