# Windows (mingw-w64) cross-compile toolchain for TkTox.
#
#   cmake -S . -B build-win \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/cross-mingw.cmake \
#     -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-win --target TkTox -j4
#
# The target triplet defaults to x86_64-w64-mingw32 and can be overridden
# with TT_MINGW_TRIPLET (e.g. i686-w64-mingw32 for a 32-bit build).
#
# Windows deps are provisioned into vendor/.deps-win by fetch-deps-win.sh
# (mingw-w64 PE builds of tcl/tk/sodium/opus/vpx — the Linux ELF debs under
# vendor/.deps cannot serve a Windows target). The fetch script runs on the
# build host and needs: mingw-w64, pkg-config, curl, tar, make, perl, and a
# host C compiler.
#
# wine (optional but recommended): lets the headless modes (--headless /
# --bot) of the produced PE binary be smoke-tested on the build host.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

if(NOT DEFINED TT_MINGW_TRIPLET)
  set(TT_MINGW_TRIPLET x86_64-w64-mingw32)
endif()

set(CMAKE_C_COMPILER   "${TT_MINGW_TRIPLET}-gcc")
set(CMAKE_CXX_COMPILER "${TT_MINGW_TRIPLET}-g++")
set(CMAKE_RC_COMPILER  "${TT_MINGW_TRIPLET}-windres")

# The vendored .deps-win tree lives inside TkTox/vendor/. Its .pc files carry
# absolute vendored paths (written by fetch-deps-win.sh), so pkg-config
# resolves them directly; we must NOT re-root them under a find root path.
# The cross compiler's own sysroot supplies winsock/mingw runtime libs.
set(TT_DEPS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../vendor/.deps-win")

# pkg-config triplet for the vendored .deps-win layout (used by fetch-deps-win.sh).
set(TT_DEPS_TRIPLET "mingw64" CACHE STRING "Vendored .deps-win triplet subdir")

# search for programs (windres) in the host environment only
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# search for libraries/headers in the target sysroot and vendored tree only
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)