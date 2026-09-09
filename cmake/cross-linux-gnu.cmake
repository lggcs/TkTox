# Generic Linux cross-compile toolchain for trenchtox.
#
# The target triplet is derived from CMAKE_SYSTEM_PROCESSOR, which the
# toolchain sets and CMake propagates into try_compile subprojects (a -D
# cache var does NOT propagate there, so we avoid relying on one). Override
# the processor on the command line to pick a target:
#
#   cmake -S . -B build-aarch64 \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/cross-linux-gnu.cmake \
#     -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
#     -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-aarch64 --target trenchtox -j4
#
# Supported processors -> triplets:
#   aarch64 -> aarch64-linux-gnu
#   x86_64  -> x86_64-linux-gnu
#   riscv64 -> riscv64-linux-gnu
#
# Requires the cross toolchain (<triplet>-gcc) and the vendored .deps tree
# provisioned for that arch (bash fetch-deps.sh <arch>). env.sh must be
# sourced first so PKG_CONFIG_PATH points at the target's vendored .pc files.

if(NOT DEFINED CMAKE_SYSTEM_PROCESSOR)
  set(CMAKE_SYSTEM_PROCESSOR aarch64)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(TT_CROSS_TRIPLET aarch64-linux-gnu)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
  set(TT_CROSS_TRIPLET x86_64-linux-gnu)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
  set(TT_CROSS_TRIPLET riscv64-linux-gnu)
else()
  set(TT_CROSS_TRIPLET "${CMAKE_SYSTEM_PROCESSOR}-linux-gnu")
endif()

set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_C_COMPILER "${TT_CROSS_TRIPLET}-gcc")
set(CMAKE_CXX_COMPILER "${TT_CROSS_TRIPLET}-g++")

# The vendored .deps tree lives inside TkTox/vendor/. Its .pc files
# carry absolute vendored paths (set by fetch-deps.sh), so pkg-config resolves
# them directly; we must NOT re-root them under a find root path. The cross
# compiler's own sysroot supplies libc/libm/etc. automatically.
set(TT_DEPS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../vendor/.deps")

# The multiarch triplet for the vendored lib layout.
set(TT_DEPS_TRIPLET "${TT_CROSS_TRIPLET}" CACHE STRING "Vendored .deps multiarch triplet")
