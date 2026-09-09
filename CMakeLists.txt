cmake_minimum_required(VERSION 3.24)
project(TkTox VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wformat=2 -Wformat-security -Wundef
  -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes)

find_package(PkgConfig REQUIRED)
# UI: Tk 8.6 (portable, C-embedded interp, no Tcl scripts).
# alsa (libasound) drives the M-AV3 audio device layer.
# Vendored deps resolve through PKG_CONFIG_PATH; pass their lib dirs to the linker.
# xft is included so the linker can resolve libtk8.6's transitive libXft dependency.
# opus/vpx provide toxav's codecs (extracted from Ubuntu dev debs).
#
# Link mode selects static vs dynamic resolution:
#   static  -> pkg-config --static (all .a); ALSA stays shared (Ubuntu ships
#              libasound shared-only), so glibc stays dynamic too.
#   dynamic -> pkg-config --libs (all .so).
# pkg_check_modules always populates <prefix>_STATIC_LIBRARIES (the --static
# libs); we select them explicitly for the static path.
pkg_check_modules(TCLTK REQUIRED tcl8.6 tk8.6)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPUS REQUIRED opus)
pkg_check_modules(VPX REQUIRED vpx)
pkg_check_modules(XFT REQUIRED xft)
pkg_check_modules(ALSA REQUIRED alsa)
if(TT_LINK_MODE STREQUAL "static")
  set(TT_STATIC_LIBS
    ${SODIUM_STATIC_LIBRARIES} ${TCLTK_STATIC_LIBRARIES}
    ${OPUS_STATIC_LIBRARIES} ${VPX_STATIC_LIBRARIES} ${XFT_STATIC_LIBRARIES})
endif()
#
# The deb multiarch triplet is the single arch knob: it drives the vendored
# .deps/<pkg>/usr/lib/<triplet> layout. It defaults from the host/target
# processor and can be overridden for cross-compiling, e.g.
#   -DTT_DEPS_TRIPLET=x86_64-linux-gnu
#   -DTT_DEPS_TRIPLET=riscv64-linux-gnu
if(NOT DEFINED TT_DEPS_TRIPLET)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(TT_DEPS_TRIPLET "aarch64-linux-gnu")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(TT_DEPS_TRIPLET "x86_64-linux-gnu")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    set(TT_DEPS_TRIPLET "riscv64-linux-gnu")
  else()
    set(TT_DEPS_TRIPLET "${CMAKE_SYSTEM_PROCESSOR}-linux-gnu")
  endif()
endif()
set(TT_DEPS_LIBDIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps")
link_directories(${TCLTK_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS}
  ${TT_DEPS_LIBDIR}/xft/usr/lib/${TT_DEPS_TRIPLET}
  ${TT_DEPS_LIBDIR}/opus/usr/lib/${TT_DEPS_TRIPLET}
  ${TT_DEPS_LIBDIR}/vpx/usr/lib/${TT_DEPS_TRIPLET}
  ${TT_DEPS_LIBDIR}/alsa/usr/lib/${TT_DEPS_TRIPLET})

# Vendored Tcl/Tk script trees: setenv("TCL_LIBRARY"/"TK_LIBRARY") in ui_run
# pins the interp to these (system /usr/share/tcltk may hold another 8.6.x).
add_compile_definitions(
  TT_TCL_SCRIPT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps/tcl/usr/share/tcltk/tcl8.6"
  TT_TK_SCRIPT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps/tk/usr/share/tcltk/tk8.6")

include(FetchContent)

# Vendored reference toxcore (clean-room client uses its public C API only).
set(EXPERIMENTAL_API OFF CACHE BOOL "" FORCE)
set(UNITTEST OFF CACHE BOOL "" FORCE)
set(AUTOTEST OFF CACHE BOOL "" FORCE)
set(BUILD_MISC_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_FUN_UTILS OFF CACHE BOOL "" FORCE)
set(BUILD_FUZZ_TESTS OFF CACHE BOOL "" FORCE)
set(DHT_BOOTSTRAP OFF CACHE BOOL "" FORCE)
set(BOOTSTRAP_DAEMON OFF CACHE BOOL "" FORCE)
set(BUILD_TOXAV ON CACHE BOOL "" FORCE)
set(MUST_BUILD_TOXAV ON CACHE BOOL "" FORCE)
# Build only the toxcore flavor the link mode needs (avoids building both).
if(TT_LINK_MODE STREQUAL "static")
  set(ENABLE_SHARED OFF CACHE BOOL "" FORCE)
  set(ENABLE_STATIC ON CACHE BOOL "" FORCE)
else()
  set(ENABLE_SHARED ON CACHE BOOL "" FORCE)
  set(ENABLE_STATIC OFF CACHE BOOL "" FORCE)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/c-toxcore toxcore_build)

# Post-quantum KEM (Streamlined NTRU Prime 761), public-domain supercop code,
# vendored from the simplexmq review tree.
add_library(sntrup761 STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/sntrup761/sntrup761.c)
target_include_directories(sntrup761 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/sntrup761)

set(TT_SOURCES
  src/main.c
  src/headless.c
  src/tox_thread.c
  src/av.c
  src/audio_alsa.c
  src/video_v4l2.c
  src/offline_queue.c
  src/session_store.c
  src/app_state.c
  src/log.c
  src/ui/ui_tk.c
  src/crypto/kdf.c
  src/crypto/aead.c
  src/crypto/kem.c
  src/crypto/frame.c
  src/session.c)

add_executable(TkTox ${TT_SOURCES})
target_include_directories(TkTox PRIVATE src ${CMAKE_CURRENT_BINARY_DIR})

# ---- Link the two build paths ----
# static:  everything static except ALSA. Ubuntu ships libasound shared-only, so
#          ALSA (and therefore glibc) stays dynamic. We wrap the static libs in
#          -Wl,-Bstatic ... -Wl,-Bdynamic so the linker prefers .a for them and
#          falls back to .so for asound and the C runtime. The --start-group
#          resolves the circular static deps (tk<->tcl, vpx<->pthread, etc.).
# dynamic: everything shared; toxcore_shared carries its own deps.
if(TT_LINK_MODE STREQUAL "static")
  target_link_libraries(TkTox PRIVATE
    -Wl,-Bstatic -Wl,--start-group
    toxcore_static sntrup761 ${TT_STATIC_LIBS}
    -Wl,--end-group -Wl,-Bdynamic
    asound)
else()
  # Link xft explicitly: it is a transitive dep of libtk8.6.so, and RUNPATH
  # does not propagate to transitive deps — without it the loader cannot find
  # libXft.so.2 at runtime. --no-as-needed forces it into NEEDED even though
  # the executable references no Xft symbols directly, so the executable's
  # RUNPATH (which includes the vendored xft dir) resolves it.
  target_link_libraries(TkTox PRIVATE
    toxcore_shared sntrup761 ${SODIUM_LIBRARIES} ${TCLTK_LIBRARIES}
    -Wl,--no-as-needed ${XFT_LIBRARIES} -Wl,--as-needed asound)
endif()
# Stage toxcore public headers into build/toxinclude/tox/ so #include <tox/tox.h> works
# without installing (upstream headers are flat; install layout nests them under tox/).
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/toxinclude/tox)
file(GLOB TOXCORE_PUBLIC_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/vendor/c-toxcore/toxcore/tox*.h)
foreach(h ${TOXCORE_PUBLIC_HEADERS})
  configure_file(${h} ${CMAKE_BINARY_DIR}/toxinclude/tox/ COPYONLY)
endforeach()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/vendor/c-toxcore/toxencryptsave/toxencryptsave.h
  ${CMAKE_BINARY_DIR}/toxinclude/tox/ COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/vendor/c-toxcore/toxav/toxav.h
  ${CMAKE_BINARY_DIR}/toxinclude/tox/ COPYONLY)
target_include_directories(TkTox SYSTEM PRIVATE ${CMAKE_BINARY_DIR}/toxinclude)
target_include_directories(TkTox SYSTEM PRIVATE ${TCLTK_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS}
  ${OPUS_INCLUDE_DIRS} ${VPX_INCLUDE_DIRS} ${XFT_INCLUDE_DIRS} ${ALSA_INCLUDE_DIRS})