cmake_minimum_required(VERSION 3.24)
project(TkTox VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wformat=2 -Wformat-security -Wundef
  -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes)

if(WIN32)
  # ---- Windows (mingw-w64 cross or native) ----
  # Windows has no ALSA/X11 and links the vendored static deps (mingw's own
  # -static would also freeze winpthreads, which is what we want for a
  # self-contained exe). Default the mode before the blocks that key off it.
  if(NOT DEFINED TT_LINK_MODE)
    set(TT_LINK_MODE "static")
  endif()
  # Deps are mingw PE builds provisioned into vendor/.deps-win by
  # fetch-deps-win.sh; their .pc files carry absolute vendored paths.
  find_package(PkgConfig REQUIRED)
  # mingw tcl/tk static builds name their archives libtcl86.a / libtk86.a
  pkg_check_modules(TCLTK REQUIRED tcl86 tk86)
  pkg_check_modules(SODIUM REQUIRED libsodium)
  pkg_check_modules(OPUS REQUIRED opus)
  pkg_check_modules(VPX REQUIRED vpx)
  # No XFT (Tk links GDI directly, not X11) and no ALSA (waveIn/waveOut).
  set(TT_AUDIO_SRC src/audio_win.c)
  set(TT_VIDEO_SRC src/video_win.c)
  set(TT_PLATFORM_SRC src/platform_win.c)
  # ws2_32/iphlpapi: toxcore sockets + interface list; winmm: waveIn/waveOut;
  # bcrypt: toxcore's random; the rest are Tk's Windows GUI deps (its win
  # build's LIBS_GUI: gdi32 comdlg32 imm32 comctl32 shell32 uuid ole32
  # oleaut32) plus netapi32/userenv/user32/advapi32 from Tk's and Tcl's LIBS.
  set(TT_WIN_LIBS ws2_32 iphlpapi winmm bcrypt
    user32 advapi32 netapi32 userenv
    gdi32 comdlg32 imm32 comctl32 shell32 uuid ole32 oleaut32)
  # mingw gates localtime_r behind _POSIX_C_SOURCE (evaluated at the first
  # time.h) and msvcrt printf's %zu behind __USE_MINGW_ANSI_STDIO (evaluated
  # at the first CRT header); both must be set before any include, i.e. as
  # compile definitions.
  add_compile_definitions(_WIN32_WINNT=0x0601
    _POSIX_C_SOURCE=200809L __USE_MINGW_ANSI_STDIO=1)
  # tcl.h/tk.h mark their API __declspec(dllimport) unless this is set; the
  # vendored archives are static (plain T symbols, no __imp_ stubs).
  add_compile_definitions(STATIC_BUILD=1)
  # GCC's builtin knowledge of the printf family uses the MSVCRT format
  # profile, which overrides mingw's __gnu_printf__ declarations and makes
  # every %zu/%hhd site warn (and real format bugs misreport). Disabling the
  # builtins makes GCC validate against the declared gnu_printf profile.
  add_compile_options(-fno-builtin-printf -fno-builtin-fprintf
    -fno-builtin-sprintf -fno-builtin-snprintf -fno-builtin-vsnprintf
    -fno-builtin-vfprintf -fno-builtin-vprintf -fno-builtin-sscanf)
else()
  # ---- Linux/BSD (unchanged resolution path) ----
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
  set(TT_AUDIO_SRC src/audio_alsa.c)
  set(TT_VIDEO_SRC src/video_v4l2.c)
  set(TT_PLATFORM_SRC "")
  set(TT_WIN_LIBS "")
endif()
if(TT_LINK_MODE STREQUAL "static")
  set(TT_STATIC_LIBS
    ${SODIUM_STATIC_LIBRARIES} ${TCLTK_STATIC_LIBRARIES}
    ${OPUS_STATIC_LIBRARIES} ${VPX_STATIC_LIBRARIES}
    ${XFT_STATIC_LIBRARIES})
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
if(WIN32)
  set(TT_DEPS_LIBDIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps-win")
endif()
if(NOT WIN32)
  link_directories(${TCLTK_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS}
    ${TT_DEPS_LIBDIR}/xft/usr/lib/${TT_DEPS_TRIPLET}
    ${TT_DEPS_LIBDIR}/opus/usr/lib/${TT_DEPS_TRIPLET}
    ${TT_DEPS_LIBDIR}/vpx/usr/lib/${TT_DEPS_TRIPLET}
    ${TT_DEPS_LIBDIR}/alsa/usr/lib/${TT_DEPS_TRIPLET})
else()
  # pkg-config *_LIBRARIES are bare -l names against the .pc libdirs, and
  # toxcore_static lands in its own build dir; both need a search path.
  link_directories(${TCLTK_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS}
    ${OPUS_LIBRARY_DIRS} ${VPX_LIBRARY_DIRS}
    ${CMAKE_BINARY_DIR}/toxcore_build)
endif()

# Vendored Tcl/Tk script trees: setenv("TCL_LIBRARY"/"TK_LIBRARY") in ui_run
# pins the interp to these (system /usr/share/tcltk may hold another 8.6.x).
if(WIN32)
  add_compile_definitions(
    TT_TCL_SCRIPT_DIR="${TT_DEPS_LIBDIR}/tcl/lib/tcl8.6"
    TT_TK_SCRIPT_DIR="${TT_DEPS_LIBDIR}/tk/lib/tk8.6")
else()
  add_compile_definitions(
    TT_TCL_SCRIPT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps/tcl/usr/share/tcltk/tcl8.6"
    TT_TK_SCRIPT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vendor/.deps/tk/usr/share/tcltk/tk8.6")
endif()

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
  src/selfcheck.c
  src/tox_thread.c
  src/chess.c
  src/av.c
  ${TT_AUDIO_SRC}
  ${TT_VIDEO_SRC}
  ${TT_PLATFORM_SRC}
  src/offline_queue.c
  src/resume.c
  src/history.c
  src/session_store.c
  src/app_state.c
  src/log.c
  src/tunnel.c
  src/ui/ui_tk.c
  src/ui/profiles.c
  src/crypto/kdf.c
  src/crypto/aead.c
  src/crypto/kem.c
  src/crypto/frame.c
  src/session.c)

add_executable(TkTox ${TT_SOURCES})
target_include_directories(TkTox PRIVATE src ${CMAKE_CURRENT_BINARY_DIR})
# --selfcheck prints this; keep it in step with project(TkTox VERSION ...).
target_compile_definitions(TkTox PRIVATE TT_VERSION="${PROJECT_VERSION}")

# ---- Link the two build paths ----
# static:  everything static except ALSA. Ubuntu ships libasound shared-only, so
#          ALSA (and therefore glibc) stays dynamic. We wrap the static libs in
#          -Wl,-Bstatic ... -Wl,-Bdynamic so the linker prefers .a for them and
#          falls back to .so for asound and the C runtime. The --start-group
#          resolves the circular static deps (tk<->tcl, vpx<->pthread, etc.).
# dynamic: everything shared; toxcore_shared carries its own deps.
if(WIN32)
  # Windows: static toxcore + static vendored deps; system libs stay dynamic
  # (mingw's -static would also freeze winpthreads/winmm, which we want for
  # a self-contained exe — so we do link the vendored .a directly).
  if(TT_LINK_MODE STREQUAL "static")
    target_link_libraries(TkTox PRIVATE
      -Wl,--start-group
      toxcore_static sntrup761 ${SODIUM_STATIC_LIBRARIES} ${TCLTK_STATIC_LIBRARIES}
      ${OPUS_STATIC_LIBRARIES} ${VPX_STATIC_LIBRARIES}
      -Wl,--end-group
      ${TT_WIN_LIBS})
  else()
    target_link_libraries(TkTox PRIVATE
      toxcore_shared sntrup761 ${SODIUM_LIBRARIES} ${TCLTK_LIBRARIES}
      ${OPUS_LIBRARIES} ${VPX_LIBRARIES}
      ${TT_WIN_LIBS})
  endif()
elseif(TT_LINK_MODE STREQUAL "static")
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
if(WIN32)
  target_include_directories(TkTox SYSTEM PRIVATE ${TCLTK_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS}
    ${OPUS_INCLUDE_DIRS} ${VPX_INCLUDE_DIRS})
  # Make the build tree runnable as-is: the exe resolves TCL_LIBRARY/TK_LIBRARY
  # relative to itself, and imports three non-system DLLs. Stage all of it next
  # to TkTox.exe so a copy of build-win/ (or an install) is self-contained.
  add_custom_command(TARGET TkTox POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      ${TT_DEPS_LIBDIR}/tcl/lib/tcl8.6 ${CMAKE_BINARY_DIR}/tcl/lib/tcl8.6
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      ${TT_DEPS_LIBDIR}/tk/lib/tk8.6 ${CMAKE_BINARY_DIR}/tk/lib/tk8.6
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${TT_DEPS_LIBDIR}/bin/libwinpthread-1.dll
      ${TT_DEPS_LIBDIR}/bin/libopus-0.dll
      ${TT_DEPS_LIBDIR}/bin/libvpx-1.dll
      ${CMAKE_BINARY_DIR}
    COMMENT "Staging vendored Tcl/Tk script trees and runtime DLLs")
else()
  target_include_directories(TkTox SYSTEM PRIVATE ${TCLTK_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS}
    ${OPUS_INCLUDE_DIRS} ${VPX_INCLUDE_DIRS} ${XFT_INCLUDE_DIRS} ${ALSA_INCLUDE_DIRS})
endif()