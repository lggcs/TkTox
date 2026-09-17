# BUILD.md — dependencies for a clean TkTox build

TkTox supports two clean build paths, selected with the `TT_LINK_MODE` CMake
option:

1. **Fully static / standalone** (`-DTT_LINK_MODE=static`) — the crypto core,
   codecs, and the entire X/UI stack are linked statically into one
   self-contained binary. The only exceptions are ALSA (`libasound`) and glibc,
   which stay dynamic because Ubuntu ships `libasound` shared-only.
2. **Fully dynamic** (`-DTT_LINK_MODE=dynamic`, the default) — everything is
   linked as shared libraries; the binary is small and depends on shared libs
   at runtime.

```sh
# static (standalone) build
cmake -S . -B build-static -DTT_LINK_MODE=static -DCMAKE_BUILD_TYPE=Release
cmake --build build-static --target TkTox -j4

# dynamic build
cmake -S . -B build-dyn -DTT_LINK_MODE=dynamic -DCMAKE_BUILD_TYPE=Release
cmake --build build-dyn --target TkTox -j4
```

This file lists every package you must install on an Ubuntu host for each path.
The vendored deps (tcl, tk, xft, sodium, opus, vpx, alsa) are **not** installed
via apt — they are provisioned into `vendor/.deps/` by `fetch-deps.sh` (see
below). Only the host build tools, cross toolchains, and the OS X/UI stack are
installed via apt.

---

## 1. Host build tools (required for BOTH paths)

```sh
sudo apt-get install -y \
  build-essential \
  cmake \
  pkg-config \
  curl \
  dpkg-dev
```

| Package          | Purpose                                        |
|------------------|------------------------------------------------|
| `build-essential` | gcc, make, binutils (host compiler)            |
| `cmake`          | build system (>= 3.24)                         |
| `pkg-config`     | resolves vendored `.pc` files                  |
| `curl`           | `fetch-deps.sh` downloads the vendored debs    |
| `dpkg-dev`       | `dpkg-deb` extracts the vendored debs          |

---

## 2. Vendored deps (required for BOTH paths — NOT via apt)

These are fetched and extracted into `vendor/.deps/` by `fetch-deps.sh`. Do
**not** install them with apt; the build resolves them through `PKG_CONFIG_PATH`
set by `env.sh`.

```sh
cd TkTox
bash fetch-deps.sh arm64        # or amd64 / riscv64
```

The debs are downloaded over HTTPS. TLS protects the fetch against a
network MITM but not against a compromised mirror; for hardened builds,
provision from a local apt mirror or aptly snapshot instead (apt's Release
signatures verify what a plain curl cannot).

| Vendored pkg | Provides                          |
|--------------|-----------------------------------|
| `tcl8.6`     | Tcl 8.6 (UI interpreter)          |
| `tk8.6`      | Tk 8.6 (GUI toolkit)             |
| `libxft`     | Xft (Tk transitive dep)          |
| `libsodium`  | crypto (X25519, XChaCha20, AES)  |
| `libopus`    | audio codec (toxav)              |
| `libvpx`     | video codec (toxav)              |
| `libasound2` | ALSA audio device layer          |

Each is provisioned with both `.a` (static) and `.so` (shared) where the
upstream deb ships them, so the same tree serves both build paths.

---

## 3. OS X/UI stack (required for BOTH paths)

These are the system libraries the GUI needs. The **runtime** shared libs are
already present on a desktop Ubuntu; the **`-dev`** packages are needed to
build against them.

### 3a. Runtime shared libs (present on a desktop; verify)

```sh
sudo apt-get install -y \
  libfontconfig1 \
  libfreetype6 \
  libpng16-16 \
  libbz2-1.0 \
  libasound2 \
  libx11-6 \
  libxrender1 \
  libxcb1 \
  libxext6 \
  libxss1
```

### 3b. Development headers + static archives (required to BUILD)

```sh
sudo apt-get install -y \
  libfontconfig1-dev \
  libfreetype6-dev \
  libpng-dev \
  libbz2-dev \
  libasound2-dev \
  libx11-dev \
  libxrender-dev \
  libxcb1-dev \
  libxext-dev \
  libxss-dev \
  zlib1g-dev \
  libexpat1-dev
```

> **Fully-static note:** the `-dev` packages above are what provide the static
> `.a` archives (`libfontconfig.a`, `libfreetype.a`, `libpng16.a`,
> `libbz2.a`, `libX11.a`, ...) that the static link pulls in. If any of
> these `.a` files are missing after install, the static link will fail
> with an "undefined reference" / "cannot find -l..." error — that is the
> signal that the corresponding `-dev` package is not installed.
>
> `libasound2-dev` is the one exception: Ubuntu ships it **shared-only** (no
> `libasound.a`), so ALSA stays dynamic even in the static path. That is
> expected and not an error.

---

## 4. Cross toolchains (only for cross-compiling to other arches)

The host build (aarch64) needs only `gcc-aarch64-linux-gnu` (already present).
To cross-compile for **x86_64** or **riscv64**, install the matching toolchain:

```sh
# x86_64 target
sudo apt-get install -y gcc-x86-64-linux-gnu g++-x86-64-linux-gnu

# riscv64 target
sudo apt-get install -y gcc-riscv64-linux-gnu g++-riscv64-linux-gnu
```

Then provision the vendored deps for that arch and build with the toolchain
file (see `README.md` → Build):

```sh
bash fetch-deps.sh amd64        # or riscv64
. ./env.sh
cmake -S . -B build-amd64 \
  -DCMAKE_TOOLCHAIN_FILE=cmake/cross-linux-gnu.cmake \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-amd64 --target TkTox -j4
```

---

## 5. Windows (mingw-w64 cross-compile)

The Windows build is a cross-compile from Linux and is entirely additive: the
Linux path above is unchanged, and every Windows-specific change is gated on
`_WIN32` (see `src/platform.h`, which is a pure POSIX pass-through on
non-Windows).

### 5a. Toolchain

```sh
sudo apt-get install -y gcc-mingw-w64-x86-64-win32
```

This provides `x86_64-w64-mingw32-gcc`. The `-win32` variant (not `-posix`)
is required: it uses the Win32 threads model, and winpthreads supplies the
`pthread_*`, `clock_gettime`, and `nanosleep` symbols TkTox and toxcore need.

### 5b. Vendored Windows deps (NOT via apt)

Windows has no ALSA and no X11, so the Windows dep set is **tcl, tk, sodium,
opus, vpx** — built from source as mingw PE static archives and provisioned
into `vendor/.deps-win/` by `fetch-deps-win.sh`.

```sh
cd TkTox
bash fetch-deps-win.sh          # all: tcl, tk, sodium, opus, vpx, runtime DLLs
bash fetch-deps-win.sh tcl      # or tk / sodium / opus / dlls / clean
```

The Windows tree differs from the Linux one: it holds **static `.a` archives
plus runtime DLLs**, not `.deb` trees.

| Vendored pkg | Provides                                            |
|--------------|-----------------------------------------------------|
| `tcl`        | `libtcl86.a` + `libtclstub86.a` + `lib/tcl8.6` scripts |
| `tk`         | `libtk86.a` + `lib/tk8.6` scripts + Tk's X11 headers |
| `libsodium`  | crypto (X25519, XChaCha20, AES)                     |
| `libopus`    | audio codec (toxav)                                 |
| `libvpx`     | video codec (toxav)                                 |
| `bin/`       | `libwinpthread-1.dll`, `libopus-0.dll`, `libvpx-1.dll` |

Three mingw-specific details are load-bearing and would otherwise be silent
failures:

- **`STATIC_BUILD=1`** — `tcl.h`/`tk.h` mark their API `__declspec(dllimport)`
  unless this macro is set, so the linker would hunt for `__imp_*` stubs that
  the static archives do not contain. Upstream documents this verbatim in
  `tcl.h`. Tk is built with `USE_TCL_STUBS`, so consumers must also link
  `libtclstub86.a` (supplies `Tcl_InitStubs` and `tclStubsPtr`).
- **`-fno-builtin-printf` and friends** — GCC's builtin knowledge of the
  `printf` family uses the MSVCRT format profile, which overrides mingw's
  `__attribute__((format(__gnu_printf__)))` declarations. The result is
  spurious `unknown conversion type character 'z'` and bogus
  `'%d' expects argument of type 'int'` warnings on every `%zu` site.
  Disabling the builtins makes GCC validate against the declared
  `gnu_printf` profile instead. `__USE_MINGW_ANSI_STDIO=1` alone is **not**
  sufficient.
- **`_POSIX_C_SOURCE=200809L`** — `localtime_r` is gated behind
  `_POSIX_THREAD_SAFE_FUNCTIONS`, which is evaluated at the *first* inclusion
  of `time.h`. It must therefore be a command-line define, not a header
  define.

### 5c. Configure and build

```sh
cd TkTox
PKG_CONFIG_PATH="$PWD/vendor/.deps-win/tcl/lib/pkgconfig:\
$PWD/vendor/.deps-win/tk/lib/pkgconfig:\
$PWD/vendor/.deps-win/sodium/lib/pkgconfig:\
$PWD/vendor/.deps-win/opus/lib/pkgconfig:\
$PWD/vendor/.deps-win/vpx/lib/pkgconfig" \
cmake -S . -B build-win \
  -DCMAKE_TOOLCHAIN_FILE=cmake/cross-mingw.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-win -j"$(nproc)"
```

`TT_LINK_MODE` defaults to `static` for Windows (toxcore + all vendored deps
static; only the system DLLs are dynamic), which yields a self-contained
`build-win/TkTox.exe`. There is no `. ./env.sh` for Windows: `env.sh` builds
the Linux `PKG_CONFIG_PATH`, so the Windows path sets `PKG_CONFIG_PATH`
explicitly as above.

### 5d. Running it

`build-win/` is self-contained and can be copied to a Windows machine as-is:
a POST_BUILD step stages the Tcl/Tk script trees under `tcl/lib/tcl8.6` and
`tk/lib/tk8.6`, and the three non-system DLLs next to the exe. TkTox locates
the script trees **relative to the running executable** (not via the
build-time path baked into `TCL_LIBRARY`/`TK_LIBRARY`), so a copy of the
directory works from anywhere.

```
build-win/
├── TkTox.exe
├── libopus-0.dll  libvpx-1.dll  libwinpthread-1.dll
├── tcl/lib/tcl8.6/     (22 files)
└── tk/lib/tk8.6/       (37 files)
```

Smoke test — run this first. It needs no profile, network, or display, and it
checks the things most likely to be wrong in a cross-compiled exe: that the
Tcl/Tk script trees were staged next to the binary, that the three DLLs are
present, that Winsock starts, and that the `%zu`/`localtime_r` shims work.

```sh
cd build-win
TkTox.exe --selfcheck
```

Expected tail (`Tk_Init` is present on Windows; the Tcl/Tk patch levels and
toxcore/libsodium versions reflect whatever the vendored trees provide):

```
TkTox self-check
  version 0.1.0
  platform windows
Platform glue
  [ok] tt_net_init (WSAStartup)
  [ok] __USE_MINGW_ANSI_STDIO %zu     1234567890
  [ok] localtime_r
  [ok] libopus-0.dll                  <exe dir>\libopus-0.dll
  [ok] libvpx-1.dll                   <exe dir>\libvpx-1.dll
  [ok] libwinpthread-1.dll            <exe dir>\libwinpthread-1.dll
Tcl/Tk interpreter
  tcl library: <exe dir>\tcl\lib\tcl8.6
  tk  library: <exe dir>\tk\lib\tk8.6
  [ok] tcl script tree                <exe dir>\tcl\lib\tcl8.6
  [ok] tk script tree                 <exe dir>\tk\lib\tk8.6
  [ok] Tcl_CreateInterp
  [ok] Tcl_Init                       <patchlevel>
  [ok] Tk_Init                        <patchlevel>
Engine and crypto
  [ok] toxcore                        <major.minor.patch>
  [ok] libsodium                      <version>
  [ok] tox_new                        ok
  [ok] tox_self_get_address
SELF-CHECK PASSED
```

Exit code 0 means every check passed; 1 prints the failing entries. A
`[FAIL] tcl script tree` naming the **build machine's** path means the exe
was copied without the staged trees — copy the whole `build-win/` directory,
not just the `.exe`. Then, once the self-check is green, the network path:

```sh
cd build-win
TkTox.exe --headless myprofile      # prints ToxID and self-connection state
```

### 5e. Windows platform notes

- **Video capture is disabled.** `src/video_win.c` is a stub:
  `tt_video_start` returns false and logs "video: capture unavailable on this
  platform — disabled". Audio capture/playback works via `waveIn`/`waveOut`
  (`src/audio_win.c`).
- **No ALSA, no X11, no Xft.** Tk links GDI directly on Windows; the system
  lib list is Tk's `win/configure` `LIBS` + `LIBS_GUI` plus `ws2_32`/
  `iphlpapi` (toxcore sockets), `winmm` (waveIn/waveOut), and `bcrypt`
  (toxcore's random).
- **Sidecar file permissions.** `fchmod` has no MSVCRT counterpart, so
  `tt_fchmod` is a no-op on Windows; the sidecars already live under the
  user's profile directory, which Windows ACLs own.
- **`rename` semantics.** `rename(2)` on Windows refuses to clobber an
  existing target, so atomic sidecar writes go through `tt_rename`, which
  removes the target first.

---

## Summary checklist

| Dependency                          | Static path | Dynamic path |
|-------------------------------------|:-----------:|:------------:|
| `build-essential`, `cmake`, `pkg-config`, `curl`, `dpkg-dev` | ✅ | ✅ |
| `fetch-deps.sh` (vendored tcl/tk/xft/sodium/opus/vpx/alsa)   | ✅ | ✅ |
| X/UI `-dev` packages (3b)           | ✅ | ✅ |
| X/UI runtime shared libs (3a)       | ✅ | ✅ |
| `gcc-aarch64-linux-gnu` (host)      | ✅ | ✅ |
| `gcc-x86-64-linux-gnu` (cross)      | only if cross-compiling | only if cross-compiling |
| `gcc-riscv64-linux-gnu` (cross)     | only if cross-compiling | only if cross-compiling |
| `gcc-mingw-w64-x86-64-win32` + `fetch-deps-win.sh` (Windows) | n/a | n/a — see §5 |

**Minimum for a host aarch64 build of either path:**

```sh
sudo apt-get install -y \
  build-essential cmake pkg-config curl dpkg-dev \
  libfontconfig1-dev libfreetype6-dev libpng-dev libbz2-dev libasound2-dev \
  libx11-dev libxrender-dev libxcb1-dev libxext-dev libxss-dev \
  zlib1g-dev libexpat1-dev
cd TkTox && bash fetch-deps.sh arm64
```
