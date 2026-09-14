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

**Minimum for a host aarch64 build of either path:**

```sh
sudo apt-get install -y \
  build-essential cmake pkg-config curl dpkg-dev \
  libfontconfig1-dev libfreetype6-dev libpng-dev libbz2-dev libasound2-dev \
  libx11-dev libxrender-dev libxcb1-dev libxext-dev libxss-dev \
  zlib1g-dev libexpat1-dev
cd TkTox && bash fetch-deps.sh arm64
```
