# TkTox

A portable Tox messaging client with text messaging, file transfers, group chats, Tor support, port forwarding, and one-to-one audio/video calls.

TkTox is written in C17 and uses a Tk 8.6 interface. It supports:

- Linux and Windows
- `x86_64`and`aarch64`
- One-to-one and NGC group messaging
- Encrypted file transfers with resume support
- Contact avatars and offline message queueing
- Optional post-quantum end-to-end encryption
- Tor transport through SOCKS5
- One-to-one audio and video calls
- UDP and TCP port forwarding over Tox

This repository contains the TkTox client. Vendored dependencies under `vendor/` are third-party code.

<img width="554" height="340" alt="TkTox Screenshot" src="https://github.com/user-attachments/assets/02a356c6-2499-4d3d-8e31-4507d0feadb7" />


> [!CAUTION]
> ### ⚠️ EXPERIMENTAL SOFTWARE
>
> **This repository contains experimental cryptographic and stability-focused code.** It is a proof of concept and has **not** undergone a formal, independent security audit. 
> 
> By interacting with this software, you explicitly acknowledge and agree to the following risks:
>
> * **Cryptographic Vulnerabilities:** Undiscovered exploits, logic flaws, or edge-case economic attack vectors may exist within the protocol.
> * **Breaking Changes:** The API, state transitions, and underlying architecture are subject to rapid, unannounced modifications that may break backwards compatibility.
>
> **USE AT YOUR OWN RISK.** This software is provided "as is" without warranties of any kind. Never deploy un-audited code to production or risk capital you cannot afford to lose entirely.

## Security

### Message encryption

Set `TT_E2EE=1` to enable an additional encryption layer for one-to-one messages:

```bash
TT_E2EE=1 build/TkTox my.tox
```

The optional encryption layer uses X25519, SNTRUP761, and a double ratchet. It provides:

- Forward secrecy for message contents
- Post-quantum protection
- Automatic key rotation
- Out-of-order message handling
- Replay and corruption detection

A lock icon appears after a session is established. TkTox also displays a 32-character verification code for each contact. Compare this code with your contact through another trusted channel to protect against an active man-in-the-middle attack.

The encryption layer does not hide traffic metadata, provide deniability, or protect against an unverified active man-in-the-middle attack. See `CRYPTO_PLAN.md` for the full design.

### Encrypted local files

The following files are encrypted with `toxencryptsave`:

```text
<profile>.tox    Tox identity and savedata
<profile>.oq     Offline message queue
<profile>.ses    E2EE session state
<profile>.rsum   File-transfer resume data
```

A passphrase is required every time TkTox starts.

Interactive use:

```text
getpass
```

Headless use:

```bash
export TT_PASSPHRASE='your-passphrase'
```

An incorrect passphrase causes TkTox to exit instead of creating a new identity or overwriting the existing profile.

Older unencrypted profiles are migrated when they are next saved.

## Tor

TkTox can route all Tox traffic through a SOCKS5 proxy, including Tor.

Configure Tor in Settings or with:

```bash
export TT_PROXY_HOST=127.0.0.1
export TT_PROXY_PORT=9050
```

When Tor mode is enabled:

- UDP is disabled.
- DHT bootstrapping uses IP addresses.
- The interface shows the onion address prefix.
- Calls warn that audio should work but video may be unreliable.

Tor hides your real IP address from peers and Tox infrastructure. A global observer may still correlate traffic timing and volume.

## Building

The project uses vendored dependencies in `vendor/` — Tcl, Tk, Sodium, Opus,
VPX, Xft, ALSA (`vendor/.deps/`), the pinned `c-toxcore` checkout, and the
`sntrup761` KEM. `vendor/` is gitignored (third-party code), so a fresh clone
provisions it with one command:

```bash
bash fetch-vendor.sh            # everything for the host arch (Linux)
bash fetch-vendor.sh win        # ... or for the mingw Windows build
bash fetch-vendor.sh check      # report what is present / missing
```

`fetch-vendor.sh` clones `c-toxcore` at a pinned commit (with its `cmp`
submodule), restores the tracked `sntrup761` snapshot, and drives
`fetch-deps.sh` / `fetch-deps-win.sh` for the binary deps — including the
host `-dev` set (fontconfig, freetype, png, brotli, bz2) that `xft.pc`
requires when the host lacks those `-dev` packages. The tiny public-domain
`sntrup761` KEM source itself is tracked in `vendor-sntrup761/` (see
BUILD.md §2b).

### Native Linux build

```bash
bash fetch-vendor.sh            # first time on a fresh clone
. ./env.sh
cmake --build build --target TkTox -j4
```

`env.sh` detects the host architecture and configures the required library paths. Set `TT_DEPS_TRIPLET` to override the detected dependency triplet.

### Cross-compiling for Linux

Fetch dependencies for the target architecture:

```bash
bash fetch-deps.sh amd64
```

Other supported targets include `arm64` and `riscv64`.

Configure and build:

```bash
. ./env.sh

cmake -S . -B build-amd64 \
  -DCMAKE_TOOLCHAIN_FILE=cmake/cross-linux-gnu.cmake \
  -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-amd64 --target TkTox -j4
```

### Windows with MinGW

Windows builds use `vendor/.deps-win/` and do not use `env.sh`.

```bash
bash fetch-deps-win.sh
```

Then configure and build:

```bash
PKG_CONFIG_PATH="$PWD/vendor/.deps-win/tcl/lib/pkgconfig:\
$PWD/vendor/.deps-win/tk/lib/pkgconfig:\
$PWD/vendor/.deps-win/sodium/lib/pkgconfig:\
$PWD/vendor/.deps-win/opus/lib/pkgconfig:\
$PWD/vendor/.deps-win/vpx/lib/pkgconfig" \
cmake -S . -B build-win \
  -DCMAKE_TOOLCHAIN_FILE=cmake/cross-mingw.cmake \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-win -j4
```

See `BUILD.md` for complete Windows requirements.

## Running

Launch the graphical client:

```bash
build/TkTox
```

Open a specific profile:

```bash
build/TkTox my.tox
```

Starting without a profile opens a profile picker, where you can create, rename, delete, or open profiles.

Run the manual UI test client:

```bash
./test-ui.sh [profile.tox]
```

Run the platform and dependency self-check:

```bash
build/TkTox --selfcheck
```

The self-check does not require a profile, network connection, or display.

### Headless modes

```bash
build/TkTox --bot PROFILE [PEER_TOXID]
build/TkTox --echo PROFILE
build/TkTox --headless PROFILE
```

These modes provide scripted testing, an echo bot, and a Tox engine without the graphical interface.

## Audio and Video Calls

TkTox has preliminary support for one-to-one audio and video calls

Available controls include:

- Answer, decline, or cancel
- Hang up
- Pause and resume
- Microphone mute
- Speaker mute
- Start and stop the camera
- Switch between local and remote video

Audio uses Opus. Video uses VPX and can be enabled when the call starts or during an active audio call.

The camera uses `/dev/video0` through V4L2 on Linux and tries these resolutions:

```
1280x720
640x480
320x240
```

If no camera or audio device is available, the call continues in audio-only mode where possible.

Group audio/video is not supported.

## Port Forwarding

TkTox can forward local UDP and TCP ports between friends over an encrypted Tox connection. This is useful for LAN games, SSH, RDP, and other services.

No public IP address, router configuration, or central server is required.

### Supported transports

- **UDP:** Best for real-time game traffic. Packets may be lost or reordered.
- **TCP:** Reliable and ordered. Suitable for SSH, RDP, Minecraft, and web services.

Each tunnel supports up to eight port ranges and 32 ports per protocol.

Use comma-separated ports and ranges:

```
2300-2310,80
```

Example:

```
MineTest/Luanti:
UDP 30000

Minecraft:
TCP 25565
```

Enter ports in the field matching the protocol used by the service. A TCP value of `0` means that TCP forwarding is disabled.

### Client addresses

Each client tunnel receives a separate loopback address, such as:

```
127.0.0.2
127.0.0.3
```

This allows multiple tunnels to use the same ports without conflicts. No network configuration is required.

### Tunnel commands

Host a service:

```bash
build/TkTox --tunnel-host PROFILE SERVER_HOST UDP_PORTS [TCP_PORTS] \
  [--tunnel-trust-all] [FRIEND_TOXID...]
```

Join a service:

```bash
build/TkTox --tunnel-client PROFILE HOST_TOXID UDP_PORTS [TCP_PORTS]
```

The graphical interface provides a **Tunnels** panel, a **Share a port…** action, and Accept/Decline controls for incoming invitations.

## File-Transfer Resume

Interrupted incoming transfers can resume after a restart.

TkTox stores the file ID, destination path, and received offset in:

```text
<profile>.rsum
```

When the same file is offered again, TkTox continues from the existing partial file instead of downloading it again from the beginning.

## Profile Files

A profile may contain:

```text
<profile>.tox    Encrypted Tox profile
<profile>.oq     Offline message queue
<profile>.tt     Tor/proxy settings
<profile>.ses    E2EE session state
<profile>.rsum   File-transfer resume data
```

Audio/video settings are session-only and are not saved.

## Tests

Run the messaging, file, and group tests:

```bash
bash ngc-test.sh full
```

Run call signaling tests:

```bash
bash av-test.sh
TT_BOT_CALL_VTEST=1 bash av-test.sh
TT_BOT_CALL_PAUSE=1 bash av-test.sh
TT_BOT_CALL_DECLINE=1 bash av-test.sh
TT_BOT_CALL_OFFLINE=1 bash av-test.sh
```

Run calls as part of the full test flow:

```bash
TT_BOT_CALL=1 bash ngc-test.sh full
```

Test end-to-end encryption:

```bash
bash e2ee-test.sh
bash e2ee-test.sh reorder
bash e2ee-test.sh replay
```

Test port forwarding:

```bash
bash tunnel-test.sh
bash tunnel-multi-test.sh
```

Test file-transfer resume:

```bash
bash resume-test.sh
```

All regression tests should exit with status `0` on both peers. Warnings and errors from `TkTox/src` are treated as build failures.

Additional call-development notes are available in `AV_PLAN.md`.

