TkTox — a portable Tox messaging client for Linux
=====================================================

A clean-room C17 client on the vendored c-toxcore: text messaging (1:1 + NGC
groups), file transfer, avatars, offline queueing, Tor (SOCKS5) transport, and
1:1 audio/video calls. Tk 8.6 GUI (C-embedded interpreter, no Tcl scripts);
everything runs on a single tox thread plus one UI thread. The client is
architecture-portable (aarch64 / x86_64 / riscv64) — the multiarch triplet is
a single build knob (see Build below).

This tree is the TkTox project. Vendored upstream (vendor/c-toxcore,
vendor/.deps/*) is third-party code; TkTox/src is the client.

End-to-end encryption (TT_E2EE=1)
---------------------------------
An application-layer PQDR (Post-Quantum Double Ratchet) on top of the 1:1
friend-message channel, modeled on SimpleX's pqdr.md: hybrid X25519 + SNTRUP761
key agreement, with the KEM secret folded into EVERY root step (the property
libsignal's PQXDH lacks — PQ covers session init only). Tox remains the
transport; this layer rides inside friend messages as defense in depth. See
CRYPTO_PLAN.md for the full design.

- **Enable:** run with `TT_E2EE=1`. The layer handshakes in-band on the first
  message (no pre-exchange UX); a 🔒 badge appears on the roster row once the
  session is established.
- **Verify:** Settings shows the 32-hex verification code for the selected
  contact — it derives from the handshake root and is identical on both peers.
  Compare it out-of-band to confirm no MITM.
- **Ratchet:** per-direction roots fold `DH_out || KEM_secret` every re-key
  (auto-triggered every 64 frames); out-of-order frames are recovered through a
  skipped-key store (maxSkip 512); replayed/corrupt frames are rejected without
  consuming chain state. An undecryptable frame shows a generic system line
  ("[encrypted message could not be decrypted]") — never failure details.
- **Honest limits:** in-band init trusts Tox's transport E2EE for the handshake
  (the verify code is the OOB check); forward secrecy survives clean restarts
  (v2 session persistence — see below) but a crash (SIGKILL/power loss) still
  loses the in-memory session, so it is best-effort, not absolute; no
  deniability claim (Tox long-term identity keys pin the session).

Threat model (what the PQ ratchet actually protects)
----------------------------------------------------
The PQDR ratchet protects **message content** against two real-world attack
classes:

- **Long-term key compromise (retrospective decryption).** If an attacker
  exfiltrates a long-term identity key, they cannot decrypt previously
  recorded message content. The per-direction ratchet folds
  `DH_out || KEM_secret` every re-key, so past chain keys are unrecoverable
  from the long-term key alone — forward secrecy at the content layer.
- **Harvest-now-decrypt-later (quantum).** An attacker recording ciphertext
  today cannot decrypt it later with a quantum computer. The SNTRUP761 KEM
  secret is folded into *every* root step, not just session init, so the
  post-quantum property holds for the whole session, not only the handshake.

**Threat level — content confidentiality is the strong claim; metadata is
not.** The ratchet raises content confidentiality to a strong level (forward
secrecy + PQ), but it is defense-in-depth layered on a transport that itself
has no ratchet. It does **not** protect:

- **Metadata / traffic analysis.** A passive observer still sees that two
  endpoints are exchanging messages over the static toxcore transport; the
  onion layer hides *which* endpoints, not *that* traffic flows.
- **Active MITM during the in-band handshake.** Mitigated only by comparing
  the 32-hex verify code out-of-band; without that check, an active MITM can
  establish a session.
- **Deniability.** Tox long-term identity keys pin the session; there is no
  deniability claim.

Safest usage (how to close the metadata gap)
--------------------------------------------
The metadata gap above is closed by running over Tor (see the Tor section):
Tor hides your real IP from every peer and DHT/relay node, and hides the fact
that you are using tox at all from a local observer (your ISP / LAN) — the
traffic looks like ordinary Tor TLS. The tox onion layer then hides the
friend relationship from the Tor exit node. For the strongest posture:

- **Run in Tor mode** (Settings, or `TT_PROXY_HOST`/`TT_PROXY_PORT`) so all
  tox traffic rides the tunnel. This is the single biggest metadata win.
- **Verify the 32-hex code out-of-band** for each contact before trusting a
  session — it is the only defense against an active MITM during the in-band
  handshake.
- **Accept the residual Tor limit:** a global passive adversary that can
  observe both your guard node and your contact's guard node may correlate
  timing/volume. This is inherent to low-latency anonymity networks, not a
  tox-specific flaw.

Session persistence (v2)
------------------------
Established sessions are persisted to a `<profile>.ses` sidecar so the M4
ratchet continues folding across clean restarts (forward secrecy survives
restarts). The sidecar is encrypted with a **separate** at-rest key derived
from the same passphrase but a **distinct random salt**, so the profile key
and session key are cryptographically independent. Pending handshake scratch
is deliberately NOT persisted — it is stale on restart; a fresh handshake is
the correct recovery. No active sessions -> the sidecar is removed. The
sidecar serializes its multi-byte fields big-endian, so a profile moved
between architectures restores correctly.

At-rest encryption (mandatory)
------------------------------
The `<profile>.tox` savedata and the `<profile>.oq` offline queue are
encrypted with toxencryptsave (scrypt KDF, NaCl `crypto_box` AEAD) — the same
module uTox and qTox use. The passphrase is required at every start:

- **Interactive:** a `getpass` prompt on a tty.
- **Headless/automation:** `TT_PASSPHRASE` env (the test scripts set their
  own). A non-tty run without `TT_PASSPHRASE` refuses to start.
- **Wrong passphrase:** startup fails hard (rc=1) rather than create a fresh
  identity and overwrite the profile.
- **Migration:** a pre-encryption plaintext profile loads as-is and is
  re-saved encrypted on the next save.
- **Atomicity:** profile and offline-queue saves are temp-file + rename, so a
  crash mid-write cannot corrupt the identity.

Build
-----
Requires the vendored dependency tree inside the project (vendor/.deps/:
tcl, tk, xft, sodium, opus, vpx, alsa) and a configured cmake build dir
(build/). The vendored tree is laid out per multiarch triplet
(vendor/.deps/<pkg>/usr/lib/<triplet>); `env.sh` computes the triplet from
the host (or `$TT_DEPS_TRIPLET`) and sets `PKG_CONFIG_PATH` +
`LD_LIBRARY_PATH`:

    . ./env.sh
    cmake --build build --target TkTox -j4

Cross-compiling: provision `vendor/.deps/` for the target arch, then
configure with the toolchain file (which derives the triplet from the
target processor):

    bash fetch-deps.sh amd64            # or arm64 / riscv64
    . ./env.sh
    cmake -S . -B build-amd64 \
      -DCMAKE_TOOLCHAIN_FILE=cmake/cross-linux-gnu.cmake \
      -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
      -DCMAKE_BUILD_TYPE=Release
    cmake --build build-amd64 --target TkTox -j4

Windows (mingw-w64 cross-compile): a separate dep tree, a separate toolchain
file, and no `env.sh` (set `PKG_CONFIG_PATH` yourself). `TT_LINK_MODE`
defaults to `static`, so the result is a self-contained `build-win/` you can
copy to a Windows machine as-is. See BUILD.md §5 for the full list of
mingw-specific requirements.

    bash fetch-deps-win.sh              # tcl, tk, sodium, opus, vpx + runtime DLLs
    PKG_CONFIG_PATH="$PWD/vendor/.deps-win/tcl/lib/pkgconfig:\
    $PWD/vendor/.deps-win/tk/lib/pkgconfig:\
    $PWD/vendor/.deps-win/sodium/lib/pkgconfig:\
    $PWD/vendor/.deps-win/opus/lib/pkgconfig:\
    $PWD/vendor/.deps-win/vpx/lib/pkgconfig" \
    cmake -S . -B build-win \
      -DCMAKE_TOOLCHAIN_FILE=cmake/cross-mingw.cmake \
      -DCMAKE_BUILD_TYPE=Release
    cmake --build build-win -j4

Run
---
    ./test-ui.sh [profile.tox]     # Tk UI + a long-lived echo bot for manual testing
    build/TkTox                # Tk UI (normal mode)

Diagnostics (run first on a new machine or after moving a Windows build):
    --selfcheck                    platform glue, Tcl/Tk trees, crypto, engine
The self-check needs no profile, network, or display: it resolves the same
Tcl/Tk script trees the UI uses (on Windows, the staged copy beside the
exe), boots an interpreter, and creates a throwaway tox instance. Exits 0
when everything is present, 1 with a per-check report otherwise.

Headless modes (regression/automation; see ngc-test.sh / av-test.sh):
    --bot PROFILE [PEER_TOXID]     scripted bot (message/file/group/call phases)
    --echo PROFILE                 never exits, echoes messages (UI test peer)
    --headless PROFILE             run the tox engine without the UI
Environment: TT_BOT_CALL=1 (call phase), TT_BOT_CALL_SOLO=1 (call-only),
TT_BOT_CALL_VTEST=1 (video wire test), TT_PROXY_HOST/TT_PROXY_PORT (Tor).

Calls (1:1 audio/video)
-----------------------
Chat header: 📞 Call starts audio (32 kbit/s Opus) and shows 📵 Cancel while
ringing; the callee gets ✅ Answer / ✖ Decline / 📹 Video (Video answers with
2500 kbit/s VPX video). In-call: 📵 Hang up, ⏸ Pause / ▶ Resume (toxav call
control — Resume only after OUR pause; while the PEER's pause is up the
button renders disabled "⏸ Peer paused"), 🎤 Mute / 🎤 Unmute (our MIC),
🔊 Mute out / 🔇 Unmute out (our SPEAKER), 📷 Camera / 📷 Stop cam (start or
stop OUR camera mid-call — video is no longer peer-initiated-only), duration
timer ("M:SS on call" / "M:SS paused"), and — when the call carries video
(peer-offered or our own camera) — 🔄 Show self / 🔄 Show peer (video pane
swap). The roster callmark follows the sub-state:
🔔 ringing, ⏸ paused, 📞 active. The contact avatar (when set) sits at the
far right of the header, outside the call buttons. Incoming/outgoing video is a
Tk photo pane (YUV420 -> BT.601 RGB in C, ~30 fps repaint ceiling, auto-hide
after 3 s of no frames). The camera layer opens /dev/video0 (V4L2 MMAP,
YUYV -> planar YUV420, sizes 1280x720 -> 640x480 -> 320x240) when the call
sends video — either because the peer offered it or because you pressed
📷 Camera (the engine toggles video sending mid-call via
toxav_video_set_bit_rate); without a camera (or ALSA device) the call
continues audio-only / mute-recv with a log note. Bit-rate adaptation: toxav
packet-loss suggestions (> 10%) are applied via toxav_*_set_bit_rate,
adjust-down only.

Group A/V is NOT supported (upstream toxcore groupav covers legacy
conferences only; NGC has no A/V). Audio never crosses the UI event queue
(device rings drain straight into toxav on the tox thread).

Tunnels (UDP + TCP port forwarding over Tox)
--------------------------------------------
A tuntox-style port forwarder for LAN-party gaming: the host shares a local
game server's ports with friends over the encrypted Tox channel, and each
friend's game connects to a local loopback IP on their own machine — no port
forwarding, no public IP, no central server. Two transports ride the same
tunnel:

- **UDP (lossy)** — Tox lossy custom packets (type 200). For real-time game
  traffic (MineTest UDP 30000, AoE3 UDP 2300-2310). May drop/reorder.
- **TCP (lossless)** — Tox lossless custom packets (type 162). For SSH, RDP,
  Minecraft (TCP 25565), AoE3 TCP 80/2300-2310. Reliable and ordered.

Each tunnel carries a **list of disjoint port ranges per protocol** (up to 8
ranges / 32 ports per protocol), so one tunnel can carry all of a game's
scattered ports — e.g. AoE3 Original (UDP 2300-2310 + TCP 80,2300-2310) or
AoE3 DE (TCP 3478,5222,8888,27015,27036). Ports are entered as comma-separated
numbers/ranges (e.g. `2300-2310,80`).

**Loopback octets (client side).** Each client tunnel auto-assigns its own
loopback IP (`127.0.0.2`, `.3`, …) instead of all binding `127.0.0.1`, so
multiple simultaneous tunnels sharing the same ports don't collide — and
games that only accept an IP (not individual ports) can point at the tunnel's
IP on the well-known port. The whole `127.0.0.0/8` block is loopback on both
Linux and Windows, so this works with zero config. The assignment is an
atomic bind-and-claim (no probe race), so two friends joining the same host
with the same ports get distinct octets.

**Host side.** The host never binds a local port — it only makes outbound
connections to the server, one per friend. So sharing the same port combo
with multiple friends works: each friend gets an independent tunnel, the game
server sees them as distinct clients, and the Tunnels panel lists one row per
friend (endpoint + friend name + Stop). The host tunnel accepts an arbitrary
`server_host`, so you can point different host tunnels at different loopback
octets on the host to run two services on the same port number.

**UI.** The tool-row **Tunnels** button opens a panel listing active tunnels
endpoint-first ("Hosting 127.0.0.1 udp 2300-2310 tcp 80" / "Joined
127.0.0.2 udp 2300-2310 tcp 80"), each with the friend underneath and a Stop
button. The roster menu **Share a port…** opens the host dialog (server host +
UDP ports + TCP ports); an incoming invite shows Accept/Decline with an
optional local-port override (blank = auto-pick free ones). Host access is
allowlist-controlled (the invited friend is auto-allowlisted; `--tunnel-trust-all`
auto-allowlists any friend that connects, opt-in for testing).

Headless entry points (see tunnel-test.sh / tunnel-multi-test.sh):
    --tunnel-host <profile> <server_host> <udp_ports> [<tcp_ports>]
        [--tunnel-trust-all] [<friend_toxid>...]
    --tunnel-client <profile> <host_toxid> <udp_ports> [<tcp_ports>]

Tor
---
SOCKS5 proxy (Tor SocksPort) routes ALL tox traffic: UDP disabled, DHT
bootstrap via IP literals only. Configure in Settings (persisted in the
<profile>.tt sidecar) or TT_PROXY_HOST/TT_PROXY_PORT env (env wins). The
status badge shows the onion prefix while Tor mode is active; calls warn
"audio ok, video may struggle" in the transcript.

Profiles
--------
<profile>.tox (toxencryptsave-encrypted savedata; passphrase required at
every start — see "At-rest encryption" above) + <profile>.oq (encrypted
offline queue) + <profile>.tt (proxy sidecar) + <profile>.ses (encrypted
E2EE session persistence, v2 — see above) + <profile>.rsum (encrypted
file-transfer resume index — see "File-transfer resume" below). AV settings
are session-only — nothing to persist.

Launching `build/TkTox` with no profile argument opens a **profile picker**
(Tk): list existing profiles in the current directory, plus New / Rename /
Delete / Open. New and Rename sanitize names to `[A-Za-z0-9._-]` and refuse
to clobber an existing profile; Rename/Delete also move/remove the profile's
sidecars (.oq, .tt, .ses, .hist, .ava, .rsum). Passing a profile argument
(`build/TkTox my.tox`) or any headless mode (`--bot`, `--echo`, `--headless`,
tunnel modes) bypasses the picker entirely.

File-transfer resume
--------------------
A receive-side transfer that is interrupted (cancel, crash, or disconnect)
persists a resumable partial: the engine records the sender's stable
`file_id` (the sender's content SHA-256), the destination path, and the byte
offset in the encrypted `<profile>.rsum` sidecar. When the same file is
re-offered after a restart, the engine auto-resumes — it seeks the partial
and sends `TOX_FILE_CONTROL_RESUME` to the sender, so only the missing tail
is re-downloaded (no accept dialog; the UI shows a "resuming" line). The
entry is dropped once the transfer completes. Senders use a content-hash
`file_id` so re-offers of the same file match across restarts.

Tests
-----
    bash ngc-test.sh full                        # messaging/files/groups regression
    bash av-test.sh                              # call signaling (solo, ~15 s)
    TT_BOT_CALL_VTEST=1 bash av-test.sh          # + synthetic video exchange both ways,
                                                 #   + mid-call video bit-rate change
    TT_BOT_CALL_PAUSE=1 bash av-test.sh          # + mid-call pause/resume cycle
    TT_BOT_CALL_DECLINE=1 bash av-test.sh        # peer declines; caller sees FINISHED,
                                                 #   never an ACTIVE state
    TT_BOT_CALL_OFFLINE=1 bash av-test.sh        # call to an unreachable friend is
                                                 #   rejected (NOT_CONNECTED), no crash
    TT_BOT_CALL=1 bash ngc-test.sh full          # call phase inside the full flow
    bash e2ee-test.sh                            # E2EE handshake + roundtrip + verify codes
    bash e2ee-test.sh reorder                    # + out-of-order frames via skipped-key store
    bash e2ee-test.sh replay                     # + re-injected frame rejected as replay
    bash tunnel-test.sh                          # UDP lossy + TCP lossless round-trips over Tox
    bash tunnel-multi-test.sh                    # 2 clients, same ports, distinct loopback octets
    bash resume-test.sh                          # cross-restart file-transfer resume (partial
                                                 #   -> cancel -> restart -> auto-resume -> full)

Engine commands beyond the UI buttons (session-only, scriptable):
TT_CMD_AV_SET_VIDEO_BR (mid-call video kbit/s, 1..1000000) — Pause/Resume
and the mute gates all have UI buttons now (see Calls above).

All regressions must PASS (rc=0 both peers) with a zero-warning build
(warnings/errors from TkTox/src fail the bar; vendored upstream is
excluded). AV milestones: AV_PLAN.md.

Honest limits
-------------
The device layers (ALSA capture/playback, V4L2 camera) and the Tk UI are
logic-verified in CI-like regressions here (headless container: no audio hw,
no camera, no X) — first live run is user-side: two-way voice, camera frames,
pane rendering. Video-over-Tor is expected to struggle (TCP transport,
suggestion-driven bit-rate drop mitigates but cannot fix it).