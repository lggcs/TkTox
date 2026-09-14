# TkTox AV (voice/video calls) — feature plan

Status: PLANNED (not started). 1:1 friend calls via vendored toxav. Ground facts below were
verified in-tree this session; anything not verified is marked.

E2EE decision (2026-09-14): AV media relies on toxcore's built-in transport E2EE (X25519 +
ChaCha20-Poly1305). No PQDR layer on the media path — toxav's codec+RTP pipeline is closed and
media sizes don't fit the E2EE packet channel. See CRYPTO_PLAN.md "AV (voice/video) E2EE".
This is a transport-layer decision only; it does not change the AV milestones below.

## Non-goals (explicit)

- **Group voice/video.** The vendored toxcore's NGC groups have no A/V (groupav.c serves the
  legacy conference API only). Until toxcore ships NGC A/V this cannot be built on our root.
- Screen share, call recording, SIP bridging, multi-device.

## Verified ground facts

1. **toxav is present and complete in the vendored tree** (`c-toxcore/toxav/`: toxav.c/h,
   msi.c, rtp.c, bwcontroller.c, audio.c, video.c, groupav.c) and builds *into*
   `toxcore_static` when `BUILD_TOXAV=ON` (c-toxcore/CMakeLists.txt:424-456) — no new link
   target, just opus+vpx deps. TkTox currently sets `BUILD_TOXAV OFF` (TkTox
   CMakeLists.txt).
2. **Codec deps**: opus + vpx are hard requirements (CMakeLists.txt:200-207). Note the trap:
   with `MUST_BUILD_TOXAV OFF` (default), a missing dep is only a *warning* and BUILD_TOXAV
   is silently forced OFF — we must set `MUST_BUILD_TOXAV ON` to fail loudly.
3. **System state**: runtime libs installed (`libopus0 1.6.1`, `libvpx12 1.16.0`), dev
   headers NOT installed, no pkg-config `.pc` for either. Ubuntu ports (resolute) is a
   configured apt source, so `apt-get download libopus-dev libvpx-dev` + `dpkg -x` into
   `.deps/` reproduces the proven Tcl/Tk/sodium pattern.
4. **Threading contract** (toxav.h): only `toxav_iterate` is thread-safe; every other
   toxav call must run on the tox thread. In single-thread mode `toxav_iterate` =
   `audio_iterate` + `video_iterate` sequentially (toxav.c:581-584). All call-state events
   fire from the tox thread; media frame callbacks fire during the media iterate.
5. **API shape** (toxav.h, verified): `toxav_new/kill`, `toxav_call(f, audio_br, video_br)`,
   `toxav_answer(f, audio_br, video_br)`, `toxav_call_control(..., CANCEL/HOLD/RESUME/...)`,
   `toxav_callback_call_state` (bitmask: NONE/ERROR/FINISHED/SENDING_A/SENDING_V/ACCEPTING_A/
   ACCEPTING_V), `toxav_audio_send_frame(pcm, count, ch, rate)` (rates 8/12/16/24/48 kHz,
   frame lengths 2.5/5/10/20/40/60 ms), `toxav_video_send_frame(w, h, y, u, v)` (planar
   YUV420), audio/video bit-rate suggestion callbacks, receive-frame callbacks. No video
   dimension caps in this header.
6. **Tor mode interplay**: AV rides the same Tox instance, so in Tor mode media flows through
   TCP relays via SOCKS5 automatically — no engine change. Expect audio to work and video to
   be poor/marginal (Tor bandwidth/latency). Document, don't gate.

## Architecture

```
UI (Tk) ──TT_CMD_AV_*──► tox thread ──toxav_*──► toxav (opus/vpx)
   ▲                        │   ▲   ▲
   │ call-state events      │   │   └─ capture ring drained by tox loop → audio_send_frame
   │                        │   └───── ALSA capture thread → ring
   └── video: shared latest-frame buffer + Tk after-timer (NOT the event queue)
```

Design decisions:

- **Single-thread iterate mode first.** Fold `toxav_iterate` into the existing tox loop right
  after `tox_iterate` (toxav owns its interval math). Split to audio/video threads later only
  if audio glitches. `toxav_new` at tox-thread init, `toxav_kill` before `tox_kill` (order
  mandated by toxav.h).
- **Audio never crosses the UI queue.** PCM at 20 ms / 48 kHz / mono ≈ 50 events/s would
  saturate `TT_QUEUE_CAP 256` and its condvar. Instead: `toxav_audio_receive_frame` callback
  (tox thread) pushes into a lock-guarded ring consumed by an ALSA playback worker; capture
  thread pushes into a second ring drained by the tox loop, which calls
  `toxav_audio_send_frame` (on the tox thread, as required). Full ring = drop newest (audio
  tolerates loss; blocking the tox thread does not).
- **Video via shared buffer, not events.** `toxav_video_receive_frame` decodes into a
  double-buffered latest-frame slot (mutex); a Tk `after` timer (30 fps) pulls, converts
  YUV420→RGB in C, updates a Tk photo. A 900 KB/frame heap event at 30 fps through the UI
  condvar queue would be allocation churn; the slot is O(1).
- **Offline queue untouched**: AV has no offline semantics — a call to an offline friend just
  times out (`call_state` ERROR/timeout path).

New plumbing:

- Commands: `TT_CMD_AV_CALL` (fn, ival/ival2 = audio/video kbps), `TT_CMD_AV_ANSWER` (same),
  `TT_CMD_AV_HANGUP` (CANCEL), `TT_CMD_AV_PAUSE`/`TT_CMD_AV_RESUME`, `TT_CMD_AV_MUTE`
  (ival: mic / speaker, 0/1), `TT_CMD_AV_SET_VIDEO_BR`.
- Events: `TT_EV_AV_INCOMING` (fn, ival2: audio/video enabled bits), `TT_EV_AV_STATE`
  (fn, ival = Toxav_Friend_Call_State bitmask), `TT_EV_AV_ENDED` (fn, ival: reason —
  FINISHED/ERROR/timeout), plus audio/video bit-rate suggestion events (informational log).
- Engine call state machine per friend: NONE → RINGING_OUT/RINGING_IN → ACTIVE →
  PAUSED → ENDED. One call per friend (toxav rule); UI greys the call button while active.

Defaults (KISS): audio 48 kHz mono 20 ms frames @ 32 kbps; video 640×480 @ 30 fps YUV420
@ 2500 kbps; bit-rate suggestion callbacks adjust down only.

## Milestones (each ends: zero-warning build + ngc-test.sh full PASS + test.log entry)

**M-AV0 — deps + build wiring.**
`apt-get download libopus-dev libvpx-dev` (+`libasound2-dev`), `dpkg -x` into
`.deps/opus|.deps/vpx|.deps/alsa`, extend PKG_CONFIG_PATH (build cmd + CMakeLists
`link_directories` pattern). Flip `BUILD_TOXAV=ON`, `MUST_BUILD_TOXAV=ON`. Verify
`toxcore_static` builds+links with toxav; `nm` smoke: toxav_new present.
Exit: build clean, existing tests unchanged PASS.

**M-AV1 — engine layer (headless, no devices).**
`src/av.c/h`: toxav lifecycle on tox thread, all callbacks → TT_EV_AV_*; call state
machine; command handlers; headless commands (call/answer/hangup/mute/status). PCM ring +
playback/capture worker skeletons with ALSA behind a compile flag (device-less build keeps
rings stubbed so headless still works).
Exit: unit smoke — state machine transitions in headless log.

**M-AV2 — headless loopback regression (the protocol proof).**
`av-test.sh` reusing the ngc-test.sh two-instance pattern: initiator calls, responder
answers, responder streams PCM from a WAV (decoded to PCM in C or pre-converted), initiator
receives → writes PCM/WAV; assert audio frames flowed + roundtrip decode sanity (opus is
lossy: assert duration/format, not byte equality). Video: send synthetic YUV420 gradient
frames both directions, assert frames received with matching dims. Negative paths: call to
offline friend → timeout/ERROR; responder declines → FINISHED at both ends; mid-call hangup
both directions.
Exit: av-test.sh PASS, zero warnings, ngc-test.sh still PASS.

**M-AV3 — audio device layer (real mics/speakers).**
ALSA via `.deps/alsa` (libasound2-dev), tiny wrapper (~200 lines): 20 ms 48 kHz mono
capture + playback, latency budget ~60 ms; mic-mute honored at capture source. Documented
`arecord`/`aplay` subprocess fallback (no new dep) behind a flag.
Exit: compile + static checks here; **live audio test is user-side** (container has no
sound device — same honesty rule as visual checks).

**M-AV4 — video device layer + render.**
V4L2 capture (kernel headers only, no new lib): MMAP, YUYV→YUV420 conversion in C, 640×480@30
fallback chain 1280×720→640×480→320×240; decode→shared slot→Tk photo pane in chat view
(self-view small overlay toggle).
Exit: compile here; **live camera test user-side** (no camera here).

**M-AV5 — call UX in Tk.**
Chat header call button (audio/video), in-call strip: duration timer, mute mic / mute
output / hangup, video pane swap. Incoming-call banner on roster + chat: Accept audio /
Accept video / Decline. `TT_EV_AV_ENDED` → system transcript line ("call ended — 4:12").
Tor-mode note line when call starts in tor_mode ("audio ok, video may struggle").
Exit: build clean; user-side visual pass.

**M-AV6 — hardening + docs.**
Bit-rate adaptation wired (suggestion callbacks → set), Tor-mode measured note, profile
savedata untouched (AV is session-only — nothing to persist), README section, final
regression sweep (ngc + av tests), memory/test.log closeout.

Dependencies: M-AV0 → M-AV1 → M-AV2 → M-AV3 → M-AV5; M-AV4 parallel after M-AV2; M-AV6 last.

## Risks / honest limits

- **No audio/video hardware in this container** — M-AV3/M-AV4 device layers are compile- and
  logic-tested here; real-device verification lands on the user's host (documented procedure).
- **Group voice** blocked by toxcore (see non-goals) — revisit when upstream NGC A/V lands.
- **UI-stall backpressure**: rings must drop, never block the tox thread (design above).
- **Video over Tor**: expected poor; not a defect.