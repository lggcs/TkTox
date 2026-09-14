# CRYPTO_PLAN — SimpleX-style E2EE layer for TkTox (PQDR over Tox)

Status: M1–M5 DONE (ROUND 36). Decisions locked with the user 2026-09-08.

## What this is

An application-layer encryption on top of the existing 1:1 friend-message channel, modeled on
SimpleX's PQDR (simplexmq/protocol/pqdr.md): hybrid X25519 + SNTRUP761 key agreement, and a
double-ratchet whose ROOT step always folds the KEM secret — the property libsignal's PQXDH
lacks (PQ covers session init only). Tox remains the transport (its own transport crypto stays);
this layer rides inside friend messages and is defense in depth.

## Locked decisions (user, 2026-09-08)

1. **Layer over Tox** — PQDR encrypts message payloads; toxcore transport crypto unchanged.
   No toxcore modifications, full interop preserved.
2. **1:1 friends only** — NGC groups keep toxcore's built-in session E2EE. sntrup761 keygen is
   slow (~10-20 keys/s per simplexmq/protocol/pqdr.md); pairwise PQ ratchets per member are a
   non-goal for v1.
3. **AEAD: AES-256-GCM (SimpleX parity)** — libsodium gates AES-GCM on hardware support
   (`crypto_aead_aes256gcm_is_available()`), so the frame carries a cipher byte and the
   implementation MUST fall back to XChaCha20-Poly1305 (pure-software, always available).
   Selection: sender picks GCM when available, else XChaCha; receiver decrypts per frame's byte.
4. **Trust: in-band init + verification code** — the first encrypted message carries the full
   handshake (rides Tox's existing E2EE channel; no pre-exchange UX). A short verification code
   derived from the established session secrets is shown in the UI for OOB comparison. Optional
   hardening later: TrenchCard-style prekey pinning (out of scope v1).

## Primitives (all vendored/path, zero new deps)

- X25519 + XChaCha20-Poly1305 + AES-256-GCM + HKDF-style extract/expand: **libsodium** (linked).
- **SNTRUP761**: vendored supercop C (`vendor/sntrup761/sntrup761.{c,h}`), CMake target
  `sntrup761` already exists — link it into TkTox when M1 lands. RNG via sodium
  `randombytes_buf` bound to `sntrup761_random_func`.
- Sizes (from vendor/sntrup761/sntrup761.h): pk 1158, sk 1763, ct 1039, shared 32.

## Wire format (v1, as implemented in M2)

Frame (raw binary, one friend message each — the Tox message API is
binary-safe, so no base64 armor and no fragmentation layer):

    TTZ1 magic || ver(u8) || type(u8) || flags(u8) || seq(u32 BE)
      || nonce(12 GCM / 24 XChaCha) || hdr_len(u16 BE) || hdr || ct || aead_tag(16)

- type: 0 INIT, 1 REPLY, 2 DATA. seq replaces the old msg_id/part/parts.
- hdr is constant-size per type (geometry beyond type leaks nothing):
  INIT  dh1||dh2||dh3 pk (96) + fresh sntrup761 pk (1158) = 1254B;
  REPLY dh1||dh2||dh3 pk (96) + encapsulated kem ct (1039) = 1135B;
  DATA  0B, or a piggybacked re-key kem ct (1039B) with bit1 set.
- Everything before ct (head + hdr) is the AEAD AD; nonce bytes are inside it.
- flags: bit0 cipher used (1 = AES-256-GCM, 0 = XChaCha20-Poly1305), bit1
  KEM material in hdr, bit2 sender GCM-capable (peer capability hint),
  bits 3..7 reserved and must be zero. The AEAD honors the requested cipher
  or fails — no silent fallback (aead.c), because the frame flag must match.
- Budget (TOX_MAX_MESSAGE_LENGTH = 1372, tox.h): head 37B; INIT 1303+pt
  (pt <= 65B); REPLY 1188+pt (pt <= 184B); DATA 53+pt (pt <= 1319B).
- Session init: INIT carries the initiator's 3 X25519 ephemeral pks + a fresh
  sntrup761 keypair's pk (in-band init needs no pre-exchanged KEM pk);
  responder encapsulates and REPLY carries its own 3 ephemeral pks + the kem ct.
  root = KDF(DH1 || DH2 || DH3 || KEM_shared || ToxID-both-sides as context).

## Ratchet (PQDR-style, simplified but PQ-in-every-root-step)

- Root per direction: `root' = KDF(root || DH_out || KEM_secret)`; message keys derived from a
  symmetric hash chain (`mk(n+1) = KDF(mk(n))`) so out-of-order delivery derives skipped keys
  deterministically; **maxSkip = 512** (SimpleX parity), beyond that the session re-inits.
- KEM re-key: every 64 messages the sender piggybacks a fresh sntrup761 encapsulation; both
  sides fold the new KEM secret into the root from then on (per-direction eventual consistency,
  same as SimpleX transitional state).
- Failed decrypt -> try skipped-key window -> re-key request -> last resort session re-init.
  Never echo decryption failure details to the wire (oracle hygiene).

## Session state

v1: **in-memory only** (TTAvg-style struct on the tox thread; lost on restart -> automatic fresh
handshake on next message). Persistence to a `<profile>` sidecar is v2 (the at-rest passphrase
now exists via toxencryptsave; the session keys need a separate at-rest key).

v2 (DONE, ROUND 38): established sessions persist to `<profile>.ses`, encrypted with a SEPARATE
at-rest key derived from the same passphrase but a DISTINCT random salt (embedded in the
toxencryptsave blob; read back via tox_get_salt + tox_pass_key_derive_with_salt on the next boot,
so the key always matches). Only ACTIVE sessions are stored — the full M4 ratchet + re-key state
(send/recv chain, seq, root, since_fold, skipped ring, rekey keypairs + protocol flags) so the
ratchet continues folding across a clean restart. Pending handshake scratch (eph_a2/a3, init_seal,
reply_cache, eph_b1/b3, kem_ct, pending stash) is deliberately NOT stored — it is stale on
restart; a fresh handshake is the correct recovery. A crash (SIGKILL/power loss) still loses the
in-memory session, so forward secrecy is best-effort, not absolute.

## Milestones (each: zero-warning build, unit tests, full regression battery stays green)

- **M1 crypto core**: crypto/kdf.c (extract/expand), crypto/aead.c (GCM w/ availability gate +
  XChaCha fallback, one API), sntrup glue; `tests/test_crypto.c` roundtrip + malformed-rejection
  tests (pattern: tests/test_strip_dht.c). Done when: unit binary passes, regressions green.
- **M2 frame codec**: crypto/frame.c encode/decode, base64 armor, fragmentation, fixed-size
  header padding; fuzz-ish unit tests (truncated/bit-flipped frames must reject, never crash).
  Done when: codec roundtrips + malformed suite passes.
- **M3 session + handshake**: session struct per friend, X3DH+KEM init, reply frame, engine
  commands/events (encrypt on send, decrypt on rx, plaintext passthrough unchanged); regression
  mode TT_BOT_E2EE=1: two-bot roundtrip proves wire bytes decrypt + verify codes match.
  Done when: TT_BOT_E2EE=1 PASS both rc=0.
  **DONE (ROUND 35)**: session.c/session.h + engine wiring; `tests/test_session.c` →
  "session: ALL PASS" (handshake, verify-code equality, replay/corrupt rejection, retransmit +
  cached REPLY, max-skip boundary, stash ring, collision tiebreak). Engine: INIT on friend-online
  or NO_SESSION, DATA mutates in place to plaintext passthrough, stashed texts pump after the
  handshake (MESSAGE_SENT per frame), offline queue flushes encrypted, TT_EV_E2EE_STATE carries
  the 32-hex verify code. Live run exercised the simultaneous-INIT collision path on the wire
  (both sides INITed the same second; lower pk won, higher yielded). e2ee-test.sh PASS (codes
  match both sides, receipt on the encrypted ping).
- **M4 ratchet**: DH/KEM re-key steps, skipped-key store, out-of-order injection test in the
  harness (deliver frame 2 before frame 1), maxSkip boundary, replay rejection.
  Done when: reorder + replay harness modes PASS.
  **DONE (ROUND 36)**: session.c/session.h rewritten with the M4 ratchet — per-direction
  `TTRatchet` (chain, seq, root, since_fold, skipped[96] ring), shared `TTRekey` keypair set,
  `root' = KDF(root || DH_out || KEM_secret)` folds with PQ material in EVERY root step, seq
  continues across folds (pre-fold frames reject as replay), skipped-key store recovers
  out-of-order frames (maxSkip 512, ring cap 96), derive-without-commit receive hygiene
  (corrupt/replayed frames never consume chain state). Re-key material rides DATA hdrs:
  KEMPUB (1190B, flag PK) publishes fresh keys, REKEY (1071B, flags KEM|PK) folds the
  direction; auto-trigger every 64 frames. `tests/test_session.c` out_of_order now expects
  M4 skipped-key recovery; `tests/test_frame.c` roundtrips the REKEY/KEMPUB hdrs (frame.c
  reserved-bit mask 0xF8→0xF0 so the new PK flag 0x08 is accepted). e2ee-test.sh gained
  `reorder` (deliver seq 3,2,4 out of order; responder recovers 2,3 via the skipped store,
  echoes all three) and `replay` (re-inject the last DATA frame; engine logs TT_E2EE_REPLAY)
  harness modes — both PASS.
- **M5 UX + docs**: 🔒 roster callmark-style badge for encrypted peers, verify-code dialog
  (Settings), "peer lacks the layer" system line for undecryptable frames, README + root
  PLAN.md rewrite (current PLAN.md still describes the retired Rust/libsignal design).
  Done when: user-side visual pass documented; README/PLAN in sync.
  **DONE (ROUND 36)**: 🔒 badge in roster_render (Contact.e2ee, set from TT_EV_E2EE_STATE);
  verify-code shown in the Settings dialog (selected contact's 32-hex code, OOB comparison);
  undecryptable-frame system line "[encrypted message could not be decrypted]" already in
  e2ee_rx (shown once per session). README + root PLAN.md rewritten to the as-implemented
  C17/Tk design.

## Tunnel E2EE channel (ROUND 40)

The UDP/TCP-over-Tox tunnels (commit 3efe985) are now protected by the same PQDR ratchet,
via a SEPARATE per-friend session (`t->tun_e2ee[fn]`) so tunnel frames never interleave
with chat seq numbers. Tunnels are ephemeral, so the session is in-memory only (nothing
persisted). The session is marked `lossy`, which disables the reliable-transport buffering
(no stash, no ACK/RESEND, no re-send) — a dropped datagram is simply dropped, matching the
gaming use case.

- Handshake (INIT/REPLY) rides lossless custom packets (type 164).
- UDP data rides lossy custom packets (type 201); the plaintext is the WHOLE 200 packet
  (header + payload), so the receiver's `tt_tunnel_rx` parses the 200 header from the
  decrypted bytes (symmetric with the raw path).
- TCP data rides lossless custom packets (type 165); the plaintext is the WHOLE 162 frame.
- When E2EE is off, the tunnel falls back to the raw 200/162 types (plaintext over
  toxcore's transport crypto).
- Re-key headers (REKEY/KEMPUB) leave too little room for a full datagram, so the engine
  drains them as empty carrier frames first (`tt_session_rekey_pending`), then sends the
  datagram as a plain DATA frame.
- A desync on the tunnel channel re-establishes with a fresh handshake (lossy — there is
  no reliable transport to recover the lost datagram).

## AV (voice/video) E2EE — decision (2026-09-14)

**Decision (user): accept toxcore transport E2EE for AV.** No extra PQDR layer on the media
path. toxav's codec+RTP path is a closed pipeline — `toxav_audio_send_frame` /
`toxav_video_send_frame` hand raw PCM/YUV to toxav, which does Opus/VP8 + RTP, then toxcore's
transport layer encrypts it end-to-end. We cannot inject our PQDR ratchet into that path
without forking toxcore, and the media sizes don't fit the existing E2EE packet channel:

- Audio: 20 ms mono S16 = **1920 B** > `TT_FRAME_DATA_MAX` (1319 B); 10 ms = 960 B would fit.
- Video: 1280×720 YUV420 ≈ **1.38 MB** — far too large for any friend-message/custom-packet
  channel.

So AV relies on toxcore's built-in transport E2EE (the same crypto that protects the
handshake of our chat/tunnel PQDR sessions). This is defense in depth at the transport layer,
not the application layer. The chat/tunnel PQDR layer is unaffected.

**Why not the alternatives (evaluated, rejected):**
- *Custom lossy E2EE media channel* (like tunnels): would need our own media framing + a
  codec (raw PCM is huge); video is impractical. High effort, high risk.
- *Fork/vendor toxcore to encrypt the codec path*: cleanest crypto placement but forks
  toxcore and is the heaviest lift; breaks the "no toxcore modifications" decision (locked
  decision #1).

**Honest limit:** toxcore's transport E2EE is X25519 + ChaCha20-Poly1305 (classical, not
PQ). AV media is therefore NOT post-quantum protected, unlike chat/tunnel payloads. If PQ
AV becomes a requirement, the path is a custom lossy E2EE media channel (audio first) or a
toxcore fork — both out of scope for now.

## Honest limits (stated up front)

- AES-GCM path needs ARMv8 crypto extensions; aarch64 dev box has them, but the cipher byte +
  XChaCha fallback exist precisely because that is not universal.
- In-band init trusts Tox's transport E2EE for the handshake; the verify code is the OOB check.
  An active MITM of BOTH Tox transport and the OOB comparison defeats this — same trade-off
  SimpleX documents in protocol/security.md.
- Forward secrecy survives clean restarts (v2, ROUND 38): established sessions persist to
  `<profile>.ses` under a separate at-rest key; a crash still loses the in-memory session
  (best-effort, not absolute).
- No deniability claim: Tox long-term identity keys pin the session (this is the deliberate
  contrast with SimpleX's no-identity design).
- Frame is loud (base64 blob) — no steganographic carrier in v1. The old stego tiers
  are out of scope per the KISS scope ruling.