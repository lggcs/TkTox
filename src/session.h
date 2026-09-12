#ifndef TT_SESSION_H
#define TT_SESSION_H

/* E2EE session layer (CRYPTO_PLAN M3 handshake + M4 ratchet) over the
   frame codec (crypto.h). Pure state machine — NO Tox calls; the engine
   (tox_thread.c) feeds transport + identity keys in. tt_e2ee_init_mode
   gates the layer (ON by default; TT_E2EE=0 disables it).

   Handshake (in-band, authenticated by the Tox friend-list identity keys):
     INIT  hdr = IKa(32) || ephA2 pk (32) || ephA3 pk (32) || kem pk A (1158)
     REPLY hdr = IKb(32) || ephB1 pk (32) || ephB3 pk (32) || kem ct (1039)
     dh1 = DH(IKa_sk, ephB1)  dh2 = DH(ephA2, IKb)  dh3 = DH(ephA3, ephB3)
     root = KDF(dh1||dh2||dh3||kem_ss, ctx="tt-e2ee-root:"||IKa||IKb)
   A MITM substituting identities cannot derive dh1/dh2 without a Tox secret
   key; the claimed IK is additionally checked against the friend list.

   M4 ratchet (PQDR-style, per direction, PQ material in EVERY root step):
     root' = KDF(root || DH_out || KEM_secret)   — per direction
     the msg chain re-seeds from the new root; seq continues (does NOT
     restart at 1 — a restart would make pre-fold frames indistinguishable
     from reordered post-fold frames, so old frames are rejected as replay).
   Re-key material rides DATA hdrs (SimpleX transitional re-key):
     DATA hdr 1190 (flag PK)      = kem pk(1158) || our DH eph pk(32):
       publish our fresh keys, no fold.
     DATA hdr 1071 (flags KEM|PK) = kem ct(1039) || our DH eph pk(32):
       the sender folded its direction (ss = Enc(peer's published kem pk),
       DH = DH(our eph sk, peer's published eph pk)); the receiver
       decapsulates ct with its own kem sk and folds the same root — both
       sides converge on identical per-direction roots.
   Each side keeps ONE re-key keypair set (DH ephemeral + sntrup761 KEM),
   shared across both directions. The sender of a direction initiates the
   re-key every TT_SESSION_REKEY_EVERY frames: it publishes its keys
   (KEMPUB) if the peer does not have them, then sends REKEY (fold + fold
   its direction), regenerates its keys and publishes them so the peer can
   re-key the opposite direction. The receiver folds on REKEY receipt but
   keeps its own keys until it re-keys its own direction.
   The verification code derives from the HANDSHAKE root and stays stable
   across folds. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "crypto/crypto.h"

#define TT_SESSION_MAX_SKIP 512u
#define TT_SESSION_REKEY_EVERY 64u
#define TT_SESSION_PENDING_MAX 4u /* texts stashed while the handshake runs */
#define TT_SESSION_HDR_IK 32u     /* claimed IK offset in INIT/REPLY hdr */
#define TT_SESSION_HDR_KEM 96u    /* kem material offset in INIT/REPLY hdr */
#define TT_SESSION_SKIPPED_MAX 96u /* skipped (seq, msg_key) store cap; the
   oldest entry is evicted over a newer one (still bounded by maxSkip) */

/* Reliable transport (receiver-driven re-send on chain desync). The sender
   buffers unacked outgoing plaintext; the receiver ACKs the highest
   contiguous seq it has decrypted, bounding the buffer. On a desync the
   receiver re-establishes and sends a RESEND request; the sender re-encrypts
   the buffered messages under the fresh chain. The generation counter
   disambiguates the old seq space (where the failed message lives) from the
   new one, so a re-send never wrongly re-sends fresh messages. */
#define TT_SENT_MAX 32u /* unacked outgoing messages buffered per direction;
   evicted by ACK (normal flow) or FIFO when full. The failed message is
   always the sender's most recent, so 32 recovers any burst that fits.
   Bounds the persisted sidecar and the fixed 256-session array
   (32 * 1319B * 256 ≈ 10.8MB). */

typedef struct TTSentMsg {
    uint32_t gen;   /* session generation at send time */
    uint32_t seq;   /* ratchet seq at send time */
    uint16_t len;   /* plaintext length */
    uint8_t data[TT_FRAME_DATA_MAX];
} TTSentMsg;

typedef struct TTSentBuf {
    TTSentMsg m[TT_SENT_MAX];
    uint16_t head;  /* oldest entry index */
    uint16_t count; /* number of live entries */
} TTSentBuf;

/* Reliable-transport state, preserved across re-establishment (like the
   pending stash) so recovery survives a desync and a restart. The session
   generation is NOT stored here — it is derived from the handshake root
   (rel_gen in session.c), so both peers always agree on it even when they
   re-establish at different times. */
typedef struct TTReliable {
    TTSentBuf sent;            /* outgoing unacked messages */
    uint32_t recv_acked;       /* highest contiguous seq decrypted (for ACK) */
    bool ack_due;              /* an ACK is pending to send */
    bool resend_req_pending;   /* we detected a desync; send a RESEND request */
    uint32_t resend_req_gen, resend_req_from;
    bool resend_rep_pending;   /* we received a RESEND; re-send buffered msgs */
    uint32_t resend_rep_gen, resend_rep_from;
    uint16_t resend_rep_pos;   /* next buffered index to re-send (0..count) */
} TTReliable;

/* session-level failure codes (the UI shows one generic line; the code
   only ever reaches logs) */
typedef enum {
    TT_E2EE_OK = 0,
    TT_E2EE_NO_SESSION = -1,   /* nothing established for this friend yet */
    TT_E2EE_NOKEY = -2,        /* friend not in the Tox friend list */
    TT_E2EE_DECODE_FAIL = -3,  /* malformed or inauthentic frame */
    TT_E2EE_BAD_ID = -4,       /* handshake claims a foreign Tox identity */
    TT_E2EE_SEQ_TOO_OLD = -5,  /* beyond maxSkip */
    TT_E2EE_REPLAY = -6,       /* seq already consumed */
    TT_E2EE_BUSY = -7,         /* pending ring full (handshake stalled) */
    TT_E2EE_BAD_STATE = -8,    /* e.g. REPLY with no INIT outstanding */
} TTE2EEStatus;

/* transport identity material, supplied by the engine (tox thread) */
typedef struct TTE2EEEnv {
    const uint8_t *self_sk;  /* tox secret key (32B) */
    const uint8_t *self_pk;  /* tox public key (32B) */
    const uint8_t *peer_pk;  /* tox public key (32B), NULL = not a friend */
} TTE2EEEnv;

/* M4 ratchet state, one per direction. The chain is a symmetric hash chain
   seeded from the direction root; msg keys derive deterministically so
   out-of-order delivery re-derives skipped keys. */
typedef struct TTRatchetState {
    uint8_t chain[TT_KEY32]; /* msg key for the next frame derives here */
    uint32_t seq;            /* next seq: 1-based (recv: expected seq) */
    uint8_t root[TT_KEY32];  /* direction ratchet root (advances on folds) */
    uint16_t since_fold;     /* frames since the last fold (send side) */
    /* skipped (seq, msg_key) pairs for out-of-order delivery */
    uint16_t n_skipped;
    struct {
        uint32_t seq;
        uint8_t key[TT_KEY32];
    } skipped[TT_SESSION_SKIPPED_MAX];
} TTRatchet;

/* M4 re-key state, shared across both directions (one keypair set per
   side; the peer's published keys feed the DH + KEM fold). */
typedef struct TTRekey {
    /* our fresh re-key material */
    uint8_t eph_sk[TT_KEY32], eph_pk[TT_KEY32];
    bool have_kem;
    uint8_t kem_pk[TT_KEM_PK], kem_sk[TT_KEM_SK];
    /* the peer's published re-key keys */
    bool peer_have;
    uint8_t peer_kem_pk[TT_KEM_PK];
    uint8_t peer_eph_pk[TT_KEY32];
    /* re-key protocol state (send side) */
    bool rekey_due;        /* a re-key is pending (set every 64 frames) */
    bool awaiting_peer;    /* we published; waiting for the peer's keys to fold */
    bool published;        /* our current keys are published (peer has them) */
    bool post_fold_publish; /* publish our regenerated keys after a fold */
    bool publish_back;     /* peer published its keys; publish ours in reply */
} TTRekey;

typedef struct TTSession {
    bool active;         /* both directions established */
    bool lossy;          /* tunnel channel: no reliable-transport buffering
                            (datagrams are lossy; a dropped frame is fine) */
    bool i_am_initiator;
    bool init_pending;   /* INIT sent, REPLY awaited (initiator) */
    bool reply_due;      /* INIT accepted, REPLY to build (responder) */
    time_t init_at;      /* last INIT send (retransmit timer) */
    TTRatchet send;      /* M4: per-direction ratchets */
    TTRatchet recv;
    TTRekey rekey;       /* M4: shared re-key state */
    uint8_t root[TT_KEY32];      /* handshake root (verification code) */
    /* initiator scratch (kept for tick-retransmit until the REPLY lands) */
    uint8_t eph_a2_sk[TT_KEY32], eph_a2_pk[TT_KEY32];
    uint8_t eph_a3_sk[TT_KEY32], eph_a3_pk[TT_KEY32];
    uint8_t init_seal[TT_KEY32]; /* INIT seal key = DH(eph_a2, IKb) */
    uint8_t kem_pk[TT_KEM_PK], kem_sk[TT_KEM_SK]; /* our INIT material */
    /* responder scratch (INIT accepted, REPLY not yet acked) */
    uint8_t eph_b1_sk[TT_KEY32], eph_b1_pk[TT_KEY32];
    uint8_t eph_b3_sk[TT_KEY32], eph_b3_pk[TT_KEY32];
    uint8_t kem_ct[TT_KEM_CT];   /* encapsulated for the initiator */
    uint8_t reply_cache[TT_FRAME_MAX];
    uint16_t reply_cache_len;    /* 0 = none */
    /* M4 harness hooks: last incoming frame (the replay mode re-injects a
       copy; it must decrypt or reject via the ring, never crash) */
    uint8_t last_in[TT_FRAME_MAX];
    uint16_t last_in_len;
    bool no_session_notified;    /* undecryptable-frame system line shown once */
    /* reliable transport (receiver-driven re-send on desync); preserved
       across re-establishment so recovery survives a desync and a restart */
    TTReliable rel;
    /* outgoing texts stashed while init_pending; flushed in order */
    uint8_t n_pending;
    struct {
        uint16_t len;
        uint8_t data[TT_FRAME_DATA_MAX];
    } pending[TT_SESSION_PENDING_MAX];
} TTSession;

/* Layer switch: read once by the engine (ON by default; TT_E2EE=0 off). */
bool tt_e2ee_init_mode(void);

void tt_session_init(TTSession *s);
void tt_session_clear(TTSession *s);

/* 32-hex verification code from the established session roots. Returns
   false until both directions are established (session_active). */
bool tt_session_verify_code(const TTSession *s, char out[33]);

/* ---- engine-facing operations (all take the transport env) ---- */

/* Establish the session as initiator: builds an INIT frame to send.
   Returns frame length or a negative TTE2EEStatus. */
int tt_session_start(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap);

/* Responder side: build (or re-send) the REPLY frame; the first build is
   cached so INIT retransmits get byte-identical REPLYs. Returns frame
   length or a negative status. */
int tt_session_reply(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap);

/* Feed one received friend message. INIT/REPLY return 0 (nothing to show;
   *handshaked flips true when the session turned active). DATA decrypts
   into pt (up to pt_cap) and returns its length. Out-of-order DATA within
   TT_SESSION_MAX_SKIP is recovered through the skipped-key store; replayed
   or too-old frames are rejected without consuming chain state. Re-key
   material rides DATA hdrs and is applied transparently. */
int tt_session_feed(TTSession *s, const TTE2EEEnv *env,
                    const uint8_t *in, size_t in_len,
                    uint8_t *pt, size_t pt_cap, bool *handshaked);

/* Encrypt one outgoing message as a single DATA frame into out (cap bytes).
   Returns the frame length (>0), or 0 when the handshake is still running
   and the text was stashed (TT_SESSION_PENDING_MAX bounds the stash), or a
   negative TTE2EEStatus. len must not exceed TT_FRAME_DATA_MAX. */
int tt_session_send(TTSession *s, const TTE2EEEnv *env, const uint8_t *text,
                    size_t len, uint8_t *out, size_t cap);

/* Lossy (tunnel) channel send: encrypt one datagram as a DATA frame. A
   not-yet-active session DROPS the datagram (lossy semantics — no stash,
   no re-send). The caller must drain any pending re-key carrier first (see
   tt_session_rekey_pending) so the datagram fits in a plain DATA frame. */
int tt_session_send_lossy(TTSession *s, const TTE2EEEnv *env,
                          const uint8_t *text, size_t len,
                          uint8_t *out, size_t cap);

/* True when the next emit_frame would carry a re-key header (REKEY or
   KEMPUB), which leaves too little room for a full datagram. The tunnel
   engine drains these as empty carrier frames before sending a datagram. */
bool tt_session_rekey_pending(const TTSession *s);

/* Pop ONE stashed text as a DATA frame into out (same return convention).
   Call repeatedly until it returns 0. */
int tt_session_flush(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap);

/* Engine periodic tick (tox thread loop): retransmit a stalled INIT.
   Returns the frame length (>0 = send it) or <= 0 when there is nothing
   to do this tick. */
int tt_session_tick(TTSession *s, const TTE2EEEnv *env, time_t now,
                    uint8_t *out, size_t cap);

/* ---- reliable transport (receiver-driven re-send on desync) ---- */

/* Build the next pending reliable-transport control frame (ACK or RESEND
   request/reply) into out, if any. Returns the frame length (>0 = send it)
   or <= 0 when nothing is pending. The engine calls this after every feed
   and after a re-establishment. */
int tt_session_rel_poll(TTSession *s, const TTE2EEEnv *env, uint8_t *out,
                        size_t cap);

/* ---- M4 ratchet engine hooks ---- */

/* Force a re-key on the next outgoing frame (the engine calls this every
   TT_SESSION_REKEY_EVERY frames; emit_frame also auto-triggers via the
   since_fold counter). */
void tt_session_rekey_due(TTSession *s);

/* ---- M4 ratchet test hooks (TT_BOT_E2EE reorder/replay modes) ---- */

/* Build the DATA frame for `seq` ("m<N>") WITHOUT committing send state,
   so the harness can deliver frames out of order on the wire. */
int tt_session_frame_at(TTSession *s, const TTE2EEEnv *env, uint32_t seq,
                        uint8_t *out, size_t cap);

/* Copy the last incoming DATA frame for a re-inject (replay mode). */
int tt_session_inject_older(TTSession *s, const TTE2EEEnv *env,
                            uint8_t *out, size_t cap);

#endif
