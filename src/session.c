#include "session.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool sodium_ready;

static void sodium_init_once(void) {
    if (!sodium_ready) {
        if (sodium_init() < 0) return;
        sodium_ready = true;
    }
}

/* E2EE is ON by default; only an explicit TT_E2EE=0 disables it. The env
   var remains as an escape hatch for legacy/headless runs that must not
   encrypt (e.g. a plaintext-only harness). */
bool tt_e2ee_init_mode(void) {
    const char *v = getenv("TT_E2EE");
    if (v && v[0] == '0') return false;
    return true;
}

/* ---- local helpers (crypto.h stays primitive-only) ---- */

/* KDF(root, label): ikm = root(32) || 0x01, ctx = label. The 0x01 byte is
   a fixed-length separator (root is always 32B). */
static void derive_from_root(uint8_t out[TT_KEY32], const uint8_t root[TT_KEY32],
                             const char *label) {
    uint8_t ikm[TT_KEY32 + 1];
    memcpy(ikm, root, TT_KEY32);
    ikm[TT_KEY32] = 0x01;
    tt_kdf_root(out, ikm, sizeof ikm, (const uint8_t *)label, strlen(label));
    sodium_memzero(ikm, sizeof ikm);
}

/* INIT/REPLY seal key = one DH leg of the handshake, domain-separated:
   INIT  seals under dh2 = DH(ephA2_sk, IKb)   (initiator precomputes)
   REPLY seals under dh1 = DH(ephB1_sk, IKa)   (responder precomputes)
   The peer opens with the mirrored DH; a MITM without a Tox secret key can
   compute neither. ad = "tt-e2ee-seal" (12B fixed) || ad_ik (32B), where
   ad_ik is the identity key of the STATIC party of the leg (INIT: IKb,
   REPLY: IKa) — the sealer passes it as its DH peer, the opener as its own
   self_pk. */
static int seal_key_derive(uint8_t out[TT_KEY32], const uint8_t sk[TT_KEY32],
                           const uint8_t dh_peer[TT_KEY32],
                           const uint8_t ad_ik[TT_KEY32]) {
    uint8_t ss[TT_KEY32], ad[12 + TT_KEY32];
    if (tt_dh_shared(ss, sk, dh_peer) != 0) return -1;
    memcpy(ad, "tt-e2ee-seal", 12);
    memcpy(ad + 12, ad_ik, TT_KEY32);
    tt_kdf_root(out, ss, TT_KEY32, ad, sizeof ad);
    sodium_memzero(ss, sizeof ss);
    return 0;
}

/* ---- M4 ratchet (PQDR-style; both DH and KEM fold every re-key) ---- */

/* fresh ratchet state from the handshake root; chain seeds from it */
static void ratchet_reset(TTRatchet *r, const uint8_t root[TT_KEY32],
                          bool initiator_dir) {
    sodium_memzero(r, sizeof *r);
    memcpy(r->root, root, TT_KEY32);
    derive_from_root(r->chain, root, initiator_dir ? "tt-e2ee-i" : "tt-e2ee-r");
    r->seq = 1;
    r->since_fold = 0;
}

/* one ratchet fold: root' = KDF(root || DH_out || KEM_secret) — PQ material
   in EVERY root step (the property libsignal's PQXDH lacks); the chain
   re-seeds from the NEW root. seq CONTINUES (a restart would make pre-fold
   frames indistinguishable from reordered post-fold frames, so old frames
   are rejected as replay); skipped keys from the old chain are invalid. */
static void ratchet_fold(TTRatchet *r, const uint8_t dh[TT_KEY32],
                         const uint8_t kem[TT_KEY32]) {
    uint8_t new_root[TT_KEY32], new_chain[TT_KEY32];
    tt_kdf_root_step(new_root, new_chain, r->root, dh, kem);
    memcpy(r->root, new_root, TT_KEY32);
    memcpy(r->chain, new_chain, TT_KEY32);
    sodium_memzero(new_root, sizeof new_root);
    sodium_memzero(new_chain, sizeof new_chain);
    r->since_fold = 0;
    r->n_skipped = 0;
}

/* msg key + nonce for the sender's next seq; consumes one chain step */
static void send_key(TTRatchet *r, uint32_t *seq, uint8_t key[TT_KEY32],
                     uint8_t nonce[TT_NONCE24]) {
    uint8_t mk[TT_KEY32], nc[TT_KEY32];
    tt_kdf_chain_step(nc, mk, r->chain);
    memcpy(r->chain, nc, TT_KEY32);
    sodium_memzero(nc, sizeof nc);
    tt_kdf_msg_material(key, nonce, mk);
    sodium_memzero(mk, sizeof mk);
    *seq = r->seq;
    r->seq++;
}

/* msg key + nonce for `seq` (>= r->seq) from a scratch copy of the chain,
   WITHOUT committing — the caller commits only after a successful decrypt. */
static void msg_key_at(const TTRatchet *r, uint32_t seq, uint8_t key[TT_KEY32],
                       uint8_t nonce[TT_NONCE24]) {
    uint8_t c[TT_KEY32], mk[TT_KEY32], nc[TT_KEY32];
    memcpy(c, r->chain, TT_KEY32);
    for (uint32_t k = r->seq; k < seq; k++) {
        tt_kdf_chain_step(nc, mk, c);
        memcpy(c, nc, TT_KEY32);
    }
    tt_kdf_chain_step(nc, mk, c);
    tt_kdf_msg_material(key, nonce, mk);
    sodium_memzero(c, sizeof c);
    sodium_memzero(mk, sizeof mk);
    sodium_memzero(nc, sizeof nc);
}

/* skipped-key ring ops (out-of-order delivery) */
static void skipped_add(TTRatchet *r, uint32_t seq, const uint8_t key[TT_KEY32]) {
    if (r->n_skipped >= TT_SESSION_SKIPPED_MAX) {
        memmove(&r->skipped[0], &r->skipped[1],
                (TT_SESSION_SKIPPED_MAX - 1) * sizeof r->skipped[0]);
        r->n_skipped--;
    }
    r->skipped[r->n_skipped].seq = seq;
    memcpy(r->skipped[r->n_skipped].key, key, TT_KEY32);
    r->n_skipped++;
}

static int skipped_take(TTRatchet *r, uint32_t seq, uint8_t key[TT_KEY32]) {
    for (int i = 0; i < r->n_skipped; i++) {
        if (r->skipped[i].seq == seq) {
            memcpy(key, r->skipped[i].key, TT_KEY32);
            sodium_memzero(r->skipped[i].key, TT_KEY32);
            for (int k = i + 1; k < r->n_skipped; k++)
                r->skipped[k - 1] = r->skipped[k];
            r->n_skipped--;
            return 0;
        }
    }
    return -1;
}

void tt_session_init(TTSession *s) { memset(s, 0, sizeof *s); }

void tt_session_clear(TTSession *s) { sodium_memzero(s, sizeof *s); }

/* ---- reliable transport (receiver-driven re-send on chain desync) ---- */

/* preserve stashed texts + reliable-transport state across a re-establish.
   The generation is NOT bumped here — it is derived from the fresh root
   (rel_gen), so both peers agree on it automatically. The resend request
   (if any) keeps the OLD gen so the peer re-sends the right messages; the
   sent buffer keeps its entries' original gens. */
static void reestablish_preserve(TTSession *s) {
    TTReliable rel = s->rel;
    bool lossy = s->lossy;
    uint8_t stash[sizeof s->pending];
    uint8_t np = s->n_pending;
    memcpy(stash, s->pending, sizeof stash);
    tt_session_clear(s);
    memcpy(s->pending, stash, sizeof stash);
    s->n_pending = np;
    s->rel = rel;
    s->lossy = lossy;
}

/* buffer one outgoing message tagged {gen, seq}; FIFO-evicts the oldest
   when full (the failed message is always the most recent, so 32 recovers
   any burst that fits) */
static void rel_sent_add(TTSession *s, uint32_t gen, uint32_t seq,
                         const uint8_t *text, size_t len) {
    TTSentBuf *b = &s->rel.sent;
    if (b->count >= TT_SENT_MAX) {
        uint16_t old = b->head;
        sodium_memzero(&b->m[old], sizeof b->m[old]);
        b->head = (b->head + 1) % TT_SENT_MAX;
        b->count--;
    }
    uint16_t idx = (b->head + b->count) % TT_SENT_MAX;
    b->m[idx].gen = gen;
    b->m[idx].seq = seq;
    b->m[idx].len = (uint16_t)len;
    memcpy(b->m[idx].data, text, len);
    b->count++;
}

/* evict buffered messages the peer has delivered (gen==g && seq<=acked) */
static void rel_sent_ack(TTSession *s, uint32_t g, uint32_t acked) {
    TTSentBuf *b = &s->rel.sent;
    uint16_t w = 0;
    for (uint16_t r = 0; r < b->count; r++) {
        uint16_t idx = (b->head + r) % TT_SENT_MAX;
        if (b->m[idx].gen == g && b->m[idx].seq <= acked) {
            sodium_memzero(&b->m[idx], sizeof b->m[idx]);
            continue;
        }
        if (w != r) {
            uint16_t widx = (b->head + w) % TT_SENT_MAX;
            b->m[widx] = b->m[idx];
            sodium_memzero(&b->m[idx], sizeof b->m[idx]);
        }
        w++;
    }
    b->count = w;
}

/* remove one specific buffered message (used after a re-send) */
static void rel_sent_remove(TTSession *s, uint32_t gen, uint32_t seq) {
    TTSentBuf *b = &s->rel.sent;
    uint16_t w = 0;
    for (uint16_t r = 0; r < b->count; r++) {
        uint16_t idx = (b->head + r) % TT_SENT_MAX;
        if (b->m[idx].gen == gen && b->m[idx].seq == seq) {
            sodium_memzero(&b->m[idx], sizeof b->m[idx]);
            continue;
        }
        if (w != r) {
            uint16_t widx = (b->head + w) % TT_SENT_MAX;
            b->m[widx] = b->m[idx];
            sodium_memzero(&b->m[idx], sizeof b->m[idx]);
        }
        w++;
    }
    b->count = w;
}

/* control-frame key: KDF(root, "tt-e2ee-ctl"). Both sides derive the same
   key from their current root, so a control frame is bound to the session
   it was sent in — a stale frame from a previous generation (old root)
   fails to decrypt and is dropped, never misapplied to the new seq space. */
static void control_key(TTSession *s, uint8_t out[TT_KEY32]) {
    uint8_t ikm[TT_KEY32 + 1];
    memcpy(ikm, s->root, TT_KEY32);
    ikm[TT_KEY32] = 0x01;
    tt_kdf_root(out, ikm, sizeof ikm, (const uint8_t *)"tt-e2ee-ctl", 12);
    sodium_memzero(ikm, sizeof ikm);
}

/* session generation: a 32-bit tag derived from the handshake root. Both
   peers derive the SAME value from the shared root, so the generation is
   synchronized (unlike a per-side counter, which drifts when the two sides
   re-establish at different times). It changes on every re-establishment
   (new root), disambiguating the old seq space (where the failed message
   lives) from the new one. */
static uint32_t rel_gen(const TTSession *s) {
    uint8_t g[TT_KEY32];
    derive_from_root(g, s->root, "tt-e2ee-gen");
    uint32_t v = ((uint32_t)g[0] << 24) | ((uint32_t)g[1] << 16) |
                 ((uint32_t)g[2] << 8) | (uint32_t)g[3];
    sodium_memzero(g, sizeof g);
    return v;
}

/* verification code from the HANDSHAKE ROOT (direction-independent, so
   both peers derive the same 32 hex chars; stays stable while M4 ratchet
   advances re-key the per-direction roots) */
bool tt_session_verify_code(const TTSession *s, char out[33]) {
    if (!s->active) return false;
    uint8_t vc[TT_KEY32];
    derive_from_root(vc, s->root, "tt-e2ee-vcode");
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i * 2] = hex[vc[i] >> 4];
        out[i * 2 + 1] = hex[vc[i] & 0x0f];
    }
    out[32] = '\0';
    sodium_memzero(vc, sizeof vc);
    return true;
}

/* session root from the three DH legs + KEM secret, then per-direction
   ratchet roots (M4). ctx = "tt-e2ee-root:" (13B) || IKa || IKb. The chain
   label is per message-flow direction relative to the initiator: the
   initiator->responder direction uses "tt-e2ee-i", responder->initiator
   uses "tt-e2ee-r" — so the initiator's send matches the responder's recv
   and vice versa. */
static void establish(TTSession *s, const uint8_t f1[TT_KEY32],
                      const uint8_t f2[TT_KEY32], const uint8_t f3[TT_KEY32],
                      const uint8_t kem_ss[TT_KEY32],
                      const uint8_t IKa[TT_KEY32], const uint8_t IKb[TT_KEY32],
                      bool i_am_initiator) {
    uint8_t ikm[TT_IKM128], ctx[13 + 2 * TT_KEY32];
    memcpy(ikm, f1, TT_KEY32);
    memcpy(ikm + 32, f2, TT_KEY32);
    memcpy(ikm + 64, f3, TT_KEY32);
    memcpy(ikm + 96, kem_ss, TT_KEY32);
    memcpy(ctx, "tt-e2ee-root:", 13);
    memcpy(ctx + 13, IKa, TT_KEY32);
    memcpy(ctx + 13 + TT_KEY32, IKb, TT_KEY32);
    tt_kdf_root(s->root, ikm, TT_IKM128, ctx, sizeof ctx);
    sodium_memzero(ikm, sizeof ikm);
    sodium_memzero(ctx, sizeof ctx);
    /* M4: per-direction ratchet roots + fresh re-key material; chains seed
       from the direction roots, seq starts at 1 */
    if (i_am_initiator) {
        ratchet_reset(&s->send, s->root, true);  /* send = "i" */
        ratchet_reset(&s->recv, s->root, false); /* recv = "r" */
    } else {
        ratchet_reset(&s->send, s->root, false); /* send = "r" */
        ratchet_reset(&s->recv, s->root, true);  /* recv = "i" */
    }
    /* one re-key keypair set, shared across both directions */
    tt_dh_keygen(s->rekey.eph_pk, s->rekey.eph_sk);
    tt_kem_keygen(s->rekey.kem_pk, s->rekey.kem_sk);
    s->rekey.have_kem = true;
}

/* ---- INIT (initiator) ---- */

static int build_init(TTSession *s, const TTE2EEEnv *env, uint8_t *out,
                      size_t cap) {
    uint8_t hdr[TT_HDR_INIT], nonce[TT_NONCE24];
    memcpy(hdr, env->self_pk, TT_KEY32);                 /* IKa claim */
    memcpy(hdr + 32, s->eph_a2_pk, TT_KEY32);            /* dh2 leg */
    memcpy(hdr + 64, s->eph_a3_pk, TT_KEY32);            /* dh3 leg */
    memcpy(hdr + TT_SESSION_HDR_KEM, s->kem_pk, TT_KEM_PK);
    randombytes_buf(nonce, sizeof nonce);
    int n = tt_frame_encode(out, cap, TT_FRAME_INIT, 0, TT_FRAME_FLAG_KEM,
                            s->init_seal, nonce, hdr, TT_HDR_INIT, NULL, 0);
    sodium_memzero(nonce, sizeof nonce);
    sodium_memzero(hdr, sizeof hdr);
    return n;
}

int tt_session_start(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap) {
    sodium_init_once();
    if (!env->self_sk || !env->self_pk || !env->peer_pk) return TT_E2EE_NOKEY;

    /* reset any stale state but keep stashed texts + reliable-transport
       state (typed while a previous handshake was pending) — they flush
       over the new session; the generation bumps so the old seq space is
       stale */
    reestablish_preserve(s);
    s->i_am_initiator = true;
    s->init_pending = true;
    s->init_at = time(NULL);
    tt_dh_keygen(s->eph_a2_pk, s->eph_a2_sk);
    tt_dh_keygen(s->eph_a3_pk, s->eph_a3_sk);
    tt_kem_keygen(s->kem_pk, s->kem_sk);
    /* INIT seal key = dh2 = DH(ephA2, IKb); AD labels the static party IKb */
    if (seal_key_derive(s->init_seal, s->eph_a2_sk, env->peer_pk, env->peer_pk) != 0)
        return TT_E2EE_BAD_ID;
    int n = build_init(s, env, out, cap);
    return n > 0 ? n : TT_E2EE_BAD_STATE;
}

/* ---- REPLY (responder) ---- */

int tt_session_reply(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap) {
    sodium_init_once();
    if (!env->self_sk || !env->self_pk || !env->peer_pk) return TT_E2EE_NOKEY;
    /* retransmit-driven re-send of an already-built REPLY (the INIT was a
       duplicate); no state changes */
    if (!s->reply_due) {
        if (s->reply_cache_len > 0) {
            if (cap < s->reply_cache_len) return TT_E2EE_BAD_STATE;
            memcpy(out, s->reply_cache, s->reply_cache_len);
            return s->reply_cache_len;
        }
        return TT_E2EE_BAD_STATE;
    }
    s->reply_due = false;

    /* first REPLY build: ephB1/ephB3 sks + kem_ct were set by feed() */
    uint8_t hdr[TT_HDR_REPLY], nonce[TT_NONCE24], key[TT_KEY32];
    memcpy(hdr, env->self_pk, TT_KEY32);                 /* IKb claim */
    memcpy(hdr + 32, s->eph_b1_pk, TT_KEY32);
    memcpy(hdr + 64, s->eph_b3_pk, TT_KEY32);
    memcpy(hdr + TT_SESSION_HDR_KEM, s->kem_ct, TT_KEM_CT);
    /* REPLY seal key = dh1 = DH(ephB1, IKa); static party = IKa (the peer) */
    if (seal_key_derive(key, s->eph_b1_sk, env->peer_pk, env->peer_pk) != 0)
        return TT_E2EE_BAD_ID;
    randombytes_buf(nonce, sizeof nonce);
    int n = tt_frame_encode(out, cap, TT_FRAME_REPLY, 0, TT_FRAME_FLAG_KEM,
                            key, nonce, hdr, TT_HDR_REPLY, NULL, 0);
    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    sodium_memzero(hdr, sizeof hdr);
    if (n < 0) return TT_E2EE_BAD_STATE;
    memcpy(s->reply_cache, out, (size_t)n);
    s->reply_cache_len = (uint16_t)n;
    return n;
}

/* ---- receive ---- */

int tt_session_feed(TTSession *s, const TTE2EEEnv *env, const uint8_t *in,
                    size_t in_len, uint8_t *pt, size_t pt_cap, bool *handshaked) {
    sodium_init_once();
    *handshaked = false;
    TTFrameDesc d;
    if (tt_frame_peek(in, in_len, &d) != 0) return TT_E2EE_DECODE_FAIL;
    if (d.type == TT_FRAME_DATA) { /* M4 harness hook: keep for replay */
        if (in_len <= sizeof s->last_in) {
            memcpy(s->last_in, in, in_len);
            s->last_in_len = (uint16_t)in_len;
        }
    }

    if (d.type == TT_FRAME_INIT) {
        if (d.hdr_len != TT_HDR_INIT) return TT_E2EE_DECODE_FAIL;
        if (!env->peer_pk || memcmp(d.hdr, env->peer_pk, TT_KEY32) != 0)
            return TT_E2EE_BAD_ID; /* claimed IK must be the friend's */

        /* INIT retransmit of the session we already accepted? */
        if (s->active && !s->i_am_initiator) {
            uint8_t key0[TT_KEY32], scratch[16];
            TTFrameDesc dd;
            if (seal_key_derive(key0, env->self_sk, d.hdr + 32, env->self_pk) == 0 &&
                tt_frame_decode(in, in_len, key0, &dd, scratch,
                                sizeof scratch) == 0 &&
                dd.seq == 0) {
                *handshaked = true; /* engine resends reply_cache */
            }
            sodium_memzero(key0, sizeof key0);
            if (*handshaked) return 0;
        }
        /* simultaneous-initiator collision: the LOWER identity pk wins the
           initiator role — the higher side clears and re-runs as responder
           to the peer's INIT (stashed texts survive), the lower side
           ignores the peer's INIT and keeps waiting for the REPLY. The
           gate covers init_pending too: INITs can cross before either
           side is active.
           Established-session case: if we are ACTIVE and the peer sends a
           fresh INIT, the peer has lost its session (it is re-initiating)
           — yield and re-establish as responder regardless of pk, or the
           two sides wedge forever (one restored a session the other lost). */
        if (s->i_am_initiator && (s->active || s->init_pending)) {
            if (s->active || memcmp(d.hdr, env->self_pk, TT_KEY32) < 0) {
                /* peer is the lower pk (or we are established): yield,
                   re-run as responder (stashed texts + reliable state
                   survive; generation bumps) */
                reestablish_preserve(s);
            } else {
                return 0; /* lower pk: our INIT carries the session */
            }
        }

        /* fresh INIT: open with dh2 = DH(IKb_sk, ephA2), AD labels IKb */
        uint8_t key[TT_KEY32], scratch[16];
        if (seal_key_derive(key, env->self_sk, d.hdr + 32, env->self_pk) != 0)
            return TT_E2EE_BAD_ID;
        int n = tt_frame_decode(in, in_len, key, &d, scratch, sizeof scratch);
        if (n < 0) {
            sodium_memzero(key, sizeof key);
            return TT_E2EE_DECODE_FAIL;
        }
        /* keep the seal key for INIT-retransmit detection */
        memcpy(s->init_seal, key, TT_KEY32);
        sodium_memzero(key, sizeof key);

        /* responder scratch + KEM encapsulation */
        tt_dh_keygen(s->eph_b1_pk, s->eph_b1_sk);
        tt_dh_keygen(s->eph_b3_pk, s->eph_b3_sk);
        uint8_t ss[TT_KEY32];
        tt_kem_enc(s->kem_ct, ss, d.hdr + TT_SESSION_HDR_KEM);
        /* dh1 = DH(ephB1, IKa), dh2 = DH(IKb, ephA2), dh3 = DH(ephB3, ephA3) */
        uint8_t f1[TT_KEY32], f2[TT_KEY32], f3[TT_KEY32];
        int rc = 0;
        if (tt_dh_shared(f1, s->eph_b1_sk, env->peer_pk) != 0) rc = -1;
        if (rc == 0 && tt_dh_shared(f2, env->self_sk, d.hdr + 32) != 0) rc = -1;
        if (rc == 0 && tt_dh_shared(f3, s->eph_b3_sk, d.hdr + 64) != 0) rc = -1;
        if (rc != 0) {
            sodium_memzero(ss, sizeof ss);
            return TT_E2EE_BAD_ID;
        }
        establish(s, f1, f2, f3, ss, env->peer_pk, env->self_pk, false);
        sodium_memzero(f1, sizeof f1);
        sodium_memzero(f2, sizeof f2);
        sodium_memzero(f3, sizeof f3);
        sodium_memzero(ss, sizeof ss);
        s->i_am_initiator = false;
        s->active = true;
        s->reply_due = true;
        s->init_pending = false;
        *handshaked = true;
        return 0;
    }

    if (d.type == TT_FRAME_REPLY) {
        if (!s->init_pending || s->active) return 0; /* dup/late REPLY */
        if (d.hdr_len != TT_HDR_REPLY) return TT_E2EE_DECODE_FAIL;
        if (!env->peer_pk || memcmp(d.hdr, env->peer_pk, TT_KEY32) != 0)
            return TT_E2EE_BAD_ID;
        /* open with dh1 = DH(IKa_sk, ephB1), AD labels IKa */
        uint8_t key[TT_KEY32], scratch[16];
        if (seal_key_derive(key, env->self_sk, d.hdr + 32, env->self_pk) != 0)
            return TT_E2EE_BAD_ID;
        int n = tt_frame_decode(in, in_len, key, &d, scratch, sizeof scratch);
        sodium_memzero(key, sizeof key);
        if (n < 0) return TT_E2EE_DECODE_FAIL;
        /* dh1 = DH(IKa, ephB1), dh2 = DH(ephA2, IKb), dh3 = DH(ephA3, ephB3) */
        uint8_t f1[TT_KEY32], f2[TT_KEY32], f3[TT_KEY32], ss[TT_KEY32];
        int rc = 0;
        if (tt_dh_shared(f1, env->self_sk, d.hdr + 32) != 0) rc = -1;
        if (rc == 0 && tt_dh_shared(f2, s->eph_a2_sk, env->peer_pk) != 0) rc = -1;
        if (rc == 0 && tt_dh_shared(f3, s->eph_a3_sk, d.hdr + 64) != 0) rc = -1;
        if (rc != 0) return TT_E2EE_BAD_ID;
        tt_kem_dec(ss, d.hdr + TT_SESSION_HDR_KEM, s->kem_sk);
        establish(s, f1, f2, f3, ss, env->self_pk, env->peer_pk, true);
        sodium_memzero(f1, sizeof f1);
        sodium_memzero(f2, sizeof f2);
        sodium_memzero(f3, sizeof f3);
        sodium_memzero(ss, sizeof ss);
        s->init_pending = false;
        s->i_am_initiator = true;
        s->active = true;
        *handshaked = true;
        return 0;
    }

    /* ---- reliable-transport control frames (ACK / RESEND) ---- */
    if (d.type == TT_FRAME_ACK || d.type == TT_FRAME_RESEND) {
        if (!s->active) return TT_E2EE_NO_SESSION;
        /* a lossy (tunnel) session never sends these and never buffers, so
           a stray control frame is a decode failure, not a recovery cue */
        if (s->lossy) return TT_E2EE_DECODE_FAIL;
        if (d.hdr_len != 0) return TT_E2EE_DECODE_FAIL;
        uint8_t ck[TT_KEY32], scratch[16];
        control_key(s, ck);
        int n = tt_frame_decode(in, in_len, ck, &d, scratch, sizeof scratch);
        sodium_memzero(ck, sizeof ck);
        if (n < 0) return TT_E2EE_DECODE_FAIL; /* stale gen or corrupt */
        if (n != 8) return TT_E2EE_DECODE_FAIL; /* exactly two u32s */
        uint32_t a = ((uint32_t)scratch[0] << 24) | ((uint32_t)scratch[1] << 16) |
                     ((uint32_t)scratch[2] << 8) | (uint32_t)scratch[3];
        uint32_t b = ((uint32_t)scratch[4] << 24) | ((uint32_t)scratch[5] << 16) |
                     ((uint32_t)scratch[6] << 8) | (uint32_t)scratch[7];
        if (d.type == TT_FRAME_ACK) {
            /* peer delivered up to seq `a` in generation `b`; evict */
            rel_sent_ack(s, b, a);
        } else {
            /* peer lost its chain at gen `a`, seq `b`; re-send buffered
               messages from that generation/seq under the fresh chain */
            s->rel.resend_rep_pending = true;
            s->rel.resend_rep_gen = a;
            s->rel.resend_rep_from = b;
            s->rel.resend_rep_pos = 0;
        }
        return 0;
    }

    /* ---- DATA (M4 ratchet receive) ---- */
    if (!s->active) return TT_E2EE_NO_SESSION;
    if (d.hdr_len != 0 && d.hdr_len != TT_HDR_DATA_REKEY &&
        d.hdr_len != TT_HDR_DATA_KEMPUB)
        return TT_E2EE_DECODE_FAIL;

    /* derive the msg key WITHOUT committing chain state (receive hygiene:
       a corrupt/replayed frame must not consume the chain) */
    uint8_t key[TT_KEY32], nonce[TT_NONCE24];
    bool from_ring = false;
    if (d.seq == s->recv.seq) {
        msg_key_at(&s->recv, d.seq, key, nonce);
    } else if (d.seq > s->recv.seq) {
        if (d.seq - s->recv.seq >= TT_SESSION_MAX_SKIP)
            return TT_E2EE_SEQ_TOO_OLD;
        msg_key_at(&s->recv, d.seq, key, nonce);
    } else {
        if (skipped_take(&s->recv, d.seq, key) != 0)
            return TT_E2EE_REPLAY;
        from_ring = true;
    }

    int n = tt_frame_decode(in, in_len, key, &d, pt, pt_cap);
    if (n < 0) {
        /* restore the original skipped key (not the zeroed one) so a
           corrupt frame cannot poison the ring with a known key */
        if (from_ring) skipped_add(&s->recv, d.seq, key);
        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        /* chain desync: remember the failed seq so the engine can re-send
           it after re-establishing (receiver-driven recovery). The re-send
           must start at the receiver's next-expected seq (recv.seq), not
           the failed frame's seq — messages between them may have been
           dropped on the wire and are missing too. */
        if (s->active && !s->lossy) {
            s->rel.resend_req_pending = true;
            s->rel.resend_req_gen = rel_gen(s);
            s->rel.resend_req_from = s->recv.seq;
        }
        return TT_E2EE_DECODE_FAIL;
    }

    /* commit the chain advance (in-order or skip): store skipped keys for
       the gap, then advance past d.seq */
    if (!from_ring) {
        while (s->recv.seq < d.seq) {
            uint8_t mk[TT_KEY32], nc[TT_KEY32], ek[TT_KEY32], nz[TT_NONCE24];
            tt_kdf_chain_step(nc, mk, s->recv.chain);
            memcpy(s->recv.chain, nc, TT_KEY32);
            tt_kdf_msg_material(ek, nz, mk);
            skipped_add(&s->recv, s->recv.seq, ek);
            s->recv.seq++;
        }
        uint8_t mk[TT_KEY32], nc[TT_KEY32];
        tt_kdf_chain_step(nc, mk, s->recv.chain);
        memcpy(s->recv.chain, nc, TT_KEY32);
        s->recv.seq++;
    }

    /* reliable transport: the highest contiguous seq delivered is now
       recv.seq-1; mark an ACK due so the peer can evict its buffer. A lossy
       (tunnel) session never buffers, so no ACK is needed. */
    if (!s->lossy && s->recv.seq - 1 > s->rel.recv_acked) {
        s->rel.recv_acked = s->recv.seq - 1;
        s->rel.ack_due = true;
    }

    /* apply re-key material (after decrypt; the REKEY frame itself was
       encrypted under the pre-fold key) */
    if (d.hdr_len == TT_HDR_DATA_REKEY) {
        uint8_t ss[TT_KEY32], dh[TT_KEY32];
        tt_kem_dec(ss, d.hdr, s->rekey.kem_sk);
        /* contributory check: a rejected DH (small-order peer point)
           leaves dh unwritten — folding it would mix uninitialized stack
           into the root. Skip the fold (and the peer eph pk store) and
           keep the pre-fold chain; an honest sender can never send a
           small-order eph point (its own fold would have failed), so
           skipping cannot desync a genuine peer. */
        if (tt_dh_shared(dh, s->rekey.eph_sk, d.hdr + TT_HDR_DATA_DH_OFF) == 0) {
            ratchet_fold(&s->recv, dh, ss);
            memcpy(s->rekey.peer_eph_pk, d.hdr + TT_HDR_DATA_DH_OFF, TT_KEY32);
            /* Rotate our re-key keypair NOW, in the same step that consumes
               it. Our pair is what the PEER encapsulates its next REKEY to,
               and applying that REKEY is exactly the moment the pair it
               targeted is spent — so rotating here is the earliest safe
               point, and the latest one that keeps a fold already in flight
               on the wire from targeting a retired pair (`tt_kem_dec` has
               implicit rejection, so that would surface only as a silently
               wrong recv root). The two peers auto-fold in the same window
               every TT_SESSION_REKEY_EVERY frames, and rotating on our own
               send fold instead is what diverged every transfer past ~500KB.
               The fresh pair is published before any pending send fold (see
               emit_frame), so the peer's next re-key targets the pair it
               will consume.
               `peer_have` (the PEER's keys) is deliberately untouched: it
               goes stale only when the peer rotates, and the peer's KEMPUB
               (sent right after its rotation) refreshes it. Our own pair is
               what this branch rotates. */
            tt_dh_keygen(s->rekey.eph_pk, s->rekey.eph_sk);
            tt_kem_keygen(s->rekey.kem_pk, s->rekey.kem_sk);
            s->rekey.have_kem = true;
            s->rekey.published = false;
            s->rekey.post_fold_publish = true; /* publish before any fold */
        }
        sodium_memzero(ss, sizeof ss);
        sodium_memzero(dh, sizeof dh);
    } else if (d.hdr_len == TT_HDR_DATA_KEMPUB) {
        /* reject the published eph pk unless it is contributory with OUR
           re-key eph sk — exactly the DH emit_frame will run when folding
           the peer's direction, so a point it would reject can never be
           stored (and later folded). The KEM pk needs no check: tt_kem_dec
           has implicit rejection and handles arbitrary bytes. */
        uint8_t probe[TT_KEY32];
        int ok = tt_dh_shared(probe, s->rekey.eph_sk, d.hdr + TT_KEM_PK) == 0;
        sodium_memzero(probe, sizeof probe);
        if (ok) {
            memcpy(s->rekey.peer_kem_pk, d.hdr, TT_KEM_PK);
            memcpy(s->rekey.peer_eph_pk, d.hdr + TT_KEM_PK, TT_KEY32);
            s->rekey.peer_have = true;
            if (s->rekey.awaiting_peer) {
                /* we published and were waiting: now we can fold our direction */
                s->rekey.awaiting_peer = false;
                s->rekey.rekey_due = true;
            } else if (s->rekey.have_kem && !s->rekey.published) {
                /* publish ours back so the peer can fold its direction */
                s->rekey.publish_back = true;
            }
        }
    }

    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    return n;
}

/* ---- send ---- */

/* encrypt one text into a DATA frame. On a lossy (tunnel) session
   `carrier_only` selects which of the two frame kinds is built:
     carrier_only = true  — the re-key carrier (empty plaintext; the re-key
                            header if one is due). The result is PARKED so it
                            can be re-offered verbatim until the transport
                            accepts it.
     carrier_only = false — a plain payload frame. No header is ever attached:
                            a re-key that comes due stays pending for the next
                            carrier build, so a payload frame can never be the
                            peer's only route to a fold (it would have to be
                            retried verbatim AND its payload delivered twice).
   The non-lossy chat path always uses carrier_only = false and keeps the
   in-line header behaviour (tox messages are retransmitted by the chat
   reliable transport, so a lost header is recoverable there). */
static int emit_frame(TTSession *s, const uint8_t *text, size_t len,
                      uint8_t *out, size_t cap, bool carrier_only) {
    uint8_t key[TT_KEY32], nonce[TT_NONCE24];
    uint8_t flags = tt_aead_gcm_available()
                        ? (uint8_t)(TT_FRAME_FLAG_GCM | TT_FRAME_FLAG_AES_HW)
                        : 0u;
    uint8_t hdr[TT_HDR_DATA_KEMPUB]; /* largest DATA hdr */
    size_t hdr_len = 0;
    bool do_fold = false;
    uint8_t fold_dh[TT_KEY32], fold_ss[TT_KEY32];

    /* A re-key carrier is parked until the transport accepts it (see
       TTRekey.carrier): a fold is committed in the very call that builds its
       carrier, so the peer can only follow through that exact frame, and the
       frames built after it already use the new chain. Until it lands,
       nothing else may be emitted on this session. */
    if (s->lossy && s->rekey.carrier_len > 0) return TT_E2EE_CARRIER;

    /* auto-re-key trigger (every TT_SESSION_REKEY_EVERY frames); does not
       re-fire while we are already waiting for the peer's keys */
    if (!s->rekey.awaiting_peer && s->send.since_fold >= TT_SESSION_REKEY_EVERY)
        s->rekey.rekey_due = true;

    /* Only the carrier build attaches a re-key header on a lossy session; a
       payload frame must stay plain so it is freely droppable (a header
       there would make it the peer's only route to a fold, and it would have
       to be retried verbatim — delivering its payload twice). */
    if (!s->lossy || carrier_only) {
        if (s->rekey.post_fold_publish) {
            /* Our keypair was just rotated (we consumed the peer's REKEY and
               folded our recv direction): publish the fresh pair before
               anything else, so the peer's NEXT re-key targets the pair it
               will actually consume — not the one we just retired. This takes
               priority over a pending fold of our own send direction, which
               uses the PEER's keys and is unaffected by our rotation;
               deferring the publish would let the peer re-key against the
               retired pair (the very divergence this rotation order exists to
               prevent). */
            memcpy(hdr, s->rekey.kem_pk, TT_KEM_PK);
            memcpy(hdr + TT_KEM_PK, s->rekey.eph_pk, TT_KEY32);
            hdr_len = TT_HDR_DATA_KEMPUB;
            flags |= TT_FRAME_FLAG_PK;
            s->rekey.published = true;
            s->rekey.post_fold_publish = false;
            s->rekey.publish_back = false; /* superseded: ours just went out */
        } else if (s->rekey.rekey_due && s->rekey.peer_have) {
            /* REKEY: fold our send direction after encrypting. The peer's
               keys passed the contributory check on receipt, so the DH
               cannot normally fail; on rejection (small-order point) skip
               the REKEY header entirely — a plain frame goes out and the
               re-key stays pending, instead of folding unwritten dh[] into
               the send root. */
            if (tt_dh_shared(fold_dh, s->rekey.eph_sk,
                             s->rekey.peer_eph_pk) == 0) {
                tt_kem_enc(hdr, fold_ss, s->rekey.peer_kem_pk);
                memcpy(hdr + TT_HDR_DATA_DH_OFF, s->rekey.eph_pk, TT_KEY32);
                hdr_len = TT_HDR_DATA_REKEY;
                flags |= TT_FRAME_FLAG_KEM | TT_FRAME_FLAG_PK;
                do_fold = true;
            }
        } else if (s->rekey.rekey_due && !s->rekey.awaiting_peer) {
            /* publish our keys first (peer does not have them yet) */
            if (!s->rekey.have_kem) {
                tt_kem_keygen(s->rekey.kem_pk, s->rekey.kem_sk);
                s->rekey.have_kem = true;
            }
            memcpy(hdr, s->rekey.kem_pk, TT_KEM_PK);
            memcpy(hdr + TT_KEM_PK, s->rekey.eph_pk, TT_KEY32);
            hdr_len = TT_HDR_DATA_KEMPUB;
            flags |= TT_FRAME_FLAG_PK;
            s->rekey.published = true;
            s->rekey.awaiting_peer = true;
            s->rekey.rekey_due = false; /* fold completes when the peer's
                                           keys land */
        } else if (s->rekey.publish_back) {
            /* peer published its keys; publish ours back so it can fold */
            memcpy(hdr, s->rekey.kem_pk, TT_KEM_PK);
            memcpy(hdr + TT_KEM_PK, s->rekey.eph_pk, TT_KEY32);
            hdr_len = TT_HDR_DATA_KEMPUB;
            flags |= TT_FRAME_FLAG_PK;
            s->rekey.published = true;
            s->rekey.publish_back = false;
        }
    }

    uint32_t seq;
    send_key(&s->send, &seq, key, nonce);
    int n = tt_frame_encode(out, cap, TT_FRAME_DATA, seq, flags, key, nonce,
                            hdr_len ? hdr : NULL, hdr_len, text, len);
    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    sodium_memzero(hdr, sizeof hdr);
    if (n < 0) return TT_E2EE_BAD_STATE;

    /* reliable transport: buffer the plaintext tagged {gen, seq} so a
       desync re-send can recover it under the fresh chain. A lossy (tunnel)
       session skips this — datagrams are ephemeral and never re-sent, so
       buffering them would only waste memory. */
    if (!s->lossy) rel_sent_add(s, rel_gen(s), seq, text, len);

    if (do_fold) {
        ratchet_fold(&s->send, fold_dh, fold_ss);
        /* Our re-key keypair is deliberately NOT rotated here. That pair is
           what the PEER encapsulates its next REKEY to, and the peer's REKEY
           folds OUR RECV direction — so the pair must stay valid until we
           have consumed it (see the REKEY handler in tt_session_feed, which
           rotates *after* using it). Rotating on the send fold instead lets
           a fold that is already in flight on the wire target a pair we have
           just replaced: tt_kem_dec has implicit rejection, so the
           decapsulation silently yields a wrong secret and corrupts our recv
           root, with no error to notice. That is the concurrent-rekey stall
           seen past ~500KB, where both peers auto-fold inside the same
           window: each rotated on its own send fold and destroyed the pair
           the other was still encapsulating to. */
        s->rekey.rekey_due = false;
        /* Sending a REKEY is what makes the PEER rotate its pair (it rotates
           on applying our REKEY, see tt_session_feed). Our cached copy of the
           peer's keys is therefore stale now: drop it, so the next REKEY waits
           for the peer's fresh KEMPUB instead of encapsulating to keys the
           peer has retired — a stale ct would decapsulate to garbage and
           corrupt the peer's recv root just as silently. */
        s->rekey.peer_have = false;
        s->send.since_fold = 0;
        sodium_memzero(fold_dh, sizeof fold_dh);
        sodium_memzero(fold_ss, sizeof fold_ss);
    } else {
        s->send.since_fold++;
    }
    /* Park a carrier that carries re-key material. The fold above is already
       committed, so this frame is the peer's only route to the new root: the
       caller must keep re-offering it verbatim until the transport accepts
       it. Every frame built after it uses the post-fold chain and MUST NOT be
       delivered first, or the peer rejects it (AEAD failure) and the session
       diverges permanently. */
    if (s->lossy && (hdr_len == TT_HDR_DATA_REKEY ||
                     hdr_len == TT_HDR_DATA_KEMPUB) &&
        (size_t)n <= sizeof s->rekey.carrier) {
        memcpy(s->rekey.carrier, out, (size_t)n);
        s->rekey.carrier_len = (uint16_t)n;
    }
    return n;
}

/* Build the next re-key carrier for a lossy (tunnel) session, if any is due.
   Returns the frame length (>0), 0 when no carrier is needed right now, or a
   negative status. The frame is parked internally: re-offer it verbatim
   until the transport accepts it (then call tt_session_carrier_done), and
   never emit anything else on this session while a carrier is outstanding. */
int tt_session_carrier(TTSession *s, uint8_t *out, size_t cap) {
    if (!s->active) return 0;
    if (s->rekey.carrier_len > 0) {
        if (cap < s->rekey.carrier_len) return TT_E2EE_BAD_STATE;
        memcpy(out, s->rekey.carrier, s->rekey.carrier_len);
        return (int)s->rekey.carrier_len;
    }
    if (!tt_session_rekey_pending(s)) return 0;
    return emit_frame(s, NULL, 0, out, cap, true);
}

/* True while a built-but-unsent re-key carrier is outstanding. A folded
   session cannot emit payload frames until it lands (see TTRekey.carrier). */
bool tt_session_carrier_pending(const TTSession *s) {
    return s->lossy && s->rekey.carrier_len > 0;
}

/* The transport accepted the outstanding carrier: clear it and resume
   normal emission. */
void tt_session_carrier_done(TTSession *s) {
    sodium_memzero(s->rekey.carrier, s->rekey.carrier_len);
    s->rekey.carrier_len = 0;
}

int tt_session_send(TTSession *s, const TTE2EEEnv *env, const uint8_t *text,
                    size_t len, uint8_t *out, size_t cap) {
    (void)env;
    if (len > TT_FRAME_DATA_MAX) return TT_E2EE_BAD_STATE;
    if (!s->active) {
        if (s->n_pending >= TT_SESSION_PENDING_MAX) return TT_E2EE_BUSY;
        if (len > 0) {
            memcpy(s->pending[s->n_pending].data, text, len);
            s->pending[s->n_pending].len = (uint16_t)len;
            s->n_pending++;
        }
        return 0;
    }
    return emit_frame(s, text, len, out, cap, false);
}

/* Lossy (tunnel) channel send: encrypt one datagram as a DATA frame. Unlike
   tt_session_send, a not-yet-active session DROPS the datagram (lossy
   semantics — no stash, no re-send). Datagrams are freely droppable, so this
   never attaches a re-key header; any due re-key is carried by the separate
   parked carrier (see tt_session_carrier) which the caller must drain
   first. */
int tt_session_send_lossy(TTSession *s, const TTE2EEEnv *env,
                          const uint8_t *text, size_t len,
                          uint8_t *out, size_t cap) {
    (void)env;
    if (len > TT_FRAME_DATA_MAX) return TT_E2EE_BAD_STATE;
    if (!s->active) return 0; /* lossy: drop, never stash */
    return emit_frame(s, text, len, out, cap, false);
}

/* True when a re-key header is due to go out (REKEY or KEMPUB). The tunnel
   engine turns these into the separate parked carrier, so a payload frame is
   never the peer's only route to a fold and stays freely droppable.

   This must mirror emit_frame's header selection EXACTLY, including its
   auto-re-key trigger: if this says "no header" while emit_frame decides to
   attach one, the carrier ordering breaks and the peer rejects post-fold
   frames. */
bool tt_session_rekey_pending(const TTSession *s) {
    if (!s->active) return false;
    /* auto-re-key trigger in emit_frame: a header is attached on this very
       send (and only while not already waiting for the peer's keys) */
    if (!s->rekey.awaiting_peer &&
        s->send.since_fold >= TT_SESSION_REKEY_EVERY)
        return true;
    if (s->rekey.rekey_due && s->rekey.peer_have) return true;
    if (s->rekey.rekey_due && !s->rekey.awaiting_peer) return true;
    if (s->rekey.post_fold_publish) return true;
    if (s->rekey.publish_back) return true;
    return false;
}

int tt_session_flush(TTSession *s, const TTE2EEEnv *env, uint8_t *out, size_t cap) {
    (void)env;
    if (!s->active || s->n_pending == 0) return 0;
    int n = emit_frame(s, s->pending[0].data, s->pending[0].len, out, cap,
                       false);
    if (n <= 0) return n;
    sodium_memzero(s->pending[0].data, sizeof s->pending[0].data);
    for (int i = 1; i < s->n_pending; i++) s->pending[i - 1] = s->pending[i];
    s->n_pending--;
    return n;
}

/* ---- reliable transport: build the next pending control frame ---- */

int tt_session_rel_poll(TTSession *s, const TTE2EEEnv *env, uint8_t *out,
                        size_t cap) {
    (void)env;
    if (!s->active) return 0;
    uint8_t ck[TT_KEY32], nonce[TT_NONCE24], payload[8];
    int n = 0;

    /* 1. RESEND request (we detected a desync): ask the peer to re-send
       everything from gen/from_seq onward. Sent once; the peer's re-sends
       are the recovery. */
    if (s->rel.resend_req_pending) {
        s->rel.resend_req_pending = false;
        payload[0] = (uint8_t)(s->rel.resend_req_gen >> 24);
        payload[1] = (uint8_t)(s->rel.resend_req_gen >> 16);
        payload[2] = (uint8_t)(s->rel.resend_req_gen >> 8);
        payload[3] = (uint8_t)s->rel.resend_req_gen;
        payload[4] = (uint8_t)(s->rel.resend_req_from >> 24);
        payload[5] = (uint8_t)(s->rel.resend_req_from >> 16);
        payload[6] = (uint8_t)(s->rel.resend_req_from >> 8);
        payload[7] = (uint8_t)s->rel.resend_req_from;
        control_key(s, ck);
        randombytes_buf(nonce, sizeof nonce);
        n = tt_frame_encode(out, cap, TT_FRAME_RESEND, 0, 0, ck, nonce,
                            NULL, 0, payload, sizeof payload);
        sodium_memzero(ck, sizeof ck);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(payload, sizeof payload);
        return n > 0 ? n : 0;
    }

    /* 2. RESEND reply: re-encrypt one buffered message (gen==req_gen &&
       seq>=req_from) under the FRESH chain, one per poll call. The re-sent
       message is tagged with the CURRENT gen/seq, so the peer's ACK evicts
       it normally. We scan from the head each call because emit_frame
       mutates the ring (appends the re-send, possibly evicting the head). */
    if (s->rel.resend_rep_pending) {
        TTSentBuf *b = &s->rel.sent;
        for (uint16_t r = 0; r < b->count; r++) {
            uint16_t idx = (b->head + r) % TT_SENT_MAX;
            TTSentMsg *m = &b->m[idx];
            if (m->gen != s->rel.resend_rep_gen ||
                m->seq < s->rel.resend_rep_from)
                continue;
            uint32_t old_gen = m->gen, old_seq = m->seq;
            n = emit_frame(s, m->data, m->len, out, cap, false);
            if (n > 0) {
                /* the re-send consumed a fresh seq; drop the old entry so
                   it is not re-sent again */
                rel_sent_remove(s, old_gen, old_seq);
                return n;
            }
        }
        s->rel.resend_rep_pending = false;
        return 0;
    }

    /* 3. ACK: tell the peer the highest contiguous seq we delivered, so it
       can evict its buffer. Sent once per delivered batch. */
    if (s->rel.ack_due) {
        s->rel.ack_due = false;
        uint32_t a = s->rel.recv_acked, g = rel_gen(s);
        payload[0] = (uint8_t)(a >> 24);
        payload[1] = (uint8_t)(a >> 16);
        payload[2] = (uint8_t)(a >> 8);
        payload[3] = (uint8_t)a;
        payload[4] = (uint8_t)(g >> 24);
        payload[5] = (uint8_t)(g >> 16);
        payload[6] = (uint8_t)(g >> 8);
        payload[7] = (uint8_t)g;
        control_key(s, ck);
        randombytes_buf(nonce, sizeof nonce);
        n = tt_frame_encode(out, cap, TT_FRAME_ACK, 0, 0, ck, nonce,
                            NULL, 0, payload, sizeof payload);
        sodium_memzero(ck, sizeof ck);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero(payload, sizeof payload);
        return n > 0 ? n : 0;
    }

    return 0;
}

/* ---- tick: INIT retransmit ---- */

int tt_session_tick(TTSession *s, const TTE2EEEnv *env, time_t now, uint8_t *out,
                    size_t cap) {
    if (!s->init_pending) return 0;
    if (now - s->init_at < 5) return 0;
    s->init_at = now;
    int n = build_init(s, env, out, cap);
    return n > 0 ? n : 0;
}

/* ---- M4 ratchet engine hooks ---- */

void tt_session_rekey_due(TTSession *s) {
    if (!s->active) return;
    s->rekey.rekey_due = true;
}

/* ---- M4 harness hooks (TT_BOT_E2EE reorder/replay modes) ---- */

/* build the DATA frame for `seq` ("m<N>") WITHOUT committing any send
   state, so the engine can deliver frames out of order (reorder mode). */
int tt_session_frame_at(TTSession *s, const TTE2EEEnv *env, uint32_t seq,
                        uint8_t *out, size_t cap) {
    (void)env;
    if (!s->active) return TT_E2EE_NO_SESSION;
    uint8_t key[TT_KEY32], nonce[TT_NONCE24];
    msg_key_at(&s->send, seq, key, nonce);
    char text[16];
    int tl = snprintf(text, sizeof text, "m%u", (unsigned)seq);
    uint8_t flags = tt_aead_gcm_available()
                        ? (uint8_t)(TT_FRAME_FLAG_GCM | TT_FRAME_FLAG_AES_HW)
                        : 0u;
    int n = tt_frame_encode(out, cap, TT_FRAME_DATA, seq, flags, key, nonce,
                            NULL, 0, (const uint8_t *)text, (size_t)tl);
    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    return n;
}

/* copy the LAST incoming DATA frame for a re-inject (replay mode) */
int tt_session_inject_older(TTSession *s, const TTE2EEEnv *env, uint8_t *out,
                            size_t cap) {
    (void)env;
    if (!s->active) return TT_E2EE_NO_SESSION;
    if (s->last_in_len == 0 || s->last_in_len > cap) return 0;
    memcpy(out, s->last_in, s->last_in_len);
    return (int)s->last_in_len;
}
