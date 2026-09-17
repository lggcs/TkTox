/* Session re-key regression tests (post-audit fixes, 2026-09-14).
   Covers the three TTZ1 re-key defects found in the security audit:

   F1  unchecked tt_dh_shared in both re-key folds — a small-order peer
       eph point used to fold uninitialized stack into the ratchet root.
       Fixed: the fold (and the peer eph store) is skipped on rejection.
   F2  unconditional REKEY fold (implicit-rejection KEM always "succeeds")
       — a crafted REKEY wedged the session. Fixed: no fold without a
       contributory DH; genuine traffic keeps flowing.
   F3  KEMPUB stored with no validation — a non-contributory eph point
       could be stored and later poison a fold. Fixed: contributory probe
       before storing.

   Also exercises the honest re-key cycle across the 64-frame boundary in
   both directions to prove the fixes do not disturb normal operation. */
#include "../src/session.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

static uint8_t fbuf[TT_FRAME_MAX], fb2[TT_FRAME_MAX];
static uint8_t pt[TT_FRAME_MAX], got[TT_FRAME_MAX];

typedef struct Peer {
    uint8_t sk[TT_KEY32], pk[TT_KEY32];
    TTE2EEEnv env;
    TTSession s;
} Peer;

static void peer_init(Peer *p) {
    tt_dh_keygen(p->pk, p->sk);
    p->env.self_sk = p->sk;
    p->env.self_pk = p->pk;
    p->env.peer_pk = NULL;
    tt_session_init(&p->s);
}

static int handshake(Peer *ini, Peer *rsp) {
    bool hs = false;
    int n = tt_session_start(&ini->s, &ini->env, fbuf, sizeof fbuf);
    if (n <= 0) return -1;
    if (tt_session_feed(&rsp->s, &rsp->env, fbuf, (size_t)n, pt, sizeof pt, &hs) != 0 || !hs)
        return -1;
    n = tt_session_reply(&rsp->s, &rsp->env, fb2, sizeof fb2);
    if (n <= 0) return -1;
    if (tt_session_feed(&ini->s, &ini->env, fb2, (size_t)n, pt, sizeof pt, &hs) != 0 || !hs)
        return -1;
    return 0;
}

/* encrypt one text on `from` without committing send state (same msg-key
   derivation as session.c send_key()) — lets tests craft attacker frames */
static int craft_data(Peer *from, uint8_t hdr_flags, const uint8_t *hdr,
                      size_t hdr_len, const void *payload, size_t plen,
                      uint8_t *out, size_t cap) {
    uint8_t key[TT_KEY32], nonce[TT_NONCE24], mk[TT_KEY32], nc[TT_KEY32];
    tt_kdf_chain_step(nc, mk, from->s.send.chain);
    tt_kdf_msg_material(key, nonce, mk);
    sodium_memzero(mk, sizeof mk);
    sodium_memzero(nc, sizeof nc);
    uint8_t flags = tt_aead_gcm_available()
                        ? (uint8_t)(TT_FRAME_FLAG_GCM | TT_FRAME_FLAG_AES_HW)
                        : 0u;
    flags |= hdr_flags;
    int n = tt_frame_encode(out, cap, TT_FRAME_DATA, from->s.send.seq, flags,
                            key, nonce, hdr_len ? hdr : NULL, hdr_len,
                            payload, plen);
    sodium_memzero(key, sizeof key);
    sodium_memzero(nonce, sizeof nonce);
    return n;
}

/* commit the send-state step a REAL sender would have consumed when it
   emitted the crafted frame (craft_data itself commits nothing, so a
   following genuine frame would otherwise reuse the same seq) */
static void commit_crafted(Peer *from) {
    uint8_t mk[TT_KEY32], nc[TT_KEY32];
    tt_kdf_chain_step(nc, mk, from->s.send.chain);
    memcpy(from->s.send.chain, nc, TT_KEY32);
    sodium_memzero(mk, sizeof mk);
    sodium_memzero(nc, sizeof nc);
    from->s.send.seq++;
}

/* relay one message from a to b (send -> feed -> ACK round trip) */
static void relay_ack(Peer *a, Peer *b, const char *text, size_t len) {
    bool hs = false;
    int n = tt_session_send(&a->s, &a->env, (const uint8_t *)text, len,
                            fbuf, sizeof fbuf);
    CHECK(n > 0);
    int m = tt_session_feed(&b->s, &b->env, fbuf, (size_t)n, got, sizeof got, &hs);
    CHECK(m == (int)len && memcmp(got, text, len) == 0);
    if (a->s.lossy) return;
    /* drain the receiver's ACK and the sender's pending re-sends */
    int c;
    while ((c = tt_session_rel_poll(&b->s, &b->env, fb2, sizeof fb2)) > 0)
        CHECK(tt_session_feed(&a->s, &a->env, fb2, (size_t)c, pt, sizeof pt, &hs) == 0);
    while ((c = tt_session_rel_poll(&a->s, &a->env, fb2, sizeof fb2)) > 0)
        CHECK(tt_session_feed(&b->s, &b->env, fb2, (size_t)c, pt, sizeof pt, &hs) == 0);
}

/* u = 0: the order-4 point; libsodium 1.0.18 rejects it (rc=-1) and does
   NOT write the output buffer (see audit-probe-run.txt) */
static const uint8_t small_order_pk[TT_KEY32]; /* all-zero */

/* F3 + F1: a KEMPUB whose eph pk is non-contributory (small-order) must
   not be stored — it would poison a later fold */
static void test_kempub_small_order_rejected(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B);
    A.env.peer_pk = B.pk; B.env.peer_pk = A.pk;
    CHECK(handshake(&A, &B) == 0);

    uint8_t atk_kem_pk[TT_KEM_PK], atk_kem_sk[TT_KEM_SK];
    tt_kem_keygen(atk_kem_pk, atk_kem_sk);
    uint8_t khdr[TT_HDR_DATA_KEMPUB];
    memcpy(khdr, atk_kem_pk, TT_KEM_PK);
    memcpy(khdr + TT_KEM_PK, small_order_pk, TT_KEY32);
    int n = craft_data(&B, TT_FRAME_FLAG_PK, khdr, TT_HDR_DATA_KEMPUB,
                       "poison", 6, fbuf, sizeof fbuf);
    CHECK(n > 0);
    bool hs = false;
    /* the frame itself decrypts (payload delivered), but the keys are
       rejected: no store, no publish_back */
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)n, got, sizeof got, &hs) == 6);
    CHECK(!A.s.rekey.peer_have);
    commit_crafted(&B); /* the attacker did consume its chain step */
    relay_ack(&B, &A, "still-alive", 11); /* session unaffected */

    /* a VALID KEMPUB (real eph point) is still accepted: interop kept */
    uint8_t vhdr[TT_HDR_DATA_KEMPUB];
    memcpy(vhdr, B.s.rekey.kem_pk, TT_KEM_PK);
    memcpy(vhdr + TT_KEM_PK, B.s.rekey.eph_pk, TT_KEY32);
    n = craft_data(&B, TT_FRAME_FLAG_PK, vhdr, TT_HDR_DATA_KEMPUB,
                   "ok", 2, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)n, got, sizeof got, &hs) == 2);
    CHECK(A.s.rekey.peer_have);
    commit_crafted(&B);
    relay_ack(&B, &A, "after-ok", 8);
}

/* F1 (recv fold): a REKEY whose DH leg is a small-order point must not
   fold — the root stays put and genuine traffic keeps flowing */
static void test_rekey_small_order_skips_fold(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B);
    A.env.peer_pk = B.pk; B.env.peer_pk = A.pk;
    CHECK(handshake(&A, &B) == 0);

    uint8_t root_before[TT_KEY32];
    memcpy(root_before, A.s.recv.root, TT_KEY32);

    uint8_t ct[TT_KEM_CT], ss0[TT_KEY32];
    tt_kem_enc(ct, ss0, A.s.rekey.kem_pk); /* attacker knows ss0 */
    uint8_t rhdr[TT_HDR_DATA_REKEY];
    memcpy(rhdr, ct, TT_KEM_CT);
    memcpy(rhdr + TT_HDR_DATA_DH_OFF, small_order_pk, TT_KEY32);
    int n = craft_data(&B, (uint8_t)(TT_FRAME_FLAG_KEM | TT_FRAME_FLAG_PK),
                       rhdr, TT_HDR_DATA_REKEY, "wedge", 5, fbuf, sizeof fbuf);
    CHECK(n > 0);
    bool hs = false;
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)n, got, sizeof got, &hs) == 5);
    CHECK(memcmp(A.s.recv.root, root_before, TT_KEY32) == 0); /* NO fold */
    commit_crafted(&B); /* the attacker did consume its chain step */
    sodium_memzero(ss0, sizeof ss0);
    sodium_memzero(ct, sizeof ct);

    /* genuine traffic continues — no wedge */
    relay_ack(&B, &A, "unwedged", 8);
    CHECK(memcmp(A.s.recv.root, root_before, TT_KEY32) == 0);
}

/* Concurrent auto-re-key: both peers reach the 64-frame boundary in the same
   window, which is what a bulk transfer does to a saturated link. Regression
   for the shared published-keypair defect: the fold used to regenerate our
   keypair, so when both sides folded before consuming the other's REKEY, each
   decapsulated the in-flight ct with a retired secret and tt_kem_dec's
   implicit rejection silently corrupted the recv root (the next frame then
   failed AEAD and the stream stalled for good — the ~1MB transfer failure).
   The pair must be rotated only when we APPLY the peer's REKEY, never on our
   own send fold. */
static void test_rekey_concurrent_fold(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B);
    A.env.peer_pk = B.pk; B.env.peer_pk = A.pk;
    CHECK(handshake(&A, &B) == 0);

    /* Drive BOTH sides past the re-key boundary before delivering either, so
       each reaches the fold with the peer's keys on file and its own re-key
       material still in flight. */
    enum { N = TT_SESSION_REKEY_EVERY + 4 };
    static uint8_t a[N][TT_FRAME_MAX], b[N][TT_FRAME_MAX];
    int an[N], bn[N];
    for (unsigned i = 0; i < N; i++) {
        char t[16];
        snprintf(t, sizeof t, "a%u", i);
        an[i] = tt_session_send(&A.s, &A.env, (const uint8_t *)t, strlen(t),
                                a[i], sizeof a[i]);
        CHECK(an[i] > 0);
        snprintf(t, sizeof t, "b%u", i);
        bn[i] = tt_session_send(&B.s, &B.env, (const uint8_t *)t, strlen(t),
                                b[i], sizeof b[i]);
        CHECK(bn[i] > 0);
    }
    bool hs = false;
    CHECK(A.s.rekey.awaiting_peer && B.s.rekey.awaiting_peer);

    /* cross-deliver so each side learns the peer's published keys */
    for (unsigned i = 0; i < N; i++)
        CHECK(tt_session_feed(&B.s, &B.env, a[i], (size_t)an[i], got,
                              sizeof got, &hs) > 0);
    for (unsigned i = 0; i < N; i++)
        CHECK(tt_session_feed(&A.s, &A.env, b[i], (size_t)bn[i], got,
                              sizeof got, &hs) > 0);

    /* both are due to fold — fold BOTH before delivering either REKEY, so each
       ct is in flight while its target pair is retired by the sender's own
       fold (the exact concurrent case) */
    int ar = tt_session_send(&A.s, &A.env, (const uint8_t *)"x", 1, a[0],
                             sizeof a[0]);
    int br = tt_session_send(&B.s, &B.env, (const uint8_t *)"y", 1, b[0],
                             sizeof b[0]);
    CHECK(ar > 0 && br > 0);

    /* each REKEY decrypts, but the discriminating effect is the recv ROOT: on
       the old rotation order these folds mix a garbage secret, so the frames
       below fail AEAD */
    CHECK(tt_session_feed(&A.s, &A.env, b[0], (size_t)br, got, sizeof got, &hs) > 0);
    CHECK(tt_session_feed(&B.s, &B.env, a[0], (size_t)ar, got, sizeof got, &hs) > 0);

    /* The ratchets must still interoperate in both directions. Keep this
       bounded (a plain DATA exchange, not relay_ack): on the pre-fix code the
       session is broken and relay_ack's unacked-message drain would spin
       forever re-requesting a re-send, turning a failure into a hang. */
    int m = tt_session_send(&A.s, &A.env, (const uint8_t *)"post", 4, a[0],
                            sizeof a[0]);
    CHECK(m > 0);
    CHECK(tt_session_feed(&B.s, &B.env, a[0], (size_t)m, got, sizeof got, &hs) == 4);
    m = tt_session_send(&B.s, &B.env, (const uint8_t *)"post", 4, b[0],
                        sizeof b[0]);
    CHECK(m > 0);
    CHECK(tt_session_feed(&A.s, &A.env, b[0], (size_t)m, got, sizeof got, &hs) == 4);
}

/* honest re-key cycle: 70 frames each way crosses the 64-frame re-key
   boundary in both directions (KEMPUB publish -> REKEY fold ->
   post-fold publish -> peer fold); every message must decrypt and the
   verify code must stay stable across the folds */
static void test_rekey_honest_cycle(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B);
    A.env.peer_pk = B.pk; B.env.peer_pk = A.pk;
    CHECK(handshake(&A, &B) == 0);

    char vc0[33], vc1[33];
    CHECK(tt_session_verify_code(&A.s, vc0));
    CHECK(tt_session_verify_code(&B.s, vc0));

    for (unsigned i = 0; i < 70; i++) {
        char ta[32], tb[32];
        snprintf(ta, sizeof ta, "a%u", i);
        snprintf(tb, sizeof tb, "b%u", i);
        relay_ack(&A, &B, ta, strlen(ta));
        relay_ack(&B, &A, tb, strlen(tb));
    }
    /* both directions folded at least once */
    CHECK(A.s.send.since_fold < TT_SESSION_REKEY_EVERY);
    CHECK(B.s.send.since_fold < TT_SESSION_REKEY_EVERY);
    CHECK(tt_session_verify_code(&A.s, vc1));
    CHECK(memcmp(vc0, vc1, 33) == 0); /* stable across folds */
    relay_ack(&A, &B, "post-cycle", 10);
    relay_ack(&B, &A, "post-cycle", 10);
}

int main(void) {
    if (sodium_init() < 0) return 2;
    test_kempub_small_order_rejected();
    test_rekey_small_order_skips_fold();
    test_rekey_concurrent_fold();
    test_rekey_honest_cycle();
    if (fails == 0) puts("rekey: ALL PASS");
    return fails ? 1 : 0;
}