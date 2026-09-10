/* Session layer unit tests (CRYPTO_PLAN M3): two in-process TTSession
   instances cross-feeding frames through the public API — INIT/REPLY
   handshake, verify-code equality, DATA roundtrip, replay / corrupt-frame
   rejection, INIT retransmit detection, out-of-order behavior, max-skip
   boundary, stash+flush, status paths, simultaneous-INIT collision.
   Same pattern as tests/test_frame.c. */
#include "../src/session.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

static uint8_t fbuf[TT_FRAME_MAX], fb2[TT_FRAME_MAX], fb3[TT_FRAME_MAX];
static uint8_t pt[TT_FRAME_MAX];

typedef struct Peer {
    uint8_t sk[TT_KEY32], pk[TT_KEY32];
    TTE2EEEnv env;
    TTSession s;
} Peer;

static void peer_init(Peer *p) {
    tt_dh_keygen(p->pk, p->sk);
    p->env.self_sk = p->sk;
    p->env.self_pk = p->pk;
    p->env.peer_pk = NULL; /* pair_link() or the test sets it */
    tt_session_init(&p->s);
}

static void pair_link(Peer *a, Peer *b) {
    a->env.peer_pk = b->pk;
    b->env.peer_pk = a->pk;
}

/* full INIT/REPLY handshake; returns 0 on success */
static int handshake(TTSession *ini, TTE2EEEnv *ei, TTSession *rsp, TTE2EEEnv *er) {
    bool hs = false;
    int n = tt_session_start(ini, ei, fbuf, sizeof fbuf);
    if (n <= 0) return -1;
    if (tt_session_feed(rsp, er, fbuf, (size_t)n, pt, sizeof pt, &hs) != 0 || !hs)
        return -1;
    n = tt_session_reply(rsp, er, fb2, sizeof fb2);
    if (n <= 0) return -1;
    if (tt_session_feed(ini, ei, fb2, (size_t)n, pt, sizeof pt, &hs) != 0 || !hs)
        return -1;
    return 0;
}

/* encrypt on `from`, decrypt on `to`; returns the plaintext length */
static int relay(TTSession *from, TTE2EEEnv *ef, const void *text, size_t len,
                 TTSession *to, TTE2EEEnv *et, uint8_t *got, size_t got_cap) {
    bool hs = false;
    int n = tt_session_send(from, ef, text, len, fbuf, sizeof fbuf);
    if (n <= 0) return n;
    return tt_session_feed(to, et, fbuf, (size_t)n, got, got_cap, &hs);
}

static void test_layer_switch(void) {
    unsetenv("TT_E2EE");
    CHECK(!tt_e2ee_init_mode());
    setenv("TT_E2EE", "1", 1);
    CHECK(tt_e2ee_init_mode());
    setenv("TT_E2EE", "", 1);
    CHECK(tt_e2ee_init_mode());
    unsetenv("TT_E2EE");
}

static void test_handshake_and_data(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);

    /* verify code: 32 lowercase hex chars, identical on both peers */
    char vca[33], vcb[33];
    CHECK(tt_session_verify_code(&A.s, vca));
    CHECK(tt_session_verify_code(&B.s, vcb));
    CHECK(strlen(vca) == 32 && strcmp(vca, vcb) == 0);
    CHECK(strspn(vca, "0123456789abcdef") == 32 && vca[32] == '\0');

    uint8_t got[TT_FRAME_MAX];
    int n = relay(&A.s, &A.env, "hello", 5, &B.s, &B.env, got, sizeof got);
    CHECK(n == 5 && memcmp(got, "hello", 5) == 0);
    n = relay(&B.s, &B.env, "bonjour", 7, &A.s, &A.env, got, sizeof got);
    CHECK(n == 7 && memcmp(got, "bonjour", 7) == 0);

    /* replay: the same frame a second time */
    bool hs = false;
    n = tt_session_send(&A.s, &A.env, (const uint8_t *)"dup", 3, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, got, sizeof got, &hs) == 3);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, got, sizeof got, &hs)
          == TT_E2EE_REPLAY);

    /* corrupt frame: rejected, and it must not consume receive-chain state */
    n = tt_session_send(&A.s, &A.env, (const uint8_t *)"intact", 6, fbuf, sizeof fbuf);
    CHECK(n > 0);
    memcpy(fb3, fbuf, (size_t)n);
    fb3[n - 1] ^= 0x01;
    CHECK(tt_session_feed(&B.s, &B.env, fb3, (size_t)n, got, sizeof got, &hs)
          == TT_E2EE_DECODE_FAIL);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, got, sizeof got, &hs) == 6);
    CHECK(memcmp(got, "intact", 6) == 0);

    /* max-size payload roundtrip; one byte over is refused */
    static uint8_t big[TT_FRAME_DATA_MAX];
    memset(big, 0x5a, sizeof big);
    n = relay(&A.s, &A.env, big, sizeof big, &B.s, &B.env, got, sizeof got);
    CHECK(n == (int)sizeof big && memcmp(got, big, sizeof big) == 0);
    CHECK(tt_session_send(&A.s, &A.env, big, sizeof big + 1, fbuf, sizeof fbuf)
          == TT_E2EE_BAD_STATE);
}

static void test_retransmit(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    bool hs = false;
    time_t t0 = time(NULL);
    int n = tt_session_start(&A.s, &A.env, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, pt, sizeof pt, &hs) == 0);
    CHECK(hs);
    n = tt_session_reply(&B.s, &B.env, fb2, sizeof fb2);
    CHECK(n > 0);
    /* tick fires only after the 5s retransmit interval */
    CHECK(tt_session_tick(&A.s, &A.env, t0, fbuf, sizeof fbuf) <= 0);
    CHECK(tt_session_tick(&A.s, &A.env, t0 + 4, fbuf, sizeof fbuf) <= 0);
    int rn = tt_session_tick(&A.s, &A.env, t0 + 6, fbuf, sizeof fbuf);
    CHECK(rn > 0);
    /* duplicate INIT: responder re-sends the cached REPLY byte-identically */
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)rn, pt, sizeof pt, &hs) == 0);
    CHECK(hs);
    uint8_t again[TT_FRAME_MAX];
    CHECK(tt_session_reply(&B.s, &B.env, again, sizeof again) == n);
    CHECK(memcmp(again, fb2, (size_t)n) == 0);
    CHECK(tt_session_feed(&A.s, &A.env, fb2, (size_t)n, pt, sizeof pt, &hs) == 0);
    CHECK(hs);
    uint8_t got[TT_FRAME_MAX];
    int m = relay(&A.s, &A.env, "after-retry", 11, &B.s, &B.env, got, sizeof got);
    CHECK(m == 11 && memcmp(got, "after-retry", 11) == 0);
    /* established: tick is idle */
    CHECK(tt_session_tick(&A.s, &A.env, t0 + 60, fbuf, sizeof fbuf) <= 0);
}

static void test_out_of_order(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);
    bool hs = false;
    uint8_t got[TT_FRAME_MAX];
    int n1 = tt_session_send(&A.s, &A.env, (const uint8_t *)"aa", 2, fbuf, sizeof fbuf);
    int n2 = tt_session_send(&A.s, &A.env, (const uint8_t *)"bb", 2, fb2, sizeof fb2);
    int n3 = tt_session_send(&A.s, &A.env, (const uint8_t *)"cc", 2, fb3, sizeof fb3);
    CHECK(n1 > 0 && n2 > 0 && n3 > 0);
    /* deliver 3 first: inside maxSkip -> accepted, chain jumps to 4;
       1 and 2 are recovered through the M4 skipped-key store */
    CHECK(tt_session_feed(&B.s, &B.env, fb3, (size_t)n3, got, sizeof got, &hs) == 2);
    CHECK(memcmp(got, "cc", 2) == 0);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n1, got, sizeof got, &hs) == 2);
    CHECK(memcmp(got, "aa", 2) == 0);
    CHECK(tt_session_feed(&B.s, &B.env, fb2, (size_t)n2, got, sizeof got, &hs) == 2);
    CHECK(memcmp(got, "bb", 2) == 0);
    /* a genuine replay (same seq again) is still rejected */
    CHECK(tt_session_feed(&B.s, &B.env, fb3, (size_t)n3, got, sizeof got, &hs)
          == TT_E2EE_REPLAY);
}

/* seq next+maxSkip-1 is the last acceptable frame; seq next+maxSkip exceeds
   the skip window and must be refused */
static void test_max_skip_boundary(void) {
    Peer A, B, C, D;
    peer_init(&A); peer_init(&B); peer_init(&C); peer_init(&D);
    pair_link(&A, &B); pair_link(&C, &D);
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);
    CHECK(handshake(&C.s, &C.env, &D.s, &D.env) == 0);
    bool hs = false;
    uint8_t got[TT_FRAME_MAX];
    int n = 0;
    for (unsigned i = 0; i < TT_SESSION_MAX_SKIP; i++) /* last seq = 512 */
        n = tt_session_send(&A.s, &A.env, (const uint8_t *)"x", 1, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, got, sizeof got, &hs) == 1);
    n = 0;
    for (unsigned i = 0; i < TT_SESSION_MAX_SKIP + 1; i++) /* last seq = 513 */
        n = tt_session_send(&C.s, &C.env, (const uint8_t *)"x", 1, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&D.s, &D.env, fbuf, (size_t)n, got, sizeof got, &hs)
          == TT_E2EE_SEQ_TOO_OLD);
}

static void test_stash_flush(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    uint8_t got[TT_FRAME_MAX];
    /* inactive: texts stash in order until the ring is full */
    CHECK(tt_session_send(&A.s, &A.env, (const uint8_t *)"t1", 2, fbuf, sizeof fbuf) == 0);
    CHECK(tt_session_send(&A.s, &A.env, (const uint8_t *)"t2", 2, fbuf, sizeof fbuf) == 0);
    CHECK(tt_session_send(&A.s, &A.env, (const uint8_t *)"t3", 2, fbuf, sizeof fbuf) == 0);
    CHECK(tt_session_send(&A.s, &A.env, (const uint8_t *)"t4", 2, fbuf, sizeof fbuf) == 0);
    CHECK(tt_session_send(&A.s, &A.env, (const uint8_t *)"t5", 2, fbuf, sizeof fbuf) == TT_E2EE_BUSY);
    /* flush before establishment is a no-op */
    CHECK(tt_session_flush(&A.s, &A.env, fbuf, sizeof fbuf) == 0);
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);
    for (int i = 0; i < 4; i++) {
        bool hs = false;
        int n = tt_session_flush(&A.s, &A.env, fbuf, sizeof fbuf);
        CHECK(n > 0);
        CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n, got, sizeof got, &hs)
              == 2);
        CHECK(got[0] == 't' && got[1] == (uint8_t)('1' + i));
    }
    CHECK(tt_session_flush(&A.s, &A.env, fbuf, sizeof fbuf) == 0);
}

static void test_status_paths(void) {
    Peer A, B, C, D;
    peer_init(&A); peer_init(&B); peer_init(&C); peer_init(&D);
    pair_link(&A, &B);
    C.env.peer_pk = B.pk; /* C expects B but will see A's INIT */
    D.env.peer_pk = A.pk; /* D paired with A, session never started */
    bool hs = false;
    int n = tt_session_start(&A.s, &A.env, fbuf, sizeof fbuf);
    CHECK(n > 0);
    /* INIT claiming a foreign identity */
    CHECK(tt_session_feed(&C.s, &C.env, fbuf, (size_t)n, pt, sizeof pt, &hs)
          == TT_E2EE_BAD_ID);
    /* REPLY build with no outstanding INIT */
    CHECK(tt_session_reply(&D.s, &D.env, fb2, sizeof fb2) == TT_E2EE_BAD_STATE);
    /* start with a missing peer key */
    TTE2EEEnv bad = {.self_sk = A.sk, .self_pk = A.pk, .peer_pk = NULL};
    CHECK(tt_session_start(&D.s, &bad, fb2, sizeof fb2) == TT_E2EE_NOKEY);
    /* DATA with no established session */
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);
    n = tt_session_send(&A.s, &A.env, (const uint8_t *)"m", 1, fbuf, sizeof fbuf);
    CHECK(n > 0);
    CHECK(tt_session_feed(&D.s, &D.env, fbuf, (size_t)n, pt, sizeof pt, &hs)
          == TT_E2EE_NO_SESSION);
}

/* both peers run tt_session_start at once: the LOWER identity pk keeps the
   initiator role and ignores the peer's INIT; the higher pk yields, clears,
   re-runs as responder to the peer's INIT (stashed texts survive), and the
   resulting session is a single normal session */
static void test_collision(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    Peer *lo = memcmp(A.pk, B.pk, TT_KEY32) < 0 ? &A : &B;
    Peer *hi = lo == &A ? &B : &A;
    int nl = tt_session_start(&lo->s, &lo->env, fbuf, sizeof fbuf);
    int nh = tt_session_start(&hi->s, &hi->env, fb2, sizeof fb2);
    CHECK(nl > 0 && nh > 0);
    /* hi stashes a text while its handshake is pending; must survive yield */
    CHECK(tt_session_send(&hi->s, &hi->env, (const uint8_t *)"mine", 4, fb3, sizeof fb3) == 0);
    bool hs = false;
    /* hi sees lo's INIT: yields and accepts it as responder */
    CHECK(tt_session_feed(&hi->s, &hi->env, fbuf, (size_t)nl, pt, sizeof pt, &hs)
          == 0);
    CHECK(hs);
    /* lo sees hi's INIT: lower pk -> ignore, keep waiting for the REPLY */
    CHECK(tt_session_feed(&lo->s, &lo->env, fb2, (size_t)nh, pt, sizeof pt, &hs)
          == 0);
    CHECK(!hs);
    /* hi replies; lo completes the handshake */
    int nr = tt_session_reply(&hi->s, &hi->env, fb2, sizeof fb2);
    CHECK(nr > 0);
    CHECK(tt_session_feed(&lo->s, &lo->env, fb2, (size_t)nr, pt, sizeof pt, &hs)
          == 0);
    CHECK(hs);
    /* hi flushed its stashed text over the new session */
    uint8_t got[TT_FRAME_MAX];
    int nf = tt_session_flush(&hi->s, &hi->env, fbuf, sizeof fbuf);
    CHECK(nf > 0);
    CHECK(tt_session_feed(&lo->s, &lo->env, fbuf, (size_t)nf, got, sizeof got, &hs)
          == 4);
    CHECK(memcmp(got, "mine", 4) == 0);
    CHECK(tt_session_flush(&hi->s, &hi->env, fbuf, sizeof fbuf) == 0);
    /* normal traffic both ways + matching verify codes */
    int n = relay(&lo->s, &lo->env, "l2h", 3, &hi->s, &hi->env, got, sizeof got);
    CHECK(n == 3 && memcmp(got, "l2h", 3) == 0);
    n = relay(&hi->s, &hi->env, "h2l", 3, &lo->s, &lo->env, got, sizeof got);
    CHECK(n == 3 && memcmp(got, "h2l", 3) == 0);
    char vcl[33], vch[33];
    CHECK(tt_session_verify_code(&lo->s, vcl));
    CHECK(tt_session_verify_code(&hi->s, vch));
    CHECK(strcmp(vcl, vch) == 0);
}

/* reliable transport: a chain desync (receiver's recv chain diverged) drops
   the sender's frame; the receiver re-establishes, sends a RESEND request,
   and the sender re-encrypts its buffered messages under the fresh chain so
   nothing is lost. */
static void test_desync_recovery(void) {
    Peer A, B;
    peer_init(&A); peer_init(&B); pair_link(&A, &B);
    CHECK(handshake(&A.s, &A.env, &B.s, &B.env) == 0);
    bool hs = false;
    uint8_t got[TT_FRAME_MAX];

    /* A sends m1..m3; B does NOT receive them (dropped on the wire), so
       they sit in A's reliable buffer tagged with the initial gen */
    int n1 = tt_session_send(&A.s, &A.env, (const uint8_t *)"m1", 2, fbuf, sizeof fbuf);
    int n2 = tt_session_send(&A.s, &A.env, (const uint8_t *)"m2", 2, fb2, sizeof fb2);
    int n3 = tt_session_send(&A.s, &A.env, (const uint8_t *)"m3", 2, fb3, sizeof fb3);
    CHECK(n1 > 0 && n2 > 0 && n3 > 0);
    CHECK(A.s.rel.sent.count == 3);
    uint32_t gen0 = A.s.rel.sent.m[0].gen; /* the initial generation */

    /* B's recv chain diverges (simulated corruption); A's next frame fails */
    B.s.recv.chain[0] ^= 0xff;
    int n4 = tt_session_send(&A.s, &A.env, (const uint8_t *)"m4", 2, fbuf, sizeof fbuf);
    CHECK(n4 > 0);
    CHECK(tt_session_feed(&B.s, &B.env, fbuf, (size_t)n4, got, sizeof got, &hs)
          == TT_E2EE_DECODE_FAIL);
    /* B recorded a RESEND request from its next-expected seq (1) */
    CHECK(B.s.rel.resend_req_pending);
    CHECK(B.s.rel.resend_req_gen == gen0 && B.s.rel.resend_req_from == 1);

    /* B re-establishes; the RESEND request survives */
    int nb = tt_session_start(&B.s, &B.env, fbuf, sizeof fbuf);
    CHECK(nb > 0);
    CHECK(B.s.rel.resend_req_pending);

    /* B's INIT makes A (active initiator) yield and re-establish as
       responder; A's buffer survives */
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)nb, pt, sizeof pt, &hs) == 0);
    CHECK(hs);
    CHECK(A.s.rel.sent.count == 4); /* m1..m4 still buffered */

    /* A (now responder) replies; B (initiator) completes the handshake;
       both active on the fresh generation */
    int nr = tt_session_reply(&A.s, &A.env, fb2, sizeof fb2);
    CHECK(nr > 0);
    CHECK(tt_session_feed(&B.s, &B.env, fb2, (size_t)nr, pt, sizeof pt, &hs) == 0);
    CHECK(hs);
    CHECK(A.s.active && B.s.active);

    /* B sends the RESEND request (old gen, from=1); A can now decrypt it */
    int rr = tt_session_rel_poll(&B.s, &B.env, fbuf, sizeof fbuf);
    CHECK(rr > 0);
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)rr, pt, sizeof pt, &hs) == 0);
    CHECK(A.s.rel.resend_rep_pending);
    CHECK(A.s.rel.resend_rep_gen == gen0 && A.s.rel.resend_rep_from == 1);

    /* A re-sends m1..m4 under the fresh chain; B recovers all four */
    const char *expect[] = { "m1", "m2", "m3", "m4" };
    for (int i = 0; i < 4; i++) {
        int rs = tt_session_rel_poll(&A.s, &A.env, fbuf, sizeof fbuf);
        CHECK(rs > 0);
        int rn = tt_session_feed(&B.s, &B.env, fbuf, (size_t)rs, got, sizeof got, &hs);
        CHECK(rn == 2 && memcmp(got, expect[i], 2) == 0);
    }
    /* nothing left to re-send */
    CHECK(tt_session_rel_poll(&A.s, &A.env, fbuf, sizeof fbuf) <= 0);

    /* B ACKs the recovered messages; A evicts its buffer */
    int ac = tt_session_rel_poll(&B.s, &B.env, fbuf, sizeof fbuf);
    CHECK(ac > 0); /* ACK */
    CHECK(tt_session_feed(&A.s, &A.env, fbuf, (size_t)ac, pt, sizeof pt, &hs) == 0);
    CHECK(A.s.rel.sent.count == 0);
}

int main(void) {
    if (sodium_init() < 0) return 2;
    test_layer_switch();
    test_handshake_and_data();
    test_retransmit();
    test_out_of_order();
    test_max_skip_boundary();
    test_stash_flush();
    test_status_paths();
    test_collision();
    test_desync_recovery();
    if (fails == 0) puts("session: ALL PASS");
    return fails ? 1 : 0;
}