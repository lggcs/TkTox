/* Frame codec unit tests (CRYPTO_PLAN M2): roundtrips for all frame types +
   malformed-input suite (truncation, bit-flips, bad fields) — every reject
   path must return -1 and never crash. Standalone harness, same pattern as
   tests/test_crypto.c. */
#include "../src/crypto/crypto.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

#define MAXPT 1319 /* TT_FRAME_DATA_MAX */

static uint8_t key[TT_KEY32], nonce24[TT_NONCE24];
static uint8_t hdr_init[TT_HDR_INIT], hdr_reply[TT_HDR_REPLY];
static uint8_t hdr_rekey[TT_HDR_DATA_REKEY], hdr_kempub[TT_HDR_DATA_KEMPUB];
static uint8_t fbuf[TT_FRAME_MAX], ptbuf[TT_FRAME_MAX];
static TTFrameDesc d;

static void roundtrip(TTFrameType type, uint8_t flags, const uint8_t *hdr,
                      size_t hdr_len, const uint8_t *pt, size_t pt_len,
                      uint32_t seq) {
    int n = tt_frame_encode(fbuf, sizeof fbuf, type, seq, flags, key, nonce24,
                            hdr, hdr_len, pt, pt_len);
    CHECK(n > 0);
    uint8_t out[TT_FRAME_MAX];
    n = tt_frame_decode(fbuf, (size_t)n, key, &d, out, sizeof out);
    CHECK(n == (int)pt_len);
    if (pt_len > 0) CHECK(memcmp(pt, out, pt_len) == 0);
    CHECK(d.type == type);
    CHECK(d.flags == flags);
    CHECK(d.seq == seq);
    CHECK(d.nonce_len == ((flags & TT_FRAME_FLAG_GCM) ? TT_NONCE12 : TT_NONCE24));
    CHECK(d.hdr_len == hdr_len);
    if (hdr_len > 0) CHECK(memcmp(d.hdr, hdr, hdr_len) == 0);
    CHECK(d.nonce == fbuf + 11);
    CHECK(memcmp(d.nonce, nonce24, d.nonce_len) == 0);
}

static void test_roundtrips(void) {
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce24, sizeof nonce24);
    randombytes_buf(hdr_init, sizeof hdr_init);
    randombytes_buf(hdr_reply, sizeof hdr_reply);
    randombytes_buf(hdr_rekey, sizeof hdr_rekey);
    randombytes_buf(hdr_kempub, sizeof hdr_kempub);
    randombytes_buf(ptbuf, sizeof ptbuf);

    /* INIT: max plaintext budget = 1372 - 37 - 1254 - 16 = 65 */
    roundtrip(TT_FRAME_INIT, TT_FRAME_FLAG_KEM | TT_FRAME_FLAG_AES_HW,
              hdr_init, sizeof hdr_init, ptbuf, 65, 1);
    roundtrip(TT_FRAME_INIT, TT_FRAME_FLAG_KEM, hdr_init, sizeof hdr_init,
              ptbuf, 0, 2);
    /* REPLY */
    roundtrip(TT_FRAME_REPLY, TT_FRAME_FLAG_KEM | TT_FRAME_FLAG_AES_HW,
              hdr_reply, sizeof hdr_reply, ptbuf, 33, 0xffffffffu);
    /* DATA plain + DATA with M4 re-key hdrs */
    roundtrip(TT_FRAME_DATA, TT_FRAME_FLAG_AES_HW, NULL, 0, ptbuf, MAXPT, 7);
    roundtrip(TT_FRAME_DATA, TT_FRAME_FLAG_KEM | TT_FRAME_FLAG_PK,
              hdr_rekey, sizeof hdr_rekey, ptbuf, 100, 8);
    roundtrip(TT_FRAME_DATA, TT_FRAME_FLAG_PK, hdr_kempub, sizeof hdr_kempub,
              ptbuf, 50, 10);
    roundtrip(TT_FRAME_DATA, 0, NULL, 0, NULL, 0, 9); /* empty pt is legal */
    /* empty pt decodes to length 0 (not an error) */
    int n = tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 9, 0, key,
                            nonce24, NULL, 0, NULL, 0);
    CHECK(n == (int)(11 + TT_NONCE24 + 2 + TT_MAC16));
    n = tt_frame_decode(fbuf, (size_t)n, key, &d, ptbuf, sizeof ptbuf);
    CHECK(n == 0 && d.pt_len == 0);

    /* GCM path when the hardware is present */
    if (tt_aead_gcm_available()) {
        roundtrip(TT_FRAME_DATA, TT_FRAME_FLAG_GCM | TT_FRAME_FLAG_AES_HW,
                  NULL, 0, ptbuf, 77, 3);
        n = tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 3,
                            TT_FRAME_FLAG_GCM, key, nonce24, NULL, 0,
                            ptbuf, 77);
        CHECK(n == (int)(11 + TT_NONCE12 + 2 + 77 + TT_MAC16));
    }

    /* determinism: identical inputs -> identical bytes */
    int n1 = tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 42, 0, key,
                             nonce24, NULL, 0, ptbuf, 16);
    uint8_t f2[TT_FRAME_MAX];
    int n2 = tt_frame_encode(f2, sizeof f2, TT_FRAME_DATA, 42, 0, key,
                             nonce24, NULL, 0, ptbuf, 16);
    CHECK(n1 == n2 && memcmp(fbuf, f2, (size_t)n1) == 0);
}

static void test_rejects(void) {
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce24, sizeof nonce24);
    randombytes_buf(hdr_init, sizeof hdr_init);
    randombytes_buf(ptbuf, sizeof ptbuf);

    int n = tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 1, 0, key,
                            nonce24, NULL, 0, ptbuf, 64);
    CHECK(n > 0);
    size_t flen = (size_t)n;
    uint8_t out[TT_FRAME_MAX];
    uint8_t good[TT_FRAME_MAX];
    memcpy(good, fbuf, flen);

    /* every truncation length must be rejected */
    for (size_t i = 0; i < flen; i++)
        CHECK(tt_frame_decode(good, i, key, &d, out, sizeof out) == -1);

    /* every single-bit flip anywhere must be rejected (AEAD covers head,
       hdr, ct and tag; nonce is inside the AD) */
    uint8_t flip[TT_FRAME_MAX];
    for (size_t i = 0; i < flen; i++) {
        memcpy(flip, good, flen);
        flip[i] ^= 0x01;
        CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
        memcpy(flip, good, flen);
        flip[i] ^= 0x80;
        CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
    }

    /* wrong key */
    uint8_t other[TT_KEY32];
    randombytes_buf(other, sizeof other);
    CHECK(tt_frame_decode(good, flen, other, &d, out, sizeof out) == -1);

    /* bad magic / version / type / reserved flags */
    memcpy(flip, good, flen);
    flip[0] = 'X';
    CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
    memcpy(flip, good, flen);
    flip[4] = 2;
    CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
    memcpy(flip, good, flen);
    flip[5] = 9;
    CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
    memcpy(flip, good, flen);
    flip[6] |= 0x08; /* reserved bit */
    CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);

    /* oversized input */
    uint8_t junk[1400];
    randombytes_buf(junk, sizeof junk);
    CHECK(tt_frame_decode(junk, sizeof junk, key, &d, out, sizeof out) == -1);

    /* pt_out zeroed on auth failure */
    memset(out, 0xaa, sizeof out);
    memcpy(flip, good, flen);
    flip[flen - 1] ^= 1;
    CHECK(tt_frame_decode(flip, flen, key, &d, out, sizeof out) == -1);
    bool all_zero = true;
    for (size_t i = 0; i < 64; i++) all_zero = all_zero && out[i] == 0;
    CHECK(all_zero);

    /* pt_cap smaller than the payload must be refused, not truncated */
    CHECK(tt_frame_decode(good, flen, key, &d, out, 63) == -1);

    /* encode-side validation */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 1, 0, key,
                          nonce24, NULL, 0, ptbuf, MAXPT + 1) == -1);
    CHECK(tt_frame_encode(fbuf, 12, TT_FRAME_DATA, 1, 0, key,
                          nonce24, NULL, 0, ptbuf, 64) == -1); /* cap */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 1, 0xF8u, key,
                          nonce24, NULL, 0, ptbuf, 16) == -1); /* reserved */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_INIT, 1, 0, key,
                          nonce24, hdr_init, sizeof hdr_init, ptbuf, 16)
          == -1); /* INIT without KEM flag */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_INIT, 1,
                          TT_FRAME_FLAG_KEM, key, nonce24, hdr_init, 1253,
                          ptbuf, 16) == -1); /* wrong hdr_len */
    /* INIT plaintext budget: 65 ok, 66 exceeds one Tox message */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_INIT, 1,
                          TT_FRAME_FLAG_KEM, key, nonce24, hdr_init,
                          sizeof hdr_init, ptbuf, 66) == -1);
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_INIT, 1,
                          TT_FRAME_FLAG_KEM, key, nonce24, hdr_init,
                          sizeof hdr_init, ptbuf, 65) > 0);
    /* DATA claiming a re-key without the hdr */
    CHECK(tt_frame_encode(fbuf, sizeof fbuf, TT_FRAME_DATA, 1,
                          TT_FRAME_FLAG_KEM, key, nonce24, NULL, 0,
                          ptbuf, 16) == -1);
}

int main(void) {
    if (sodium_init() < 0) return 2;
    test_roundtrips();
    test_rejects();
    if (fails == 0) puts("frame codec: ALL PASS");
    return fails ? 1 : 0;
}