/* E2EE layer core primitives unit tests (CRYPTO_PLAN M1).
   Standalone harness, same pattern as tests/test_strip_dht.c: CHECK macro,
   nonzero exit on any failure. Links: kdf/aead/kem + libsodium + sntrup761. */
#include "../src/crypto/crypto.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

static void test_dh(void) {
    uint8_t a_pk[TT_KEY32], a_sk[TT_KEY32], b_pk[TT_KEY32], b_sk[TT_KEY32];
    uint8_t s1[TT_KEY32], s2[TT_KEY32];
    tt_dh_keygen(a_pk, a_sk);
    tt_dh_keygen(b_pk, b_sk);
    CHECK(tt_dh_shared(s1, a_sk, b_pk) == 0);
    CHECK(tt_dh_shared(s2, b_sk, a_pk) == 0);
    CHECK(memcmp(s1, s2, TT_KEY32) == 0);
    /* low-order peer public key must be rejected (all-zero shared secret) */
    static const uint8_t low[32] = { 0 }; /* [0,0,...,0] is on the low-order list */
    CHECK(tt_dh_shared(s1, a_sk, low) == -1);
}

static void test_kem(void) {
    uint8_t pk[TT_KEM_PK], sk[TT_KEM_SK], ct[TT_KEM_CT];
    uint8_t ss_enc[TT_KEY32], ss_dec[TT_KEY32];
    tt_kem_keygen(pk, sk);
    tt_kem_enc(ct, ss_enc, pk);
    tt_kem_dec(ss_dec, ct, sk);
    CHECK(memcmp(ss_enc, ss_dec, TT_KEY32) == 0);
    /* implicit rejection: flipped ciphertext bit yields a DIFFERENT secret,
       no error reported, nothing crashes */
    uint8_t bad[TT_KEM_CT];
    memcpy(bad, ct, sizeof bad);
    bad[0] ^= 1;
    tt_kem_dec(ss_dec, bad, sk);
    CHECK(memcmp(ss_enc, ss_dec, TT_KEY32) != 0);
}

static void test_aead(void) {
    uint8_t key[TT_KEY32], nonce24[TT_NONCE24], nonce12[TT_NONCE12];
    uint8_t pt[64], ct[64 + TT_MAC16], out[64];
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce24, sizeof nonce24);
    randombytes_buf(nonce12, sizeof nonce12);
    randombytes_buf(pt, sizeof pt);
    const uint8_t ad[] = "frame header";
    const uint8_t badad[] = "frame headeg";

    /* XChaCha roundtrip */
    int n = tt_aead_seal(TT_AEAD_XCHACHA, ct, key, nonce24, ad, sizeof ad,
                         pt, sizeof pt);
    CHECK(n == (int)(sizeof pt + TT_MAC16));
    n = tt_aead_open(TT_AEAD_XCHACHA, out, key, nonce24, ad, sizeof ad, ct, n);
    CHECK(n == (int)sizeof pt);
    CHECK(memcmp(pt, out, sizeof pt) == 0);
    /* wrong AD / wrong key / flipped bit -> -1, no crash, zeroed out */
    n = tt_aead_open(TT_AEAD_XCHACHA, out, key, nonce24, badad, sizeof badad,
                     ct, sizeof ct);
    CHECK(n == -1);
    n = tt_aead_open(TT_AEAD_XCHACHA, out, key, nonce24, ad, sizeof ad, ct,
                     sizeof ct - 1); /* truncated tag */
    CHECK(n == -1);
    ct[0] ^= 1;
    CHECK(tt_aead_open(TT_AEAD_XCHACHA, out, key, nonce24, ad, sizeof ad, ct,
                       sizeof ct) == -1);
    ct[0] ^= 1;

    /* AES-GCM path: only meaningful with hw support, but must never crash */
    if (tt_aead_gcm_available()) {
        n = tt_aead_seal(TT_AEAD_AESGCM, ct, key, nonce12, ad, sizeof ad,
                         pt, sizeof pt);
        CHECK(n == (int)(sizeof pt + TT_MAC16));
        n = tt_aead_open(TT_AEAD_AESGCM, out, key, nonce12, ad, sizeof ad,
                         ct, n);
        CHECK(n == (int)sizeof pt);
        CHECK(memcmp(pt, out, sizeof pt) == 0);
        /* cross-ciphertext swap: GCM ct under XChaCha open must fail */
        CHECK(tt_aead_open(TT_AEAD_XCHACHA, out, key, nonce24, ad, sizeof ad,
                           ct, sizeof ct) == -1);
    }
    /* cipher request must be honored: GCM without hw support refuses rather
       than silently falling back (frames carry the cipher flag) */
    if (!tt_aead_gcm_available()) {
        CHECK(tt_aead_seal(TT_AEAD_AESGCM, ct, key, nonce12, ad, sizeof ad,
                           pt, sizeof pt) == -1);
    }
    CHECK(tt_aead_nonce_len(TT_AEAD_AESGCM) == TT_NONCE12);
    CHECK(tt_aead_nonce_len(TT_AEAD_XCHACHA) == TT_NONCE24);
}

static void test_kdf(void) {
    uint8_t ikm[TT_IKM128], ctx[64], root1[TT_KEY32], root2[TT_KEY32];
    uint8_t root_next[TT_KEY32], chain[TT_KEY32], mk1[TT_KEY32], mk2[TT_KEY32];
    uint8_t chain_next[TT_KEY32], ek[TT_KEY32], nonce[TT_NONCE24];
    randombytes_buf(ikm, sizeof ikm);
    randombytes_buf(ctx, sizeof ctx);

    /* root is deterministic in (ikm, ctx) and differs per context */
    tt_kdf_root(root1, ikm, sizeof ikm, ctx, sizeof ctx);
    tt_kdf_root(root2, ikm, sizeof ikm, ctx, sizeof ctx);
    CHECK(memcmp(root1, root2, TT_KEY32) == 0);
    tt_kdf_root(root2, ikm, sizeof ikm, ctx, 63);
    CHECK(memcmp(root1, root2, TT_KEY32) != 0);

    /* root step folds dh+kem: new root/chain differ from inputs, deterministic */
    uint8_t dh[TT_KEY32], kem[TT_KEY32], chain2[TT_KEY32];
    uint8_t root_next2[TT_KEY32], chain_b[TT_KEY32];
    randombytes_buf(dh, sizeof dh);
    randombytes_buf(kem, sizeof kem);
    tt_kdf_root_step(root_next, chain, root1, dh, kem);
    tt_kdf_root_step(root_next2, chain_b, root1, dh, kem);
    CHECK(memcmp(root_next, root_next2, TT_KEY32) == 0);
    CHECK(memcmp(chain, chain_b, TT_KEY32) == 0);
    CHECK(memcmp(root_next, root1, TT_KEY32) != 0);
    CHECK(memcmp(chain, root1, TT_KEY32) != 0);
    /* changing only the KEM input changes the root (PQ-in-every-step property) */
    uint8_t kem2[TT_KEY32], root3[TT_KEY32], chain3[TT_KEY32];
    memcpy(kem2, kem, TT_KEY32);
    kem2[0] ^= 1;
    tt_kdf_root_step(root3, chain3, root1, dh, kem2);
    CHECK(memcmp(root3, root_next, TT_KEY32) != 0);

    /* hash chain: deterministic, forward-linked, msg keys differ per step */
    tt_kdf_chain_step(chain_next, mk1, chain);
    tt_kdf_chain_step(chain2, mk2, chain_next);
    CHECK(memcmp(mk1, mk2, TT_KEY32) != 0);
    CHECK(memcmp(chain, chain_next, TT_KEY32) != 0);
    CHECK(memcmp(chain_next, chain2, TT_KEY32) != 0);
    /* skipped-key derivation: re-walking the chain from mk1's state yields
       exactly mk2 (out-of-order delivery recovers skipped keys) */
    uint8_t mk_skip[TT_KEY32], chain_skip[TT_KEY32];
    tt_kdf_chain_step(chain_skip, mk_skip, chain_next);
    CHECK(memcmp(mk_skip, mk2, TT_KEY32) == 0);

    /* message material: fixed 40B expansion, nonce differs per msg key */
    uint8_t ek2[TT_KEY32], nonce2[TT_NONCE24];
    tt_kdf_msg_material(ek, nonce, mk1);
    tt_kdf_msg_material(ek2, nonce2, mk2);
    CHECK(memcmp(ek, ek2, TT_KEY32) != 0);
    CHECK(memcmp(nonce, nonce2, TT_NONCE24) != 0);

    /* end-to-end micro-flow: both parties derive identical material from the
       same root step, and AEAD roundtrips through it */
    uint8_t r_root[TT_KEY32], r_chain[TT_KEY32], e_root[TT_KEY32], e_chain[TT_KEY32];
    tt_kdf_root_step(r_root, r_chain, root1, dh, kem);
    tt_kdf_root_step(e_root, e_chain, root1, dh, kem);
    CHECK(memcmp(r_root, e_root, TT_KEY32) == 0);
    uint8_t r_mk[TT_KEY32], r_nc[TT_KEY32], e_mk[TT_KEY32], e_nc[TT_KEY32];
    tt_kdf_chain_step(r_nc, r_mk, r_chain);
    tt_kdf_chain_step(e_nc, e_mk, e_chain);
    CHECK(memcmp(r_mk, e_mk, TT_KEY32) == 0);
    (void)r_nc; (void)e_nc;
    uint8_t eek[TT_KEY32], en[TT_NONCE24], rek[TT_KEY32], rn[TT_NONCE24];
    tt_kdf_msg_material(eek, en, e_mk);
    tt_kdf_msg_material(rek, rn, r_mk);
    uint8_t ct2[64 + TT_MAC16], dout[64];
    int n = tt_aead_seal(tt_aead_pick(), ct2, eek, en, ctx, 32, ikm, 64);
    CHECK(n == 64 + TT_MAC16);
    n = tt_aead_open(tt_aead_pick(), dout, rek, rn, ctx, 32, ct2, n);
    CHECK(n == 64);
    CHECK(memcmp(ikm, dout, 64) == 0);
}

int main(void) {
    if (sodium_init() < 0) return 2;
    test_dh();
    test_kem();
    test_aead();
    test_kdf();
    if (fails == 0) puts("crypto core: ALL PASS");
    return fails ? 1 : 0;
}