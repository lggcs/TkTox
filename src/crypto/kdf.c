#include "crypto.h"

#include <sodium.h>
#include <string.h>

static bool sodium_ready;

static void sodium_init_once(void) {
    if (!sodium_ready) {
        if (sodium_init() < 0) return; /* fatal; callers see random failure */
        sodium_ready = true;
    }
}

/* ---- X25519 ---- */

void tt_dh_keygen(uint8_t pk[TT_KEY32], uint8_t sk[TT_KEY32]) {
    sodium_init_once();
    randombytes_buf(sk, crypto_scalarmult_SCALARBYTES);
    /* crypto_scalarmult_base clamps the scalar internally */
    crypto_scalarmult_base(pk, sk);
}

int tt_dh_shared(uint8_t out[TT_KEY32], const uint8_t sk[TT_KEY32],
                 const uint8_t pk[TT_KEY32]) {
    sodium_init_once();
    return crypto_scalarmult(out, sk, pk);
}

/* ---- KDF (BLAKE2b-based; crypto_generichash key = extraction, domain
        separation through distinct context prefixes + crypto_kdf) ---- */

void tt_kdf_root(uint8_t root[TT_KEY32], const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *ctx, size_t ctx_len) {
    sodium_init_once();
    /* extract: keyed BLAKE2b with a fixed domain key (IKM is the message) */
    static const uint8_t salt_key[32] = {
        'T', 'T', 'Z', '1', '-', 'r', 'o', 'o', 't', '-', 'e', 'x', 't', 'r',
        'a', 'c', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    crypto_generichash_state st;
    crypto_generichash_init(&st, salt_key, sizeof salt_key, TT_KEY32);
    crypto_generichash_update(&st, ikm, ikm_len);
    crypto_generichash_update(&st, ctx, ctx_len);
    crypto_generichash_final(&st, root, TT_KEY32);
}

void tt_kdf_root_step(uint8_t new_root[TT_KEY32], uint8_t chain[TT_KEY32],
                      const uint8_t root[TT_KEY32], const uint8_t dh[TT_KEY32],
                      const uint8_t kem[TT_KEY32]) {
    /* expand: 64B = new root (0..31) + chain key (32..63); domain = "TTZ1-rs" */
    uint8_t ikm[3 * TT_KEY32];
    uint8_t out[64];
    memcpy(ikm, root, TT_KEY32);
    memcpy(ikm + TT_KEY32, dh, TT_KEY32);
    memcpy(ikm + 2 * TT_KEY32, kem, TT_KEY32);
    static const uint8_t ctx[8] = { 'T', 'T', 'Z', '1', '-', 'r', 's', 0 };
    crypto_generichash(out, sizeof out, ikm, sizeof ikm, ctx, sizeof ctx);
    sodium_memzero(ikm, sizeof ikm);
    memcpy(new_root, out, TT_KEY32);
    memcpy(chain, out + TT_KEY32, TT_KEY32);
    sodium_memzero(out, sizeof out);
}

void tt_kdf_chain_step(uint8_t new_chain[TT_KEY32], uint8_t msg_key[TT_KEY32],
                       const uint8_t chain[TT_KEY32]) {
    uint8_t out[64];
    static const uint8_t ctx[8] = { 'T', 'T', 'Z', '1', '-', 'c', 'h', 0 };
    crypto_generichash(out, sizeof out, chain, TT_KEY32, ctx, sizeof ctx);
    memcpy(msg_key, out, TT_KEY32);
    memcpy(new_chain, out + TT_KEY32, TT_KEY32);
    sodium_memzero(out, sizeof out);
}

void tt_kdf_msg_material(uint8_t enc_key[TT_KEY32], uint8_t nonce[TT_NONCE24],
                         const uint8_t msg_key[TT_KEY32]) {
    uint8_t out[TT_KEY32 + TT_NONCE24];
    static const uint8_t ctx[8] = { 'T', 'T', 'Z', '1', '-', 'm', 'k', 0 };
    crypto_generichash(out, sizeof out, msg_key, TT_KEY32, ctx, sizeof ctx);
    memcpy(enc_key, out, TT_KEY32);
    memcpy(nonce, out + TT_KEY32, TT_NONCE24);
    sodium_memzero(out, sizeof out);
}