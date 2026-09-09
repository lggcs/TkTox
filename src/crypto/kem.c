#include "crypto.h"

#include <sodium.h>
#include <sntrup761.h>
#include <string.h>

/* Vendored Streamlined NTRU Prime 761 (public-domain supercop code,
   vendor/sntrup761/sntrup761.c). The KEM wants a caller-supplied RNG;
   libsodium's CSPRNG is the source. */
static void tt_kem_random(void *ctx, size_t len, uint8_t *dst) {
    (void)ctx;
    randombytes_buf(dst, len);
}

void tt_kem_keygen(uint8_t pk[TT_KEM_PK], uint8_t sk[TT_KEM_SK]) {
    if (sodium_init() < 0) return;
    sntrup761_keypair(pk, sk, NULL, tt_kem_random);
}

void tt_kem_enc(uint8_t ct[TT_KEM_CT], uint8_t ss[TT_KEY32],
                const uint8_t pk[TT_KEM_PK]) {
    uint8_t ss_full[SNTRUP761_SIZE];
    sntrup761_enc(ct, ss_full, pk, NULL, tt_kem_random);
    memcpy(ss, ss_full, TT_KEY32);
    sodium_memzero(ss_full, sizeof ss_full);
}

void tt_kem_dec(uint8_t ss[TT_KEY32], const uint8_t ct[TT_KEM_CT],
                const uint8_t sk[TT_KEM_SK]) {
    uint8_t ss_full[SNTRUP761_SIZE];
    sntrup761_dec(ss_full, ct, sk); /* corrupted ct -> implicit-rejection ss */
    memcpy(ss, ss_full, TT_KEY32);
    sodium_memzero(ss_full, sizeof ss_full);
}