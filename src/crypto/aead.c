#include "crypto.h"

#include <sodium.h>

static bool sodium_ready;

static void sodium_init_once(void) {
    if (!sodium_ready) {
        if (sodium_init() < 0) return;
        sodium_ready = true;
    }
}

bool tt_aead_gcm_available(void) {
    sodium_init_once();
    return crypto_aead_aes256gcm_is_available() == 1;
}

TTCipher tt_aead_pick(void) {
    return tt_aead_gcm_available() ? TT_AEAD_AESGCM : TT_AEAD_XCHACHA;
}

size_t tt_aead_nonce_len(TTCipher c) {
    return c == TT_AEAD_AESGCM ? crypto_aead_aes256gcm_NPUBBYTES
                               : crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

int tt_aead_seal(TTCipher c, uint8_t *out, const uint8_t key[TT_KEY32],
                 const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                 const uint8_t *pt, size_t pt_len) {
    sodium_init_once();
    unsigned long long clen;
    int rc;
    if (c == TT_AEAD_AESGCM) {
        /* the caller picked the cipher; honor it or fail — a silent XChaCha
           fallback would mislabel frames that carry the GCM flag */
        if (!tt_aead_gcm_available()) return -1;
        rc = crypto_aead_aes256gcm_encrypt(out, &clen, pt, pt_len, ad, ad_len,
                                           NULL, nonce, key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
            out, &clen, pt, pt_len, ad, ad_len, NULL, nonce, key);
    }
    return rc == 0 && clen == pt_len + TT_MAC16 ? (int)clen : -1;
}

int tt_aead_open(TTCipher c, uint8_t *out, const uint8_t key[TT_KEY32],
                 const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                 const uint8_t *ct, size_t ct_len) {
    sodium_init_once();
    if (ct_len < TT_MAC16) return -1;
    if (c == TT_AEAD_AESGCM && !tt_aead_gcm_available()) return -1;
    unsigned long long plen;
    int rc;
    if (c == TT_AEAD_AESGCM) {
        rc = crypto_aead_aes256gcm_decrypt(out, &plen, NULL, ct, ct_len, ad,
                                           ad_len, nonce, key);
    } else {
        rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            out, &plen, NULL, ct, ct_len, ad, ad_len, nonce, key);
    }
    if (rc != 0) { /* auth failure: never leak partial plaintext */
        sodium_memzero(out, ct_len - TT_MAC16);
        return -1;
    }
    return (int)plen;
}