#ifndef TT_CRYPTO_H
#define TT_CRYPTO_H

/* E2EE layer core primitives (CRYPTO_PLAN M1/M2): KDF + X25519, AEAD
   (AES-256-GCM with XChaCha fallback), SNTRUP761 KEM glue, wire-frame codec.
   All sizes are fixed by the wire format (CRYPTO_PLAN.md); changing them
   needs a ver bump. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TT_KEY32    32u /* X25519 key/shared secret, KEM shared secret, chain keys */
#define TT_KEM_PK  1158u /* sntrup761 encapsulation key (simplexmq/cbits/sntrup761.h) */
#define TT_KEM_SK  1763u /* sntrup761 secret key */
#define TT_KEM_CT  1039u /* sntrup761 ciphertext */
#define TT_MAC16     16u /* AEAD tag size (GCM and Poly1305 agree) */
#define TT_NONCE12   12u /* AES-256-GCM nonce */
#define TT_NONCE24   24u /* XChaCha20-Poly1305 nonce */
#define TT_IKM128   128u /* root IKM: dh1[32] || dh2[32] || dh3[32] || kem_ss[32] */

typedef enum { TT_AEAD_XCHACHA = 0, TT_AEAD_AESGCM = 1 } TTCipher;

/* ---- AEAD (crypto/aead.c) ---- */
/* cipher this CPU can actually run (libsodium gates GCM on hw AES) */
bool tt_aead_gcm_available(void);
TTCipher tt_aead_pick(void);
size_t tt_aead_nonce_len(TTCipher c);
/* seal: out needs pt_len + TT_MAC16 bytes; returns ct length or -1
   (GCM requested without hw AES -> -1; no silent cipher fallback, the
   frame flags must match what was actually sealed).
   open: out needs ct_len - TT_MAC16 bytes; returns pt length or -1
   (auth failure or unavailable cipher; out is zeroed on failure). */
int tt_aead_seal(TTCipher c, uint8_t *out, const uint8_t key[TT_KEY32],
                 const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                 const uint8_t *pt, size_t pt_len);
int tt_aead_open(TTCipher c, uint8_t *out, const uint8_t key[TT_KEY32],
                 const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                 const uint8_t *ct, size_t ct_len);

/* ---- X25519 (crypto/kdf.c) ---- */
void tt_dh_keygen(uint8_t pk[TT_KEY32], uint8_t sk[TT_KEY32]);
/* -1 when the shared secret is all-zero (low-order peer point) */
int tt_dh_shared(uint8_t out[TT_KEY32], const uint8_t sk[TT_KEY32],
                 const uint8_t pk[TT_KEY32]);

/* ---- SNTRUP761 (crypto/kem.c; vendored supercop code) ---- */
void tt_kem_keygen(uint8_t pk[TT_KEM_PK], uint8_t sk[TT_KEM_SK]);
void tt_kem_enc(uint8_t ct[TT_KEM_CT], uint8_t ss[TT_KEY32],
                const uint8_t pk[TT_KEM_PK]);
/* implicit rejection: a corrupted ct yields a random-looking ss (no error) */
void tt_kem_dec(uint8_t ss[TT_KEY32], const uint8_t ct[TT_KEM_CT],
                const uint8_t sk[TT_KEM_SK]);

/* ---- KDF (crypto/kdf.c; BLAKE2b via crypto_generichash + crypto_kdf) ---- */
/* session root from the handshake IKM dh1||dh2||dh3||kem_ss (TT_IKM128 bytes)
   with OOB context salt (both static public keys, <= 64B after folding) */
void tt_kdf_root(uint8_t root[TT_KEY32], const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *ctx, size_t ctx_len);
/* PQ-in-every-root-step: root' folds the fresh DH output and KEM secret */
void tt_kdf_root_step(uint8_t new_root[TT_KEY32], uint8_t chain[TT_KEY32],
                      const uint8_t root[TT_KEY32], const uint8_t dh[TT_KEY32],
                      const uint8_t kem[TT_KEY32]);
/* symmetric message-key hash chain (out-of-order delivery re-derives) */
void tt_kdf_chain_step(uint8_t new_chain[TT_KEY32], uint8_t msg_key[TT_KEY32],
                       const uint8_t chain[TT_KEY32]);
/* per-message AEAD material: enc_key + 24B nonce (GCM consumes nonce[0..11];
   msg_key is used exactly once, so no nonce reuse is possible) */
void tt_kdf_msg_material(uint8_t enc_key[TT_KEY32], uint8_t nonce[TT_NONCE24],
                         const uint8_t msg_key[TT_KEY32]);

/* ---- Frame codec (crypto/frame.c; CRYPTO_PLAN wire format v1) ----
   One frame is exactly one Tox friend message (raw bytes; the Tox wire is
   binary-safe, no armor):

     magic "TTZ1" || ver(u8) || type(u8) || flags(u8) || seq(u32 BE)
       || nonce || hdr_len(u16 BE) || hdr || ct || aead_tag(16)

   nonce is 24B XChaCha (flags bit0 = 0) or 12B AES-256-GCM (bit0 = 1) —
   the same bytes the AEAD runs with. Everything before ct is AEAD AD.
   hdr is constant-size per type (geometry beyond type leaks nothing):
   INIT  dh1||dh2||dh3 pk (96) + kem pk (1158) = 1254B;
   REPLY dh1||dh2||dh3 pk (96) + kem ct (1039) = 1135B;
   DATA  0B, or a piggybacked re-key kem ct (1039B) with bit1 set.
   flags: bit0 cipher used, bit1 KEM material in hdr, bit2 sender is
   GCM-capable (peer capability hint for cipher selection), bits 3..7
   reserved (must be zero). */
#define TT_FRAME_VER          1u
#define TT_FRAME_MAX        1372u /* TOX_MAX_MESSAGE_LENGTH (tox.h) */
#define TT_FRAME_HEAD_MAX     37u /* magic4+ver1+type1+flags1+seq4+nonce24+hdrlen2 */
#define TT_HDR_INIT         1254u /* 3*32 DH pk + TT_KEM_PK */
#define TT_HDR_REPLY        1135u /* 3*32 DH pk + TT_KEM_CT */
#define TT_HDR_KEM_OFF        96u /* KEM material offset inside INIT/REPLY hdr */
#define TT_HDR_DATA_KEMPUB  1190u /* M4: DATA with fresh kem pk + our DH eph pk (bit2) */
#define TT_HDR_DATA_REKEY   1071u /* M4: DATA with kem ct + our DH eph pk (bits1|2) */
#define TT_HDR_DATA_DH_OFF  TT_KEM_CT /* 1039: DH eph pk offset inside REKEY hdr */
#define TT_HDR_DATA_KEM_OFF 0u        /* KEM material offset inside KEMPUB hdr */
#define TT_FRAME_DATA_REKEY TT_HDR_DATA_REKEY
#define TT_FRAME_DATA_MAX (TT_FRAME_MAX - TT_FRAME_HEAD_MAX - TT_MAC16) /* 1319 */

#define TT_FRAME_FLAG_GCM    0x01u
#define TT_FRAME_FLAG_KEM    0x02u
#define TT_FRAME_FLAG_AES_HW 0x04u
#define TT_FRAME_FLAG_PK     0x08u /* M4: DATA hdr carries our fresh kem pk */

typedef enum { TT_FRAME_INIT = 0, TT_FRAME_REPLY = 1, TT_FRAME_DATA = 2 } TTFrameType;

typedef struct {
    TTFrameType type;
    uint8_t flags;
    uint32_t seq;
    const uint8_t *nonce; size_t nonce_len; /* point into the input buffer */
    const uint8_t *hdr;    size_t hdr_len;
    size_t pt_len;
} TTFrameDesc;

/* Seal pt into out (AD = head + hdr). nonce must hold TT_NONCE24 bytes (GCM
   consumes the first 12). hdr_len is validated against the type's constant.
   Returns the frame length or -1 (bad args / would exceed one Tox message). */
int tt_frame_encode(uint8_t *out, size_t cap, TTFrameType type, uint32_t seq,
                    uint8_t flags, const uint8_t key[TT_KEY32],
                    const uint8_t *nonce, const uint8_t *hdr, size_t hdr_len,
                    const uint8_t *pt, size_t pt_len);

/* Structural + authenticated parse. On success desc points into `in` and
   pt_len plaintext bytes were written to pt_out; returns pt_len. Any
   malformed input or auth failure returns -1 and zeroes pt_out
   (pt_cap bytes). seq validity is the ratchet's concern, not the codec's. */
int tt_frame_decode(const uint8_t *in, size_t in_len, const uint8_t key[TT_KEY32],
                    TTFrameDesc *desc, uint8_t *pt_out, size_t pt_cap);

/* Head-only structural parse (NO authentication): fills desc with pointers
   into `in` (nonce/hdr) and the untrusted ciphertext length in pt_len.
   Used to pick the decryption key from hdr contents before tt_frame_decode.
   Returns 0 or -1 (malformed). */
int tt_frame_peek(const uint8_t *in, size_t in_len, TTFrameDesc *desc);

#endif