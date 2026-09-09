#include "crypto.h"

#include <sodium.h>
#include <string.h>

static bool sodium_ready;

static void sodium_init_once(void) {
    if (!sodium_ready) {
        if (sodium_init() < 0) return;
        sodium_ready = true;
    }
}

static const uint8_t frame_magic[4] = { 'T', 'T', 'Z', '1' };

/* hdr_len is a constant per (type, flags): geometry beyond type leaks nothing
   (SimpleX-style fixed-size padded headers). */
static int expected_hdr_len(uint8_t type, uint8_t flags) {
    switch (type) {
    case TT_FRAME_INIT:
    case TT_FRAME_REPLY:
        if (!(flags & TT_FRAME_FLAG_KEM)) return -1;
        return type == TT_FRAME_INIT ? (int)TT_HDR_INIT : (int)TT_HDR_REPLY;
    case TT_FRAME_DATA:
        /* M4 geometry: 0 (plain) / TT_HDR_DATA_KEMPUB (bit2: our next
           re-key pk) / TT_HDR_DATA_REKEY (bits1|2: peer's kem ct + our pk) */
        if (flags & TT_FRAME_FLAG_KEM) {
            if (!(flags & TT_FRAME_FLAG_PK)) return -1;
            return (int)TT_HDR_DATA_REKEY;
        }
        if (flags & TT_FRAME_FLAG_PK) return (int)TT_HDR_DATA_KEMPUB;
        return 0;
    default:
        return -1;
    }
}

int tt_frame_encode(uint8_t *out, size_t cap, TTFrameType type, uint32_t seq,
                    uint8_t flags, const uint8_t key[TT_KEY32],
                    const uint8_t *nonce, const uint8_t *hdr, size_t hdr_len,
                    const uint8_t *pt, size_t pt_len) {
    sodium_init_once();
    if (!out || !key || !nonce) return -1;
    if (flags & 0xF0u) return -1; /* reserved bits (4..7) must be zero */
    int want = expected_hdr_len((uint8_t)type, flags);
    if (want < 0 || hdr_len != (size_t)want) return -1;
    if (hdr_len > 0 && !hdr) return -1;
    if (pt_len > (size_t)TT_FRAME_MAX) return -1;
    if (pt_len > 0 && !pt) return -1;
    size_t nonce_len = (flags & TT_FRAME_FLAG_GCM) ? TT_NONCE12 : TT_NONCE24;
    size_t head = 11u + nonce_len + 2u;
    size_t total = head + hdr_len + pt_len + TT_MAC16;
    if (total > (size_t)TT_FRAME_MAX || total > cap) return -1;

    size_t off = 0;
    memcpy(out + off, frame_magic, 4);
    off += 4;
    out[off++] = (uint8_t)TT_FRAME_VER;
    out[off++] = (uint8_t)type;
    out[off++] = flags;
    out[off++] = (uint8_t)(seq >> 24);
    out[off++] = (uint8_t)(seq >> 16);
    out[off++] = (uint8_t)(seq >> 8);
    out[off++] = (uint8_t)seq;
    memcpy(out + off, nonce, nonce_len);
    off += nonce_len;
    out[off++] = (uint8_t)(hdr_len >> 8);
    out[off++] = (uint8_t)(hdr_len & 0xffu);
    if (hdr_len > 0) {
        memcpy(out + off, hdr, hdr_len);
        off += hdr_len;
    }
    /* everything before the ciphertext is the AEAD AD */
    int n = tt_aead_seal((flags & TT_FRAME_FLAG_GCM) ? TT_AEAD_AESGCM
                                                     : TT_AEAD_XCHACHA,
                         out + off, key, nonce, out, off, pt, pt_len);
    if (n < 0 || (size_t)n != pt_len + TT_MAC16) return -1;
    return (int)(off + (size_t)n);
}

int tt_frame_peek(const uint8_t *in, size_t in_len, TTFrameDesc *desc) {
    if (!in || !desc || in_len > (size_t)TT_FRAME_MAX) return -1;
    if (in_len < 11u + TT_NONCE12 + 2u + TT_MAC16) return -1;
    if (memcmp(in, frame_magic, 4) != 0) return -1;
    if (in[4] != (uint8_t)TT_FRAME_VER) return -1;
    uint8_t type = in[5];
    uint8_t flags = in[6];
    if (flags & 0xF0u) return -1;
    size_t nonce_len = (flags & TT_FRAME_FLAG_GCM) ? TT_NONCE12 : TT_NONCE24;
    if (in_len < 11u + nonce_len + 2u) return -1;
    size_t hdr_len = ((size_t)in[11u + nonce_len] << 8) | in[11u + nonce_len + 1u];
    const uint8_t *hdr = in + 11u + nonce_len + 2u;
    if (in_len < 11u + nonce_len + 2u + hdr_len + TT_MAC16) return -1;
    desc->type = (TTFrameType)type;
    desc->flags = flags;
    desc->seq = ((uint32_t)in[7] << 24) | ((uint32_t)in[8] << 16) |
                ((uint32_t)in[9] << 8) | (uint32_t)in[10];
    desc->nonce = in + 11u;
    desc->nonce_len = nonce_len;
    desc->hdr = hdr_len > 0 ? hdr : NULL;
    desc->hdr_len = hdr_len;
    desc->pt_len = in_len - (11u + nonce_len + 2u + hdr_len) - TT_MAC16;
    return 0;
}

int tt_frame_decode(const uint8_t *in, size_t in_len, const uint8_t key[TT_KEY32],
                    TTFrameDesc *desc, uint8_t *pt_out, size_t pt_cap) {
    sodium_init_once();
    if (!in || !key || !desc) return -1;
    if (in_len > (size_t)TT_FRAME_MAX) return -1;
    /* smallest possible frame: GCM nonce, no hdr, empty pt + tag */
    if (in_len < 11u + TT_NONCE12 + 2u + TT_MAC16) return -1;
    if (memcmp(in, frame_magic, 4) != 0) return -1;
    if (in[4] != (uint8_t)TT_FRAME_VER) return -1;
    uint8_t type = in[5];
    uint8_t flags = in[6];
    if (flags & 0xF0u) return -1;
    uint32_t seq = ((uint32_t)in[7] << 24) | ((uint32_t)in[8] << 16) |
                   ((uint32_t)in[9] << 8) | (uint32_t)in[10];
    size_t nonce_len = (flags & TT_FRAME_FLAG_GCM) ? TT_NONCE12 : TT_NONCE24;
    size_t off = 11u;
    const uint8_t *nonce = in + off;
    off += nonce_len;
    if (in_len < off + 2u) return -1;
    size_t hdr_len = ((size_t)in[off] << 8) | (size_t)in[off + 1u];
    off += 2u;
    int want = expected_hdr_len(type, flags);
    if (want < 0 || hdr_len != (size_t)want) return -1;
    if (in_len < off + hdr_len + TT_MAC16) return -1;
    const uint8_t *hdr = in + off;
    off += hdr_len;
    size_t ct_len = in_len - off;
    size_t pt_len = ct_len - TT_MAC16;
    if (pt_len > pt_cap) return -1;
    if (pt_len > 0 && !pt_out) return -1;
    int n = tt_aead_open((flags & TT_FRAME_FLAG_GCM) ? TT_AEAD_AESGCM
                                                     : TT_AEAD_XCHACHA,
                         pt_out, key, nonce, in, off, in + off, ct_len);
    if (n < 0) {
        if (pt_out && pt_cap > 0) sodium_memzero(pt_out, pt_cap);
        return -1;
    }
    desc->type = (TTFrameType)type;
    desc->flags = flags;
    desc->seq = seq;
    desc->nonce = nonce;
    desc->nonce_len = nonce_len;
    desc->hdr = hdr_len > 0 ? hdr : NULL;
    desc->hdr_len = hdr_len;
    desc->pt_len = pt_len;
    return (int)pt_len;
}