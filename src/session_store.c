#include "session_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <tox/toxencryptsave.h>

#include "log.h"
#include "session.h"   /* TTSession layout for diagnostics */
#include "tox_thread.h" /* TT_MAX_FRIENDS */

#define TT_SES_MAGIC "TTSES1"

/* Plaintext layout (big-endian for the multi-byte fields, so a profile
   moved between architectures (aarch64 <-> x86_64 <-> riscv64) restores
   correctly; the byte arrays are endian-neutral):
     magic "TTSES1" (6) || count (u8)
     per active session:
       fn (u8) || i_am_initiator (u8) || root (32)
       send: chain(32) seq(u32 BE) root(32) since_fold(u16 BE) n_skipped(u16 BE)
             skipped[n] each { seq(u32 BE) key(32) }
       recv: chain(32) seq(u32 BE) root(32) since_fold(u16 BE) n_skipped(u16 BE)
             skipped[n] each { seq(u32 BE) key(32) }
       rekey: eph_sk(32) eph_pk(32) have_kem(u8) kem_pk(1158) kem_sk(1763)
              peer_have(u8) peer_kem_pk(1158) peer_eph_pk(32)
              rekey_due(u8) awaiting_peer(u8) published(u8)
              post_fold_publish(u8) publish_back(u8)
   Transient handshake scratch (init_pending, reply_due, eph_a2/a3,
   init_seal, eph_b1/b3, kem_ct, reply_cache, last_in, pending stash) is
   deliberately NOT stored — it is stale on restart; a fresh handshake is
   the correct recovery. */

static void ses_path(const char *profile_path, char *out, size_t cap) {
    snprintf(out, cap, "%s.ses", profile_path ? profile_path : "TkTox.tox");
}

/* growable byte buffer */
typedef struct {
    uint8_t *p;
    size_t len, cap;
} Buf;

static int buf_put(Buf *b, const void *data, size_t n) {
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + n) nc *= 2;
        uint8_t *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return 0;
}

static int buf_u8(Buf *b, uint8_t v) { return buf_put(b, &v, 1); }
/* big-endian multi-byte fields (portable across architectures) */
static int buf_u16(Buf *b, uint16_t v) {
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return buf_put(b, t, 2);
}
static int buf_u32(Buf *b, uint32_t v) {
    uint8_t t[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8), (uint8_t)v };
    return buf_put(b, t, 4);
}

/* serialize one ratchet direction */
static int ratchet_put(Buf *b, const TTRatchet *r) {
    if (buf_put(b, r->chain, TT_KEY32) || buf_u32(b, r->seq) ||
        buf_put(b, r->root, TT_KEY32) || buf_u16(b, r->since_fold) ||
        buf_u16(b, r->n_skipped))
        return -1;
    for (uint16_t i = 0; i < r->n_skipped; i++) {
        if (buf_u32(b, r->skipped[i].seq) ||
            buf_put(b, r->skipped[i].key, TT_KEY32))
            return -1;
    }
    return 0;
}

static int session_put(Buf *b, const TTSession *s) {
    if (buf_u8(b, 0) /* fn placeholder, patched by caller */ ||
        buf_u8(b, s->i_am_initiator ? 1 : 0) ||
        buf_put(b, s->root, TT_KEY32) ||
        ratchet_put(b, &s->send) || ratchet_put(b, &s->recv))
        return -1;
    const TTRekey *k = &s->rekey;
    if (buf_put(b, k->eph_sk, TT_KEY32) || buf_put(b, k->eph_pk, TT_KEY32) ||
        buf_u8(b, k->have_kem ? 1 : 0) ||
        buf_put(b, k->kem_pk, TT_KEM_PK) || buf_put(b, k->kem_sk, TT_KEM_SK) ||
        buf_u8(b, k->peer_have ? 1 : 0) ||
        buf_put(b, k->peer_kem_pk, TT_KEM_PK) ||
        buf_put(b, k->peer_eph_pk, TT_KEY32) ||
        buf_u8(b, k->rekey_due ? 1 : 0) ||
        buf_u8(b, k->awaiting_peer ? 1 : 0) ||
        buf_u8(b, k->published ? 1 : 0) ||
        buf_u8(b, k->post_fold_publish ? 1 : 0) ||
        buf_u8(b, k->publish_back ? 1 : 0))
        return -1;
    return 0;
}

void tt_session_store_save(const TTSession *e2ee, const char *profile_path,
                           struct Tox_Pass_Key *session_key) {
    char path[1200];
    ses_path(profile_path, path, sizeof path);

    /* count active sessions first */
    uint8_t count = 0;
    for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++)
        if (e2ee[fn].active) count++;

    if (count == 0) { /* nothing to persist: drop the sidecar */
        remove(path);
        return;
    }

    Buf b = {0};
    if (buf_put(&b, TT_SES_MAGIC, 6) || buf_u8(&b, count)) {
        free(b.p);
        return;
    }
    for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++) {
        if (!e2ee[fn].active) continue;
        size_t fn_off = b.len; /* patch the fn placeholder */
        if (session_put(&b, &e2ee[fn])) { free(b.p); return; }
        b.p[fn_off] = (uint8_t)fn;
        TT_LOG("ses", "saving fn=%u send.seq=%u recv.seq=%u",
               fn, e2ee[fn].send.seq, e2ee[fn].recv.seq);
    }

    /* atomic write: plaintext temp, then encrypt to a second temp, swap */
    char tmp[1204];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) { free(b.p); return; }
    fchmod(fileno(fp), 0600);
    fwrite(b.p, 1, b.len, fp);
    fclose(fp);
    free(b.p);

    if (!session_key) { /* plaintext fallback (should not happen with at-rest on) */
        if (rename(tmp, path) != 0) remove(tmp);
        return;
    }

    FILE *rf = fopen(tmp, "rb");
    if (!rf) { remove(tmp); return; }
    fseek(rf, 0, SEEK_END);
    long sz = ftell(rf);
    fseek(rf, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fclose(rf); remove(tmp); return; }
    uint8_t *pt = malloc((size_t)sz);
    if (!pt) { fclose(rf); remove(tmp); return; }
    if (fread(pt, 1, (size_t)sz, rf) != (size_t)sz) {
        free(pt); fclose(rf); remove(tmp); return;
    }
    fclose(rf);

    size_t ct_len = (size_t)sz + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *ct = malloc(ct_len);
    if (!ct) { free(pt); remove(tmp); return; }
    Tox_Err_Encryption eerr;
    if (!tox_pass_key_encrypt(session_key, pt, (size_t)sz, ct, &eerr)) {
        TT_LOG("ses", "encrypt failed: %d", (int)eerr);
        free(ct); free(pt); remove(tmp); return;
    }
    free(pt);

    char tmp2[1208];
    snprintf(tmp2, sizeof tmp2, "%s.enc", path);
    FILE *ef = fopen(tmp2, "wb");
    if (!ef) { free(ct); remove(tmp); return; }
    fchmod(fileno(ef), 0600);
    fwrite(ct, 1, ct_len, ef);
    fclose(ef);
    free(ct);
    if (rename(tmp2, path) != 0) { remove(tmp2); remove(tmp); return; }
    remove(tmp);
}

/* ---- load ---- */

static int ratchet_get(const uint8_t **p, const uint8_t *end, TTRatchet *r) {
    if (*p + TT_KEY32 + 4 + TT_KEY32 + 2 + 2 > end) return -1;
    memcpy(r->chain, *p, TT_KEY32); *p += TT_KEY32;
    r->seq = ((uint32_t)(*p)[0] << 24) | ((uint32_t)(*p)[1] << 16) |
             ((uint32_t)(*p)[2] << 8) | (uint32_t)(*p)[3];
    *p += 4;
    memcpy(r->root, *p, TT_KEY32); *p += TT_KEY32;
    r->since_fold = (uint16_t)(((uint16_t)(*p)[0] << 8) | (*p)[1]);
    *p += 2;
    r->n_skipped = (uint16_t)(((uint16_t)(*p)[0] << 8) | (*p)[1]);
    *p += 2;
    if (r->n_skipped > TT_SESSION_SKIPPED_MAX) return -1;
    for (uint16_t i = 0; i < r->n_skipped; i++) {
        if (*p + 4 + TT_KEY32 > end) return -1;
        r->skipped[i].seq = ((uint32_t)(*p)[0] << 24) |
                            ((uint32_t)(*p)[1] << 16) |
                            ((uint32_t)(*p)[2] << 8) | (uint32_t)(*p)[3];
        *p += 4;
        memcpy(r->skipped[i].key, *p, TT_KEY32); *p += TT_KEY32;
    }
    return 0;
}

static int session_get(const uint8_t **p, const uint8_t *end, TTSession *s) {
    if (*p + 1 + 1 + TT_KEY32 > end) return -1;
    uint8_t fn = **p; *p += 1;
    s->i_am_initiator = (**p != 0); *p += 1;
    memcpy(s->root, *p, TT_KEY32); *p += TT_KEY32;
    if (ratchet_get(p, end, &s->send) || ratchet_get(p, end, &s->recv))
        return -1;
    TTRekey *k = &s->rekey;
    if (*p + TT_KEY32 + TT_KEY32 + 1 + TT_KEM_PK + TT_KEM_SK + 1 +
            TT_KEM_PK + TT_KEY32 + 5 > end)
        return -1;
    memcpy(k->eph_sk, *p, TT_KEY32); *p += TT_KEY32;
    memcpy(k->eph_pk, *p, TT_KEY32); *p += TT_KEY32;
    k->have_kem = (**p != 0); *p += 1;
    memcpy(k->kem_pk, *p, TT_KEM_PK); *p += TT_KEM_PK;
    memcpy(k->kem_sk, *p, TT_KEM_SK); *p += TT_KEM_SK;
    k->peer_have = (**p != 0); *p += 1;
    memcpy(k->peer_kem_pk, *p, TT_KEM_PK); *p += TT_KEM_PK;
    memcpy(k->peer_eph_pk, *p, TT_KEY32); *p += TT_KEY32;
    k->rekey_due = (**p != 0); *p += 1;
    k->awaiting_peer = (**p != 0); *p += 1;
    k->published = (**p != 0); *p += 1;
    k->post_fold_publish = (**p != 0); *p += 1;
    k->publish_back = (**p != 0); *p += 1;
    s->active = true;
    (void)fn;
    return 0;
}

void tt_session_store_load(TTSession *e2ee, const char *profile_path,
                           struct Tox_Pass_Key *session_key) {
    char path[1200];
    ses_path(profile_path, path, sizeof path);
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fclose(fp); return; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(fp); return; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return;
    }
    fclose(fp);

    /* decrypt (plaintext accepted for migration) */
    long pt_len = sz;
    if (session_key && sz >= (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH &&
        tox_is_data_encrypted(buf)) {
        pt_len = sz - (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        Tox_Err_Decryption derr;
        if (!tox_pass_key_decrypt(session_key, buf, (size_t)sz, buf, &derr)) {
            TT_LOG("ses", "decrypt failed: %d", (int)derr);
            free(buf);
            return;
        }
    }

    const uint8_t *p = buf, *end = buf + pt_len;
    if (pt_len < 6 || memcmp(p, TT_SES_MAGIC, 6) != 0) {
        free(buf);
        return;
    }
    p += 6;
    if (p >= end) { free(buf); return; }
    int count = *p++;
    if (count > TT_MAX_FRIENDS) { free(buf); return; }
    for (int i = 0; i < count; i++) {
        if (p >= end) break;
        uint32_t fn = *p;
        if (fn >= TT_MAX_FRIENDS) break;
        if (session_get(&p, end, &e2ee[fn])) break;
        TT_LOG("ses", "restored fn=%u active send.seq=%u recv.seq=%u",
               fn, e2ee[fn].send.seq, e2ee[fn].recv.seq);
    }
    free(buf);
}
