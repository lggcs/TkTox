#include "offline_queue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <tox/toxencryptsave.h>

#include "log.h"

#define TT_OQ_MAGIC "TTOQ1"

static void oq_path(const char *profile_path, char *out, size_t cap) {
    snprintf(out, cap, "%s.oq", profile_path ? profile_path : "TkTox.tox");
}

/* Decrypt a toxencryptsave blob in place (plaintext replaces ciphertext).
   Returns the plaintext length, or -1 on any failure. A blob too small to
   be encrypted (or lacking the magic) is treated as plaintext (migration). */
static long oq_decrypt(uint8_t *buf, long sz, const Tox_Pass_Key *key) {
    if (sz < (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH) return sz;
    if (!tox_is_data_encrypted(buf)) return sz; /* plaintext (migration) */
    long pt_len = sz - (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    Tox_Err_Decryption derr;
    if (!tox_pass_key_decrypt(key, buf, (size_t)sz, buf, &derr)) {
        TT_LOG("oq", "decrypt failed: %d", (int)derr);
        return -1;
    }
    return pt_len;
}

void tt_oq_load(TTOfflineQueue *q, const char *profile_path,
                struct Tox_Pass_Key *pass_key) {
    char path[1200];
    oq_path(profile_path, path, sizeof path);
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

    long pt_len = oq_decrypt(buf, sz, pass_key);
    if (pt_len < 0) { free(buf); return; }

    /* "TTOQ1" + per entry: "<fn> <len>\n<bytes>" */
    char line[TT_OQ_MAX_LINE];
    size_t off = 0;
    while (off + 5 <= (size_t)pt_len) {
        if (memcmp(buf + off, TT_OQ_MAGIC, 5) != 0) break;
        off += 5;
        unsigned fn, len;
        int n = 0;
        if (sscanf((const char *)buf + off, "%u %u%n", &fn, &len, &n) != 2 ||
            fn >= 256 || len == 0 || len > TOX_MAX_MESSAGE_LENGTH) {
            break;
        }
        off += (size_t)n;
        if (off >= (size_t)pt_len || buf[off] != '\n') break;
        off++;
        if (off + len > (size_t)pt_len) break;
        memcpy(line, buf + off, len);
        line[len] = '\0';
        tt_oq_add(q, fn, line);
        off += len;
    }
    free(buf);
}

void tt_oq_save(const TTOfflineQueue *q, const char *profile_path,
                struct Tox_Pass_Key *pass_key) {
    char path[1200], tmp[1204];
    oq_path(profile_path, path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return;
    fchmod(fileno(fp), 0600);
    fwrite(TT_OQ_MAGIC, 1, 5, fp);
    for (unsigned fn = 0; fn < 256; fn++) {
        const TTOqFriend *fr = &q->f[fn];
        if (!fr->msgs) continue;
        for (int i = 0; i < fr->count; i++) {
            const TTOqMsg *m = &fr->msgs[(fr->head + i) % TT_OQ_MAX_PER_FRIEND];
            size_t len = strlen(m->text);
            if (len == 0) continue;
            fprintf(fp, "%u %zu\n", fn, len);
            fwrite(m->text, 1, len, fp);
        }
    }
    fclose(fp);

    if (pass_key) {
        /* re-read the plaintext temp, encrypt to a second temp, swap */
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
        if (!tox_pass_key_encrypt(pass_key, pt, (size_t)sz, ct, &eerr)) {
            TT_LOG("oq", "encrypt failed: %d", (int)eerr);
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
        return;
    }

    if (rename(tmp, path) != 0) remove(tmp);
}

int tt_oq_add(TTOfflineQueue *q, uint32_t fn, const char *text) {
    if (fn >= 256 || !text || !*text) return 0;
    TTOqFriend *fr = &q->f[fn];
    if (!fr->msgs) {
        fr->msgs = calloc(TT_OQ_MAX_PER_FRIEND, sizeof *fr->msgs);
        if (!fr->msgs) return 0;
    }
    if (fr->count == TT_OQ_MAX_PER_FRIEND) {
        fr->head = (fr->head + 1) % TT_OQ_MAX_PER_FRIEND; /* drop oldest */
        fr->count--;
        TT_LOG("tox", "offline queue(%u) full: oldest dropped", fn);
    }
    TTOqMsg *slot = &fr->msgs[(fr->head + fr->count) % TT_OQ_MAX_PER_FRIEND];
    snprintf(slot->text, sizeof slot->text, "%s", text);
    fr->count++;
    return fr->count;
}

int tt_oq_take_all(TTOfflineQueue *q, uint32_t fn,
                   char out[TT_OQ_MAX_PER_FRIEND][TT_OQ_MAX_LINE], int *out_count) {
    *out_count = 0;
    if (fn >= 256) return 0;
    TTOqFriend *fr = &q->f[fn];
    if (!fr->msgs) return 0;
    while (fr->count > 0) {
        TTOqMsg *m = &fr->msgs[fr->head];
        snprintf(out[*out_count], TT_OQ_MAX_LINE, "%s", m->text);
        (*out_count)++;
        fr->head = (fr->head + 1) % TT_OQ_MAX_PER_FRIEND;
        fr->count--;
    }
    return *out_count;
}

int tt_oq_count(const TTOfflineQueue *q, uint32_t fn) {
    if (fn >= 256) return 0;
    return q->f[fn].count;
}