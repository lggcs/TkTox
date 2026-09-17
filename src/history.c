#include "history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h" /* rename/unlink shims (POSIX passthrough) */

#include <tox/toxencryptsave.h>

#include "log.h"

#define TT_HIST_MAGIC "TTHS1"
#define TT_HIST_MAX_FILE (8 * 1024 * 1024) /* 64 KiB/contact * ~100 contacts */

static void hist_path(const char *profile_path, char *out, size_t cap) {
    snprintf(out, cap, "%s.hist", profile_path ? profile_path : "TkTox.tox");
}

/* Decrypt a toxencryptsave blob in place (plaintext replaces ciphertext).
   Returns the plaintext length, or -1 on any failure. A blob too small to be
   encrypted (or lacking the magic) is treated as plaintext (migration). */
static long hist_decrypt(uint8_t *buf, long sz, const Tox_Pass_Key *key) {
    if (sz < (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH) return sz;
    if (!tox_is_data_encrypted(buf)) return sz; /* plaintext (migration) */
    long pt_len = sz - (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    Tox_Err_Decryption derr;
    if (!tox_pass_key_decrypt(key, buf, (size_t)sz, buf, &derr)) {
        TT_LOG("hist", "decrypt failed: %d", (int)derr);
        return -1;
    }
    return pt_len;
}

bool tt_hist_save(const char *profile_path, struct Tox_Pass_Key *pass_key,
                  const TTHistEntry *entries, size_t count) {
    char path[1200], tmp[1204];
    hist_path(profile_path, path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return false;
    tt_fchmod(fileno(fp), 0600);
    fwrite(TT_HIST_MAGIC, 1, 5, fp);
    for (size_t i = 0; i < count; i++) {
        const TTHistEntry *e = &entries[i];
        if (!e->key || !e->transcript || !*e->transcript) continue;
        size_t klen = strlen(e->key), tlen = strlen(e->transcript);
        if (klen == 0 || tlen == 0) continue;
        /* "<klen> <tlen>\n<key>\n<transcript>" */
        fprintf(fp, "%zu %zu\n", klen, tlen);
        fwrite(e->key, 1, klen, fp);
        fputc('\n', fp);
        fwrite(e->transcript, 1, tlen, fp);
    }
    fclose(fp);

    if (pass_key) {
        /* re-read the plaintext temp, encrypt to a second temp, swap */
        FILE *rf = fopen(tmp, "rb");
        if (!rf) { remove(tmp); return false; }
        fseek(rf, 0, SEEK_END);
        long sz = ftell(rf);
        fseek(rf, 0, SEEK_SET);
        if (sz <= 0 || sz > TT_HIST_MAX_FILE) { fclose(rf); remove(tmp); return false; }
        uint8_t *pt = malloc((size_t)sz);
        if (!pt) { fclose(rf); remove(tmp); return false; }
        if (fread(pt, 1, (size_t)sz, rf) != (size_t)sz) {
            free(pt); fclose(rf); remove(tmp); return false;
        }
        fclose(rf);

        size_t ct_len = (size_t)sz + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
        uint8_t *ct = malloc(ct_len);
        if (!ct) { free(pt); remove(tmp); return false; }
        Tox_Err_Encryption eerr;
        if (!tox_pass_key_encrypt(pass_key, pt, (size_t)sz, ct, &eerr)) {
            TT_LOG("hist", "encrypt failed: %d", (int)eerr);
            free(ct); free(pt); remove(tmp); return false;
        }
        free(pt);

        char tmp2[1208];
        snprintf(tmp2, sizeof tmp2, "%s.enc", path);
        FILE *ef = fopen(tmp2, "wb");
        if (!ef) { free(ct); remove(tmp); return false; }
        tt_fchmod(fileno(ef), 0600);
        fwrite(ct, 1, ct_len, ef);
        fclose(ef);
        free(ct);
        if (tt_rename(tmp2, path) != 0) { remove(tmp2); remove(tmp); return false; }
        remove(tmp);
        return true;
    }

    if (tt_rename(tmp, path) != 0) { remove(tmp); return false; }
    return true;
}

bool tt_hist_load(const char *profile_path, struct Tox_Pass_Key *pass_key,
                  const char *key, char *out, size_t cap) {
    if (!key || !out || cap == 0) return false;
    out[0] = '\0';
    char path[1200];
    hist_path(profile_path, path, sizeof path);
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > TT_HIST_MAX_FILE) { fclose(fp); return false; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(fp); return false; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return false;
    }
    fclose(fp);

    long pt_len = hist_decrypt(buf, sz, pass_key);
    if (pt_len < 0) { free(buf); return false; }

    /* "TTHS1" once, then per entry: "<klen> <tlen>\n<key>\n<transcript>" */
    size_t off = 0;
    bool found = false;
    if (off + 5 > (size_t)pt_len || memcmp(buf + off, TT_HIST_MAGIC, 5) != 0) {
        free(buf);
        return false;
    }
    off += 5;
    while (off < (size_t)pt_len) {
        size_t klen, tlen;
        int n = 0;
        if (sscanf((const char *)buf + off, "%zu %zu%n", &klen, &tlen, &n) != 2) break;
        off += (size_t)n;
        if (off >= (size_t)pt_len || buf[off] != '\n') break;
        off++;
        /* bound klen/tlen to the buffer size so the length arithmetic below
           cannot wrap size_t and bypass the bounds check (OOB read) */
        if (klen > (size_t)pt_len || tlen > (size_t)pt_len) break;
        if (off + klen + 1 + tlen > (size_t)pt_len) break;
        if (klen == strlen(key) && memcmp(buf + off, key, klen) == 0) {
            off += klen;
            if (buf[off] != '\n') break;
            off++;
            size_t copy = tlen < cap - 1 ? tlen : cap - 1;
            memcpy(out, buf + off, copy);
            out[copy] = '\0';
            found = true;
            break;
        }
        off += klen + 1 + tlen;
    }
    free(buf);
    return found;
}
