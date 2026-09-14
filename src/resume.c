#include "resume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <tox/toxencryptsave.h>

#include "log.h"

#define TT_RESUME_MAGIC "TTRS1"

static void rsum_path(const char *profile_path, char *out, size_t cap) {
    snprintf(out, cap, "%s.rsum", profile_path ? profile_path : "TkTox.tox");
}

/* Decrypt a toxencryptsave blob in place (plaintext replaces ciphertext).
   Returns the plaintext length, or -1 on any failure. A blob too small to
   be encrypted (or lacking the magic) is treated as plaintext (migration). */
static long rsum_decrypt(uint8_t *buf, long sz, const Tox_Pass_Key *key) {
    if (sz < (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH) return sz;
    if (!tox_is_data_encrypted(buf)) return sz; /* plaintext (migration) */
    long pt_len = sz - (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    Tox_Err_Decryption derr;
    if (!tox_pass_key_decrypt(key, buf, (size_t)sz, buf, &derr)) {
        TT_LOG("rsum", "decrypt failed: %d", (int)derr);
        return -1;
    }
    return pt_len;
}

void tt_resume_load(TTResumeEntry *idx, int *count, const char *profile_path,
                    struct Tox_Pass_Key *key) {
    *count = 0;
    memset(idx, 0, TT_RESUME_MAX * sizeof *idx);
    if (!profile_path) return;
    char path[1200];
    rsum_path(profile_path, path, sizeof path);
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

    long pt_len = rsum_decrypt(buf, sz, key);
    if (pt_len < 0) { free(buf); return; }

    /* "TTRS1" + per entry: "<bytes> <pathlen>\n<path>\n<32-byte file_id>" */
    size_t off = 0;
    if (off + 5 <= (size_t)pt_len && memcmp(buf + off, TT_RESUME_MAGIC, 5) == 0)
        off += 5;
    while (off < (size_t)pt_len) {
        unsigned long long bytes;
        unsigned plen;
        int n = 0;
        if (sscanf((const char *)buf + off, "%llu %u%n", &bytes, &plen, &n) != 2 ||
            plen == 0 || plen > 1023) {
            break;
        }
        off += (size_t)n;
        if (off >= (size_t)pt_len || buf[off] != '\n') break;
        off++;
        if (off + plen > (size_t)pt_len) break;
        if (*count >= TT_RESUME_MAX) break;
        TTResumeEntry *e = &idx[*count];
        memcpy(e->path, buf + off, plen);
        e->path[plen] = '\0';
        off += plen;
        if (off >= (size_t)pt_len || buf[off] != '\n') break;
        off++;
        if (off + TOX_FILE_ID_LENGTH > (size_t)pt_len) break;
        memcpy(e->file_id, buf + off, TOX_FILE_ID_LENGTH);
        off += TOX_FILE_ID_LENGTH;
        e->bytes = bytes;
        e->used = true;
        (*count)++;
    }
    free(buf);
}

void tt_resume_save(const TTResumeEntry *idx, int count, const char *profile_path,
                    struct Tox_Pass_Key *key) {
    if (!profile_path) return;
    char path[1200], tmp[1204];
    rsum_path(profile_path, path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return;
    fchmod(fileno(fp), 0600);
    fwrite(TT_RESUME_MAGIC, 1, 5, fp);
    for (int i = 0; i < count; i++) {
        const TTResumeEntry *e = &idx[i];
        if (!e->used) continue;
        size_t plen = strlen(e->path);
        if (plen == 0 || plen > 1023) continue;
        fprintf(fp, "%llu %zu\n", (unsigned long long)e->bytes, plen);
        fwrite(e->path, 1, plen, fp);
        fputc('\n', fp);
        fwrite(e->file_id, 1, TOX_FILE_ID_LENGTH, fp);
    }
    fclose(fp);

    if (key) {
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
        if (!tox_pass_key_encrypt(key, pt, (size_t)sz, ct, &eerr)) {
            TT_LOG("rsum", "encrypt failed: %d", (int)eerr);
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

TTResumeEntry *tt_resume_find(TTResumeEntry *idx, int *count,
                              const uint8_t file_id[TOX_FILE_ID_LENGTH]) {
    for (int i = 0; i < *count; i++)
        if (idx[i].used && memcmp(idx[i].file_id, file_id, TOX_FILE_ID_LENGTH) == 0)
            return &idx[i];
    return NULL;
}

void tt_resume_put(TTResumeEntry *idx, int *count,
                   const uint8_t file_id[TOX_FILE_ID_LENGTH],
                   const char *path, uint64_t bytes) {
    TTResumeEntry *e = tt_resume_find(idx, count, file_id);
    if (!e) {
        if (*count >= TT_RESUME_MAX) return; /* index full: drop the new one */
        e = &idx[*count];
        memset(e, 0, sizeof *e);
        e->used = true;
        memcpy(e->file_id, file_id, TOX_FILE_ID_LENGTH);
        (*count)++;
    }
    snprintf(e->path, sizeof e->path, "%s", path);
    e->bytes = bytes;
}

void tt_resume_del(TTResumeEntry *idx, int *count,
                   const uint8_t file_id[TOX_FILE_ID_LENGTH]) {
    for (int i = 0; i < *count; i++) {
        if (idx[i].used && memcmp(idx[i].file_id, file_id, TOX_FILE_ID_LENGTH) == 0) {
            memset(&idx[i], 0, sizeof idx[i]);
            /* compact: move the last used entry into the hole */
            for (int j = *count - 1; j > i; j--) {
                if (idx[j].used) {
                    idx[i] = idx[j];
                    memset(&idx[j], 0, sizeof idx[j]);
                    break;
                }
            }
            (*count)--;
            return;
        }
    }
}
