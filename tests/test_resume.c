/* Cross-restart file-transfer resume index unit test.
   Exercises the <profile>.rsum persistence roundtrip (plaintext and
   toxencryptsave-encrypted), find/put/del semantics, and the compaction
   on delete. Compiled separately; links resume.c + toxencryptsave.c +
   libsodium. */
#include "../src/resume.c"

#include <tox/toxencryptsave.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++fails; } } while (0)

static const char *PROFILE = "/tmp/TkTox-resume-test.tox";

static void wipe(void) {
    unlink("/tmp/TkTox-resume-test.tox.rsum");
    unlink("/tmp/TkTox-resume-test.tox.rsum.tmp");
    unlink("/tmp/TkTox-resume-test.tox.rsum.enc");
}

int main(void) {
    if (sodium_init() < 0) return 1;
    wipe();

    TTResumeEntry idx[TT_RESUME_MAX];
    int count = 0;

    /* empty load on a missing file */
    tt_resume_load(idx, &count, PROFILE, NULL);
    CHECK(count == 0);

    /* put two entries, save plaintext, reload */
    uint8_t id1[TOX_FILE_ID_LENGTH], id2[TOX_FILE_ID_LENGTH];
    memset(id1, 0x11, sizeof id1);
    memset(id2, 0x22, sizeof id2);
    tt_resume_put(idx, &count, id1, "/tmp/partial-a.bin", 12345);
    tt_resume_put(idx, &count, id2, "/tmp/partial-b.bin", 67890);
    CHECK(count == 2);
    tt_resume_save(idx, count, PROFILE, NULL);

    TTResumeEntry idx2[TT_RESUME_MAX];
    int count2 = 0;
    tt_resume_load(idx2, &count2, PROFILE, NULL);
    CHECK(count2 == 2);
    TTResumeEntry *e = tt_resume_find(idx2, &count2, id1);
    CHECK(e != NULL && e->bytes == 12345 && strcmp(e->path, "/tmp/partial-a.bin") == 0);
    e = tt_resume_find(idx2, &count2, id2);
    CHECK(e != NULL && e->bytes == 67890 && strcmp(e->path, "/tmp/partial-b.bin") == 0);

    /* put with an existing id updates in place (no duplicate) */
    tt_resume_put(idx2, &count2, id1, "/tmp/partial-a2.bin", 20000);
    CHECK(count2 == 2);
    e = tt_resume_find(idx2, &count2, id1);
    CHECK(e != NULL && e->bytes == 20000 && strcmp(e->path, "/tmp/partial-a2.bin") == 0);

    /* delete compacts */
    tt_resume_del(idx2, &count2, id1);
    CHECK(count2 == 1);
    CHECK(tt_resume_find(idx2, &count2, id1) == NULL);
    e = tt_resume_find(idx2, &count2, id2);
    CHECK(e != NULL && e->bytes == 67890);

    /* encrypted roundtrip with a derived key */
    wipe();
    Tox_Err_Key_Derivation kerr;
    Tox_Pass_Key *key = tox_pass_key_derive((const uint8_t *)"test-pass", 10, &kerr);
    CHECK(key != NULL);
    TTResumeEntry idx3[TT_RESUME_MAX];
    int count3 = 0;
    tt_resume_put(idx3, &count3, id1, "/tmp/enc-partial.bin", 999);
    tt_resume_save(idx3, count3, PROFILE, key);

    TTResumeEntry idx4[TT_RESUME_MAX];
    int count4 = 0;
    tt_resume_load(idx4, &count4, PROFILE, key);
    CHECK(count4 == 1);
    e = tt_resume_find(idx4, &count4, id1);
    CHECK(e != NULL && e->bytes == 999 && strcmp(e->path, "/tmp/enc-partial.bin") == 0);

    /* wrong key must not decrypt (returns empty index) */
    Tox_Pass_Key *bad = tox_pass_key_derive((const uint8_t *)"wrong-pass", 10, &kerr);
    CHECK(bad != NULL);
    TTResumeEntry idx5[TT_RESUME_MAX];
    int count5 = 0;
    tt_resume_load(idx5, &count5, PROFILE, bad);
    CHECK(count5 == 0);

    tox_pass_key_free(key);
    tox_pass_key_free(bad);
    wipe();

    if (fails) {
        fprintf(stderr, "%d FAILURE(S)\n", fails);
        return 1;
    }
    printf("resume index: ALL PASS\n");
    return 0;
}
