#ifndef TT_RESUME_H
#define TT_RESUME_H
#include <stdint.h>
#include <stdbool.h>
#include <tox/tox.h>

/* At-rest encryption key (opaque; only resume.c touches the internals). */
struct Tox_Pass_Key;

/* Cross-restart file-transfer resume index. Maps a content-derived file_id
   (TOX_FILE_ID_LENGTH bytes) to the local partial file and how many bytes
   were received, so a re-offer of the same file after a restart can be
   auto-resumed. Persisted encrypted beside the profile (<profile>.rsum),
   same toxencryptsave scheme as the offline queue. */

#define TT_RESUME_MAX 32

typedef struct TTResumeEntry {
    bool used;
    uint8_t file_id[TOX_FILE_ID_LENGTH];
    char path[1024];
    uint64_t bytes;
} TTResumeEntry;

/* Load the index from <profile>.rsum (decrypting with key). Clears idx. */
void tt_resume_load(TTResumeEntry *idx, int *count, const char *profile_path,
                    struct Tox_Pass_Key *key);
/* Persist the index to <profile>.rsum (encrypting with key). */
void tt_resume_save(const TTResumeEntry *idx, int count, const char *profile_path,
                    struct Tox_Pass_Key *key);
/* Find an entry by file_id; returns a pointer or NULL. */
TTResumeEntry *tt_resume_find(TTResumeEntry *idx, int *count,
                              const uint8_t file_id[TOX_FILE_ID_LENGTH]);
/* Add or update an entry (replacing any with the same file_id). */
void tt_resume_put(TTResumeEntry *idx, int *count,
                   const uint8_t file_id[TOX_FILE_ID_LENGTH],
                   const char *path, uint64_t bytes);
/* Remove an entry by file_id. */
void tt_resume_del(TTResumeEntry *idx, int *count,
                   const uint8_t file_id[TOX_FILE_ID_LENGTH]);

#endif
