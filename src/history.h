#ifndef TT_HISTORY_H
#define TT_HISTORY_H
#include <stddef.h>
#include <stdbool.h>

struct Tox_Pass_Key;

/* Chat-history persistence: transcripts are saved to a "<profile>.hist"
   sidecar, encrypted with the same at-rest pass key as the profile (the
   transcript is plaintext-equivalent to the messages, so it must be
   protected like the savedata). Each entry is keyed by a stable identity:
   the friend's 64-hex public key, or the group's 64-hex chat id. The
   transcript is the raw "H:MM\x1f<flag>\x1f<who>\x1f<text>\n" buffer, which
   is self-describing and restored verbatim. */

typedef struct TTHistEntry {
    const char *key;        /* 64-hex identity (friend pubkey / group chat id) */
    const char *transcript; /* NUL-terminated transcript buffer */
} TTHistEntry;

/* Atomically write all entries to "<profile>.hist" (temp + rename, encrypted
   when pass_key is set). Returns false on any failure. */
bool tt_hist_save(const char *profile_path, struct Tox_Pass_Key *pass_key,
                  const TTHistEntry *entries, size_t count);

/* Load the transcript for a single key into out (cap bytes, NUL-terminated).
   Returns false when the key is absent or the file is unreadable. */
bool tt_hist_load(const char *profile_path, struct Tox_Pass_Key *pass_key,
                  const char *key, char *out, size_t cap);

#endif
