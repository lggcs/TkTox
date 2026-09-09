/* Faux offline messaging: toxcore has no offline store —
   tox_friend_send_message fails with FRIEND_NOT_CONNECTED for an offline
   friend and the text is lost. We queue those messages app-side (bounded,
   per friend) and flush on the next friend/self connection. The queue is
   persisted to "<profile>.oq" so queued text survives restarts. */
#ifndef TT_OFFLINE_QUEUE_H
#define TT_OFFLINE_QUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tox/tox.h>

#define TT_OQ_MAX_PER_FRIEND 64
#define TT_OQ_MAX_LINE (TOX_MAX_MESSAGE_LENGTH + 1) /* text + NUL */

struct Tox_Pass_Key; /* at-rest encryption key (NULL = plaintext) */

typedef struct TTOqMsg {
    char text[TT_OQ_MAX_LINE];
} TTOqMsg;

typedef struct TTOqFriend {
    TTOqMsg *msgs;     /* heap ring of TT_OQ_MAX_PER_FRIEND entries */
    int head, count;   /* oldest entry at (head) */
} TTOqFriend;

typedef struct TTOfflineQueue {
    TTOqFriend f[256]; /* dense friend numbers, same bound as TT_MAX_FRIENDS */
} TTOfflineQueue;

/* Load persisted lines from "<profile>.oq" (missing file is fine). When
   pass_key is non-NULL the file is expected to be toxencryptsave-encrypted
   (scrypt KDF); a plaintext file is still accepted for migration. */
void tt_oq_load(TTOfflineQueue *q, const char *profile_path,
                struct Tox_Pass_Key *pass_key);
/* Persist all queued lines atomically (temp file + rename). When pass_key
   is non-NULL the file is written toxencryptsave-encrypted. */
void tt_oq_save(const TTOfflineQueue *q, const char *profile_path,
                struct Tox_Pass_Key *pass_key);
/* Append a message for fn; drops the OLDEST entry when full. Returns the
   number of queued messages for the friend after the append. */
int tt_oq_add(TTOfflineQueue *q, uint32_t fn, const char *text);
/* Move out all pending messages for fn: sets out (NUL-terminated strings)
   and out_count (<= TT_OQ_MAX_PER_FRIEND) and clears the friend's queue.
   Entries not moved out on OOM stay queued. Returns out_count. */
int tt_oq_take_all(TTOfflineQueue *q, uint32_t fn,
                   char out[TT_OQ_MAX_PER_FRIEND][TT_OQ_MAX_LINE],
                   int *out_count);
int tt_oq_count(const TTOfflineQueue *q, uint32_t fn);

#endif