#include "tox_thread.h"
#include "log.h"
#include "av.h"
#include "session.h"
#include "session_store.h"
#include <tox/toxencryptsave.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* used by callbacks registered long before its definition below */
static void push_simple(TTToxThread *t, TTEventType type, uint32_t fn, const char *s, size_t len, int ival);
static void offline_flush_friend(TTToxThread *t, uint32_t fn);
static void emit_friend_identity(TTToxThread *t, uint32_t fn);

/* ---- E2EE layer (TT_E2EE=1; session.h) ---- */

static bool tt_e2ee_mode;

/* How long we keep retrying the in-band handshake before treating a friend
   as a legacy client (no E2EE) and falling back to plaintext. INIT
   retransmits every 5s, so this is ~6 attempts. */
#define TT_E2EE_FALLBACK_TIMEOUT 30

/* Emit the per-connection E2EE warning system line for fn (deduped). */
static void e2ee_warn(TTToxThread *t, uint32_t fn, const char *msg) {
    if (fn >= TT_MAX_FRIENDS || t->e2ee_warned[fn]) return;
    t->e2ee_warned[fn] = true;
    push_simple(t, TT_EV_E2EE_WARN, fn, msg, strlen(msg), 0);
}

/* per-friend transport env: identity keys from toxcore */
static void e2ee_env(TTToxThread *t, uint32_t fn, TTE2EEEnv *env) {
    static _Thread_local uint8_t self_sk[TOX_SECRET_KEY_SIZE];
    static _Thread_local uint8_t self_pk[TOX_PUBLIC_KEY_SIZE];
    static _Thread_local uint8_t peer_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_secret_key(t->tox, self_sk);
    tox_self_get_public_key(t->tox, self_pk);
    env->self_sk = self_sk;
    env->self_pk = self_pk;
    env->peer_pk = NULL;
    if (fn < TT_MAX_FRIENDS &&
        tox_friend_get_public_key(t->tox, fn, peer_pk, NULL))
        env->peer_pk = peer_pk; /* bool success, NOT the error enum (0) */
}

/* send one frame (no offline queueing — a queued INIT would be stale on
   arrival and refused; DATA is requeued by the normal text path instead).
   Returns the tox message id (receipt key) or 0 on failure. */
static uint32_t e2ee_send_frame(TTToxThread *t, uint32_t fn, const uint8_t *buf,
                                size_t len) {
    Tox_Err_Friend_Send_Message serr;
    uint32_t mid = tox_friend_send_message(t->tox, fn, TOX_MESSAGE_TYPE_NORMAL,
                                           buf, len, &serr);
    TT_LOG("e2ee", "frame tx(%u, %zu B): %d", fn, len, (int)serr);
    return serr == TOX_ERR_FRIEND_SEND_MESSAGE_OK ? mid : 0;
}

/* session state push to the UI (verification code on establish) */
static void e2ee_push_state(TTToxThread *t, uint32_t fn, bool established) {
    TTEvent *ev = tt_event_new(TT_EV_E2EE_STATE);
    if (!ev) return;
    ev->friend_number = fn;
    ev->ival = established ? 1 : 0;
    if (established) {
        char code[33];
        if (tt_session_verify_code(&t->e2ee[fn], code)) {
            ev->str = malloc(33);
            if (ev->str) {
                memcpy(ev->str, code, 33);
                ev->str_len = 32;
            }
        }
    }
    tt_queue_push(&t->out, ev);
}

/* flush stashed texts of one friend as DATA frames */
static void e2ee_pump(TTToxThread *t, uint32_t fn) {
    TTE2EEEnv env;
    e2ee_env(t, fn, &env);
    uint8_t out[TT_FRAME_MAX];
    for (;;) {
        int n = tt_session_flush(&t->e2ee[fn], &env, out, sizeof out);
        if (n <= 0) break;
        uint32_t mid = e2ee_send_frame(t, fn, out, (size_t)n);
        if (mid) push_simple(t, TT_EV_MESSAGE_SENT, fn, NULL, 0, (int)mid);
    }
}

/* engine tick: INIT retransmits for every pending session */
static void e2ee_tick(TTToxThread *t) {
    time_t now = time(NULL);
    for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++) {
        TTE2EEEnv env;
        e2ee_env(t, fn, &env);
        if (!env.peer_pk) continue;
        uint8_t out[TT_FRAME_MAX];
        int n = tt_session_tick(&t->e2ee[fn], &env, now, out, sizeof out);
        if (n > 0) e2ee_send_frame(t, fn, out, (size_t)n);
    }
}

/* start (or restart) the session with fn as initiator */
static void e2ee_start(TTToxThread *t, uint32_t fn) {
    TTE2EEEnv env;
    e2ee_env(t, fn, &env);
    if (!env.peer_pk) return;
    uint8_t out[TT_FRAME_MAX];
    int n = tt_session_start(&t->e2ee[fn], &env, out, sizeof out);
    if (n > 0) {
        e2ee_send_frame(t, fn, out, (size_t)n);
        t->e2ee_handshake_at[fn] = time(NULL);
        TT_LOG("e2ee", "session init(%u)", fn);
    } else {
        TT_LOG("e2ee", "session init(%u) failed: %d", fn, n);
    }
}

/* True when the friend's handshake has been pending past the fallback
   timeout (they are a legacy client that never answers INIT). */
static bool e2ee_fallback_due(TTToxThread *t, uint32_t fn) {
    if (fn >= TT_MAX_FRIENDS) return false;
    TTSession *s = &t->e2ee[fn];
    if (s->active) return false;
    time_t at = t->e2ee_handshake_at[fn];
    return at != 0 && time(NULL) - at >= TT_E2EE_FALLBACK_TIMEOUT;
}

/* post-receive hook (cb_friend_message). Returns true when the event was
   consumed by the E2EE layer (caller must not treat ev->str as chat text). */
static bool e2ee_rx(TTToxThread *t, TTEvent *ev) {
    uint32_t fn = ev->friend_number;
    if (fn >= TT_MAX_FRIENDS) return false;
    TTE2EEEnv env;
    e2ee_env(t, fn, &env);
    if (!env.peer_pk) return false;

    TTSession *s = &t->e2ee[fn];
    bool was_active = s->active;
    static _Thread_local uint8_t pt[TT_FRAME_DATA_MAX];
    bool handshaked = false;
    int n = tt_session_feed(s, &env, (const uint8_t *)ev->str, ev->str_len,
                            pt, sizeof pt, &handshaked);
    if (handshaked) {
        TT_LOG("e2ee", "handshake event(%u): n=%d active=%d", fn, n, s->active);
        if (n == 0 && s->reply_due) { /* responder: send REPLY now */
            uint8_t out[TT_FRAME_MAX];
            int rn = tt_session_reply(s, &env, out, sizeof out);
            if (rn > 0) e2ee_send_frame(t, fn, out, (size_t)rn);
        }
        if (s->active) {
            /* a live session means the friend speaks E2EE — clear any
               legacy-fallback state from a prior connection */
            t->e2ee_fallback[fn] = false;
            /* auto-enforce E2EE for this friend going forward: once we have
               a working encrypted session, never silently downgrade to
               plaintext on a future connection. Persisted in the sidecar. */
            if (!was_active && !t->e2ee_required[fn]) {
                t->e2ee_required[fn] = true;
                if (!tt_settings_store_e2ee(t->e2ee_required, t->profile_path))
                    TT_LOG("tox", "e2ee auto-enforce(%u): persist failed", fn);
                push_simple(t, TT_EV_E2EE_ENFORCE, fn, NULL, 0, 1);
            }
            e2ee_pump(t, fn); /* initiator: flush stashed texts */
            if (tt_oq_count(&t->oq, fn) > 0 && !t->oq_flushing)
                offline_flush_friend(t, fn); /* queued texts now flow encrypted */
        }
        if (s->active != was_active)
            e2ee_push_state(t, fn, s->active);
        return true;
    }
    if (n == 0) return true; /* handshake frame consumed silently */
    if (n < 0) {
        TT_LOG("e2ee", "rx(%u): %d", fn, n);
        if (n == TT_E2EE_NO_SESSION) {
            /* peer speaks the layer but we have no session: start one */
            e2ee_start(t, fn);
            return true;
        }
        if (n == TT_E2EE_DECODE_FAIL) {
            /* not a valid frame: the peer is a legacy client sending
               plaintext. Fall back to plaintext for this connection and
               warn the user (unless E2EE is enforced for this friend). */
            if (!t->e2ee_required[fn]) {
                t->e2ee_fallback[fn] = true;
                e2ee_warn(t, fn,
                          "This contact does not support end-to-end encryption "
                          "— messages are sent in plaintext.");
                return false; /* let the plaintext flow to the consumer */
            }
            /* enforced: drop the plaintext, warn once */
            e2ee_warn(t, fn,
                      "This contact does not support end-to-end encryption, "
                      "but E2EE is required for them — plaintext messages are "
                      "blocked.");
            return true;
        }
        /* undecryptable frame: generic system line, never failure details */
        if (!s->no_session_notified) {
            static const char msg[] = "[encrypted message could not be decrypted]";
            TTEvent *note = tt_event_new(TT_EV_FRIEND_MESSAGE);
            if (note) {
                note->friend_number = fn;
                note->str = malloc(sizeof msg);
                if (note->str) {
                    memcpy(note->str, msg, sizeof msg);
                    note->str_len = sizeof msg - 1;
                    tt_queue_push(&t->out, note);
                } else {
                    free(note);
                }
            }
            s->no_session_notified = true;
        }
        return true;
    }
    /* DATA: plaintext in pt (n bytes) -> mutate the event into a normal
       FRIEND_MESSAGE carrying the plaintext (consumer shows it as usual) */
    if (n <= (int)ev->str_len) { /* reuse the existing str allocation */
        memcpy(ev->str, pt, (size_t)n);
        ev->str[n] = '\0';
        ev->str_len = (size_t)n;
        return false; /* NOT consumed: the normal path displays it */
    }
    TT_LOG("e2ee", "rx(%u): plaintext overflow (%d > %zu)", fn, n, ev->str_len);
    return true;
}

/* text > 1318B does not fit one frame: the engine emits ceil(len/chunk)
   frames, each rendered as its own message line (v1: no reassembly state) */
#define TT_E2EE_CHUNK TT_FRAME_DATA_MAX

/* ---- avatar helpers ---- */

void tt_avatar_free(TTAvatar *a) {
    free(a->data);
    memset(a, 0, sizeof *a);
}

bool tt_avatar_set(TTAvatar *a, const unsigned char *png, size_t size) {
    if (!png || size == 0 || size > TT_AVATAR_MAX_SIZE) return false;
    unsigned char *copy = malloc(size);
    if (!copy) return false;
    memcpy(copy, png, size);
    free(a->data);
    a->data = copy;
    a->size = size;
    a->has = true;
    tox_hash(a->hash, png, size);
    return true;
}

/* avatar persists beside the profile: "<profile>.ava" with a small header
   so a stray file cannot be mistaken for PNG bytes */
#define TT_AVATAR_MAGIC "TTAV1"

static void avatar_persist(TTToxThread *t, const TTAvatar *a) {
    if (!t->profile_path) return;
    char path[strlen(t->profile_path) + 8];
    sprintf(path, "%s.ava", t->profile_path);
    if (!a->has) {
        remove(path);
        return;
    }
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    unsigned char hdr[8] = {0};
    memcpy(hdr, TT_AVATAR_MAGIC, 5);
    hdr[5] = (unsigned char)(a->size & 0xFF);
    hdr[6] = (unsigned char)((a->size >> 8) & 0xFF);
    hdr[7] = (unsigned char)((a->size >> 16) & 0xFF);
    fwrite(hdr, 1, sizeof hdr, fp);
    fwrite(a->data, 1, a->size, fp);
    fclose(fp);
}

static void avatar_persist_load(TTToxThread *t) {
    if (!t->profile_path) return;
    char path[strlen(t->profile_path) + 8];
    sprintf(path, "%s.ava", t->profile_path);
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    unsigned char hdr[8] = {0};
    if (fread(hdr, 1, sizeof hdr, fp) != sizeof hdr ||
        memcmp(hdr, TT_AVATAR_MAGIC, 5) != 0) {
        fclose(fp);
        return;
    }
    size_t size = (size_t)hdr[5] | ((size_t)hdr[6] << 8) | ((size_t)hdr[7] << 16);
    if (size == 0 || size > TT_AVATAR_MAX_SIZE) {
        fclose(fp);
        return;
    }
    unsigned char *buf = malloc(size);
    if (!buf || fread(buf, 1, size, fp) != size) {
        free(buf);
        fclose(fp);
        return;
    }
    fclose(fp);
    if (!tt_avatar_set(&t->self_avatar, buf, size))
        free(buf); /* tt_avatar_set keeps its own copy */
    free(buf);
}

/* push our avatar to one friend: skip when the friend already has this
   exact hash (spec: receiver cancels on identical file_id) */
static void avatar_push_to_friend(TTToxThread *t, uint32_t fn) {
    if (!t->self_avatar.has) return;
    if (memcmp(t->sent_hash[fn], t->self_avatar.hash, TOX_HASH_LENGTH) == 0)
        return;
    uint64_t fsz = (uint64_t)t->self_avatar.size;
    Tox_Err_File_Send err;
    tox_file_send(t->tox, fn, TOX_FILE_KIND_AVATAR, fsz,
                  t->self_avatar.hash, NULL, 0, &err);
    if (err != TOX_ERR_FILE_SEND_OK) {
        TT_LOG("tox", "avatar offer(%u): %d", fn, (int)err);
        return;
    }
    memcpy(t->sent_hash[fn], t->self_avatar.hash, TOX_HASH_LENGTH);
    TT_LOG("tox", "avatar offered to %u", fn);
}

/* broadcast our avatar to every friend (after set/clear/load) */
static void avatar_push_all(TTToxThread *t) {
    uint32_t count = tox_self_get_friend_list_size(t->tox);
    uint32_t *nums = calloc(count ? count : 1, sizeof *nums);
    if (!nums) return;
    tox_self_get_friend_list(t->tox, nums);
    for (uint32_t i = 0; i < count; i++)
        avatar_push_to_friend(t, nums[i]);
    free(nums);
}

static void avatar_clear_all_sent(TTToxThread *t) {
    memset(t->sent_hash, 0, sizeof t->sent_hash);
}

/* ---- settings sidecar ---- */

/* Client settings the engine must know before tox_new (currently the
   SOCKS5/Tor proxy) persist beside the profile, same convention as the
   .ava/.oq sidecars. Line format: "proxy <ip-literal> <port>" (any other
   content, including "noproxy", means defaults). */
void tt_settings_load(TTSettings *s, const char *profile_path) {
    memset(s, 0, sizeof *s);
    if (!profile_path) return;
    char path[strlen(profile_path) + 4];
    sprintf(path, "%s.tt", profile_path);
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    char line[128];
    if (fgets(line, sizeof line, fp)) {
        char host[64];
        long port = 0;
        if (sscanf(line, "proxy %63s %ld", host, &port) == 2) {
            s->proxy_set = true;
            snprintf(s->proxy_host, sizeof s->proxy_host, "%s", host);
            s->proxy_port = port;
        }
    }
    fclose(fp);
}

bool tt_settings_store_proxy(const char *profile_path, const char *host, long port) {
    if (!profile_path) return false;
    char path[strlen(profile_path) + 4];
    sprintf(path, "%s.tt", profile_path);
    char tmp[strlen(profile_path) + 8];
    sprintf(tmp, "%s.tt.new", profile_path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return false;
    if (host && host[0])
        fprintf(fp, "proxy %s %ld\n", host, port);
    else
        fputs("noproxy\n", fp);
    if (fclose(fp) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    return true;
}

/* Per-friend E2EE enforcement sidecar. The "<profile>.tt" file carries one
   line per setting group; the E2EE line lists enforced friend numbers:
     e2ee <fn> <fn> ...
   A missing line means no enforcement. The proxy line (if any) is preserved
   on write. */
void tt_settings_load_e2ee(bool required[TT_MAX_FRIENDS], const char *profile_path) {
    memset(required, 0, TT_MAX_FRIENDS * sizeof(bool));
    if (!profile_path) return;
    char path[strlen(profile_path) + 4];
    sprintf(path, "%s.tt", profile_path);
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof line, fp)) {
        if (strncmp(line, "e2ee", 4) != 0) continue;
        char *p = line + 4;
        while (*p) {
            while (*p == ' ' || *p == '\t') p++;
            if (*p < '0' || *p > '9') break;
            char *end = NULL;
            long fn = strtol(p, &end, 10);
            if (end == p) break;
            if (fn >= 0 && fn < TT_MAX_FRIENDS) required[fn] = true;
            p = end;
        }
        break;
    }
    fclose(fp);
}

bool tt_settings_store_e2ee(const bool required[TT_MAX_FRIENDS],
                             const char *profile_path) {
    if (!profile_path) return false;
    char path[strlen(profile_path) + 4];
    sprintf(path, "%s.tt", profile_path);
    char tmp[strlen(profile_path) + 8];
    sprintf(tmp, "%s.tt.new", profile_path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return false;
    /* preserve the proxy line if present */
    FILE *old = fopen(path, "rb");
    if (old) {
        char line[128];
        if (fgets(line, sizeof line, old)) {
            if (strncmp(line, "proxy", 5) == 0 || strncmp(line, "noproxy", 7) == 0)
                fputs(line, fp);
        }
        fclose(old);
    }
    /* write the enforced friend numbers (true entries only) */
    int first = 1;
    for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++) {
        if (!required[fn]) continue;
        if (first) {
            fputs("e2ee", fp);
            first = 0;
        }
        fprintf(fp, " %u", fn);
    }
    if (!first) fputc('\n', fp);
    if (fclose(fp) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return false;
    }
    return true;
}

/* ---- general-transfer forward declarations (helpers live below) ---- */
static void avatar_on_offer(TTToxThread *t, Tox *tox, uint32_t friend_number,
                            uint32_t file_number, uint64_t file_size);
static TTXfer *xfer_find(TTToxThread *t, uint32_t fn, uint32_t file_number);
static void xfer_progress(TTToxThread *t, TTXfer *x);
static void xfer_failed(TTToxThread *t, TTXfer *x);
static void xfer_done(TTToxThread *t, TTXfer *x);
static void xfer_on_offer(TTToxThread *t, uint32_t fn, uint32_t file_number,
                          uint64_t file_size, const char *name, size_t name_len);

/* ---- avatar file-transfer callbacks ---- */

static void cb_file_recv(Tox *tox, uint32_t friend_number, uint32_t file_number,
                         uint32_t kind, uint64_t file_size, const uint8_t *filename,
                         size_t filename_length, void *user_data) {
    TTToxThread *t = user_data;
    if (kind == TOX_FILE_KIND_AVATAR) {
        avatar_on_offer(t, tox, friend_number, file_number, file_size);
        return;
    }
    if (kind == TOX_FILE_KIND_DATA) {
        xfer_on_offer(t, friend_number, file_number, file_size,
                      (const char *)filename, filename_length);
        return;
    }
    /* other kinds: refuse */
    Tox_Err_File_Control cerr;
    tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
}

/* AVATAR-kind offer: mirror of xfer_on_offer; auto-resumes after dedup and
   size checks (avatar transfer is not user-visible) */
static void avatar_on_offer(TTToxThread *t, Tox *tox, uint32_t friend_number,
                            uint32_t file_number, uint64_t file_size) {
    if (friend_number >= TT_MAX_FRIENDS) return;
    TTAvatar *a = &t->avatars[friend_number];
    if (file_size == 0) {
        /* spec: 0-length avatar = friend removed theirs */
        Tox_Err_File_Control cerr;
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        tt_avatar_free(a);
        TTEvent *ev = tt_event_new(TT_EV_AVATAR_CLEARED);
        if (ev) {
            ev->friend_number = friend_number;
            tt_queue_push(&t->out, ev);
        }
        return;
    }
    if (file_size > TT_AVATAR_MAX_SIZE) {
        Tox_Err_File_Control cerr;
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        TT_LOG("tox", "avatar(%u): oversized %llu", friend_number,
               (unsigned long long)file_size);
        return;
    }
    /* the avatar file_id IS the SHA-256 of the data: always fetch it —
       it both powers the same-hash skip and becomes the expected hash
       verified once all chunks arrived */
    uint8_t fid[TOX_FILE_ID_LENGTH];
    if (!tox_file_get_file_id(tox, friend_number, file_number, fid, NULL)) {
        Tox_Err_File_Control cerr;
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        TT_LOG("tox", "avatar(%u): no file id", friend_number);
        return;
    }
    /* receiver cancels when we already hold this exact avatar */
    if (a->has && memcmp(fid, a->hash, TOX_HASH_LENGTH) == 0) {
        Tox_Err_File_Control cerr;
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        TT_LOG("tox", "avatar(%u): same hash, skipped", friend_number);
        return;
    }
    free(a->data);
    a->data = malloc((size_t)file_size);
    if (!a->data) return;
    a->rx_active = true;
    a->rx_file_number = file_number;
    a->rx_expected = (size_t)file_size;
    a->rx_got = 0;
    a->size = (size_t)file_size;
    memcpy(a->hash, fid, TOX_HASH_LENGTH); /* expected digest for verify */
    Tox_Err_File_Control cerr;
    tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, &cerr);
    TT_LOG("tox", "avatar(%u) incoming %llu bytes", friend_number,
           (unsigned long long)file_size);
}

static void cb_file_recv_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number,
                               uint64_t position, const uint8_t *data, size_t length,
                               void *user_data) {
    TTToxThread *t = user_data;
    (void)position;
    if (friend_number >= TT_MAX_FRIENDS) return;
    /* general DATA transfer takes priority: avatar and DATA offers to the
       same friend use different (file_number) slots, but never trust it */
    TTXfer *x = xfer_find(t, friend_number, file_number);
    if (x) {
        if (x->sending || !x->accepted || !x->fp) return;
        if (x->got + (uint64_t)length > x->size) { /* protocol violation */
            Tox_Err_File_Control cerr;
            tox_file_control(tox, friend_number, file_number,
                             TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_failed(t, x);
            return;
        }
        if (length && fwrite(data, 1, length, x->fp) != length) {
            TT_LOG("tox", "xfer(%u): write failed", x->id);
            Tox_Err_File_Control cerr;
            tox_file_control(tox, friend_number, file_number,
                             TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_failed(t, x);
            return;
        }
        x->got += length;
        if (x->got >= x->size) { /* 0-size files complete immediately */
            if (fflush(x->fp) != 0) {
                TT_LOG("tox", "xfer(%u): flush failed", x->id);
                xfer_failed(t, x);
                return;
            }
            TT_LOG("tox", "xfer(%u) done: %s", x->id, x->path); /* before free */
            xfer_done(t, x);
        } else {
            xfer_progress(t, x);
        }
        return;
    }
    /* avatar RX path below: the avatar stream must already be in rx state
       for this file_number */
    TTAvatar *a = &t->avatars[friend_number];
    if (!a->rx_active || a->rx_file_number != file_number) return;
    if (a->rx_got + length > a->rx_expected) { /* corrupt stream: abort */
        a->rx_active = false;
        Tox_Err_File_Control cerr;
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        return;
    }
    memcpy(a->data + a->rx_got, data, length);
    a->rx_got += length;
    if (a->rx_got < a->rx_expected) return;
    /* complete: verify the SHA-256 the friend offered */
    unsigned char h[TOX_HASH_LENGTH];
    tox_hash(h, a->data, a->rx_got);
    bool ok = memcmp(h, a->hash, TOX_HASH_LENGTH) == 0;
    a->rx_active = false;
    if (!ok) {
        TT_LOG("tox", "avatar(%u) hash mismatch", friend_number);
        tt_avatar_free(a);
        TTEvent *ev = tt_event_new(TT_EV_AVATAR_CLEARED);
        if (ev) {
            ev->friend_number = friend_number;
            tt_queue_push(&t->out, ev);
        }
        return;
    }
    a->has = true;
    TTEvent *ev = tt_event_new(TT_EV_AVATAR);
    if (ev) {
        ev->friend_number = friend_number;
        ev->str = malloc(a->size + 1);
        if (ev->str) {
            memcpy(ev->str, a->data, a->size);
            ev->str[a->size] = '\0';
            ev->str_len = a->size;
        }
        tt_queue_push(&t->out, ev);
    }
    TT_LOG("tox", "avatar(%u) stored %zu bytes", friend_number, a->size);
}

/* toxcore delivers typing as one packet per state CHANGE request, but the
   receive callback fires per received packet; dedupe via peer_typing */
static void cb_friend_typing(Tox *tox, uint32_t friend_number, bool typing,
                             void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    if (friend_number < TT_MAX_FRIENDS && t->peer_typing[friend_number] != typing) {
        t->peer_typing[friend_number] = typing;
        TT_LOG("tox", "friend %u typing: %d", friend_number, (int)typing);
        push_simple(t, TT_EV_FRIEND_TYPING, friend_number, NULL, 0, (int)typing);
    }
}

/* read receipt: the friend reports the highest message id it has read */
static void cb_friend_read_receipt(Tox *tox, uint32_t friend_number,
                                   uint32_t message_id, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    TT_LOG("tox", "friend %u read receipt: %u", friend_number, message_id);
    push_simple(t, TT_EV_FRIEND_READ_RECEIPT, friend_number, NULL, 0, (int)message_id);
}

static void cb_file_recv_control(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                 Tox_File_Control control, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    if (friend_number >= TT_MAX_FRIENDS) return;
    /* the sender got CANCEL/PAUSE from us (or we got it from them): any
       control on a tracked general transfer means it is no longer flowing */
    TTXfer *x = xfer_find(t, friend_number, file_number);
    if (x && control == TOX_FILE_CONTROL_CANCEL) {
        TT_LOG("tox", "xfer(%u) cancelled by friend", x->id);
        xfer_failed(t, x);
        return;
    }
    TTAvatar *a = &t->avatars[friend_number];
    if (a->rx_active && a->rx_file_number == file_number &&
        control == TOX_FILE_CONTROL_CANCEL) {
        a->rx_active = false;
        TT_LOG("tox", "avatar(%u) transfer cancelled by friend", friend_number);
    }
}

static void cb_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number,
                                  uint64_t position, size_t length, void *user_data) {
    TTToxThread *t = user_data;
    /* general DATA TX first: the avatar sender is a fallback for requests
       that match no tracked transfer (its file_number was never claimed) */
    TTXfer *x = xfer_find(t, friend_number, file_number);
    if (x && x->sending && x->fp) {
        if (position >= x->size || length == 0) { /* transfer complete */
            TT_LOG("tox", "xfer(%u) sent: %s", x->id, x->name);
            xfer_done(t, x);
            return;
        }
        if (fseek(x->fp, (long)position, SEEK_SET) != 0) {
            TT_LOG("tox", "xfer(%u): seek failed", x->id);
            Tox_Err_File_Control cerr;
            tox_file_control(tox, friend_number, file_number,
                             TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_failed(t, x);
            return;
        }
        uint8_t buf[4096];
        size_t chunk = length < sizeof buf ? length : sizeof buf;
        size_t n = fread(buf, 1, chunk, x->fp);
        if (n == 0) { /* source shrank under us: cannot serve the request */
            TT_LOG("tox", "xfer(%u): read failed", x->id);
            Tox_Err_File_Control cerr;
            tox_file_control(tox, friend_number, file_number,
                             TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_failed(t, x);
            return;
        }
        x->got = position + n;
        Tox_Err_File_Send_Chunk err;
        tox_file_send_chunk(tox, friend_number, file_number, position, buf, n, &err);
        if (err != TOX_ERR_FILE_SEND_CHUNK_OK) {
            TT_LOG("tox", "xfer(%u) chunk(%u): %d", x->id, file_number, (int)err);
            xfer_failed(t, x);
            return;
        }
        xfer_progress(t, x);
        return;
    }
    const TTAvatar *a = &t->self_avatar;
    if (!a->has) return;
    if (position >= a->size) { /* transfer complete */
        TT_LOG("tox", "avatar sent to %u", friend_number);
        return;
    }
    size_t chunk = a->size - (size_t)position;
    if (chunk > length) chunk = length;
    Tox_Err_File_Send_Chunk err;
    tox_file_send_chunk(tox, friend_number, file_number, position,
                        a->data + position, chunk, &err);
    if (err != TOX_ERR_FILE_SEND_CHUNK_OK)
        TT_LOG("tox", "avatar chunk(%u): %d", friend_number, (int)err);
}

/* ---- general file transfers (TOX_FILE_KIND_DATA) ----
   Transfers live in a small table keyed by our own xfer id (not tox's
   per-friend file_number, which is reused after termination). Chunk
   callbacks resolve (friend_number, file_number) -> TTXfer. Avatar chunk
   serving is separate; file_chunk_request must consult the xfer table
   FIRST so avatar offers to the same friend are not mistaken for
   general transfers (and vice versa). */

static TTXfer *xfer_alloc(TTToxThread *t) {
    for (int i = 0; i < TT_MAX_XFERS; i++)
        if (!t->xfers[i].active) {
            TTXfer *x = &t->xfers[i];
            memset(x, 0, sizeof *x);
            x->active = true;
            x->id = ++t->xfer_seq;
            x->fn = UINT32_MAX;
            x->file_number = UINT32_MAX;
            return x;
        }
    return NULL;
}

static void xfer_free(TTXfer *x) {
    if (x->fp) fclose(x->fp);
    memset(x, 0, sizeof *x);
}

/* (fn, file_number) -> active xfer; only one table entry can match */
static TTXfer *xfer_find(TTToxThread *t, uint32_t fn, uint32_t file_number) {
    for (int i = 0; i < TT_MAX_XFERS; i++) {
        TTXfer *x = &t->xfers[i];
        if (x->active && x->fn == fn && x->file_number == file_number)
            return x;
    }
    return NULL;
}

/* our stable xfer id -> active transfer (cancel from the UI) */
static TTXfer *xfer_by_id(TTToxThread *t, uint32_t xfer_id) {
    for (int i = 0; i < TT_MAX_XFERS; i++) {
        TTXfer *x = &t->xfers[i];
        if (x->active && x->id == xfer_id)
            return x;
    }
    return NULL;
}

/* RX accepted / TX started: emit progress every 256 KiB or at completion */
static void xfer_progress(TTToxThread *t, TTXfer *x) {
    bool emit = x->got >= x->size;
    static const uint64_t step = 256 * 1024;
    /* true crossing test: the previous emit point vs now, both floored to
       the step. (x->got - 1) above only fired when got landed exactly on a
       boundary — impossible for 1371B chunks — so mid-transfer events
       never emitted (round 25 r25e: 17 crossings, zero events) */
    if (!emit && x->got / step != x->got_prev / step) emit = true;
    if (!emit) return;
    x->got_prev = x->got;
    char buf[48];
    snprintf(buf, sizeof buf, "%llu/%llu", (unsigned long long)x->got,
             (unsigned long long)x->size);
    TTEvent *ev = tt_event_new(TT_EV_FILE_PROGRESS);
    if (ev) {
        ev->friend_number = x->fn;
        ev->ival = (int)x->id;
        ev->str = strdup(buf);
        if (ev->str) ev->str_len = strlen(buf);
        tt_queue_push(&t->out, ev);
    }
}

static void xfer_failed(TTToxThread *t, TTXfer *x) {
    TTEvent *ev = tt_event_new(TT_EV_FILE_FAILED);
    if (ev) {
        ev->friend_number = x->fn;
        ev->ival = (int)x->id;
        tt_queue_push(&t->out, ev);
    }
    xfer_free(x);
}

static void xfer_done(TTToxThread *t, TTXfer *x) {
    TTEvent *ev = tt_event_new(TT_EV_FILE_DONE);
    if (ev) {
        ev->friend_number = x->fn;
        ev->ival = (int)x->id;
        ev->str = strdup(x->path);
        if (ev->str) ev->str_len = strlen(x->path);
        tt_queue_push(&t->out, ev);
    }
    xfer_free(x);
}

static void xfer_all_purge(TTToxThread *t, uint32_t fn) {
    for (int i = 0; i < TT_MAX_XFERS; i++) {
        TTXfer *x = &t->xfers[i];
        if (x->active && x->fn == fn) xfer_failed(t, x);
    }
}

/* sender side: open, stat, offer */
static void handle_cmd_send_file(TTToxThread *t, uint32_t fn, const char *path) {
    if (!path) return;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        TT_LOG("tox", "send file: open failed: %s", path);
        TTEvent *ev = tt_event_new(TT_EV_FILE_FAILED);
        if (ev) tt_queue_push(&t->out, ev); /* no xfer id yet; UI matches by time */
        return;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return; }
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    TTXfer *x = xfer_alloc(t);
    if (!x) { fclose(fp); TT_LOG("tox", "send file: table full"); return; }
    x->fn = fn;
    x->sending = true;
    x->accepted = true;
    x->fp = fp;
    x->size = (uint64_t)sz;
    x->got = 0;
    snprintf(x->name, sizeof x->name, "%s", base);
    snprintf(x->path, sizeof x->path, "%s", path);
    Tox_Err_File_Send err;
    x->file_number = tox_file_send(t->tox, fn, TOX_FILE_KIND_DATA,
                                   (uint64_t)sz, NULL,
                                   (const uint8_t *)x->name, strlen(x->name), &err);
    if (err != TOX_ERR_FILE_SEND_OK) {
        TT_LOG("tox", "send file offer(%u): %d", fn, (int)err);
        xfer_failed(t, x);
        return;
    }
    char evbuf[TOX_MAX_FILENAME_LENGTH + 24];
    snprintf(evbuf, sizeof evbuf, "%s\n%llu", x->name, (unsigned long long)sz);
    TTEvent *ev = tt_event_new(TT_EV_FILE_TX_STARTED);
    if (ev) {
        ev->friend_number = fn;
        ev->ival = (int)x->id;
        ev->str = strdup(evbuf);
        if (ev->str) ev->str_len = strlen(evbuf);
        tt_queue_push(&t->out, ev);
    }
}

/* receiver side: DATA offer arrives */
static void xfer_on_offer(TTToxThread *t, uint32_t fn, uint32_t file_number,
                          uint64_t file_size, const char *name, size_t name_len) {
    TTXfer *x = xfer_alloc(t);
    if (!x) {
        Tox_Err_File_Control cerr;
        tox_file_control(t->tox, fn, file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        TT_LOG("tox", "file offer(%u): table full, cancelled", fn);
        return;
    }
    x->fn = fn;
    x->file_number = file_number;
    x->sending = false;
    x->accepted = false;
    x->size = file_size;
    x->got = 0;
    size_t n = name_len < sizeof x->name - 1 ? name_len : sizeof x->name - 1;
    memcpy(x->name, name, n);
    x->name[n] = '\0';
    /* announce; UI posts FILE_ACCEPT(path)/FILE_REJECT */
    char evbuf[TOX_MAX_FILENAME_LENGTH + 24];
    snprintf(evbuf, sizeof evbuf, "%s\n%llu", x->name,
             (unsigned long long)file_size);
    TTEvent *ev = tt_event_new(TT_EV_FILE_OFFER);
    if (ev) {
        ev->friend_number = fn;
        ev->ival = (int)x->id;
        ev->str = strdup(evbuf);
        if (ev->str) ev->str_len = strlen(evbuf);
        tt_queue_push(&t->out, ev);
    }
    TT_LOG("tox", "file offer(%u): %s (%llu bytes), xfer id %u",
           fn, x->name, (unsigned long long)file_size, x->id);
}

/* accept/reject from the UI */
static void handle_cmd_file_accept(TTToxThread *t, uint32_t xfer_id, const char *path) {
    TTXfer *x = NULL;
    for (int i = 0; i < TT_MAX_XFERS; i++)
        if (t->xfers[i].active && t->xfers[i].id == xfer_id &&
            !t->xfers[i].sending && !t->xfers[i].accepted) {
            x = &t->xfers[i];
            break;
        }
    if (!x || !path) return;
    /* Resume: if the destination already exists, append from its current
       size instead of truncating. tox_file_seek tells the sender to start
       at that offset; the existing bytes are kept (a partial download from
       an earlier attempt). Only resume when the partial is strictly smaller
       than the full size — a complete or oversized file is restarted. */
    uint64_t resume_at = 0;
    FILE *probe = fopen(path, "rb");
    if (probe) {
        fseek(probe, 0, SEEK_END);
        long got = ftell(probe);
        fclose(probe);
        if (got > 0 && (uint64_t)got < x->size)
            resume_at = (uint64_t)got;
    }
    /* O_NOFOLLOW: never follow a symlink at the destination, so a local
       attacker cannot redirect the write to an arbitrary file. */
    int fd = resume_at
        ? open(path, O_RDWR | O_NOFOLLOW)
        : open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        TT_LOG("tox", "file accept: open failed: %s", path);
        Tox_Err_File_Control cerr;
        tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        xfer_failed(t, x);
        return;
    }
    x->fp = fdopen(fd, resume_at ? "r+b" : "wb");
    if (!x->fp) {
        close(fd);
        TT_LOG("tox", "file accept: fdopen failed: %s", path);
        Tox_Err_File_Control cerr;
        tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        xfer_failed(t, x);
        return;
    }
    if (resume_at) {
        if (fseek(x->fp, (long)resume_at, SEEK_SET) != 0) {
            TT_LOG("tox", "file accept: seek failed: %s", path);
            fclose(x->fp); x->fp = NULL;
            Tox_Err_File_Control cerr;
            tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_failed(t, x);
            return;
        }
        x->got = resume_at;
        x->got_prev = resume_at;
        Tox_Err_File_Seek serr;
        tox_file_seek(t->tox, x->fn, x->file_number, resume_at, &serr);
        TT_LOG("tox", "file accept(%u): resuming %s at %llu/%llu (%d)",
               xfer_id, path, (unsigned long long)resume_at,
               (unsigned long long)x->size, (int)serr);
    }
    snprintf(x->path, sizeof x->path, "%s", path);
    x->accepted = true;
    Tox_Err_File_Control cerr;
    tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_RESUME, &cerr);
    TT_LOG("tox", "file accept(%u): %s", xfer_id, path);
}

static void handle_cmd_file_reject(TTToxThread *t, uint32_t xfer_id) {
    for (int i = 0; i < TT_MAX_XFERS; i++) {
        TTXfer *x = &t->xfers[i];
        if (x->active && x->id == xfer_id && !x->sending && !x->accepted) {
            Tox_Err_File_Control cerr;
            tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
            xfer_free(x);
            TT_LOG("tox", "file reject(%u)", xfer_id);
            return;
        }
    }
}

/* ---- groups (new group chats) ---- */

static void group_push(TTToxThread *t, TTEventType type, uint32_t gn,
                       const char *s, size_t len, int ival, int ival2) {
    TTEvent *ev = tt_event_new(type);
    if (!ev) return;
    ev->friend_number = gn;
    ev->ival = ival;
    ev->ival2 = ival2;
    if (s && len) {
        ev->str = malloc(len + 1);
        if (!ev->str) { free(ev); return; }
        memcpy(ev->str, s, len);
        ev->str[len] = '\0';
        ev->str_len = len;
    }
    tt_queue_push(&t->out, ev);
}

static void cb_group_message(Tox *tox, uint32_t group_number, uint32_t peer_id,
                             Tox_Message_Type message_type, const uint8_t *message,
                             size_t message_length, Tox_Group_Message_Id message_id,
                             void *user_data) {
    TTToxThread *t = user_data;
    (void)tox; (void)message_id;
    group_push(t, TT_EV_GROUP_MSG, group_number, (const char *)message,
               message_length, (int)peer_id, (int)message_type);
}

static void cb_group_private_message(Tox *tox, uint32_t group_number, uint32_t peer_id,
                                     Tox_Message_Type message_type, const uint8_t *message,
                                     size_t message_length, Tox_Group_Message_Id message_id,
                                     void *user_data) {
    TTToxThread *t = user_data;
    (void)tox; (void)message_id;
    group_push(t, TT_EV_GROUP_PRIV_MSG, group_number, (const char *)message,
               message_length, (int)peer_id, (int)message_type);
}

static void cb_group_topic(Tox *tox, uint32_t group_number, uint32_t peer_id,
                           const uint8_t *topic, size_t topic_length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_TOPIC, group_number, (const char *)topic,
               topic_length, 0, (int)peer_id);
}

static void cb_group_peer_join(Tox *tox, uint32_t group_number, uint32_t peer_id,
                               void *user_data) {
    TTToxThread *t = user_data;
    /* toxcore fires the peer-name callback only on NICK CHANGE broadcasts
       (handle_gc_nick) — a joining peer's name never arrives as an event.
       Query it here: the peer list already carries it at join time. Same
       for the role, so the UI never renders "peer" or a default role. */
    size_t ns = tox_group_peer_get_name_size(tox, group_number, peer_id, NULL);
    char nm[TOX_MAX_NAME_LENGTH + 1] = {0};
    if (ns > TOX_MAX_NAME_LENGTH) ns = TOX_MAX_NAME_LENGTH;
    if (ns) tox_group_peer_get_name(tox, group_number, peer_id, (uint8_t *)nm, NULL);
    group_push(t, TT_EV_GROUP_PEER_JOIN, group_number, NULL, 0, (int)peer_id, 0);
    if (ns) group_push(t, TT_EV_GROUP_PEER_NAME, group_number, nm, ns, (int)peer_id, 0);
    group_push(t, TT_EV_GROUP_PEER_ROLE, group_number, NULL, 0, (int)peer_id,
               (int)tox_group_peer_get_role(tox, group_number, peer_id, NULL));
}

static void cb_group_peer_exit(Tox *tox, uint32_t group_number, uint32_t peer_id,
                               Tox_Group_Exit_Type exit_type, const uint8_t *name,
                               size_t name_length, const uint8_t *part_message,
                               size_t part_message_length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox; (void)part_message; (void)part_message_length;
    group_push(t, TT_EV_GROUP_PEER_EXIT, group_number, (const char *)name,
               name_length, (int)peer_id, (int)exit_type);
}

static void cb_group_peer_name(Tox *tox, uint32_t group_number, uint32_t peer_id,
                               const uint8_t *name, size_t name_length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_PEER_NAME, group_number, (const char *)name,
               name_length, (int)peer_id, 0);
}

static void cb_group_peer_status(Tox *tox, uint32_t group_number, uint32_t peer_id,
                                 Tox_User_Status status, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_PEER_STATUS, group_number, NULL, 0, (int)peer_id, (int)status);
}

static void cb_group_moderation(Tox *tox, uint32_t group_number, uint32_t source_peer_id,
                                uint32_t target_peer_id, Tox_Group_Mod_Event mod_type,
                                void *user_data) {
    TTToxThread *t = user_data;
    (void)source_peer_id;
    /* kicked SELF: toxcore sets our group object CS_DISCONNECTED but does NOT
       delete it — and m_handle_packet_invite_groupchat only fires the invite
       callback for groups we DON'T have (group_not_added), so every later
       re-invite is silently swallowed. Destroy the dead object now
       (tox_group_leave -> flag_exit -> group_delete on the next do_gc). */
    if (mod_type == TOX_GROUP_MOD_EVENT_KICK) {
        Tox_Err_Group_Self_Query serr;
        uint32_t self_pid = tox_group_self_get_peer_id(tox, group_number, &serr);
        if (serr == TOX_ERR_GROUP_SELF_QUERY_OK && self_pid == target_peer_id) {
            TT_LOG("tox", "self kicked from group %u — leaving dead group object", group_number);
            Tox_Err_Group_Leave lerr;
            tox_group_leave(tox, group_number, NULL, 0, &lerr);
            TT_LOG("tox", "group leave after kick(%u): %d", group_number, (int)lerr);
        }
    }
    group_push(t, TT_EV_GROUP_MOD, group_number, NULL, 0, (int)target_peer_id, (int)mod_type);
}

static void cb_group_privacy_state(Tox *tox, uint32_t group_number,
                                   Tox_Group_Privacy_State privacy_state, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_STATE, group_number, NULL, 0, (int)privacy_state, -1);
}

static void cb_group_voice_state(Tox *tox, uint32_t group_number,
                                 Tox_Group_Voice_State voice_state, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_STATE, group_number, NULL, 0, -1, (int)voice_state);
}

static void cb_group_topic_lock(Tox *tox, uint32_t group_number,
                                Tox_Group_Topic_Lock topic_lock, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_STATE, group_number, NULL, 0, -2, (int)topic_lock);
}

static void cb_group_peer_limit(Tox *tox, uint32_t group_number, uint32_t peer_limit,
                                void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    char buf[24];
    int n = snprintf(buf, sizeof buf, "%u", peer_limit);
    group_push(t, TT_EV_GROUP_STATE, group_number, buf, (size_t)n, -3, (int)peer_limit);
}

static void cb_group_password(Tox *tox, uint32_t group_number, const uint8_t *password,
                              size_t length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox; (void)password; (void)length;
    group_push(t, TT_EV_GROUP_STATE, group_number, NULL, 0, -4, 0);
}

static void cb_group_join_fail(Tox *tox, uint32_t group_number,
                               Tox_Group_Join_Fail fail_type, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    group_push(t, TT_EV_GROUP_JOIN_FAIL, group_number, NULL, 0, (int)fail_type, 0);
    /* the failed group object is dead: drop it so the UI shows no phantom */
    Tox_Err_Group_Leave lerr;
    tox_group_leave(t->tox, group_number, NULL, 0, &lerr);
}

static void cb_group_self_join(Tox *tox, uint32_t group_number, void *user_data) {
    TTToxThread *t = user_data;
    size_t n = tox_group_get_name_size(tox, group_number, NULL);
    char gname[TOX_GROUP_MAX_GROUP_NAME_LENGTH + 1] = {0};
    if (n > TOX_GROUP_MAX_GROUP_NAME_LENGTH) n = TOX_GROUP_MAX_GROUP_NAME_LENGTH;
    tox_group_get_name(tox, group_number, (uint8_t *)gname, NULL);
    TT_LOG("tox", "group self join(%u): \"%s\"", group_number, gname);
    group_push(t, TT_EV_GROUP_JOINED, group_number, gname, n, 0, 0);
}

static void cb_group_invite(Tox *tox, uint32_t friend_number,
                            const uint8_t *invite_data, size_t invite_length,
                            const uint8_t *group_name, size_t group_name_length,
                            void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    if (!invite_data || invite_length == 0 || invite_length > TT_GROUP_INVITE_DATA_MAX)
        return;
    TTGroupInvite *slot = NULL;
    for (int i = 0; i < TT_MAX_GROUP_INVITES; i++)
        if (!t->ginvites[i].used) { slot = &t->ginvites[i]; break; }
    if (!slot) { /* reuse the oldest slot: overflow is a UI-stall symptom */
        slot = &t->ginvites[0];
        TT_LOG("tox", "group invite table full, overwriting slot 0");
    }
    memset(slot, 0, sizeof *slot);
    slot->used = true;
    slot->fn = friend_number;
    memcpy(slot->data, invite_data, invite_length);
    slot->len = invite_length;
    size_t n = group_name_length < TOX_GROUP_MAX_GROUP_NAME_LENGTH
                   ? group_name_length : TOX_GROUP_MAX_GROUP_NAME_LENGTH;
    if (group_name) memcpy(slot->name, group_name, n);
    slot->name[n] = '\0';
    int idx = (int)(slot - t->ginvites);
    TT_LOG("tox", "group invite from %u: \"%s\"", friend_number, slot->name);
    group_push(t, TT_EV_GROUP_INVITE, friend_number, slot->name, n, 0, idx);
}

/* ---- queue plumbing ---- */

void tt_queue_init(TTQueue *q) {
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    memset(q->items, 0, sizeof q->items);
    q->head = q->count = 0;
}

void tt_queue_destroy(TTQueue *q) {
    pthread_mutex_lock(&q->lock);
    for (size_t i = 0; i < q->count; i++) {
        tt_event_free(q->items[(q->head + i) % TT_QUEUE_CAP]);
    }
    pthread_mutex_unlock(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_mutex_destroy(&q->lock);
}

void tt_queue_push(TTQueue *q, TTEvent *ev) {
    pthread_mutex_lock(&q->lock);
    while (q->count == TT_QUEUE_CAP) {
        /* drop-oldest would lose connection events; block instead (backpressure) */
        TT_LOG("tox", "event queue full — UI stalled?");
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    q->items[(q->head + q->count) % TT_QUEUE_CAP] = ev;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

TTEvent *tt_queue_pop(TTQueue *q) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    TTEvent *ev = q->items[q->head];
    q->head = (q->head + 1) % TT_QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return ev;
}

TTEvent *tt_queue_pop_timed(TTQueue *q, unsigned ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        int rc = pthread_cond_timedwait(&q->not_empty, &q->lock, &ts);
        if (rc == ETIMEDOUT && q->count == 0) {
            pthread_mutex_unlock(&q->lock);
            return NULL;
        }
    }
    TTEvent *ev = q->items[q->head];
    q->head = (q->head + 1) % TT_QUEUE_CAP;
    q->count--;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return ev;
}

TTEvent *tt_event_new(TTEventType type) {
    TTEvent *ev = calloc(1, sizeof *ev);
    if (ev) ev->type = type;
    return ev;
}

void tt_event_free(TTEvent *ev) {
    if (!ev) return;
    free(ev->str);
    free(ev);
}

bool tt_queue_post(TTQueue *q, int type, uint32_t friend_number, const char *str, int ival) {
    TTEvent *ev = tt_event_new((TTEventType)type);
    if (!ev) return false;
    ev->friend_number = friend_number;
    ev->ival = ival;
    if (str) {
        size_t len = strlen(str);
        ev->str = malloc(len + 1);
        if (!ev->str) { free(ev); return false; }
        memcpy(ev->str, str, len + 1);
        ev->str_len = len;
    }
    tt_queue_push(q, ev);
    return true;
}

bool tt_queue_post2(TTQueue *q, int type, uint32_t friend_number,
                    const char *str, int ival, int ival2) {
    TTEvent *ev = tt_event_new((TTEventType)type);
    if (!ev) return false;
    ev->friend_number = friend_number;
    ev->ival = ival;
    ev->ival2 = ival2;
    if (str) {
        size_t len = strlen(str);
        ev->str = malloc(len + 1);
        if (!ev->str) { free(ev); return false; }
        memcpy(ev->str, str, len + 1);
        ev->str_len = len;
    }
    tt_queue_push(q, ev);
    return true;
}

/* ---- tox thread ---- */

static void push_simple(TTToxThread *t, TTEventType type, uint32_t fn, const char *s, size_t len, int ival) {
    TTEvent *ev = tt_event_new(type);
    if (!ev) return;
    ev->friend_number = fn;
    ev->ival = ival;
    if (s && len) {
        ev->str = malloc(len + 1);
        if (!ev->str) { free(ev); return; }
        memcpy(ev->str, s, len);
        ev->str[len] = '\0';
        ev->str_len = len;
    }
    tt_queue_push(&t->out, ev);
}

/* Publish the full own ToxID (public key + nospam + checksum) to the UI.
   Called once at startup and again after a nospam change. */
static void publish_toxid(TTToxThread *t) {
    uint8_t addr[TOX_ADDRESS_SIZE];
    tox_self_get_address(t->tox, addr);
    char hex[TOX_ADDRESS_SIZE * 2 + 1] = {0};
    for (size_t i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(hex + i * 2, "%02x", addr[i]); /* fixed-width, safe */
    }
    TTEvent *ev = tt_event_new(TT_EV_TOXID);
    if (ev) {
        ev->str = strdup(hex);
        ev->str_len = strlen(hex);
        tt_queue_push(&t->out, ev);
    }
}

static void offline_flush_all(TTToxThread *t);

static void cb_self_connection(Tox *tox, Tox_Connection connection, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    TT_LOG("tox", "self connection: %d", (int)connection);
    push_simple(t, TT_EV_SELF_CONNECTION, 0, NULL, 0, (int)connection);
    /* flush offline-queued messages as soon as we can reach the network
       again; per-friend callbacks fire separately, this covers friends
       whose connection state never changes (they were online all along) */
    t->self_online = connection != TOX_CONNECTION_NONE;
    if (t->self_online && !t->oq_flushing)
        offline_flush_all(t);
}

/* ---- faux offline messaging ---- */

static void offline_flush_friend(TTToxThread *t, uint32_t fn);

/* Flush every pending offline-queued message whose friend is connected.
   Called on self reconnect and on each FRIEND_CONNECTION online event. */
static void offline_flush_all(TTToxThread *t) {
    t->oq_flushing = true;
    uint32_t count = tox_self_get_friend_list_size(t->tox);
    uint32_t *nums = calloc(count ? count : 1, sizeof *nums);
    if (nums) {
        tox_self_get_friend_list(t->tox, nums);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t fn = nums[i];
            if (tt_oq_count(&t->oq, fn) == 0) continue;
            if (tox_friend_get_connection_status(t->tox, fn, NULL) == TOX_CONNECTION_NONE)
                continue;
            offline_flush_friend(t, fn);
        }
        free(nums);
    }
    t->oq_flushing = false;
    tt_oq_save(&t->oq, t->profile_path, t->pass_key);
}

/* Send every queued message for fn now (friend just came online). With the
   E2EE layer on, each text is encrypted through tt_session_send (handshake
   frames would have been dropped en route, so the stash is empty until the
   session establishes; flush() delivers stashed texts in order). */
static void offline_flush_friend(TTToxThread *t, uint32_t fn) {
    static char texts[TT_OQ_MAX_PER_FRIEND][TT_OQ_MAX_LINE];
    int n = 0;
    tt_oq_take_all(&t->oq, fn, texts, &n);
    if (n == 0) return;
    if (tt_e2ee_mode && t->e2ee && fn < TT_MAX_FRIENDS) {
        TTE2EEEnv env;
        e2ee_env(t, fn, &env);
        if (env.peer_pk) {
            TTSession *s = &t->e2ee[fn];
            if (!s->active && e2ee_fallback_due(t, fn)) {
                /* legacy friend: enforced -> block the flush; else fall back
                   to plaintext with a warning */
                if (t->e2ee_required[fn]) {
                    e2ee_warn(t, fn,
                              "E2EE is required for this contact, but they do "
                              "not support it — queued messages not sent.");
                    tt_oq_save(&t->oq, t->profile_path, t->pass_key);
                    return;
                }
                t->e2ee_fallback[fn] = true;
                e2ee_warn(t, fn,
                          "This contact does not support end-to-end encryption "
                          "— queued messages sent in plaintext.");
                /* fall through to the plain flush below */
            } else {
                uint8_t frame[TT_FRAME_MAX];
                for (int i = 0; i < n; i++) {
                    size_t len = strlen(texts[i]);
                    size_t off = 0;
                    while (off < len) {
                        size_t chunk = len - off;
                        if (chunk > TT_E2EE_CHUNK) chunk = TT_E2EE_CHUNK;
                        int sn = tt_session_send(&t->e2ee[fn], &env,
                                                 (const uint8_t *)texts[i] + off,
                                                 chunk, frame, sizeof frame);
                        if (sn < 0) break;
                        if (sn == 0) {
                            /* inactive session: the chunk is stashed for the
                               post-handshake flush; requeue only what the stash
                               did not take (multi-chunk texts) */
                            if (off + chunk < len)
                                tt_oq_add(&t->oq, fn, texts[i] + off + chunk);
                            off = len;
                            break;
                        }
                        if (e2ee_send_frame(t, fn, frame, (size_t)sn) == 0)
                            break; /* friend dropped mid-flush: requeue the rest */
                        off += chunk;
                    }
                    if (off < len) { /* session lost mid-text: requeue the rest */
                        for (int k = i; k < n; k++) tt_oq_add(&t->oq, fn, texts[k]);
                        break;
                    }
                }
                tt_oq_save(&t->oq, t->profile_path, t->pass_key);
                push_simple(t, TT_EV_OFFLINE_FLUSHED, fn, NULL, 0, n);
                return;
            }
        }
    }
    for (int i = 0; i < n; i++) {
        Tox_Err_Friend_Send_Message serr;
        uint32_t mid = tox_friend_send_message(t->tox, fn, TOX_MESSAGE_TYPE_NORMAL,
                                               (const uint8_t *)texts[i], strlen(texts[i]), &serr);
        TT_LOG("tox", "offline flush(%u) msg %d/%d: %d", fn, i + 1, n, (int)serr);
        if (serr == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
            /* raced: friend dropped again — requeue the rest */
            for (int k = i; k < n; k++) tt_oq_add(&t->oq, fn, texts[k]);
            break;
        }
        if (serr == TOX_ERR_FRIEND_SEND_MESSAGE_OK)
            push_simple(t, TT_EV_MESSAGE_SENT, fn, NULL, 0, (int)mid);
    }
    char name[TOX_MAX_NAME_LENGTH + 1] = {0};
    size_t nsz = tox_friend_get_name_size(t->tox, fn, NULL);
    if (nsz > TOX_MAX_NAME_LENGTH) nsz = TOX_MAX_NAME_LENGTH;
    tox_friend_get_name(t->tox, fn, (uint8_t *)name, NULL);
    TT_LOG("tox", "%d queued message%s delivered to %s",
           n, n == 1 ? "" : "s", name[0] ? name : "?");
    /* UI renders the per-contact system line itself (name not needed) */
    push_simple(t, TT_EV_OFFLINE_FLUSHED, fn, NULL, 0, n);
}

/* ---- bootstrap ---- */

static void bootstrap_all(TTToxThread *t, Tox *tox) {
    static const struct {
        const char *host;
        uint16_t port;
        const char *keyhex;
        bool relay;
        bool tor_ok;   /* IP literal: safe to bootstrap in Tor mode (no DNS) */
    } boots[] = {
        /* verified live via nodes.tox.chat 2026-09-03 */
        {"144.217.167.73",   33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", true,  true},
        {"tox.abilinski.com", 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E", false, false},
        {"tox1.mf-net.eu",   33445, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", true,  false},
        {"3.0.24.15",        33445, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D", false, true},
        {"139.162.110.188",  33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55", true,  true},
        {"tox2.mf-net.eu",   33445, "70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", true,  false},
        {"144.172.88.203",   33445, "2016A0F2797EE3A8B004BA623F11AAFC8146F1B8F45107232A1A1AECCE856674", true,  true},
        {"172.104.215.182",  33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239", true,  true},
        {"tox.initramfs.io", 33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", true,  false},
        {"tox3.mf-net.eu",   33445, "F4FC9398B7167668ED2BCF85634E04D4CDCDD2F95DA5F305BD234888B6E6A771", true,  false},
        {"188.214.122.30",   33445, "2A9F7A620581D5D1B09B004624559211C5ED3D1D712E8066ACDB0896A7335705", true,  true},
    };
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    for (size_t i = 0; i < sizeof boots / sizeof boots[0]; i++) {
        if (t->tor_mode && !boots[i].tor_ok) continue; /* no DNS in Tor mode */
        const char *h = boots[i].keyhex;
        bool ok = strlen(h) == TOX_PUBLIC_KEY_SIZE * 2;
        for (size_t j = 0; ok && j < TOX_PUBLIC_KEY_SIZE; j++) {
            unsigned char b; if (sscanf(h + j * 2, "%2hhx", &b) != 1) ok = false; else key[j] = (uint8_t)b;
        }
        if (!ok) continue;
        tox_bootstrap(tox, boots[i].host, boots[i].port, key, NULL);
        if (boots[i].relay)
            tox_add_tcp_relay(tox, boots[i].host, boots[i].port, key, NULL);
    }
    t->last_bootstrap = time(NULL);
}

static void cb_friend_name(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    push_simple(t, TT_EV_FRIEND_NAME, friend_number, (const char *)name, length, 0);
}

static void cb_friend_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type,
                              const uint8_t *message, size_t length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    /* E2EE layer first: frames are consumed in-place (DATA mutates the
       payload into plaintext and still flows to the consumer below) */
    TTEvent *probe = tt_event_new(TT_EV_FRIEND_MESSAGE);
    if (!probe) return; /* OOM: drop silently, next event still flows */
    probe->friend_number = friend_number;
    probe->str = malloc(length + 1);
    if (probe->str) {
        memcpy(probe->str, message, length);
        probe->str[length] = '\0';
        probe->str_len = length;
        if (tt_e2ee_mode && e2ee_rx(t, probe)) {
            tt_event_free(probe);
            return;
        }
        /* passthrough (layer off, plaintext DATA, or plain text) */
        tt_queue_push(&t->out, probe);
        return;
    }
    free(probe);
    /* OOM fallback: original push_simple path */
    push_simple(t, TT_EV_FRIEND_MESSAGE, friend_number, (const char *)message, length, (int)type);
}

static void cb_friend_connection(Tox *tox, uint32_t friend_number, Tox_Connection connection, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    TT_LOG("tox", "friend %u connection: %d", friend_number, (int)connection);
    push_simple(t, TT_EV_FRIEND_CONNECTION, friend_number, NULL, 0, (int)connection);
    /* friend went offline: toxcore purges their transfers (we free ours and
       report failures); their stale typing state can no longer be cleared
       by a packet, so reset the dedupe cache (UI clears its indicator) */
    if (connection == TOX_CONNECTION_NONE) {
        xfer_all_purge(t, friend_number);
        if (friend_number < TT_MAX_FRIENDS && t->peer_typing[friend_number]) {
            t->peer_typing[friend_number] = false;
            push_simple(t, TT_EV_FRIEND_TYPING, friend_number, NULL, 0, 0);
        }
    }
    /* friend came online: offer our avatar if they don't have this hash yet,
       then flush anything queued while they were offline */
    if (connection != TOX_CONNECTION_NONE) {
        emit_friend_identity(t, friend_number);
        avatar_push_to_friend(t, friend_number);
        /* E2EE layer: a fresh connection re-evaluates legacy status — clear
           the fallback/warn flags so a legacy friend is re-detected (and
           re-warned) on each reconnect, and a friend who upgraded to E2EE
           stops falling back. */
        if (tt_e2ee_mode && t->e2ee && friend_number < TT_MAX_FRIENDS) {
            t->e2ee_fallback[friend_number] = false;
            t->e2ee_warned[friend_number] = false;
        }
        if (tt_oq_count(&t->oq, friend_number) > 0 && !t->oq_flushing)
            offline_flush_friend(t, friend_number);
        /* E2EE layer: kick the in-band handshake when a friend comes
           online; simultaneous INITs from both sides are resolved by the
           lower-identity-pk tiebreak inside tt_session_feed */
        if (tt_e2ee_mode && t->e2ee && friend_number < TT_MAX_FRIENDS) {
            TTSession *es = &t->e2ee[friend_number];
            if (!es->active && !es->init_pending && !es->reply_due)
                e2ee_start(t, friend_number);
        }
    }
}

static void cb_friend_status_message(Tox *tox, uint32_t friend_number,
                                     const uint8_t *message, size_t length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    push_simple(t, TT_EV_FRIEND_STATUS_MSG, friend_number, (const char *)message, length, 0);
}

static void cb_friend_status(Tox *tox, uint32_t friend_number,
                             Tox_User_Status status, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    push_simple(t, TT_EV_FRIEND_STATUS, friend_number, NULL, 0, (int)status);
}

static void cb_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *message,
                              size_t length, void *user_data) {
    TTToxThread *t = user_data;
    (void)tox;
    /* public key is exactly TOX_PUBLIC_KEY_SIZE; render hex here so the event
       carries only bounded, NUL-terminated data */
    char hex[TOX_PUBLIC_KEY_SIZE * 2 + 1] = {0};
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        hex[i * 2]     = digits[public_key[i] >> 4];
        hex[i * 2 + 1] = digits[public_key[i] & 0xF];
    }
    push_simple(t, TT_EV_FRIEND_REQUEST, 0, hex, sizeof hex - 1, 0);
    if (message && length) {
        push_simple(t, TT_EV_FRIEND_REQUEST, 0, (const char *)message, length, 0);
    }
}

static void save_profile(TTToxThread *t) {
    if (!t->profile_path) return;
    size_t ssz = tox_get_savedata_size(t->tox);
    uint8_t *sd = malloc(ssz ? ssz : 1);
    if (!sd) return;
    tox_get_savedata(t->tox, sd);

    /* atomic write: temp file + rename (a crash mid-write must not corrupt
       the identity). With a pass key the blob is toxencryptsave-encrypted. */
    char tmp[strlen(t->profile_path) + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", t->profile_path);
    FILE *fp = fopen(tmp, "wb");
    if (fp) {
        fchmod(fileno(fp), 0600);
        if (t->pass_key) {
            size_t ct_len = ssz + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
            uint8_t *ct = malloc(ct_len);
            if (ct) {
                Tox_Err_Encryption eerr;
                if (tox_pass_key_encrypt(t->pass_key, sd, ssz, ct, &eerr)) {
                    fwrite(ct, 1, ct_len, fp);
                } else {
                    TT_LOG("tox", "profile encrypt failed: %d", (int)eerr);
                }
                free(ct);
            }
        } else {
            fwrite(sd, 1, ssz, fp);
        }
        fclose(fp);
        if (rename(tmp, t->profile_path) != 0) remove(tmp);
    }
    free(sd);
}

/* Extract a 76-hex-char ToxID from a pasted string: users copy IDs with
   surrounding whitespace/newlines or as part of a line ("ToxID: <id>").
   Returns the hex span via s/len, or NULL when no valid-length span exists. */
static const char *extract_toxid_hex(const char *s, size_t *out_len) {
    const size_t want = TOX_ADDRESS_SIZE * 2;
    for (const char *p = s; p[want - 1]; p++) {
        size_t j = 0;
        while (j < want && isxdigit((unsigned char)p[j])) j++;
        if (j == want) { *out_len = want; return p; }
        if (j > 0) p += j - 1;
    }
    return NULL;
}

static void handle_cmd_add(TTToxThread *t, const char *s) {
    if (!s) { TT_LOG("tox", "friend add: missing ToxID"); return; }
    size_t len = 0;
    const char *hex = extract_toxid_hex(s, &len);
    if (!hex) {
        TT_LOG("tox", "friend add: bad ToxID (len %zu, need %u)",
               strlen(s), (unsigned)(TOX_ADDRESS_SIZE * 2));
        return;
    }
    s = hex;
    uint8_t addr[TOX_ADDRESS_SIZE];
    for (size_t j = 0; j < TOX_ADDRESS_SIZE; j++) {
        unsigned char b; if (sscanf(s + j * 2, "%2hhx", &b) != 1) { TT_LOG("tox", "friend add: bad hex"); return; }
        addr[j] = (uint8_t)b;
    }
    /* optional custom request message: "<76-hex>\n<message>" */
    const char *msg = "adding you on TkTox";
    char msgbuf[TOX_MAX_FRIEND_REQUEST_LENGTH];
    const char *nl = strchr(s + len, '\n');
    if (nl) {
        size_t ml = strlen(nl + 1);
        if (ml > sizeof msgbuf - 1)
            ml = sizeof msgbuf - 1;
        memcpy(msgbuf, nl + 1, ml);
        msgbuf[ml] = '\0';
        msg = msgbuf;
    }
    Tox_Err_Friend_Add aerr;
    tox_friend_add(t->tox, addr, (const uint8_t *)msg, strlen(msg), &aerr);
    TT_LOG("tox", "friend add: %d", (int)aerr);
    save_profile(t);
}

static void handle_cmd_accept(TTToxThread *t, const char *s) {
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    if (!s || strlen(s) != TOX_PUBLIC_KEY_SIZE * 2) {
        TT_LOG("tox", "accept: bad key");
        return;
    }
    for (size_t j = 0; j < TOX_PUBLIC_KEY_SIZE; j++) {
        unsigned char b; if (sscanf(s + j * 2, "%2hhx", &b) != 1) { TT_LOG("tox", "accept: bad key"); return; }
        pk[j] = (uint8_t)b;
    }
    Tox_Err_Friend_Add aerr;
    tox_friend_add_norequest(t->tox, pk, &aerr);
    TT_LOG("tox", "friend accept: %d", (int)aerr);
    save_profile(t);
}

/* ---- group commands ---- */

static void handle_cmd_group_create(TTToxThread *t, const char *s) {
    if (!s) return;
    /* str: "<name>\n<public|private>" */
    const char *nl = strchr(s, '\n');
    if (!nl) { TT_LOG("tox", "group create: missing privacy"); return; }
    bool public_g = strcmp(nl + 1, "public") == 0;
    size_t name_len = (size_t)(nl - s);
    if (name_len == 0 || name_len > TOX_GROUP_MAX_GROUP_NAME_LENGTH) {
        TT_LOG("tox", "group create: bad name length %zu", name_len);
        return;
    }
    char gname[TOX_GROUP_MAX_GROUP_NAME_LENGTH + 1];
    memcpy(gname, s, name_len);
    gname[name_len] = '\0';
    size_t self_len = tox_self_get_name_size(t->tox);
    char self_name[TOX_MAX_NAME_LENGTH + 1] = {0};
    if (self_len > TOX_MAX_NAME_LENGTH) self_len = TOX_MAX_NAME_LENGTH;
    tox_self_get_name(t->tox, (uint8_t *)self_name);
    if (self_len == 0) { self_name[0] = '_'; self_len = 1; }
    Tox_Err_Group_New nerr;
    uint32_t gn = tox_group_new(t->tox,
                                public_g ? TOX_GROUP_PRIVACY_STATE_PUBLIC
                                         : TOX_GROUP_PRIVACY_STATE_PRIVATE,
                                (const uint8_t *)gname, name_len,
                                (const uint8_t *)self_name, self_len, &nerr);
    TT_LOG("tox", "group create \"%s\" (%s): gn=%u err=%d",
           gname, public_g ? "public" : "private", gn, (int)nerr);
    if (nerr == TOX_ERR_GROUP_NEW_OK)
        group_push(t, TT_EV_GROUP_NEW, gn, gname, name_len,
                   0, public_g ? 0 : 1);
}

static void handle_cmd_group_join(TTToxThread *t, const char *s, const char *pw) {
    if (!s || strlen(s) != TOX_GROUP_CHAT_ID_SIZE * 2) {
        TT_LOG("tox", "group join: bad chat id");
        return;
    }
    uint8_t cid[TOX_GROUP_CHAT_ID_SIZE];
    for (size_t j = 0; j < TOX_GROUP_CHAT_ID_SIZE; j++) {
        unsigned char b;
        if (sscanf(s + j * 2, "%2hhx", &b) != 1) { TT_LOG("tox", "group join: bad hex"); return; }
        cid[j] = (uint8_t)b;
    }
    size_t self_len = tox_self_get_name_size(t->tox);
    char self_name[TOX_MAX_NAME_LENGTH + 1] = {0};
    if (self_len > TOX_MAX_NAME_LENGTH) self_len = TOX_MAX_NAME_LENGTH;
    tox_self_get_name(t->tox, (uint8_t *)self_name);
    if (self_len == 0) { self_name[0] = '_'; self_len = 1; }
    const uint8_t *pass = (pw && pw[0]) ? (const uint8_t *)pw : NULL;
    size_t pass_len = pass ? strlen(pw) : 0;
    Tox_Err_Group_Join jerr;
    uint32_t gn = tox_group_join(t->tox, cid, pass, pass_len,
                                 (const uint8_t *)self_name, self_len, &jerr);
    TT_LOG("tox", "group join %s: gn=%u err=%d", s, gn, (int)jerr);
}

static void handle_cmd_group_send(TTToxThread *t, uint32_t gn, const char *msg, int mtype) {
    if (!msg || !msg[0]) return;
    size_t len = strlen(msg);
    if (len > TOX_GROUP_MAX_MESSAGE_LENGTH) len = TOX_GROUP_MAX_MESSAGE_LENGTH;
    Tox_Err_Group_Send_Message serr;
    tox_group_send_message(t->tox, gn, (Tox_Message_Type)mtype,
                           (const uint8_t *)msg, len, &serr);
    TT_LOG("tox", "group send(%u): %d", gn, (int)serr);
}

static void handle_cmd_group_priv_send(TTToxThread *t, uint32_t gn, uint32_t pid,
                                       const char *msg) {
    if (!msg || !msg[0]) return;
    size_t len = strlen(msg);
    if (len > TOX_GROUP_MAX_MESSAGE_LENGTH) len = TOX_GROUP_MAX_MESSAGE_LENGTH;
    Tox_Err_Group_Send_Private_Message serr;
    tox_group_send_private_message(t->tox, gn, pid, TOX_MESSAGE_TYPE_NORMAL,
                                   (const uint8_t *)msg, len, &serr);
    TT_LOG("tox", "group priv send(%u,%u): %d", gn, pid, (int)serr);
}

static void handle_cmd_group_topic(TTToxThread *t, uint32_t gn, const char *topic) {
    if (!topic) return;
    size_t len = strlen(topic);
    if (len > TOX_GROUP_MAX_TOPIC_LENGTH) len = TOX_GROUP_MAX_TOPIC_LENGTH;
    Tox_Err_Group_Topic_Set terr;
    tox_group_set_topic(t->tox, gn, (const uint8_t *)topic, len, &terr);
    TT_LOG("tox", "group topic(%u): %d", gn, (int)terr);
    if (terr == TOX_ERR_GROUP_TOPIC_SET_OK) {
        /* toxcore fires no topic callback for the ACTOR (broadcast-only,
           like moderation) — echo the fresh local state back so the UI
           header/dialog update. ival2 -1 = quiet SYNC variant. */
        size_t tsz = tox_group_get_topic_size(t->tox, gn, NULL);
        char cur[TOX_GROUP_MAX_TOPIC_LENGTH + 1] = {0};
        if (tsz > sizeof cur - 1) tsz = sizeof cur - 1;
        tox_group_get_topic(t->tox, gn, (uint8_t *)cur, NULL);
        group_push(t, TT_EV_GROUP_TOPIC, gn, cur, tsz, 0, -1);
    }
}

static void handle_cmd_group_invite_accept(TTToxThread *t, int idx) {
    if (idx < 0 || idx >= TT_MAX_GROUP_INVITES || !t->ginvites[idx].used) return;
    TTGroupInvite *gi = &t->ginvites[idx];
    size_t self_len = tox_self_get_name_size(t->tox);
    char self_name[TOX_MAX_NAME_LENGTH + 1] = {0};
    if (self_len > TOX_MAX_NAME_LENGTH) self_len = TOX_MAX_NAME_LENGTH;
    tox_self_get_name(t->tox, (uint8_t *)self_name);
    if (self_len == 0) { self_name[0] = '_'; self_len = 1; }
    Tox_Err_Group_Invite_Accept aerr;
    uint32_t gn = tox_group_invite_accept(t->tox, gi->fn, gi->data, gi->len,
                                          (const uint8_t *)self_name, self_len,
                                          NULL, 0, &aerr);
    TT_LOG("tox", "group invite accept(%d): gn=%u err=%d", idx, gn, (int)aerr);
    if (aerr == TOX_ERR_GROUP_INVITE_ACCEPT_OK) {
        group_push(t, TT_EV_GROUP_JOINED, gn, gi->name, strlen(gi->name), 0, 0);
    }
    gi->used = false;
}

static void handle_cmd_group_invite_decline(TTToxThread *t, int idx) {
    if (idx < 0 || idx >= TT_MAX_GROUP_INVITES || !t->ginvites[idx].used) return;
    TT_LOG("tox", "group invite(%d) declined", idx);
    t->ginvites[idx].used = false;
}

static void handle_cmd(TTToxThread *t, TTEvent *ev) {
    switch ((TTCommandType)ev->type) {
    case TT_CMD_ADD_FRIEND: handle_cmd_add(t, ev->str); break;
    case TT_CMD_ACCEPT_FRIEND: handle_cmd_accept(t, ev->str); break;
    case TT_CMD_DELETE_FRIEND: {
        Tox_Err_Friend_Delete derr;
        tox_friend_delete(t->tox, ev->friend_number, &derr);
        TT_LOG("tox", "friend delete(%u): %d", ev->friend_number, (int)derr);
        if (tt_oq_count(&t->oq, ev->friend_number) > 0) {
            static char out[TT_OQ_MAX_PER_FRIEND][TT_OQ_MAX_LINE];
            int n = 0;
            tt_oq_take_all(&t->oq, ev->friend_number, out, &n);
            tt_oq_save(&t->oq, t->profile_path, t->pass_key);
        }
        save_profile(t);
        break;
    }
    case TT_CMD_SEND_MESSAGE: {
        if (!ev->str) break;
        if (tt_e2ee_mode && t->e2ee && ev->friend_number < TT_MAX_FRIENDS) {
            TTE2EEEnv env;
            e2ee_env(t, ev->friend_number, &env);
            TTSession *s = &t->e2ee[ev->friend_number];
            if (env.peer_pk) {
                if (!s->active && e2ee_fallback_due(t, ev->friend_number)) {
                    /* the handshake never landed: this friend is a legacy
                       client. Enforced friends are blocked; others fall back
                       to plaintext with a warning. */
                    if (t->e2ee_required[ev->friend_number]) {
                        e2ee_warn(t, ev->friend_number,
                                  "E2EE is required for this contact, but they "
                                  "do not support it — message not sent.");
                        break;
                    }
                    t->e2ee_fallback[ev->friend_number] = true;
                    e2ee_warn(t, ev->friend_number,
                              "This contact does not support end-to-end "
                              "encryption — message sent in plaintext.");
                    /* fall through to the plain path below */
                } else {
                    /* texts > chunk emit consecutive frames, each a message line */
                    uint8_t out[TT_FRAME_MAX];
                    size_t len = ev->str_len;
                    size_t off = 0;
                    while (off < len) {
                        size_t chunk = len - off;
                        if (chunk > TT_E2EE_CHUNK) chunk = TT_E2EE_CHUNK;
                        int n = tt_session_send(s, &env, (const uint8_t *)ev->str + off,
                                                chunk, out, sizeof out);
                        if (n < 0) {
                            TT_LOG("e2ee", "send(%u): %d", ev->friend_number, n);
                            break;
                        }
                        if (n > 0) {
                            uint32_t mid = e2ee_send_frame(t, ev->friend_number,
                                                           out, (size_t)n);
                            if (mid) {
                                /* receipt key for the encrypted text (same
                                   contract as the plain path) */
                                push_simple(t, TT_EV_MESSAGE_SENT, ev->friend_number,
                                            NULL, 0, (int)mid);
                            } else {
                                break; /* friend dropped: requeue the tail below */
                            }
                        }
                        off += chunk; /* n == 0: stashed, flush follows handshake */
                    }
                    if (off < len) { /* send failed mid-way: keep the tail queued */
                        tt_oq_add(&t->oq, ev->friend_number, ev->str + off);
                        tt_oq_save(&t->oq, t->profile_path, t->pass_key);
                    }
                    break;
                }
            }
            /* no friend key, or legacy fallback: plain path (will fail there
               too if the friend is offline, but keeps the normal error
               behavior) */
        }
        Tox_Err_Friend_Send_Message serr;
        /* ival2: Tox_Message_Type (0 NORMAL, 1 ACTION for "/me ");
           offline-queue flushes always go out as NORMAL (no type stored) */
        uint32_t mid = tox_friend_send_message(t->tox, ev->friend_number,
                                               (Tox_Message_Type)ev->ival2,
                                               (const uint8_t *)ev->str, ev->str_len, &serr);
        TT_LOG("tox", "send(%u): %d", ev->friend_number, (int)serr);
        if (serr == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            /* receipts key on this id (TT_EV_FRIEND_READ_RECEIPT.ival) */
            push_simple(t, TT_EV_MESSAGE_SENT, ev->friend_number, NULL, 0, (int)mid);
            /* sending ends our typing state for this friend */
            tox_self_set_typing(t->tox, ev->friend_number, false, NULL);
        } else if (serr == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
            /* faux offline messaging: toxcore drops the text, so queue it
               app-side and flush when the friend (or self) reconnects */
            int n = tt_oq_add(&t->oq, ev->friend_number, ev->str);
            TT_LOG("tox", "friend %u offline: message queued (%d pending)",
                   ev->friend_number, n);
            tt_oq_save(&t->oq, t->profile_path, t->pass_key);
        }
        break;
    }
    case TT_CMD_SET_TYPING: {
        Tox_Err_Set_Typing terr;
        tox_self_set_typing(t->tox, ev->friend_number, ev->ival != 0, &terr);
        TT_LOG("tox", "set typing(%u): %d -> %d", ev->friend_number, (int)terr, ev->ival);
        break;
    }
    case TT_CMD_FILE_CANCEL: {
        TTXfer *x = xfer_by_id(t, (uint32_t)ev->ival);
        if (!x) break;
        Tox_Err_File_Control cerr;
        tox_file_control(t->tox, x->fn, x->file_number, TOX_FILE_CONTROL_CANCEL, &cerr);
        TT_LOG("tox", "file cancel(%u): %d", (uint32_t)ev->ival, (int)cerr);
        xfer_failed(t, x);
        break;
    }
    case TT_CMD_AV_CALL:
        tt_av_cmd_call(t, ev->friend_number, ev->ival, ev->ival2);
        break;
    case TT_CMD_AV_ANSWER:
        tt_av_cmd_answer(t, ev->friend_number, ev->ival, ev->ival2);
        break;
    case TT_CMD_AV_HANGUP:
        tt_av_cmd_hangup(t, ev->friend_number);
        break;
    case TT_CMD_AV_PAUSE:
        tt_av_cmd_pause(t, ev->friend_number);
        break;
    case TT_CMD_AV_RESUME:
        tt_av_cmd_resume(t, ev->friend_number);
        break;
    case TT_CMD_AV_MUTE:
        tt_av_cmd_mute(t, ev->friend_number, ev->ival != 0);
        break;
    case TT_CMD_AV_DEAF:
        tt_av_cmd_deaf(t, ev->friend_number, ev->ival != 0);
        break;
    case TT_CMD_AV_SELFVIEW:
        tt_av_cmd_selfview(t, ev->friend_number, ev->ival);
        break;
    case TT_CMD_AV_VTEST:
        tt_av_cmd_vtest(t, ev->friend_number, ev->ival);
        break;
    case TT_CMD_AV_SET_VIDEO_BR:
        tt_av_cmd_video_br(t, ev->friend_number, ev->ival);
        break;
    case TT_CMD_SET_NAME: {
        if (!ev->str) break;
        size_t nl = ev->str_len;
        if (nl > TOX_MAX_NAME_LENGTH) nl = TOX_MAX_NAME_LENGTH;
        Tox_Err_Set_Info serr;
        tox_self_set_name(t->tox, (const uint8_t *)ev->str, nl, &serr);
        TT_LOG("tox", "set name: %d", (int)serr);
        if (serr == TOX_ERR_SET_INFO_OK)
            push_simple(t, TT_EV_SELF_NAME, 0, ev->str, nl, 0);
        save_profile(t);
        break;
    }
    case TT_CMD_SET_STATUS_MSG: {
        if (!ev->str) break;
        size_t nl = ev->str_len;
        if (nl > TOX_MAX_STATUS_MESSAGE_LENGTH) nl = TOX_MAX_STATUS_MESSAGE_LENGTH;
        Tox_Err_Set_Info serr;
        tox_self_set_status_message(t->tox, (const uint8_t *)ev->str, nl, &serr);
        TT_LOG("tox", "set status msg: %d", (int)serr);
        if (serr == TOX_ERR_SET_INFO_OK)
            push_simple(t, TT_EV_SELF_STATUS_MSG, 0, ev->str, nl, 0);
        save_profile(t);
        break;
    }
    case TT_CMD_CYCLE_STATUS: {
        /* online -> away -> busy -> online */
        Tox_User_Status next = (Tox_User_Status)(((int)ev->ival + 1) % 3);
        tox_self_set_status(t->tox, next);
        push_simple(t, TT_EV_SELF_STATUS, 0, NULL, 0, (int)next);
        save_profile(t);
        break;
    }
    case TT_CMD_SET_STATUS: {
        /* explicit presence pick from the badge menu */
        if (ev->ival < TOX_USER_STATUS_NONE || ev->ival > TOX_USER_STATUS_BUSY) break;
        tox_self_set_status(t->tox, (Tox_User_Status)ev->ival);
        push_simple(t, TT_EV_SELF_STATUS, 0, NULL, 0, ev->ival);
        save_profile(t);
        break;
    }
    case TT_CMD_SET_NOSPAM: {
        /* Randomize the 4-byte nospam (anti-spam) field of the own ToxID.
           The public key is unchanged; only the nospam + checksum move.
           Re-publish so the UI shows the new ID. */
        uint32_t nospam;
        randombytes_buf(&nospam, sizeof nospam);
        tox_self_set_nospam(t->tox, nospam);
        publish_toxid(t);
        save_profile(t);
        TT_LOG("tox", "nospam randomized");
        break;
    }
    case TT_CMD_SET_AVATAR: {
        if (!ev->str) break;
        FILE *fp = fopen(ev->str, "rb");
        if (!fp) { TT_LOG("tox", "avatar open failed: %s", ev->str); break; }
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (sz <= 0 || sz > TT_AVATAR_MAX_SIZE) {
            TT_LOG("tox", "avatar too large: %ld bytes", sz);
            fclose(fp);
            break;
        }
        unsigned char *buf = malloc((size_t)sz);
        if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
            free(buf);
            fclose(fp);
            break;
        }
        fclose(fp);
        if (sz < 8 || memcmp(buf, "\x89PNG\r\n\x1a\n", 8) != 0) {
            TT_LOG("tox", "avatar: not a PNG: %s", ev->str);
            free(buf);
            break;
        }
        if (tt_avatar_set(&t->self_avatar, buf, (size_t)sz)) {
            avatar_clear_all_sent(t);
            avatar_push_all(t);
            avatar_persist(t, &t->self_avatar);
            TTEvent *out = tt_event_new(TT_EV_AVATAR_SELF);
            if (out) {
                out->str = malloc((size_t)sz + 1);
                if (out->str) {
                    memcpy(out->str, buf, (size_t)sz);
                    out->str[(size_t)sz] = '\0';
                    out->str_len = (size_t)sz;
                }
                tt_queue_push(&t->out, out);
            }
            TT_LOG("tox", "avatar set: %ld bytes", sz);
        }
        free(buf);
        break;
    }
    case TT_CMD_CLEAR_AVATAR: {
        tt_avatar_free(&t->self_avatar);
        avatar_clear_all_sent(t);
        avatar_persist(t, &t->self_avatar);
        uint32_t count = tox_self_get_friend_list_size(t->tox);
        uint32_t *nums = calloc(count ? count : 1, sizeof *nums);
        if (nums) {
            tox_self_get_friend_list(t->tox, nums);
            for (uint32_t i = 0; i < count; i++) {
                /* spec: 0-length avatar offer tells friends it was removed */
                Tox_Err_File_Send err;
                tox_file_send(t->tox, nums[i], TOX_FILE_KIND_AVATAR, 0, NULL,
                              NULL, 0, &err);
                TT_LOG("tox", "avatar clear offer(%u): %d", nums[i], (int)err);
            }
            free(nums);
        }
        TTEvent *out = tt_event_new(TT_EV_AVATAR_SELF); /* empty str = cleared */
        if (out) tt_queue_push(&t->out, out);
        break;
    }
    case TT_CMD_SEND_FILE:
        handle_cmd_send_file(t, ev->friend_number, ev->str);
        break;
    case TT_CMD_FILE_ACCEPT:
        handle_cmd_file_accept(t, (uint32_t)ev->ival, ev->str);
        break;
    case TT_CMD_FILE_REJECT:
        handle_cmd_file_reject(t, (uint32_t)ev->ival);
        break;
    case TT_CMD_GROUP_CREATE:
        handle_cmd_group_create(t, ev->str);
        break;
    case TT_CMD_GROUP_JOIN: {
        /* str: "<64-hex chat id>\n<password>" (password part optional) */
        if (!ev->str) break;
        const char *nl = strchr(ev->str, '\n');
        size_t id_len = nl ? (size_t)(nl - ev->str) : strlen(ev->str);
        if (id_len != TOX_GROUP_CHAT_ID_SIZE * 2) {
            TT_LOG("tox", "group join: bad chat id length %zu", id_len);
            break;
        }
        char cid_hex[TOX_GROUP_CHAT_ID_SIZE * 2 + 1];
        memcpy(cid_hex, ev->str, id_len);
        cid_hex[id_len] = '\0';
        handle_cmd_group_join(t, cid_hex, nl ? nl + 1 : NULL);
        break;
    }
    case TT_CMD_GROUP_LEAVE: {
        Tox_Err_Group_Leave lerr;
        tox_group_leave(t->tox, ev->friend_number, NULL, 0, &lerr);
        TT_LOG("tox", "group leave(%u): %d", ev->friend_number, (int)lerr);
        if (lerr == TOX_ERR_GROUP_LEAVE_OK)
            group_push(t, TT_EV_GROUP_LEFT, ev->friend_number, NULL, 0, 0, 0);
        break;
    }
    case TT_CMD_GROUP_SEND:
        handle_cmd_group_send(t, ev->friend_number, ev->str, ev->ival2);
        break;
    case TT_CMD_GROUP_PRIV_SEND:
        handle_cmd_group_priv_send(t, ev->friend_number, (uint32_t)ev->ival, ev->str);
        break;
    case TT_CMD_GROUP_TOPIC:
        handle_cmd_group_topic(t, ev->friend_number, ev->str);
        break;
    case TT_CMD_GROUP_INVITE: {
        Tox_Err_Group_Invite_Friend ierr;
        tox_group_invite_friend(t->tox, ev->friend_number, ev->ival, &ierr);
        TT_LOG("tox", "group invite(%u -> friend %u): %d",
               ev->friend_number, ev->ival, (int)ierr);
        break;
    }
    case TT_CMD_GROUP_INVITE_ACC:
        handle_cmd_group_invite_accept(t, ev->ival2);
        break;
    case TT_CMD_GROUP_INVITE_DEC:
        handle_cmd_group_invite_decline(t, ev->ival2);
        break;
    case TT_CMD_GROUP_PASSWORD: {
        size_t pl = ev->str ? strlen(ev->str) : 0;
        if (pl > TOX_GROUP_MAX_PASSWORD_SIZE) pl = TOX_GROUP_MAX_PASSWORD_SIZE;
        Tox_Err_Group_Set_Password perr;
        tox_group_set_password(t->tox, ev->friend_number,
                               pl ? (const uint8_t *)ev->str : NULL, pl, &perr);
        TT_LOG("tox", "group password(%u): %d", ev->friend_number, (int)perr);
        break;
    }
    case TT_CMD_GROUP_PRIVACY: {
        Tox_Err_Group_Set_Privacy_State perr;
        tox_group_set_privacy_state(t->tox, ev->friend_number,
                                    ev->ival2 == 0 ? TOX_GROUP_PRIVACY_STATE_PUBLIC
                                                   : TOX_GROUP_PRIVACY_STATE_PRIVATE,
                                    &perr);
        TT_LOG("tox", "group privacy(%u): %d", ev->friend_number, (int)perr);
        break;
    }
    case TT_CMD_GROUP_VOICE: {
        if (ev->ival2 < TOX_GROUP_VOICE_STATE_ALL || ev->ival2 > TOX_GROUP_VOICE_STATE_FOUNDER) break;
        Tox_Err_Group_Set_Voice_State verr;
        tox_group_set_voice_state(t->tox, ev->friend_number,
                                  (Tox_Group_Voice_State)ev->ival2, &verr);
        TT_LOG("tox", "group voice(%u): %d", ev->friend_number, (int)verr);
        break;
    }
    case TT_CMD_GROUP_TOPIC_LOCK: {
        Tox_Err_Group_Set_Topic_Lock terr;
        tox_group_set_topic_lock(t->tox, ev->friend_number,
                                 ev->ival2 ? TOX_GROUP_TOPIC_LOCK_ENABLED
                                           : TOX_GROUP_TOPIC_LOCK_DISABLED,
                                 &terr);
        TT_LOG("tox", "group topic lock(%u): %d", ev->friend_number, (int)terr);
        break;
    }
    case TT_CMD_GROUP_PEER_LIMIT: {
        Tox_Err_Group_Set_Peer_Limit lerr;
        tox_group_set_peer_limit(t->tox, ev->friend_number,
                                 ev->ival2 > 0 ? (uint16_t)ev->ival2 : 0, &lerr);
        TT_LOG("tox", "group peer limit(%u): %d", ev->friend_number, (int)lerr);
        break;
    }
    case TT_CMD_GROUP_ROLE: {
        if (ev->ival2 < TOX_GROUP_ROLE_FOUNDER || ev->ival2 > TOX_GROUP_ROLE_OBSERVER) break;
        Tox_Err_Group_Set_Role rerr;
        tox_group_set_role(t->tox, ev->friend_number, (uint32_t)ev->ival,
                           (Tox_Group_Role)ev->ival2, &rerr);
        TT_LOG("tox", "group role(%u, peer %u -> %d): %d",
               ev->friend_number, ev->ival, ev->ival2, (int)rerr);
        /* toxcore fires no moderation callback for the actor: confirm locally */
        size_t ns = tox_group_peer_get_name_size(t->tox, ev->friend_number,
                                                 (uint32_t)ev->ival, NULL);
        char nm[TOX_MAX_NAME_LENGTH + 1] = {0};
        if (ns > TOX_MAX_NAME_LENGTH) ns = TOX_MAX_NAME_LENGTH;
        if (ns) tox_group_peer_get_name(t->tox, ev->friend_number, (uint32_t)ev->ival,
                                        (uint8_t *)nm, NULL);
        static const int selfev[4] = {
            TOX_GROUP_MOD_EVENT_KICK + TT_MOD_EV_FAIL_BASE, /* FOUNDER n/a */
            TOX_GROUP_MOD_EVENT_MODERATOR,
            TOX_GROUP_MOD_EVENT_USER,
            TOX_GROUP_MOD_EVENT_OBSERVER,
        };
        int slot = (ev->ival2 >= TOX_GROUP_ROLE_FOUNDER && ev->ival2 <= TOX_GROUP_ROLE_OBSERVER)
                       ? selfev[ev->ival2] : -1;
        if (slot >= 0)
            group_push(t, TT_EV_GROUP_MOD_SELF, ev->friend_number,
                       rerr == TOX_ERR_GROUP_SET_ROLE_OK ? nm : NULL,
                       rerr == TOX_ERR_GROUP_SET_ROLE_OK ? ns : 0,
                       (int)ev->ival,
                       rerr == TOX_ERR_GROUP_SET_ROLE_OK ? slot : TT_MOD_EV_FAIL_BASE + slot);
        break;
    }
    case TT_CMD_GROUP_KICK: {
        /* fetch the name BEFORE the kick: gc_kick_peer marks the peer for
           deletion on success, so the query would already be invalid */
        size_t ns = tox_group_peer_get_name_size(t->tox, ev->friend_number,
                                                 (uint32_t)ev->ival, NULL);
        char nm[TOX_MAX_NAME_LENGTH + 1] = {0};
        if (ns > TOX_MAX_NAME_LENGTH) ns = TOX_MAX_NAME_LENGTH;
        if (ns) tox_group_peer_get_name(t->tox, ev->friend_number, (uint32_t)ev->ival,
                                        (uint8_t *)nm, NULL);
        Tox_Err_Group_Kick_Peer kerr;
        tox_group_kick_peer(t->tox, ev->friend_number, (uint32_t)ev->ival, &kerr);
        TT_LOG("tox", "group kick(%u, peer %u): %d", ev->friend_number, ev->ival, (int)kerr);
        if (kerr == TOX_ERR_GROUP_KICK_PEER_OK)
            group_push(t, TT_EV_GROUP_MOD_SELF, ev->friend_number, nm, ns,
                       ev->ival, TOX_GROUP_MOD_EVENT_KICK);
        else
            /* failure feedback so the UI can say why nothing happened */
            group_push(t, TT_EV_GROUP_MOD_SELF, ev->friend_number, NULL, 0,
                       ev->ival, TT_MOD_EV_FAIL_BASE + TOX_GROUP_MOD_EVENT_KICK);
        break;
    }
    case TT_CMD_GROUP_IGNORE: {
        Tox_Err_Group_Set_Ignore ierr;
        bool ok = tox_group_set_ignore(t->tox, ev->friend_number,
                                       (uint32_t)ev->ival, ev->ival2 != 0, &ierr);
        TT_LOG("tox", "group ignore(%u, peer %u -> %d): %d",
               ev->friend_number, ev->ival, ev->ival2 != 0, (int)ierr);
        /* gc_set_ignore is local-only (no toxcore callback): confirm locally */
        size_t ns = tox_group_peer_get_name_size(t->tox, ev->friend_number,
                                                 (uint32_t)ev->ival, NULL);
        char nm[TOX_MAX_NAME_LENGTH + 1] = {0};
        if (ns > TOX_MAX_NAME_LENGTH) ns = TOX_MAX_NAME_LENGTH;
        if (ns) tox_group_peer_get_name(t->tox, ev->friend_number, (uint32_t)ev->ival,
                                        (uint8_t *)nm, NULL);
        if (ok)
            group_push(t, TT_EV_GROUP_IGNORE_SELF, ev->friend_number, nm, ns,
                       ev->ival, ev->ival2 != 0);
        else
            group_push(t, TT_EV_GROUP_IGNORE_SELF, ev->friend_number, NULL, 0,
                       ev->ival, TT_MOD_EV_FAIL_BASE + 1);
        break;
    }
    case TT_CMD_GROUP_SYNC: {
        /* Roster burst for the UI: peer names/roles (peer numbers are dense),
           chat id, self role, then the current topic. */
        uint32_t gn = ev->friend_number;
        Tox_Err_Group_Peer_Query qerr;
        for (uint32_t pid = 0;
             tox_group_peer_get_name_size(t->tox, gn, pid, &qerr) != 0 &&
             qerr == TOX_ERR_GROUP_PEER_QUERY_OK; pid++) {
            size_t ns = tox_group_peer_get_name_size(t->tox, gn, pid, NULL);
            char nm[TOX_MAX_NAME_LENGTH + 1] = {0};
            if (ns > TOX_MAX_NAME_LENGTH) ns = TOX_MAX_NAME_LENGTH;
            tox_group_peer_get_name(t->tox, gn, pid, (uint8_t *)nm, NULL);
            group_push(t, TT_EV_GROUP_PEER_NAME, gn, nm, ns, (int)pid, 0);
            Tox_Group_Role pr = tox_group_peer_get_role(t->tox, gn, pid, NULL);
            group_push(t, TT_EV_GROUP_PEER_ROLE, gn, NULL, 0, (int)pid, (int)pr);
        }
        uint8_t cid[TOX_GROUP_CHAT_ID_SIZE];
        if (tox_group_get_chat_id(t->tox, gn, cid, NULL)) {
            char hex[TOX_GROUP_CHAT_ID_SIZE * 2 + 1];
            for (size_t i = 0; i < TOX_GROUP_CHAT_ID_SIZE; i++)
                snprintf(hex + i * 2, 3, "%02x", cid[i]);
            group_push(t, TT_EV_GROUP_STATE, gn, hex, TOX_GROUP_CHAT_ID_SIZE * 2, -5, 0);
        }
        Tox_Group_Role sr = tox_group_self_get_role(t->tox, gn, NULL);
        group_push(t, TT_EV_GROUP_STATE, gn, NULL, 0, -6, (int)sr);
        /* self peer id (so the UI can hide self-actions like Ignore) */
        Tox_Err_Group_Self_Query serr;
        uint32_t self_pid = tox_group_self_get_peer_id(t->tox, gn, &serr);
        if (serr == TOX_ERR_GROUP_SELF_QUERY_OK)
            group_push(t, TT_EV_GROUP_STATE, gn, NULL, 0, -11, (int)self_pid);
        /* current moderation state so the owner-settings dialog opens with
           live values; -7/-8/-9 are the quiet (no transcript line) SYNC
           variants of the -1/-2/-3 change events */
        group_push(t, TT_EV_GROUP_STATE, gn, NULL, 0, -7,
                   (int)tox_group_get_voice_state(t->tox, gn, NULL));
        group_push(t, TT_EV_GROUP_STATE, gn, NULL, 0, -8,
                   (int)tox_group_get_topic_lock(t->tox, gn, NULL));
        char plim[8];
        snprintf(plim, sizeof plim, "%u",
                 tox_group_get_peer_limit(t->tox, gn, NULL));
        group_push(t, TT_EV_GROUP_STATE, gn, plim, strlen(plim), -9, 0);
        group_push(t, TT_EV_GROUP_STATE, gn, NULL, 0, -10,
                   (int)tox_group_get_privacy_state(t->tox, gn, NULL));
        size_t tsz = tox_group_get_topic_size(t->tox, gn, NULL);
        char topic[TOX_GROUP_MAX_TOPIC_LENGTH + 1] = {0};
        if (tsz > sizeof topic - 1) tsz = sizeof topic - 1;
        tox_group_get_topic(t->tox, gn, (uint8_t *)topic, NULL);
        group_push(t, TT_EV_GROUP_TOPIC, gn, topic, tsz, 0, -1);
        break;
    }
    case TT_CMD_E2EE_REORDER: {
        /* M4 harness: build DATA frames seq 2,3,4 via frame_at (no send-state
           commit) and deliver 3,2,4 out of order. The peer's skipped-key
           store recovers 2 and 3; seq 4 lands in order. (seq 1 was the
           ping, already consumed — the reorder frames must start at 2.) */
        if (!tt_e2ee_mode || !t->e2ee || ev->friend_number >= TT_MAX_FRIENDS)
            break;
        TTE2EEEnv env;
        e2ee_env(t, ev->friend_number, &env);
        TTSession *s = &t->e2ee[ev->friend_number];
        if (!env.peer_pk || !s->active) break;
        static const uint32_t order[3] = {3, 2, 4};
        uint8_t frame[TT_FRAME_MAX];
        for (int i = 0; i < 3; i++) {
            int n = tt_session_frame_at(s, &env, order[i], frame, sizeof frame);
            if (n <= 0) {
                TT_LOG("e2ee", "reorder: frame_at(%u) failed: %d", order[i], n);
                break;
            }
            e2ee_send_frame(t, ev->friend_number, frame, (size_t)n);
            TT_LOG("e2ee", "reorder: delivered seq %u", order[i]);
        }
        break;
    }
    case TT_CMD_E2EE_REPLAY: {
        /* M4 harness: re-inject the last incoming DATA frame into the local
           session — the seq is already consumed, so it must reject as
           TT_E2EE_REPLAY (never crash, never consume chain state). */
        if (!tt_e2ee_mode || !t->e2ee || ev->friend_number >= TT_MAX_FRIENDS)
            break;
        TTE2EEEnv env;
        e2ee_env(t, ev->friend_number, &env);
        TTSession *s = &t->e2ee[ev->friend_number];
        if (!env.peer_pk || !s->active) break;
        uint8_t frame[TT_FRAME_MAX];
        int n = tt_session_inject_older(s, &env, frame, sizeof frame);
        if (n <= 0) {
            TT_LOG("e2ee", "replay: no prior frame to re-inject (%d)", n);
            break;
        }
        static _Thread_local uint8_t pt[TT_FRAME_DATA_MAX];
        bool hs = false;
        int r = tt_session_feed(s, &env, frame, (size_t)n, pt, sizeof pt, &hs);
        TT_LOG("e2ee", "replay: re-inject -> %d (expect %d)", r, TT_E2EE_REPLAY);
        break;
    }
    case TT_CMD_E2EE_ENFORCE: {
        /* per-friend E2EE enforcement toggle: persist in the settings sidecar
           and apply immediately. Enforcing blocks the plaintext fallback for
           this friend (both send and receive). */
        if (ev->friend_number >= TT_MAX_FRIENDS) break;
        t->e2ee_required[ev->friend_number] = (ev->ival != 0);
        if (!tt_settings_store_e2ee(t->e2ee_required, t->profile_path))
            TT_LOG("tox", "e2ee enforce(%u): failed to persist sidecar",
                   ev->friend_number);
        TT_LOG("tox", "e2ee enforce(%u): %s", ev->friend_number,
               t->e2ee_required[ev->friend_number] ? "required" : "allowed");
        break;
    }
    default:
        TT_LOG("tox", "unknown command %d", (int)ev->type);
        break;
    }
}

/* Publish a friend's identity to the UI: the 64-hex public key (stable
   identity, independent of nospam) and the last-online timestamp. Called
   once per friend at startup and again when a friend comes online (their
   last-online is refreshed by toxcore on reconnect). */
static void emit_friend_identity(TTToxThread *t, uint32_t fn) {
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    if (tox_friend_get_public_key(t->tox, fn, pk, NULL)) {
        char hex[TOX_PUBLIC_KEY_SIZE * 2 + 1] = {0};
        for (size_t i = 0; i < TOX_PUBLIC_KEY_SIZE; i++)
            sprintf(hex + i * 2, "%02x", pk[i]); /* fixed-width, safe */
        push_simple(t, TT_EV_FRIEND_PUBKEY, fn, hex, TOX_PUBLIC_KEY_SIZE * 2, 0);
    }
    Tox_Err_Friend_Get_Last_Online lerr;
    uint64_t last = tox_friend_get_last_online(t->tox, fn, &lerr);
    if (lerr == TOX_ERR_FRIEND_GET_LAST_ONLINE_OK && last != UINT64_MAX)
        push_simple(t, TT_EV_FRIEND_LAST_ONLINE, fn, NULL, 0, (int)last);
}

/* Emit the initial friend list to the UI: name+connection for each loaded
   friend, then TT_EV_FRIEND_LIST_END so the UI can bind its list. */
static void emit_initial_friend_list(TTToxThread *t) {
    uint32_t count = tox_self_get_friend_list_size(t->tox);
    if (count == 0) {
        TTEvent *ev = tt_event_new(TT_EV_FRIEND_LIST_END);
        if (ev) tt_queue_push(&t->out, ev);
        return;
    }
    uint32_t *nums = calloc(count, sizeof *nums);
    if (!nums) return;
    tox_self_get_friend_list(t->tox, nums);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t fn = nums[i];
        size_t nsz = tox_friend_get_name_size(t->tox, fn, NULL);
        char name[TOX_MAX_NAME_LENGTH + 1] = {0};
        if (nsz > TOX_MAX_NAME_LENGTH) nsz = TOX_MAX_NAME_LENGTH;
        tox_friend_get_name(t->tox, fn, (uint8_t *)name, NULL);
        push_simple(t, TT_EV_FRIEND_NAME, fn, name, nsz, 0);
        int conn = (int)tox_friend_get_connection_status(t->tox, fn, NULL);
        push_simple(t, TT_EV_FRIEND_CONNECTION, fn, NULL, 0, conn);
        size_t ssz2 = tox_friend_get_status_message_size(t->tox, fn, NULL);
        char smsg[TOX_MAX_STATUS_MESSAGE_LENGTH + 1] = {0};
        if (ssz2 > TOX_MAX_STATUS_MESSAGE_LENGTH) ssz2 = TOX_MAX_STATUS_MESSAGE_LENGTH;
        tox_friend_get_status_message(t->tox, fn, (uint8_t *)smsg, NULL);
        push_simple(t, TT_EV_FRIEND_STATUS_MSG, fn, smsg, ssz2, 0);
        push_simple(t, TT_EV_FRIEND_STATUS, fn, NULL, 0,
                    (int)tox_friend_get_status(t->tox, fn, NULL));
        emit_friend_identity(t, fn);
    }
    free(nums);
    TTEvent *ev = tt_event_new(TT_EV_FRIEND_LIST_END);
    if (ev) tt_queue_push(&t->out, ev);
}

/* Restore burst for persisted groups (toxcore savedata STATE_TYPE_GROUPS):
   loaded groups reconnect by themselves (gc_group_load sets CS_CONNECTING)
   and the self-join callback later fires on first sync response, posting
   GROUP_JOINED again (group_add is idempotent) which triggers the UI's SYNC
   request. This burst makes groups visible in the roster immediately, even
   before reconnect completes (e.g. all peers offline). Events are
   GROUP_JOINED-shaped (not GROUP_NEW: that handler asserts founder) with
   privacy in ival2; SYNC later corrects role/topic/privacy. */
static void emit_initial_group_list(TTToxThread *t) {
    /* Dead-restore sweep: a group whose object died as CS_DISCONNECTED in a
       previous session (e.g. kicked by an old binary — the kick handler never
       fires at restore) is loaded CONNECTING-free and swallowed one re-invite
       (invite callback only fires for groups we "don't have"). Leave them
       right here, let do_gc's flag_exit pass delete them, then enumerate.
       group numbers are array indices that compact on delete, so they are
       only published to the UI after the sweep settles. */
    uint32_t n0 = tox_group_get_group_list_size(t->tox);
    if (n0 > 0) {
        uint32_t *pre = calloc(n0, sizeof *pre);
        if (pre) {
            tox_group_get_group_list(t->tox, pre);
            for (uint32_t i = 0; i < n0; i++) {
                Tox_Err_Group_Is_Connected cerr;
                if (!tox_group_is_connected(t->tox, pre[i], &cerr)
                        && cerr == TOX_ERR_GROUP_IS_CONNECTED_OK) {
                    TT_LOG("tox", "restored group %u is dead (disconnected) — leaving it", pre[i]);
                    tox_group_leave(t->tox, pre[i], NULL, 0, NULL);
                }
            }
            free(pre);
            tox_iterate(t->tox, t); /* warmup: do_gc deletes flag_exit groups and compacts indices */
        }
    }
    uint32_t count = tox_group_get_group_list_size(t->tox);
    if (count == 0) return;
    uint32_t *nums = calloc(count, sizeof *nums);
    if (!nums) return;
    tox_group_get_group_list(t->tox, nums);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t gn = nums[i];
        Tox_Err_Group_State_Query qerr;
        size_t nsz = tox_group_get_name_size(t->tox, gn, &qerr);
        if (qerr != TOX_ERR_GROUP_STATE_QUERY_OK) continue;
        char gname[TOX_GROUP_MAX_GROUP_NAME_LENGTH + 1] = {0};
        if (nsz > TOX_GROUP_MAX_GROUP_NAME_LENGTH) nsz = TOX_GROUP_MAX_GROUP_NAME_LENGTH;
        tox_group_get_name(t->tox, gn, (uint8_t *)gname, NULL);
        group_push(t, TT_EV_GROUP_JOINED, gn, gname, nsz,
                   0, (int)tox_group_get_privacy_state(t->tox, gn, NULL));
        TT_LOG("tox", "restored group %u: \"%s\"", gn, gname);
        /* persisted topic: pushed NOW (quiet -1 variant) so the header shows
           it before the first post-reconnect SYNC round-trip lands */
        size_t tsz = tox_group_get_topic_size(t->tox, gn, NULL);
        char gtopic[TOX_GROUP_MAX_TOPIC_LENGTH + 1] = {0};
        if (tsz > sizeof gtopic - 1) tsz = sizeof gtopic - 1;
        tox_group_get_topic(t->tox, gn, (uint8_t *)gtopic, NULL);
        if (tsz > 0)
            group_push(t, TT_EV_GROUP_TOPIC, gn, gtopic, tsz, 0, -1);
    }
    free(nums);
}

/* Strip the savedata STATE_TYPE_DHT section (type 2). toxcore re-saves every
   section it loaded, and the DHT section carries past direct-IP history — a
   Tor-only profile must never accumulate it. In-memory, before tox_new:
   [8B global cookie][len u32 LE][cookie u32 LE = 0x01ce<<16|type][payload]...,
   last section is a zero-length END (255) which is always kept. Returns a
   malloc'd copy the caller frees after tox_new, or NULL if nothing changed
   (then *out_len is untouched and the original buffer is used as-is). */
static uint8_t *savedata_strip_dht(const uint8_t *buf, size_t len, size_t *out_len) {
    if (len < 16) return NULL;
    const uint32_t cookie_len = 8;
    const size_t body_off = cookie_len;
    if (buf[0] != 0) return NULL; /* cookie low word must be 0 */
    uint32_t ck;
    memcpy(&ck, buf + 4, sizeof ck); /* LE blob, host is LE on all our targets */
    if (ck != 0x15ed1b1fu) return NULL;

    uint8_t *out = malloc(len);
    if (!out) return NULL;
    memcpy(out, buf, cookie_len);
    size_t w = cookie_len, r = body_off;
    bool stripped = false;

    while (r + 8 <= len) {
        uint32_t slen, scook;
        memcpy(&slen, buf + r, sizeof slen);
        memcpy(&scook, buf + r + 4, sizeof scook);
        if ((uint64_t)slen > len - (r + 8)) break; /* truncated */
        const uint16_t type = (uint16_t)(scook & 0xffffu);
        const uint32_t total = 8 + slen;
        if (type == 2 /* STATE_TYPE_DHT */) {
            r += total;
            stripped = true;
            continue;
        }
        memcpy(out + w, buf + r, total);
        w += total;
        r += total;
        if (type == 255 /* STATE_TYPE_END */) break;
    }

    if (r != len || !stripped) { free(out); return NULL; }
    *out_len = w;
    return out;
}

/* Acquire the at-rest passphrase (mandatory encryption). Returns a malloc'd
   NUL-terminated string the caller wipes+frees, or NULL on failure.
   Priority: TT_PASSPHRASE env (headless/automation), else in GUI mode a
   Tk dialog (the tox thread posts TT_EV_PASSPHRASE_NEEDED and blocks until
   the UI thread replies), else an interactive getpass prompt. A non-tty,
   non-GUI run without TT_PASSPHRASE is fatal — we refuse to start rather
   than silently write a plaintext identity. */
static char *tt_passphrase_acquire(TTToxThread *t) {
    const char *env = getenv("TT_PASSPHRASE");
    if (env && env[0]) return strdup(env);
    if (t->gui_mode) {
        /* Ask the UI thread for the passphrase. The UI owns the dialog; we
           just post the request and wait. */
        TTEvent *ev = tt_event_new(TT_EV_PASSPHRASE_NEEDED);
        if (ev) tt_queue_push(&t->out, ev);
        pthread_mutex_lock(&t->pass_lock);
        t->pass_waiting = true;
        while (!t->pass_buf && !t->pass_cancel)
            pthread_cond_wait(&t->pass_cond, &t->pass_lock);
        t->pass_waiting = false;
        char *pass = t->pass_buf; /* ownership transfers to the caller */
        t->pass_buf = NULL;
        bool cancelled = t->pass_cancel;
        pthread_mutex_unlock(&t->pass_lock);
        if (cancelled) {
            TT_LOG("tox", "passphrase dialog cancelled — refusing to start");
            return NULL;
        }
        return pass;
    }
    if (isatty(STDIN_FILENO)) {
        char *p = getpass("TkTox profile passphrase: ");
        if (p) return strdup(p);
        return NULL;
    }
    TT_LOG("tox", "no TT_PASSPHRASE and stdin is not a tty — refusing to start "
           "(mandatory at-rest encryption)");
    return NULL;
}

static void *tox_thread_main(void *arg) {
    TTToxThread *t = arg;

    struct Tox_Options *opts = tox_options_new(NULL);
    if (!opts) return NULL;

    /* Group persistence: toxcore serializes DHT group chats into the
       savedata STATE_TYPE_GROUPS section (name, privacy, password, topic,
       roles, mod list, self role) and reconnects automatically on load
       (gc_group_load -> CS_CONNECTING; self-join callback fires on first
       sync response). Off by default — must opt in here or groups are
       silently dropped from the save. */
    tox_options_set_experimental_groups_persistence(opts, true);

    /* Tor/socks5 mode: a SOCKS5 endpoint (tor's SocksPort) routes ALL
       traffic. Configured via the "<profile>.tt" sidecar or TT_PROXY_HOST /
       TT_PROXY_PORT (env wins when both are set). toxcore then forces UDP
       off (no UDP-over-proxy support) and never opens a direct socket; we
       additionally refuse hostname proxy/relay addresses so nothing
       resolves via the plaintext system resolver. */
    {
        TTSettings set;
        tt_settings_load(&set, t->profile_path);
        char host[64];
        long port;
        const char *env_host = getenv("TT_PROXY_HOST");
        if (env_host && env_host[0]) {
            if (set.proxy_set)
                TT_LOG("tox", "TT_PROXY_HOST set — overriding sidecar proxy %s:%ld",
                       set.proxy_host, set.proxy_port);
            snprintf(host, sizeof host, "%s", env_host);
            const char *pp = getenv("TT_PROXY_PORT");
            port = pp && pp[0] ? atol(pp) : 9050;
            if (port <= 0 || port > 65535) {
                TT_LOG("tox", "TT_PROXY_PORT '%s' invalid — defaulting to 9050", pp ? pp : "");
                port = 9050;
            }
        } else if (set.proxy_set) {
            snprintf(host, sizeof host, "%s", set.proxy_host);
            port = set.proxy_port;
            if (port <= 0 || port > 65535) {
                TT_LOG("tox", "sidecar proxy port %ld invalid — defaulting to 9050", port);
                port = 9050;
            }
        } else {
            host[0] = '\0';
        }
        if (host[0]) {
            bool ip_literal = true;
            for (const char *p = host; *p; p++)
                if (!isdigit((unsigned char)*p) && *p != '.') ip_literal = false;
            if (!ip_literal) {
                /* fatal: the user asked for proxied mode; silently continuing
                   direct would broadcast the real IP — refuse to start */
                TT_LOG("tox", "proxy host '%s' is not an IPv4 literal — refusing "
                       "to start (hostname would leak via plaintext DNS; no direct fallback)", host);
                tox_options_free(opts);
                TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
                if (ev) tt_queue_push(&t->out, ev);
                return NULL;
            }
            tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
            tox_options_set_proxy_host(opts, host);
            tox_options_set_proxy_port(opts, (uint16_t)port);
            /* belt-and-braces (toxcore would disable UDP anyway with a
               proxy set, and local discovery is UDP-only) */
            tox_options_set_udp_enabled(opts, false);
            tox_options_set_local_discovery_enabled(opts, false);
            tox_options_set_hole_punching_enabled(opts, false);
            t->tor_mode = true;
            TT_LOG("tox", "TOR MODE: SOCKS5 %s:%ld, UDP disabled, relays by IP literal only", host, port);
        }
    }

    /* At-rest encryption (mandatory): acquire the passphrase ONCE and derive
       both keys from it — the profile/offline-queue key and the session
       sidecar key. The two keys use DISTINCT random salts so they are
       cryptographically independent (a leaked profile key cannot decrypt
       the session sidecar and vice versa). The passphrase is wiped after
       both derivations; the derived keys live in t->pass_key and
       t->session_key. tox_pass_key_derive uses a RANDOM salt, so for an
       existing profile/sidecar we must derive from the salt embedded in the
       savedata (tox_get_salt) or the key will never match. A fresh
       profile/sidecar gets a fresh random salt. */
    char *pass = tt_passphrase_acquire(t);
    if (!pass) {
        tox_options_free(opts);
        TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
        if (ev) tt_queue_push(&t->out, ev);
        return NULL;
    }
    {
        Tox_Err_Key_Derivation kerr;
        Tox_Pass_Salt salt;
        bool have_salt = false;
        if (t->profile_path) {
            FILE *fp = fopen(t->profile_path, "rb");
            if (fp) {
                uint8_t head[TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
                if (fread(head, 1, sizeof head, fp) == sizeof head &&
                    tox_is_data_encrypted(head)) {
                    Tox_Err_Get_Salt gerr;
                    if (tox_get_salt(head, salt, &gerr)) have_salt = true;
                }
                fclose(fp);
            }
        }
        if (have_salt) {
            t->pass_key = tox_pass_key_derive_with_salt(
                (const uint8_t *)pass, strlen(pass), salt, &kerr);
        } else {
            t->pass_key = tox_pass_key_derive(
                (const uint8_t *)pass, strlen(pass), &kerr);
        }
        if (!t->pass_key) {
            TT_LOG("tox", "pass-key derivation failed: %d", (int)kerr);
            sodium_memzero(pass, strlen(pass));
            free(pass);
            tox_options_free(opts);
            TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
            if (ev) tt_queue_push(&t->out, ev);
            return NULL;
        }
        TT_LOG("tox", "at-rest encryption: ON (scrypt pass-key derived%s)",
               have_salt ? " from profile salt" : "");
    }
    {
        Tox_Err_Key_Derivation kerr;
        Tox_Pass_Salt salt;
        bool have_salt = false;
        if (t->profile_path) {
            char spath[strlen(t->profile_path) + 8];
            snprintf(spath, sizeof spath, "%s.ses", t->profile_path);
            FILE *fp = fopen(spath, "rb");
            if (fp) {
                uint8_t head[TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
                if (fread(head, 1, sizeof head, fp) == sizeof head &&
                    tox_is_data_encrypted(head)) {
                    Tox_Err_Get_Salt gerr;
                    if (tox_get_salt(head, salt, &gerr)) have_salt = true;
                }
                fclose(fp);
            }
        }
        if (have_salt) {
            t->session_key = tox_pass_key_derive_with_salt(
                (const uint8_t *)pass, strlen(pass), salt, &kerr);
        } else {
            t->session_key = tox_pass_key_derive(
                (const uint8_t *)pass, strlen(pass), &kerr);
        }
        if (!t->session_key) {
            TT_LOG("tox", "session key derivation failed: %d", (int)kerr);
            sodium_memzero(pass, strlen(pass));
            free(pass);
            tox_options_free(opts);
            TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
            if (ev) tt_queue_push(&t->out, ev);
            return NULL;
        }
        TT_LOG("tox", "session at-rest key: ON (distinct salt%s)",
               have_salt ? " from sidecar salt" : "");
    }
    sodium_memzero(pass, strlen(pass));
    free(pass);

    /* Both at-rest keys are derived; drop the passphrase from the process
       environment so it is not visible via /proc/<pid>/environ or inherited
       by child processes. */
    unsetenv("TT_PASSPHRASE");

    /* Profile load/save: savedata blob handled as opaque per toxcore docs.
       tox_options_set_savedata_data stores a non-owned pointer, so the buffer
       must stay alive until tox_new has consumed it. */
    uint8_t *save_buf = NULL;
    bool decrypt_failed = false;
    if (t->profile_path) {
        FILE *fp = fopen(t->profile_path, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (sz > 0 && sz <= 4 * 1024 * 1024) {
                uint8_t *buf = malloc((size_t)sz);
                if (buf && fread(buf, 1, (size_t)sz, fp) == (size_t)sz) {
                    /* decrypt the savedata in place (plaintext migration
                       accepted: a pre-encryption profile loads as-is) */
                    if (sz >= (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH &&
                        tox_is_data_encrypted(buf)) {
                        long pt_len = sz - (long)TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
                        Tox_Err_Decryption derr;
                        if (tox_pass_key_decrypt(t->pass_key, buf, (size_t)sz,
                                                 buf, &derr)) {
                            sz = pt_len;
                        } else {
                            /* hard failure: proceeding would create a fresh
                               identity and overwrite the profile on shutdown */
                            TT_LOG("tox", "savedata decrypt failed: %d — wrong passphrase?",
                                   (int)derr);
                            decrypt_failed = true;
                            free(buf);
                            buf = NULL;
                        }
                    }
                    if (buf) {
                        if (t->tor_mode) {
                            /* Tor invariant: never persist or re-save past DHT
                               (direct-IP) history. The in-memory copy loads
                               without the DHT section, so toxcore's next save
                               writes a DHT-free blob. */
                            size_t stripped_len = 0;
                            uint8_t *stripped = savedata_strip_dht(buf, (size_t)sz, &stripped_len);
                            if (stripped) {
                                TT_LOG("tox", "savedata DHT history stripped (%ld -> %ld bytes)",
                                       sz, (long)stripped_len);
                                free(buf);
                                buf = stripped;
                                sz = (long)stripped_len;
                            } else {
                                TT_LOG("tox", "savedata DHT strip skipped (no section or parse mismatch)");
                            }
                        }
                        save_buf = buf;
                        tox_options_set_savedata_type(opts, TOX_SAVEDATA_TYPE_TOX_SAVE);
                        tox_options_set_savedata_data(opts, buf, (size_t)sz);
                    } else {
                        free(buf);
                    }
                }
            }
            fclose(fp);
        }
    }

    if (decrypt_failed) {
        /* refuse to start: a fresh identity would overwrite the encrypted
           profile on shutdown (data loss). The user must retry with the
           correct passphrase. */
        tox_options_free(opts);
        TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
        if (ev) tt_queue_push(&t->out, ev);
        return NULL;
    }

    Tox_Err_New err;
    Tox *tox = tox_new(opts, &err);
    free(save_buf);
    tox_options_free(opts);
    if (!tox) {
        TT_LOG("tox", "tox_new failed: %d", (int)err);
        TTEvent *ev = tt_event_new(TT_EV_SHUTDOWN);
        if (ev) tt_queue_push(&t->out, ev);
        return NULL;
    }
    t->tox = tox;

    if (t->tor_mode) {
        TTEvent *ev = tt_event_new(TT_EV_TOR_MODE);
        if (ev) tt_queue_push(&t->out, ev);
    }

    tox_callback_self_connection_status(tox, cb_self_connection);
    tox_callback_friend_name(tox, cb_friend_name);
    tox_callback_friend_message(tox, cb_friend_message);
    tox_callback_friend_connection_status(tox, cb_friend_connection);
    tox_callback_friend_status_message(tox, cb_friend_status_message);
    tox_callback_friend_status(tox, cb_friend_status);
    tox_callback_friend_request(tox, cb_friend_request);
    tox_callback_friend_typing(tox, cb_friend_typing);
    tox_callback_friend_read_receipt(tox, cb_friend_read_receipt);
    tox_callback_file_recv(tox, cb_file_recv);
    tox_callback_file_recv_chunk(tox, cb_file_recv_chunk);
    tox_callback_file_recv_control(tox, cb_file_recv_control);
    tox_callback_file_chunk_request(tox, cb_file_chunk_request);
    tox_callback_group_message(tox, cb_group_message);
    tox_callback_group_private_message(tox, cb_group_private_message);
    tox_callback_group_topic(tox, cb_group_topic);
    tox_callback_group_peer_join(tox, cb_group_peer_join);
    tox_callback_group_peer_exit(tox, cb_group_peer_exit);
    tox_callback_group_peer_name(tox, cb_group_peer_name);
    tox_callback_group_peer_status(tox, cb_group_peer_status);
    tox_callback_group_moderation(tox, cb_group_moderation);
    tox_callback_group_privacy_state(tox, cb_group_privacy_state);
    tox_callback_group_voice_state(tox, cb_group_voice_state);
    tox_callback_group_topic_lock(tox, cb_group_topic_lock);
    tox_callback_group_peer_limit(tox, cb_group_peer_limit);
    tox_callback_group_password(tox, cb_group_password);
    tox_callback_group_join_fail(tox, cb_group_join_fail);
    tox_callback_group_self_join(tox, cb_group_self_join);
    tox_callback_group_invite(tox, cb_group_invite);

    tt_av_init(t); /* toxav binds to this Tox instance; killed before tox_kill */

    bootstrap_all(t, tox);

    /* Publish self info to UI once */
    publish_toxid(t);
    {
        size_t nsz = tox_self_get_name_size(tox);
        char name[TOX_MAX_NAME_LENGTH + 1] = {0};
        if (nsz > TOX_MAX_NAME_LENGTH) nsz = TOX_MAX_NAME_LENGTH;
        tox_self_get_name(tox, (uint8_t *)name);
        push_simple(t, TT_EV_SELF_NAME, 0, name, nsz, 0);
    }
    {
        size_t nsz = tox_self_get_status_message_size(tox);
        char smsg[TOX_MAX_STATUS_MESSAGE_LENGTH + 1] = {0};
        if (nsz > TOX_MAX_STATUS_MESSAGE_LENGTH) nsz = TOX_MAX_STATUS_MESSAGE_LENGTH;
        tox_self_get_status_message(tox, (uint8_t *)smsg);
        push_simple(t, TT_EV_SELF_STATUS_MSG, 0, smsg, nsz, 0);
    }
    push_simple(t, TT_EV_SELF_STATUS, 0, NULL, 0, (int)tox_self_get_status(tox));

    /* restore + publish the persisted self avatar (file-transfer offer
       broadcast happens on first FRIEND_CONNECTION, once friends exist) */
    avatar_persist_load(t);
    if (t->self_avatar.has) {
        TTEvent *ev = tt_event_new(TT_EV_AVATAR_SELF);
        if (ev) {
            ev->str = malloc(t->self_avatar.size + 1);
            if (ev->str) {
                memcpy(ev->str, t->self_avatar.data, t->self_avatar.size);
                ev->str[t->self_avatar.size] = '\0';
                ev->str_len = t->self_avatar.size;
            }
            tt_queue_push(&t->out, ev);
        }
    }

    emit_initial_friend_list(t);
    emit_initial_group_list(t);

    /* restore offline-queued messages (flush when friends reconnect) */
    tt_oq_load(&t->oq, t->profile_path, t->pass_key);
    {
        int pending = 0;
        for (uint32_t fn = 0; fn < 256; fn++) pending += tt_oq_count(&t->oq, fn);
        if (pending > 0) TT_LOG("tox", "offline queue restored: %d message(s)", pending);
    }

    TT_LOG("tox", "tox thread running, iterating");
    tt_e2ee_mode = tt_e2ee_init_mode();
    if (tt_e2ee_mode) {
        t->e2ee = calloc(TT_MAX_FRIENDS, sizeof *t->e2ee);
        if (!t->e2ee) {
            TT_LOG("tox", "e2ee alloc failed — layer DISABLED");
            tt_e2ee_mode = false;
        } else {
            /* restore per-friend E2EE enforcement from the settings sidecar */
            tt_settings_load_e2ee(t->e2ee_required, t->profile_path);
            for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++)
                if (t->e2ee_required[fn])
                    push_simple(t, TT_EV_E2EE_ENFORCE, fn, NULL, 0, 1);
            /* v2: restore established sessions so forward secrecy survives
               restarts (only ACTIVE sessions are persisted; pending
               handshakes re-init fresh) */
            tt_session_store_load(t->e2ee, t->profile_path, t->session_key);
            int restored = 0;
            for (uint32_t fn = 0; fn < TT_MAX_FRIENDS; fn++)
                if (t->e2ee[fn].active) {
                    restored++;
                    /* a restored session means E2EE already worked with this
                       friend — auto-enforce it going forward (same rule as a
                       fresh handshake) */
                    if (!t->e2ee_required[fn]) {
                        t->e2ee_required[fn] = true;
                        if (!tt_settings_store_e2ee(t->e2ee_required, t->profile_path))
                            TT_LOG("tox", "e2ee auto-enforce(%u): persist failed", fn);
                        push_simple(t, TT_EV_E2EE_ENFORCE, fn, NULL, 0, 1);
                    }
                    /* tell the UI about the restored session (lock badge +
                       verification code); a fresh handshake emits this via
                       e2ee_rx, but a restored session has no handshake */
                    e2ee_push_state(t, fn, true);
                }
            if (restored > 0)
                TT_LOG("tox", "e2ee sessions restored: %d", restored);
        }
    }
    TT_LOG("tox", "e2ee layer: %s", tt_e2ee_mode ? "ON" : "off");
    while (!t->stop) {
        tox_iterate(tox, t);
        if (t->av) tt_av_iterate(t, t->av);

        for (;;) {
            TTEvent *cmd = tt_queue_pop_timed(&t->in, 0);
            if (!cmd) break;
            handle_cmd(t, cmd);
            tt_event_free(cmd);
        }

        uint32_t iv = tox_iteration_interval(tox);
        struct timespec ts = { .tv_sec = (time_t)(iv / 1000), .tv_nsec = (long)(iv % 1000) * 1000000L };
        nanosleep(&ts, NULL);

        /* E2EE session pump (TT_E2EE): INIT retransmits + flush stashed
           texts once a handshake completes */
        if (tt_e2ee_mode) e2ee_tick(t);

        /* DHT upkeep: re-bootstrap right away when self dropped offline
           (toxcore never re-adds DHT neighbors on its own once they decay),
           and every 5 minutes regardless as maintenance. */
        time_t now = time(NULL);
        if (!t->self_online) {
            if (now - t->last_bootstrap >= 10) {
                TT_LOG("tox", "self offline: re-bootstrapping DHT");
                bootstrap_all(t, tox);
                t->last_bootstrap = now;
            }
        } else if (now - t->last_bootstrap >= 300) {
            TT_LOG("tox", "maintenance re-bootstrap");
            bootstrap_all(t, tox);
            t->last_bootstrap = now;
        }
    }

    /* Persist profile on shutdown */
    save_profile(t);
    tt_oq_save(&t->oq, t->profile_path, t->pass_key);
    if (t->e2ee)
        tt_session_store_save(t->e2ee, t->profile_path, t->session_key);
    tt_av_kill(t); /* all active calls forcibly terminated (toxav.h); before tox_kill */
    tox_kill(tox);
    t->tox = NULL;
    for (int i = 0; i < TT_MAX_XFERS; i++)
        if (t->xfers[i].active) xfer_free(&t->xfers[i]);
    tt_avatar_free(&t->self_avatar);
    for (uint32_t i = 0; i < TT_MAX_FRIENDS; i++)
        tt_avatar_free(&t->avatars[i]);
    if (t->e2ee) {
        for (uint32_t i = 0; i < TT_MAX_FRIENDS; i++)
            tt_session_clear(&t->e2ee[i]);
        free(t->e2ee);
        t->e2ee = NULL;
    }
    if (t->pass_key) {
        tox_pass_key_free(t->pass_key);
        t->pass_key = NULL;
    }
    if (t->session_key) {
        tox_pass_key_free(t->session_key);
        t->session_key = NULL;
    }
    tt_e2ee_mode = false;
    return NULL;
}

bool tt_tox_thread_start(TTToxThread *t, const char *profile_path, bool gui_mode) {
    memset(t, 0, sizeof *t);
    tt_queue_init(&t->out);
    tt_queue_init(&t->in);
    pthread_mutex_init(&t->pass_lock, NULL);
    pthread_cond_init(&t->pass_cond, NULL);
    t->gui_mode = gui_mode;
    if (profile_path) {
        t->profile_path = strdup(profile_path);
        if (!t->profile_path) {
            pthread_cond_destroy(&t->pass_cond);
            pthread_mutex_destroy(&t->pass_lock);
            tt_queue_destroy(&t->in);
            tt_queue_destroy(&t->out);
            return false;
        }
    }
    t->stop = false;
    return pthread_create(&t->thread, NULL, tox_thread_main, t) == 0;
}

void tt_tox_thread_stop(TTToxThread *t) {
    t->stop = true;
    pthread_join(t->thread, NULL);
    tt_queue_destroy(&t->in);
    tt_queue_destroy(&t->out);
    pthread_cond_destroy(&t->pass_cond);
    pthread_mutex_destroy(&t->pass_lock);
    free(t->profile_path);
}