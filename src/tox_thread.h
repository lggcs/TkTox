#ifndef TT_TOX_THREAD_H
#define TT_TOX_THREAD_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <tox/tox.h>

#include "offline_queue.h"

/* Max simultaneous tunnels (mesh topology). Must match tunnel.h. */
#define TT_TUNNEL_MAX_TUNNELS 16

/* At-rest profile encryption (toxencryptsave, scrypt KDF — same module uTox
   and qTox use). Opaque; only tox_thread.c touches the internals. */
struct Tox_Pass_Key;

/* Event posted from toxcore callbacks (tox thread) to the UI thread.
   Single allocation, owned by the consumer, freed via tt_event_free. */
typedef enum {
    TT_EV_TOXID = 1,
    TT_EV_SELF_CONNECTION,
    TT_EV_SELF_NAME,
    TT_EV_SELF_STATUS_MSG,
    TT_EV_SELF_STATUS,       /* ival: Tox_User_Status */
    TT_EV_FRIEND_NAME,
    TT_EV_FRIEND_MESSAGE,
    TT_EV_FRIEND_CONNECTION,
    TT_EV_FRIEND_STATUS_MSG,
    TT_EV_FRIEND_STATUS,     /* ival: Tox_User_Status */
    TT_EV_FRIEND_PUBKEY,     /* str: 64-hex public key (friend identity) */
    TT_EV_FRIEND_LAST_ONLINE,/* ival: unix time the friend was last seen online */
    TT_EV_FRIEND_REQUEST,
    TT_EV_FRIEND_LIST_END,
    TT_EV_AVATAR_SELF,       /* str: self avatar PNG bytes; empty = cleared */
    TT_EV_AVATAR,            /* friend_number, str: friend avatar PNG bytes */
    TT_EV_AVATAR_CLEARED,    /* friend_number: friend removed their avatar */
    TT_EV_FILE_OFFER,        /* friend_number; str: "<name>\n<size>"; ival: xfer id */
    TT_EV_FILE_PROGRESS,     /* friend_number, ival: xfer id, str: "<got>/<total>" */
    TT_EV_FILE_DONE,         /* friend_number, ival: xfer id, str: save path */
    TT_EV_FILE_FAILED,       /* friend_number, ival: xfer id */
    TT_EV_FILE_TX_STARTED,   /* friend_number, ival: xfer id, str filename */
    /* groups (new group chats). friend_number carries the group number. */
    TT_EV_GROUP_NEW,         /* ival: group number; str: group name; ival2: privacy (0 public, 1 private) */
    TT_EV_GROUP_JOINED,      /* ival: group number; str: group name; self join success */
    TT_EV_GROUP_LEFT,        /* ival: group number */
    TT_EV_GROUP_MSG,         /* group, ival: peer id; ival2: msg type (0 normal 1 action) */
    TT_EV_GROUP_PRIV_MSG,    /* group, ival: peer id; ival2: msg type */
    TT_EV_GROUP_TOPIC,       /* group; str: topic; ival2: peer id (UINT32_MAX = self) */
    TT_EV_GROUP_PEER_JOIN,   /* group, ival: peer id */
    TT_EV_GROUP_PEER_EXIT,   /* group, ival: peer id; ival2: exit type; str: name */
    TT_EV_GROUP_PEER_NAME,   /* group, ival: peer id; str: nickname */
    TT_EV_GROUP_PEER_STATUS, /* group, ival: peer id; ival2: Tox_User_Status */
    TT_EV_GROUP_PEER_ROLE,   /* group, ival: peer id; ival2: Tox_Group_Role */
    TT_EV_GROUP_INVITE,      /* friend_number (inviter); str: group name; ival2: pending invite index */
    TT_EV_GROUP_MOD,         /* group, ival: target peer id; ival2: Tox_Group_Mod_Event */
    TT_EV_GROUP_STATE,       /* group; encoded in ival: 0..1 privacy, -1 ival2=voice, -2 ival2=topic lock, -3 ival2=peer limit (str=count), -4 password changed */
    TT_EV_GROUP_JOIN_FAIL,   /* group, ival: Tox_Group_Join_Fail */
    TT_EV_GROUP_MOD_SELF,    /* actor-side moderation feedback (no toxcore callback fires for the actor); ival: target peer id, ival2: Tox_Group_Mod_Event, or TT_MOD_EV_FAIL_BASE+<event> on failure; str: target name */
    TT_EV_GROUP_IGNORE_SELF, /* actor-side ignore feedback (gc_set_ignore is local-only, no callback); ival: target peer id, ival2: 0 unignored / 1 ignored, or TT_MOD_EV_FAIL_BASE+1 on failure; str: target name */
    TT_EV_OFFLINE_FLUSHED,   /* friend_number, ival: count delivered (UI renders the per-contact system line) */
    TT_EV_FRIEND_TYPING,     /* friend_number, ival: 0 stopped / 1 typing */
    TT_EV_FRIEND_READ_RECEIPT, /* friend_number, ival: last read message id */
    TT_EV_MESSAGE_SENT,      /* friend_number, ival: tox message id (receipt key) */
    TT_EV_TOR_MODE,          /* engine runs TCP-only via SOCKS5 (TT_PROXY_* env); no payload */
    TT_EV_AV_INCOMING,       /* friend_number, ival: audio offered, ival2: video offered */
    TT_EV_AV_STATE,          /* friend_number, ival: Toxav_Friend_Call_State bitmask (0 = paused) */
    TT_EV_AV_ENDED,          /* friend_number, ival: 0 finished / 1 error */
    TT_EV_AV_FRAME,          /* M-AV4: friend_number, ival: w, ival2: h; payload in str (w*h*3/2 YUV420) */
    TT_EV_E2EE_STATE,        /* M3 (TT_E2EE): session with friend_number changed state;
                                str: 32-hex verification code when ival=1 (established),
                                NULL/absent when ival=0 (lost/reset) */
    TT_EV_E2EE_WARN,         /* friend_number: E2EE warning for the chat (str: message).
                                Emitted once per connection when a friend is detected
                                as legacy (plaintext fallback) or when enforcement
                                holds a message pending E2EE. */
    TT_EV_E2EE_ENFORCE,      /* friend_number, ival: 1 = E2EE required (plaintext
                                blocked), 0 = fallback allowed. Pushed at startup
                                for each enforced friend and after a toggle. */
    TT_EV_PASSPHRASE_NEEDED, /* GUI mode: the tox thread blocks until the UI
                                provides the at-rest passphrase (or cancels) */
    /* chess interop (wire-compatible with toxic's game_chess.c). */
    TT_EV_CHESS_INVITE,      /* friend_number: someone invited us to chess;
                                str: "white"/"black" (the colour WE would play) */
    TT_EV_CHESS_START,       /* friend_number, ival: 1 = we are white, 0 = black.
                                Game is live; the UI initialises its board. */
    TT_EV_CHESS_MOVE,        /* friend_number, str: 4-char algebraic move "e2e4" */
    TT_EV_CHESS_END,         /* friend_number, ival: 0 checkmate, 1 stalemate,
                                2 resign; ival2: 1 if we won (0 draw/loss) */
    /* UDP-over-Tox tunnel (src/tunnel.c). */
    TT_EV_TUNNEL_INVITE,     /* client: friend_number invited us to a share;
                                str: server_host; ival: server_port;
                                ival2: tcp_server_port (0 = none) */
    TT_EV_TUNNEL_ADD,        /* a tunnel became live. ival: tunnel id;
                                ival2: 1 = host, 0 = client; str: endpoint */
    TT_EV_TUNNEL_STATE,      /* host: friend_number accepted (ival2=1) or
                                declined (ival2=2) our invite; ival: tunnel id */
    TT_EV_TUNNEL_REMOVE,     /* a tunnel was stopped. ival: tunnel id */
    TT_EV_SHUTDOWN,
} TTEventType;

/* Commands (UI/app -> tox thread) reuse TTEvent as the carrier; values start
   at 101 so event and command types are distinguishable in a switch. */
/* TT_EV_GROUP_MOD_SELF ival2 encoding: base Tox_Group_Mod_Event value, or
   this offset + event when the toxcore call failed */
#define TT_MOD_EV_FAIL_BASE 100
typedef enum {
    TT_CMD_ADD_FRIEND = 101, /* str: 76-char ToxID hex */
    TT_CMD_ACCEPT_FRIEND,    /* str: 64-char public key hex of the requester */
    TT_CMD_DELETE_FRIEND,    /* friend_number */
    TT_CMD_SEND_MESSAGE,     /* friend_number, str: message text */
    TT_CMD_SET_NAME,         /* str: own nickname */
    TT_CMD_SET_STATUS_MSG,   /* str: own status message */
    TT_CMD_CYCLE_STATUS,     /* ival: current Tox_User_Status; cycles to next */
    TT_CMD_SET_STATUS,       /* ival: Tox_User_Status 0..2 (explicit pick) */
    TT_CMD_SET_NOSPAM,       /* randomize the 4-byte nospam (anti-spam) field
                                of the own ToxID; re-publishes TT_EV_TOXID */
    TT_CMD_SET_AVATAR,       /* str: PNG file path for own avatar */
    TT_CMD_CLEAR_AVATAR,     /* removes own avatar (0-length FT broadcast) */
    TT_CMD_SEND_FILE,        /* friend_number, str: local file path to send */
    TT_CMD_FILE_ACCEPT,      /* ival: xfer id, str: save path */
    TT_CMD_FILE_REJECT,      /* ival: xfer id */
    /* groups: friend_number carries the group number */
    TT_CMD_GROUP_CREATE,     /* str: "<name>\n<public|private>"; founder */
    TT_CMD_GROUP_JOIN,       /* str: 64-hex chat id; ival2: password ("" = none) */
    TT_CMD_GROUP_LEAVE,      /* group number */
    TT_CMD_GROUP_SEND,       /* group, str: message; ival2: msg type (0 normal, 1 action) */
    TT_CMD_GROUP_PRIV_SEND,  /* group, ival: peer id, str: message */
    TT_CMD_GROUP_TOPIC,      /* group, str: topic */
    TT_CMD_GROUP_INVITE,     /* group, friend_number: friend to invite */
    TT_CMD_GROUP_INVITE_ACC, /* ival2: pending invite index */
    TT_CMD_GROUP_INVITE_DEC, /* ival2: pending invite index */
    TT_CMD_GROUP_PASSWORD,   /* group, str: password ("" clears) */
    TT_CMD_GROUP_PRIVACY,    /* group, ival2: 0 public, 1 private */
    TT_CMD_GROUP_VOICE,      /* group, ival2: Tox_Group_Voice_State */
    TT_CMD_GROUP_TOPIC_LOCK, /* group, ival2: 0 disabled, 1 enabled */
    TT_CMD_GROUP_PEER_LIMIT, /* group, ival2: peer limit */
    TT_CMD_GROUP_ROLE,       /* group, ival: peer id, ival2: Tox_Group_Role */
    TT_CMD_GROUP_KICK,       /* group, ival: peer id */
    TT_CMD_GROUP_IGNORE,     /* group, ival: peer id, ival2: 0 unignore / 1 ignore */
    TT_CMD_GROUP_SYNC,       /* group: pushes a roster burst (see below) */
    TT_CMD_SET_TYPING,       /* friend_number, ival: 0/1 */
    TT_CMD_FILE_CANCEL,      /* ival: xfer id (active transfer, either direction) */
    TT_CMD_AV_CALL,          /* friend_number, ival: audio kbps (0=off), ival2: video kbps (0=off) */
    TT_CMD_AV_ANSWER,        /* same payload semantics as AV_CALL */
    TT_CMD_AV_HANGUP,        /* friend_number (toxav CANCEL) */
    TT_CMD_AV_PAUSE,         /* tier B1: friend_number (toxav PAUSE; state -> 0, peer sees it) */
    TT_CMD_AV_RESUME,        /* tier B1: friend_number (toxav RESUME; only after OUR pause) */
    TT_CMD_AV_MUTE,          /* friend_number, ival: 0 unmute mic / 1 mute mic (engine-side gate) */
    TT_CMD_AV_DEAF,          /* M-AV5: friend_number, ival: 0 unmute output / 1 mute output */
    TT_CMD_AV_SELFVIEW,      /* M-AV5: friend_number, ival: 1 stream local camera to the UI pane */
    TT_CMD_AV_VTEST,         /* M-AV4 harness: ival 1 = pump test video frames, 0 = stop */
    TT_CMD_AV_SET_VIDEO_BR,  /* tier B2: friend_number, ival: video kbps 1..1000000 */
    TT_CMD_E2EE_REORDER,     /* M4 harness: friend_number; build DATA frames
                                seq 1..3 via frame_at and deliver 2,1,3 out of
                                order (the peer recovers 1,2 via the skipped
                                key store) */
    TT_CMD_E2EE_REPLAY,      /* M4 harness: friend_number; re-inject the last
                                incoming DATA frame into the local session —
                                must reject as TT_E2EE_REPLAY */
    TT_CMD_E2EE_ENFORCE,     /* friend_number, ival: 1 require E2EE (block
                                plaintext fallback), 0 allow fallback. Persisted
                                in the settings sidecar. */
    /* chess interop commands. */
    TT_CMD_CHESS_INVITE,     /* friend_number: invite the friend to a chess game.
                                The engine picks our colour at random (matching
                                toxic) and sends the invite packet. */
    TT_CMD_CHESS_ACCEPT,     /* friend_number: accept a pending chess invite. */
    TT_CMD_CHESS_DECLINE,    /* friend_number: decline a pending chess invite. */
    TT_CMD_CHESS_MOVE,       /* friend_number, str: 4-char algebraic move "e2e4" */
    TT_CMD_CHESS_RESIGN,     /* friend_number: resign the current game. */
    /* UDP-over-Tox tunnel. Runtime allowlist mutation — no tunnel teardown
       required. ival carries the tunnel id (0 = apply to every host tunnel,
       used by trust-all test mode). */
    TT_CMD_TUNNEL_ALLOW,     /* host: relay this friend's UDP to the server */
    TT_CMD_TUNNEL_DENY,      /* host: stop relaying this friend */
    /* Tunnel lifecycle (UI -> engine). */
    TT_CMD_TUNNEL_SHARE,     /* host: friend_number; str: "<server_host>\n<port>\n<tcp_port>" */
    TT_CMD_TUNNEL_ACCEPT,    /* client: friend_number; str: "<local_port>\n<tcp_local_port>" */
    TT_CMD_TUNNEL_DECLINE,   /* client: friend_number: decline a pending invite */
    TT_CMD_TUNNEL_STOP,      /* ival: tunnel id to stop */
} TTCommandType;

/* TT_CMD_GROUP_SYNC reply burst (reuses existing event types):
   per valid peer id (dense 0..n-1): GROUP_PEER_NAME + GROUP_PEER_ROLE,
   then GROUP_STATE ival=-5 str=64-hex chat id, GROUP_STATE ival=-6
   ival2=self role, GROUP_TOPIC str=topic ival2=UINT32_MAX (self). */

/* Tox avatar: PNG bytes transferred as TOX_FILE_KIND_AVATAR; the SHA-256
   hash (via tox_hash) doubles as the Tox file_id so both ends can skip
   redundant transfers. */
#define TT_AVATAR_MAX_SIZE (64 * 1024)
#define TT_MAX_FRIENDS 256 /* friend numbers are dense (0..n-1) in toxcore */
#define TT_MAX_XFERS 16    /* simultaneous general file transfers */

typedef struct TTAvatar {
    bool has;                       /* a current avatar exists */
    unsigned char hash[TOX_HASH_LENGTH];
    unsigned char *data;            /* heap PNG bytes (NULL when cleared) */
    size_t size;                    /* bytes in data */
    /* incoming transfer state */
    bool rx_active;
    uint32_t rx_file_number;
    size_t rx_expected, rx_got;
} TTAvatar;

/* general (TOX_FILE_KIND_DATA) transfer, either direction */
typedef struct TTXfer {
    bool active;
    unsigned id;                    /* our stable xfer id (event payloads) */
    uint32_t fn;                    /* friend number */
    uint32_t file_number;           /* tox per-friend transfer id */
    bool sending;
    bool accepted;                  /* RX: user accepted; TX: implicit */
    FILE *fp;
    uint64_t size, got, got_prev;   /* got_prev: last xfer_progress emit */
    char name[TOX_MAX_FILENAME_LENGTH + 1];
    char path[1024];                /* local path: source (TX) or dest (RX) */
} TTXfer;

void tt_avatar_free(TTAvatar *a);
/* Copies png (size bytes), computes the hash; returns false on OOM or
   empty data. Replaces any previous avatar. */
bool tt_avatar_set(TTAvatar *a, const unsigned char *png, size_t size);

typedef struct TTEvent {
    TTEventType type;
    uint32_t friend_number;  /* overloaded: group number for group events */
    char *str;         /* heap, NUL-terminated */
    size_t str_len;    /* bytes in str excluding NUL */
    int ival;
    int ival2;         /* second payload (peer id, msg type, invite index, ...) */
} TTEvent;

/* Bounded MPMC-free single-producer/multi-consumer queue: tox thread -> UI.
   Condvar based (no spin flags). If the UI stalls, the tox thread blocks —
   that is the intended backpressure. */
#define TT_QUEUE_CAP 256

typedef struct TTQueue {
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    TTEvent *items[TT_QUEUE_CAP];
    size_t head, count;
} TTQueue;

void tt_queue_init(TTQueue *q);
void tt_queue_destroy(TTQueue *q);
/* Copies nothing: takes ownership of *ev. Blocks while full. */
void tt_queue_push(TTQueue *q, TTEvent *ev);
/* Blocks until an event is available. Caller owns the returned event. */
TTEvent *tt_queue_pop(TTQueue *q);
/* Waits up to timeout_ms; returns NULL on timeout. Caller owns the event. */
TTEvent *tt_queue_pop_timed(TTQueue *q, unsigned ms);
TTEvent *tt_event_new(TTEventType type);
void tt_event_free(TTEvent *ev);

/* Build a command/event carrying str (copied, NUL-terminated) and push it.
   Returns false only if allocation failed. */
bool tt_queue_post(TTQueue *q, int type, uint32_t friend_number, const char *str, int ival);
/* Same with ival2 (group events need two payload ints). */
bool tt_queue_post2(TTQueue *q, int type, uint32_t friend_number,
                    const char *str, int ival, int ival2);

/* pending group invite from a friend (toxcore requires the raw invite data
   to be kept until tox_group_invite_accept) */
#define TT_MAX_GROUP_INVITES 8
#define TT_GROUP_INVITE_DATA_MAX 512

typedef struct TTGroupInvite {
    bool used;
    uint32_t fn;                              /* inviting friend */
    uint8_t data[TT_GROUP_INVITE_DATA_MAX];   /* opaque invite packet */
    size_t len;
    char name[TOX_GROUP_MAX_GROUP_NAME_LENGTH + 1]; /* group name from the invite */
} TTGroupInvite;

/* Tox thread lifecycle */
typedef struct TTToxThread {
    Tox *tox;            /* owned by the tox thread */
    TTQueue out;         /* tox -> UI events */
    TTQueue in;          /* UI -> tox commands */
    pthread_t thread;
    bool stop;
    char *profile_path;  /* savedata file */
    struct Tox_Pass_Key *pass_key; /* at-rest encryption key (NULL = plaintext) */
    struct Tox_Pass_Key *session_key; /* session sidecar at-rest key (distinct salt) */
    TTAvatar self_avatar;
    TTAvatar avatars[TT_MAX_FRIENDS]; /* per-friend current avatar */
    unsigned char sent_hash[TT_MAX_FRIENDS][TOX_HASH_LENGTH];
    TTXfer xfers[TT_MAX_XFERS];     /* general file transfers */
    unsigned xfer_seq;              /* monotonic xfer ids (0 never issued) */
    TTGroupInvite ginvites[TT_MAX_GROUP_INVITES]; /* pending friend invites */
    TTOfflineQueue oq;  /* faux offline messages (persisted <profile>.oq) */
    bool oq_flushing;   /* suppress nested flush from the callback chain */
    time_t last_bootstrap; /* monotonic-ish clock for maintenance re-bootstrap */
    bool self_online;   /* last TT self connection state */
    bool tor_mode;      /* SOCKS5 proxy active: TCP-only, IP-literal bootstraps */
    bool peer_typing[TT_MAX_FRIENDS]; /* dedupe toxcore's per-packet typing cb */
    struct ToxAV *av;   /* owned by the tox thread (toxav.h); NULL = no AV */
    struct TTAvg *avg;  /* AV engine state (src/av.h); valid only while av set */
    struct TTSession *e2ee; /* TT_MAX_FRIENDS sessions (TT_E2EE only); NULL = off */
    /* Per-friend E2EE policy (TT_E2EE only). e2ee_required: block plaintext
       fallback for this friend (persisted in the settings sidecar).
       e2ee_fallback: we detected this friend as legacy and fell back to
       plaintext this connection (reset on reconnect; drives the warning).
       e2ee_handshake_at: when we last kicked the handshake (send-side
       fallback timeout). e2ee_warned: dedupe the per-connection warning. */
    bool e2ee_required[TT_MAX_FRIENDS];
    bool e2ee_fallback[TT_MAX_FRIENDS];
    time_t e2ee_handshake_at[TT_MAX_FRIENDS];
    bool e2ee_warned[TT_MAX_FRIENDS];
    /* Chess interop state (wire-compatible with toxic's game_chess.c). One
       game per friend. The engine lives in src/chess.c. */
    struct TTChessGame *chess[TT_MAX_FRIENDS]; /* NULL = no active game */
    /* UDP-over-Tox tunnels (src/tunnel.c). A process can run several at once
       (mesh topology); each has a stable numeric id. The engine runs on the
       tox thread; the allowlist is mutable at runtime via
       TT_CMD_TUNNEL_ALLOW / TT_CMD_TUNNEL_DENY. */
    struct TTTunnel *tunnels[TT_TUNNEL_MAX_TUNNELS];
    unsigned tunnel_seq; /* monotonic tunnel id allocator */
    /* At-rest passphrase handshake (GUI mode only): the tox thread posts
       TT_EV_PASSPHRASE_NEEDED then blocks on pass_cond until the UI thread
       delivers the passphrase (pass_buf) or cancels (pass_cancel). The
       passphrase is acquired ONCE and used for both at-rest key derivations,
       so the UI is never prompted twice. */
    bool gui_mode;      /* set by tt_tox_thread_start; read by the tox thread */
    pthread_mutex_t pass_lock;
    pthread_cond_t  pass_cond;
    bool pass_waiting;  /* tox thread is blocked awaiting the passphrase */
    bool pass_cancel;   /* UI cancelled: abort startup */
    char *pass_buf;     /* UI-provided passphrase (owned by the tox thread) */
} TTToxThread;

bool tt_tox_thread_start(TTToxThread *t, const char *profile_path, bool gui_mode);
void tt_tox_thread_stop(TTToxThread *t);

/* Settings sidecar: "<profile>.tt" carries client settings that must be
   known before tox_new (currently the SOCKS5 proxy). TT_PROXY_* env vars
   win over the file when both are set. */
typedef struct TTSettings {
    bool proxy_set;
    char proxy_host[64]; /* IPv4 literal only (fatal refusal otherwise) */
    long proxy_port;
    bool history;        /* persist chat transcripts to "<profile>.hist" (off by default) */
} TTSettings;

/* Read "<profile>.tt" (missing or malformed file = defaults). */
void tt_settings_load(TTSettings *s, const char *profile_path);
/* Atomically write "<profile>.tt"; empty host clears proxy settings. */
bool tt_settings_store_proxy(const char *profile_path, const char *host, long port);
/* Persist the chat-history toggle into the "<profile>.tt" sidecar, preserving
   the proxy and e2ee lines. Returns false on I/O failure. */
bool tt_settings_store_history(const char *profile_path, bool on);
/* Per-friend E2EE enforcement: read the "<profile>.tt" sidecar into
   required[TT_MAX_FRIENDS] (true = require E2EE for that friend number).
   Missing/malformed file = all false. */
void tt_settings_load_e2ee(bool required[TT_MAX_FRIENDS], const char *profile_path);
/* Persist the per-friend E2EE enforcement set (true entries only) into the
   "<profile>.tt" sidecar, preserving the proxy line. Returns false on I/O
   failure. */
bool tt_settings_store_e2ee(const bool required[TT_MAX_FRIENDS],
                             const char *profile_path);

#endif