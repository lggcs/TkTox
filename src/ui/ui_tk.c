/* Tk frontend, uTox-inspired design (clean-room; design language only).
   Layout: dark left sidebar -- self badge (avatar, name, status message,
   clickable presence dot that opens the Online/Away/Busy picker), roster
   with presence-colored rows and status-message sublines, bottom
   search/add bar -- and a light main pane: chat header strip with friend
   avatar, message history with timestamps and sender names, multiline
   input with Send. Friend requests open as a page with Add / Ignore.
   Palette values follow uTox's default theme.

   C owns everything: Tcl interp embedded from C, widgets created exclusively
   via Tcl_EvalObjv argv arrays (no string interpolation, no Tcl scripts);
   every callback is a C obj-command. */

#include "ui.h"
#include "../app_state.h"
#include "../log.h"
#include <tcl.h>
#include <tk.h>
#include <tox/toxav.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#define TT_TRANSCRIPT_MAX (64 * 1024)
#define TT_LAST_MAX 48
#define TT_AV_VIDEO_BITRATE 2500 /* kbit/s (matches av.h engine default) */

/* qTox default theme values (themes/default/palette.ini + status SVGs) */
#define C_SIDEBAR       "#414141" /* roster bg: themeMedium */
#define C_SIDEBAR_HOVER "#4E4E4E" /* row hover: themeLight */
#define C_BADGE         "#1C1C1C" /* badge/bars: themeDark */
#define C_MAIN_BG       "#FFFFFF"
#define C_MAIN_TEXT     "#333333"
#define C_CHAT_TEXT     "#000000"
#define C_SUBTEXT       "#414141"
#define C_HINT          "#969696"
#define C_LIST_TEXT     "#FFFFFF"
#define C_LIST_SUBTEXT  "#D1D1D1"
#define C_EDGE          "#C0C0C0"
#define C_SEL_BG        "#FFFFFF" /* selected row inverts to white + dark text */
#define C_SEL_FG        "#1C1C1C"
#define C_SEL_SUB       "#414141" /* selected-row status text: statusActive */
#define C_ONLINE        "#6BC260"
#define C_AWAY          "#CDBE41"
#define C_BUSY          "#C84E4E"
#define C_OFFLINE_DOT   "#969696" /* hollow ring drawn in gray (qTox uses red) */

typedef struct Contact {
    uint32_t fn;
    bool is_request;
    char name[TT_NAME_MAX];
    char status_msg[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];
    char key_hex[65];        /* request rows */
    char last[TT_LAST_MAX];  /* list preview */
    int conn;                /* Tox_Connection */
    int presence;            /* Tox_User_Status */
    int unread;
    char avatar_img[48];     /* Tk photo image name, empty = none */
    char transcript[TT_TRANSCRIPT_MAX]; /* lines: "H:MM\x1f<0|1|2|3>\x1f<who>\x1ftext\n"
                                           (1/3 = own; 2/3 = system line) */
    /* pending incoming offer (offer_id = engine xfer id) */
    bool offer_pending;
    unsigned offer_id;
    uint64_t offer_size;
    char offer_name[TOX_MAX_FILENAME_LENGTH + 1];
    /* last (running or finished) transfer for progress/done lines */
    bool xfer_me;            /* own TX when set */
    char xfer_name[TOX_MAX_FILENAME_LENGTH + 1];
    bool xfer_running;       /* transfer in flight (Cancel button shown) */
    unsigned xfer_run_id;    /* its xfer id (cancel targets this) */
    /* receipts: last tox message id sent (0 = none) vs highest read back */
    unsigned last_mid;
    unsigned last_read;
    bool peer_typing;        /* header shows "... is typing" */
    /* call state (engine pushes AV_STATE/AV_INCOMING/AV_ENDED) */
    int call_state;          /* Toxav_Friend_Call_State bitmask; 0 = idle/paused */
    bool call_incoming;      /* banner shown until answered/declined */
    bool call_active;        /* true between SENDING_A/ACCEPTING_A and ENDED */
    bool call_muted;         /* M-AV3: our mic gate while call_active */
    bool call_deaf;          /* M-AV5: our output gate while call_active */
    bool call_video;         /* M-AV5: call negotiated video (pane swap / Video answer) */
    time_t call_started;     /* M-AV5: duration timer base (0 = not ticking) */
    bool call_paused_self;   /* WE paused (Resume valid; peer-paused renders
                                disabled "Peer paused" — toxav resumes only
                                our own pause) */
    bool call_ringing;       /* our CALL posted, no state back yet
                                (button shows Cancel; false on AV_STATE/ENDED) */
    bool e2ee;               /* M5: encrypted session established (🔒 badge) */
    char e2ee_code[33];      /* M5: 32-hex verification code (established) */
    struct Contact *next;
} Contact;

typedef enum { TT_SEL_NONE = 0, TT_SEL_REQUEST, TT_SEL_CHAT, TT_SEL_GROUP } SelKind;

/* group chat session state (engine pushes deltas; roster built from events) */
typedef struct GroupMember {
    uint32_t pid;             /* tox peer id */
    char name[TT_NAME_MAX];
    int role;                 /* Tox_Group_Role */
    bool announce;            /* join announcement pending (name not yet known) */
    struct GroupMember *next;
} GroupMember;

typedef struct Group {
    uint32_t gn;
    char name[TT_NAME_MAX];
    char topic[TOX_GROUP_MAX_TOPIC_LENGTH + 1];
    char chat_id_hex[TOX_GROUP_CHAT_ID_SIZE * 2 + 1]; /* from SYNC burst */
    int self_role;            /* Tox_Group_Role, from SYNC burst */
    int privacy;              /* 0 public, 1 private (NEW event) */
    int voice;                /* Tox_Group_Voice_State (STATE -1 events) */
    int topic_lock;           /* 0/1 (STATE -2 events) */
    int peer_limit;           /* STATE -3 events, 0 = unlimited */
    int unread;
    char last[TT_LAST_MAX];
    char transcript[TT_TRANSCRIPT_MAX]; /* same line format as Contact */
    GroupMember *members;
    struct Group *next;
} Group;

#define TT_MAX_PEERS_ROSTER 512 /* role-map cap for the members dialog */

typedef struct Ui {
    Tcl_Interp *interp;
    TTToxThread *tt;
    Contact *contacts;
    Group *groups;
    SelKind sel_kind;
    uint32_t sel_fn;         /* friend number or group number (by sel_kind) */
    /* typing indicator (1:1): debounce + auto-clear state */
    uint32_t typing_fn;      /* friend we post typing for (UINT32_MAX = none) */
    bool typing_sent;        /* TT_CMD_SET_TYPING 1 posted, stop not yet */
    time_t typing_last;      /* last keystroke observed */
    bool typing_idle_sched;  /* a tt_typing_tick timer is queued */
    bool call_timer_sched;   /* M-AV5: a tt_call_tick timer is queued */
    char self_name[128];
    char self_status_msg[TOX_MAX_STATUS_MESSAGE_LENGTH + 1];
    int self_presence;       /* Tox_User_Status */
    int self_conn;           /* Tox_Connection */
    bool tor_mode;           /* engine confirmed SOCKS5/TCP-only mode */
    char badge_name[128 + 8]; /* badge label with optional TOR prefix */
    char my_toxid[100];
    char filter[80];
    bool ready;
    bool add_open;
    bool name_open;
    bool smsg_open;
    bool st_open;            /* settings dialog (proxy sidecar) */
    bool offer_open;         /* file offer accept/decline dialog */
    bool gnew_open;          /* one dialog instance at a time */
    bool gjoin_open;
    bool ginvite_open;
    bool gtopic_open;
    bool gctl_open;          /* group owner/moderation settings dialog */
    bool quitting;
    char self_avatar_img[48];
    unsigned avatar_seq;     /* unique Tk photo names: av0, av1, ... */
    /* M-AV4 video pane: peer video frames arrive as TT_EV_AV_FRAME (heap);
       the latest frame is held here and painted by a Tk after-timer */
    char video_img[48];      /* Tk photo name ("vid0"), empty = pane hidden */
    unsigned video_seq;      /* photo re-create counter (size changes) */
    bool video_sched;        /* a tt_video_tick timer is queued */
    uint8_t *video_frame;    /* latest YUV420 frame (engine-owned copy) */
    uint16_t video_w, video_h;
    size_t video_cap;        /* allocated frame capacity */
    uint8_t *video_rgb;      /* Tk_PhotoBlock scratch (w*h*4 RGBA) */
    size_t video_rgb_cap;
    time_t video_last;       /* pane auto-hide when frames stop */
    int video_self;          /* M-AV5: pane shows the LOCAL camera (pane swap) */
} Ui;

static Ui g_ui;

/* used by roster_render long before its definition below */
static bool contact_all_read(const Contact *c);
/* used by chead_call_render long before its definition below: the call strip
   packs the avatar FIRST on the right (outermost), then the buttons */
static void chead_avatar_render(Ui *ui, const Contact *c);

/* ---- Tcl plumbing ---- */

static int ev(Ui *ui, int objc, const char *const *argv) {
    Tcl_Interp *ip = ui->interp;
    Tcl_Obj *objv[32];
    if (objc > 32) { /* never drop a command silently: skipped creations
                        segfault later at first use of the missing widget */
        TT_LOG("tk", "cmd too long (%d args): %s", objc, argv[0]);
        return TCL_ERROR;
    }
    for (int i = 0; i < objc; i++) objv[i] = Tcl_NewStringObj(argv[i], -1);
    static int trace = -1; /* TT_TRACE=1: log each cmd pre-execution */
    if (trace < 0) trace = getenv("TT_TRACE") != NULL;
    if (trace) TT_LOG("tk", "trace: %s %s", argv[0], objc > 1 ? argv[1] : "");
    int rc = Tcl_EvalObjv(ip, objc, objv, TCL_EVAL_GLOBAL);
    if (rc != TCL_OK)
        TT_LOG("tk", "cmd failed: %s :: %s", argv[0], Tcl_GetStringResult(ip));
    return rc;
}

#define EV(...) ev(ui, (int)(sizeof (const char *const[]){__VA_ARGS__} / sizeof (const char *)), \
                  (const char *const[]){__VA_ARGS__})

/* "clipboard get" ERRORS when the selection is empty or holds an
   unsupported type (Tk throws "selection doesn't exist" instead of
   returning "") — wrap in catch, read the interp variable, and copy the
   value out immediately (result pointers die at the next EV call) */
static void clipboard_get(Ui *ui, char *out, size_t outsz) {
    out[0] = '\0';
    EV("catch", "clipboard get", "cb");
    if (strcmp(Tcl_GetStringResult(ui->interp), "0") != 0)
        return;
    EV("set", "cb");
    const char *cb = Tcl_GetStringResult(ui->interp);
    int n = snprintf(out, outsz, "%s", cb ? cb : "");
    if (n < 0 || (size_t)n >= outsz) /* oversized clipboard: not a ToxID */
        out[0] = '\0';
    EV("unset", "-nocomplain", "cb");
}

static void bind_cmd(Ui *ui, const char *name, Tcl_ObjCmdProc *proc) {
    Tcl_CreateObjCommand(ui->interp, name, proc, ui, NULL);
}

/* First 76-hex-char span in a pasted string (ToxIDs get copied with
   whitespace/newlines or label prefixes). Returns the span start or NULL.
   The span is NOT NUL-terminated — callers must treat it as 76 chars. */
static const char *toxid_span(const char *s) {
    const size_t want = TOX_ADDRESS_SIZE * 2;
    for (const char *p = s; p[want - 1]; p++) {
        size_t j = 0;
        while (j < want && isxdigit((unsigned char)p[j])) j++;
        if (j == want) return p;
        if (j > 0) p += j - 1;
    }
    return NULL;
}

/* ---- contacts ---- */

static Contact *contact_by_fn(Ui *ui, uint32_t fn) {
    for (Contact *c = ui->contacts; c; c = c->next)
        if (!c->is_request && c->fn == fn) return c;
    return NULL;
}

static Contact *request_row(Ui *ui) {
    for (Contact *c = ui->contacts; c; c = c->next)
        if (c->is_request) return c;
    return NULL;
}

static Contact *contact_add(Ui *ui, uint32_t fn, bool is_request) {
    Contact **pp = &ui->contacts;
    while (*pp) pp = &(*pp)->next;
    Contact *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->fn = fn;
    c->is_request = is_request;
    c->conn = TOX_CONNECTION_NONE;
    c->presence = TOX_USER_STATUS_NONE;
    c->next = *pp;
    *pp = c;
    return c;
}

static void contact_remove(Ui *ui, Contact *dead) {
    Contact **pp = &ui->contacts;
    while (*pp && *pp != dead) pp = &(*pp)->next;
    if (!*pp) return;
    *pp = dead->next;
    if (dead->avatar_img[0]) EV("image", "delete", dead->avatar_img);
    if (dead->offer_pending) /* nobody left to answer the offer */
        tt_queue_post(&ui->tt->in, TT_CMD_FILE_REJECT, 0, NULL, (int)dead->offer_id);
    free(dead);
}

/* case-insensitive substring (ASCII), avoids GNU strcasestr */
static const char *stristr(const char *hay, const char *needle) {
    if (!*needle) return hay;
    for (; *hay; hay++) {
        size_t i = 0;
        while (hay[i] && needle[i] &&
               tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (!needle[i]) return hay;
    }
    return NULL;
}

/* ---- groups ---- */

static Group *group_by_gn(Ui *ui, uint32_t gn) {
    for (Group *g = ui->groups; g; g = g->next)
        if (g->gn == gn) return g;
    return NULL;
}

static Group *group_add(Ui *ui, uint32_t gn) {
    Group **pp = &ui->groups;
    while (*pp) pp = &(*pp)->next;
    Group *g = calloc(1, sizeof *g);
    if (!g) return NULL;
    g->gn = gn;
    g->self_role = TOX_GROUP_ROLE_USER;
    g->next = *pp;
    *pp = g;
    return g;
}

static void group_remove(Ui *ui, Group *dead) {
    Group **pp = &ui->groups;
    while (*pp && *pp != dead) pp = &(*pp)->next;
    if (!*pp) return;
    *pp = dead->next;
    while (dead->members) {
        GroupMember *m = dead->members;
        dead->members = m->next;
        free(m);
    }
    free(dead);
}

static GroupMember *group_member(Group *g, uint32_t pid) {
    for (GroupMember *m = g->members; m; m = m->next)
        if (m->pid == pid) return m;
    return NULL;
}

static GroupMember *group_member_upsert(Ui *ui, Group *g, uint32_t pid) {
    GroupMember *m = group_member(g, pid);
    if (m) return m;
    m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->pid = pid;
    m->role = TOX_GROUP_ROLE_USER;
    GroupMember **pp = &g->members;
    while (*pp) pp = &(*pp)->next;
    *pp = m;
    (void)ui;
    return m;
}

static const char *role_str(int role) {
    switch (role) {
    case TOX_GROUP_ROLE_FOUNDER: return "founder";
    case TOX_GROUP_ROLE_MODERATOR: return "moderator";
    case TOX_GROUP_ROLE_USER: return "user";
    case TOX_GROUP_ROLE_OBSERVER: return "observer";
    default: return "?";
    }
}

static const char *mod_event_str(int ev) {
    switch (ev) {
    case TOX_GROUP_MOD_EVENT_KICK: return "kicked";
    case TOX_GROUP_MOD_EVENT_OBSERVER: return "demoted to observer";
    case TOX_GROUP_MOD_EVENT_USER: return "set to user";
    case TOX_GROUP_MOD_EVENT_MODERATOR: return "promoted to moderator";
    default: return "moderated";
    }
}

static const char *exit_type_str(int t) {
    switch (t) {
    case TOX_GROUP_EXIT_TYPE_QUIT: return "left";
    case TOX_GROUP_EXIT_TYPE_TIMEOUT: return "timed out";
    case TOX_GROUP_EXIT_TYPE_DISCONNECTED: return "disconnected";
    case TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED: return "lost connection";
    case TOX_GROUP_EXIT_TYPE_KICK: return "was kicked";
    case TOX_GROUP_EXIT_TYPE_SYNC_ERROR: return "sync error";
    default: return "left";
    }
}

static const char *presence_str(int presence, int conn) {
    if (conn == TOX_CONNECTION_NONE) return "offline";
    switch (presence) {
    case TOX_USER_STATUS_AWAY: return "away";
    case TOX_USER_STATUS_BUSY: return "busy";
    default: return "online";
    }
}

/* dot image index for a presence state (images created in roster_colors) */
static int presence_dot(int presence, int conn) {
    if (conn == TOX_CONNECTION_NONE) return 3;
    switch (presence) {
    case TOX_USER_STATUS_AWAY: return 1;
    case TOX_USER_STATUS_BUSY: return 2;
    default: return 0;
    }
}

static const char *presence_color(int presence, int conn) {
    static const char *const colors[] = {C_ONLINE, C_AWAY, C_BUSY, C_OFFLINE_DOT};
    return colors[presence_dot(presence, conn)];
}

static const char *conn_str(int conn) {
    switch (conn) {
    case TOX_CONNECTION_NONE: return "offline";
    case TOX_CONNECTION_TCP:  return "online (tcp)";
    case TOX_CONNECTION_UDP:  return "online";
    default: return "?";
    }
}

static Contact *contact_by_iid(Ui *ui, const char *iid) {
    if (!iid) return NULL;
    if (strncmp(iid, "req", 3) == 0) return request_row(ui);
    if (iid[0] != 'f') return NULL;
    return contact_by_fn(ui, (uint32_t)strtoul(iid + 1, NULL, 10));
}

/* group row iid: "g<group number>"; strict: "g" alone (the GROUPS header
   row) or garbage after 'g' resolves to nothing, never group 0 */
static Group *group_by_iid(Ui *ui, const char *iid) {
    if (!iid || iid[0] != 'g' || !iid[1]) return NULL;
    for (const char *q = iid + 1; *q; q++)
        if (*q < '0' || *q > '9') return NULL;
    return group_by_gn(ui, (uint32_t)strtoul(iid + 1, NULL, 10));
}

/* create a Tk photo from PNG bytes; returns the photo name via out
   (unique "av<N>") or empty string on failure. -subsample picks a
   pixel grid so the photo is square ~36px regardless of source size. */
static void avatar_photo_create(Ui *ui, const char *png, size_t len, char *out, size_t cap) {
    out[0] = '\0';
    if (!png || len < 8) return;
    char name[12];
    snprintf(name, sizeof name, "av%u", ++ui->avatar_seq);
    EV("image", "create", "photo", name);
    /* binary PNG via -data would need base64; PNG base64 costs ~1.37x but
       stays well within the 64KB engine cap; Tcl_Obj bytes path avoided */
    char *b64 = malloc((len + 2) / 3 * 4 + 1);
    if (!b64) return;
    static const char *const tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = (unsigned)png[i] << 16;
        int pad = 0;
        if (i + 1 < len) v |= (unsigned)png[i + 1] << 8; else pad++;
        if (i + 2 < len) v |= (unsigned)png[i + 2]; else pad++;
        b64[o++] = tbl[(v >> 18) & 63];
        b64[o++] = tbl[(v >> 12) & 63];
        b64[o++] = pad > 1 ? '=' : tbl[(v >> 6) & 63];
        b64[o++] = pad > 0 ? '=' : tbl[v & 63];
    }
    b64[o] = '\0';
    EV(name, "configure", "-data", b64);
    /* dimensions come from the generic image command; the photo itself has
       no width/height subcommands (that misfire deleted valid photos) */
    EV("image", "width", name);
    int w = atoi(Tcl_GetStringResult(ui->interp));
    EV("image", "height", name);
    int h = atoi(Tcl_GetStringResult(ui->interp));
    if (w < 1 || h < 1) {          /* decode failed */
        EV("image", "delete", name);
        free(b64);
        out[0] = '\0';
        return;
    }
    int ss = 1;
    int mx = w > h ? w : h;
    while (mx / (ss + 1) >= 36) ss++; /* box-sample downscale to ~36px */
    if (ss > 1) {
        char fs[12];
        snprintf(fs, sizeof fs, "%d", ss);
        /* in-place self-copy is unsafe: bounce through a temp photo */
        EV("image", "create", "photo", "avtmp");
        EV("avtmp", "copy", name, "-subsample", fs, fs);
        EV(name, "copy", "avtmp");
        EV("image", "delete", "avtmp");
    }
    snprintf(out, cap, "%s", name);
    free(b64);
}/* ---- roster rendering (tree with presence-colored rows) ---- */

static void roster_render(Ui *ui);
static void show_selected(Ui *ui);
/* M-AV4: TT_EV_AV_FRAME sink (video pane; defined below) */
static void video_frame_take(Ui *ui, const TTEvent *e);
static const char *conn_str(int conn);
static Contact *contact_by_iid(Ui *ui, const char *iid);
static int cc_add_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]);

static void roster_render(Ui *ui) {
    SelKind keep_kind = ui->sel_kind;
    uint32_t keep_fn = ui->sel_fn;
    char keep_iid[16] = {0};
    bool have_keep = false;

    /* clear: delete with an empty item list is a no-op, so pass the
       current top-level children (root is the empty string) */
    EV(".sb.rf.roster", "children", "");
    EV(".sb.rf.roster", "delete", Tcl_GetStringResult(ui->interp));

    for (Contact *c = ui->contacts; c; c = c->next) {
        char iid[16];
        if (c->is_request) {
            snprintf(iid, sizeof iid, "req");
            if (keep_kind == TT_SEL_REQUEST) { have_keep = true; snprintf(keep_iid, sizeof keep_iid, "%s", iid); }
            EV(".sb.rf.roster", "insert", "", "end", "-id", iid, "-text", "+ friend request",
               "-open", "false");
            continue;
        }
        if (ui->filter[0] &&
            !stristr(c->name, ui->filter) && !stristr(c->status_msg, ui->filter)) {
            continue;
        }
        snprintf(iid, sizeof iid, "f%u", c->fn);
        if (keep_kind == TT_SEL_CHAT && c->fn == keep_fn) {
            have_keep = true;
            snprintf(keep_iid, sizeof keep_iid, "%s", iid);
        }
        char sub[TOX_MAX_STATUS_MESSAGE_LENGTH + TT_LAST_MAX + 64];
        if (c->last[0])
            snprintf(sub, sizeof sub, "%s  \xc2\xb7  %s", c->last,
                     presence_str(c->presence, c->conn));
        else
            snprintf(sub, sizeof sub, "%s",
                     c->status_msg[0] ? c->status_msg : presence_str(c->presence, c->conn));
        /* uTox two-line look as ONE item: "name\nsubline". A child item would
           add an expander arrow and a selectable sub-row (phantom clicks). */
        char rowtext[TT_NAME_MAX + TOX_MAX_STATUS_MESSAGE_LENGTH + TT_LAST_MAX + 128];
        const char *disp = c->name[0] ? c->name : "unknown";
        /* callmark follows the call sub-state: 🔔 ringing (incoming or our
           unanswered CALL), ⏸ paused, 📞 active */
        const char *callmark = "";
        if (c->call_active) {
            bool rpaused = !(c->call_state &
                (TOXAV_FRIEND_CALL_STATE_SENDING_A | TOXAV_FRIEND_CALL_STATE_ACCEPTING_A));
            callmark = rpaused ? " \xe2\x8f\xb8" : " \xf0\x9f\x93\x9e";
        } else if (c->call_ringing || c->call_incoming) {
            callmark = " \xf0\x9f\x94\x94";
        }
        /* M5: 🔒 badge for an established encrypted session (callmark-style) */
        const char *lockmark = c->e2ee ? " \xf0\x9f\x94\x92" : "";
        if (c->unread > 0)
            snprintf(rowtext, sizeof rowtext, "%s%s%s (%d)\n%s", disp, lockmark,
                     callmark, c->unread, sub);
        else if (c->last[0] && contact_all_read(c))
            /* last message confirmed read by the friend */
            snprintf(rowtext, sizeof rowtext, "\xe2\x9c\x93 %s%s%s\n%s", disp,
                     lockmark, callmark, sub);
        else
            snprintf(rowtext, sizeof rowtext, "%s%s%s\n%s", disp, lockmark,
                     callmark, sub);
        char imgname[8];
        snprintf(imgname, sizeof imgname, "pdot%d", presence_dot(c->presence, c->conn));
        EV(".sb.rf.roster", "insert", "", "end", "-id", iid, "-text", rowtext,
           "-image", imgname, "-open", "false");
    }

    /* groups section: header row + chat-bubble glyph so group rows read as
       a distinct section, not more friends */
    unsigned nvis_groups = 0;
    for (Group *g = ui->groups; g; g = g->next) {
        if (ui->filter[0] && !stristr(g->name, ui->filter) &&
            !stristr(g->topic, ui->filter)) {
            continue;
        }
        nvis_groups++;
    }
    if (nvis_groups) {
        EV(".sb.rf.roster", "insert", "", "end", "-id", "gheads", "-text", "GROUPS",
           "-open", "false", "-tags", "ghead");
    }
    for (Group *g = ui->groups; g; g = g->next) {
        if (ui->filter[0] && !stristr(g->name, ui->filter) &&
            !stristr(g->topic, ui->filter)) {
            continue;
        }
        char iid[16];
        snprintf(iid, sizeof iid, "g%u", g->gn);
        if (keep_kind == TT_SEL_GROUP && g->gn == keep_fn) {
            have_keep = true;
            snprintf(keep_iid, sizeof keep_iid, "%s", iid);
        }
        char sub[TT_LAST_MAX + TOX_GROUP_MAX_TOPIC_LENGTH + 48];
        if (g->last[0])
            snprintf(sub, sizeof sub, "%s  \xc2\xb7  %s", g->last,
                     g->privacy ? "private" : "public");
        else
            snprintf(sub, sizeof sub, "%s",
                     g->topic[0] ? g->topic : (g->privacy ? "private group" : "public group"));
        char rowtext[TT_NAME_MAX + TT_LAST_MAX + TOX_GROUP_MAX_TOPIC_LENGTH + 80];
        const char *disp = g->name[0] ? g->name : "group";
        if (g->unread > 0)
            snprintf(rowtext, sizeof rowtext, "%s (%d)\n%s", disp, g->unread, sub);
        else
            snprintf(rowtext, sizeof rowtext, "%s\n%s", disp, sub);
        EV(".sb.rf.roster", "insert", "", "end", "-id", iid, "-text", rowtext,
           "-image", "gdot", "-open", "false");
    }

    if (have_keep) {
        EV(".sb.rf.roster", "selection", "set", keep_iid);
        EV(".sb.rf.roster", "see", keep_iid);
    } else if (ui->sel_kind != TT_SEL_NONE) {
        ui->sel_kind = TT_SEL_NONE;
        show_selected(ui);
    }
}

static void roster_colors(Ui *ui) {
    /* per-presence row colors via ttk::treeview tags */
    /* group section header: small caps look, never a presence color */
    EV(".sb.rf.roster", "tag", "configure", "ghead", "-foreground", C_HINT,
       "-font", "f_small");
    EV(".sb.rf.roster", "tag", "configure", "st0", "-foreground", C_ONLINE);
    EV(".sb.rf.roster", "tag", "configure", "st1", "-foreground", C_AWAY);
    EV(".sb.rf.roster", "tag", "configure", "st2", "-foreground", C_BUSY);
    EV(".sb.rf.roster", "tag", "configure", "st3", "-foreground", C_OFFLINE_DOT);

    /* presence dots as treeview -image: transparent 9x11 GIFs shaped like
       qTox's status SVGs in img/status, so states survive on any bg:
       online solid disc, away ring with filled top half, busy ring with a
       horizontal bar, offline hollow ring. Uncompressed LZW keeps the
       encoder trivial; photos pdot<i> bind to rows via -image. */
    static const unsigned char dot_rgb[4][3] = {
        {0x6B, 0xC2, 0x60}, /* online  */
        {0xCD, 0xBE, 0x41}, /* away    */
        {0xC8, 0x4E, 0x4E}, /* busy    */
        {0x96, 0x96, 0x96}, /* offline */
    };
    for (int i = 0; i < 4; i++) {
        unsigned char gif[128];
        unsigned char *p = gif;
        *p++ = 'G'; *p++ = 'I'; *p++ = 'F'; *p++ = '8'; *p++ = '9'; *p++ = 'a';
        *p++ = 9;  *p++ = 0;   /* width  */
        *p++ = 11; *p++ = 0;   /* height */
        *p++ = 0x80;           /* GCT flag, 2 entries */
        *p++ = 0;  *p++ = 0;   /* bg, aspect */
        *p++ = 0;   *p++ = 0;   *p++ = 0;         /* color 0: transparent slot */
        *p++ = dot_rgb[i][0]; *p++ = dot_rgb[i][1]; *p++ = dot_rgb[i][2];
        *p++ = 0x21; *p++ = 0xF9; *p++ = 4;       /* graphic control ext */
        *p++ = 0x01;                              /* transparent index 0 */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
        *p++ = 0x2C;                              /* image descriptor */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;   /* left, top */
        *p++ = 9;  *p++ = 0;                      /* width  */
        *p++ = 11; *p++ = 0;                      /* height */
        *p++ = 0;                                 /* packed */
        *p++ = 2;                                 /* LZW min code size */
        unsigned acc = 0, nbits = 0;
        unsigned char bits[96];
        size_t bn = 0;
        for (int y = 0; y < 11; y++) {
            for (int x = 0; x < 9; x++) {
                int dx = x - 4, dy = y - 5;
                int d2 = dx * dx + dy * dy;
                int on;
                switch (i) {
                case 1: on = d2 <= 20 && (d2 >= 8 || dy < 0); break;  /* away */
                case 2: on = d2 <= 20 && (d2 >= 8 || (dy >= -1 && dy <= 1)); break; /* busy */
                case 3: on = d2 <= 20 && d2 >= 8; break;              /* offline ring */
                default: on = d2 <= 20; break;                        /* online */
                }
                /* uncompressed LZW: clear before every literal, 3-bit codes */
                acc |= 4u << nbits; nbits += 3;
                acc |= (unsigned)(on ? 1 : 0) << nbits; nbits += 3;
                while (nbits >= 8) {
                    bits[bn++] = (unsigned char)(acc & 0xFF);
                    acc >>= 8; nbits -= 8;
                }
            }
        }
        if (nbits) bits[bn++] = (unsigned char)(acc & 0xFF);
        *p++ = (unsigned char)bn;
        memcpy(p, bits, bn); p += bn;
        *p++ = 0;   /* block terminator */
        *p++ = 0x3B; /* trailer */
        char b64[180];
        static const char t[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t n = (size_t)(p - gif), o = 0;
        for (size_t k = 0; k + 2 < n; k += 3) {
            unsigned v = (gif[k] << 16) | (gif[k + 1] << 8) | gif[k + 2];
            b64[o++] = t[(v >> 18) & 63]; b64[o++] = t[(v >> 12) & 63];
            b64[o++] = t[(v >> 6) & 63];  b64[o++] = t[v & 63];
        }
        size_t rem = n % 3;
        if (rem) {
            unsigned v = gif[n - rem] << 16;
            if (rem == 2) v |= gif[n - 1] << 8;
            b64[o++] = t[(v >> 18) & 63]; b64[o++] = t[(v >> 12) & 63];
            b64[o++] = rem == 2 ? t[(v >> 6) & 63] : '=';
            b64[o++] = '=';
        }
        b64[o] = '\0';
        char name[8];
        snprintf(name, sizeof name, "pdot%d", i);
        EV("image", "create", "photo", name, "-data", b64);
    }

    /* group rows: a small chat-bubble glyph instead of a presence dot, so
       groups are visually distinct from friends (same GIF technique) */
    {
        unsigned char gif[128];
        unsigned char *p = gif;
        *p++ = 'G'; *p++ = 'I'; *p++ = 'F'; *p++ = '8'; *p++ = '9'; *p++ = 'a';
        *p++ = 9;  *p++ = 0;   /* width  */
        *p++ = 11; *p++ = 0;   /* height */
        *p++ = 0x80;           /* GCT flag, 2 entries */
        *p++ = 0;  *p++ = 0;   /* bg, aspect */
        *p++ = 0;   *p++ = 0;   *p++ = 0;         /* color 0: transparent slot */
        *p++ = 0x7E; *p++ = 0x7E; *p++ = 0x7E;    /* color 1: mid gray bubble */
        *p++ = 0x21; *p++ = 0xF9; *p++ = 4;       /* graphic control ext */
        *p++ = 0x01;                              /* transparent index 0 */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
        *p++ = 0x2C;                              /* image descriptor */
        *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;   /* left, top */
        *p++ = 9;  *p++ = 0;                      /* width  */
        *p++ = 11; *p++ = 0;                      /* height */
        *p++ = 0;                                 /* packed */
        *p++ = 2;                                 /* LZW min code size */
        unsigned acc = 0, nbits = 0;
        unsigned char bits[96];
        size_t bn = 0;
        for (int y = 0; y < 11; y++) {
            for (int x = 0; x < 9; x++) {
                /* rounded speech-bubble body (rows 0..7) with a tail toward
                   bottom-left, distinct from the presence discs */
                int on;
                if (y <= 7)
                    on = !(y == 0 && (x <= 1 || x >= 7)) &&
                         !(y == 7 && (x <= 1 || x >= 7)) &&
                         !(y >= 1 && y <= 6 && (x == 0 || x == 8) &&
                           !(y == 3 || y == 4));
                else if (y == 8) on = x >= 1 && x <= 4;
                else if (y == 9) on = x >= 1 && x <= 2;
                else on = 0;
                /* uncompressed LZW: clear before every literal, 3-bit codes */
                acc |= 4u << nbits; nbits += 3;
                acc |= (unsigned)(on ? 1 : 0) << nbits; nbits += 3;
                while (nbits >= 8) {
                    bits[bn++] = (unsigned char)(acc & 0xFF);
                    acc >>= 8; nbits -= 8;
                }
            }
        }
        if (nbits) bits[bn++] = (unsigned char)(acc & 0xFF);
        *p++ = (unsigned char)bn;
        memcpy(p, bits, bn); p += bn;
        *p++ = 0;   /* block terminator */
        *p++ = 0x3B; /* trailer */
        char b64[180];
        static const char t[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t n = (size_t)(p - gif), o = 0;
        for (size_t k = 0; k + 2 < n; k += 3) {
            unsigned v = (gif[k] << 16) | (gif[k + 1] << 8) | gif[k + 2];
            b64[o++] = t[(v >> 18) & 63]; b64[o++] = t[(v >> 12) & 63];
            b64[o++] = t[(v >> 6) & 63];  b64[o++] = t[v & 63];
        }
        size_t rem = n % 3;
        if (rem) {
            unsigned v = gif[n - rem] << 16;
            if (rem == 2) v |= gif[n - 1] << 8;
            b64[o++] = t[(v >> 18) & 63]; b64[o++] = t[(v >> 12) & 63];
            b64[o++] = rem == 2 ? t[(v >> 6) & 63] : '=';
            b64[o++] = '=';
        }
        b64[o] = '\0';
        EV("image", "create", "photo", "gdot", "-data", b64);
    }
    (void)ui;
}

/* ---- transcript helpers ---- */

/* ASCII emoticon -> Unicode, applied on send (qTox-style substitution) */
static const struct { const char *pat, *uni; } EMOTICONS[] = {
    {":'(", "\xf0\x9f\x98\xa2"}, {">:(", "\xf0\x9f\x98\xa0"},
    {":-)", "\xf0\x9f\x99\x82"}, {":-(", "\xf0\x9f\x99\x81"},
    {":-D", "\xf0\x9f\x98\x84"}, {";-)", "\xf0\x9f\x98\x89"},
    {":)", "\xf0\x9f\x99\x82"}, {":(", "\xf0\x9f\x99\x81"},
    {";)", "\xf0\x9f\x98\x89"}, {":D", "\xf0\x9f\x98\x84"},
    {":P", "\xf0\x9f\x98\x9b"}, {";P", "\xf0\x9f\x98\x9c"},
    {":o", "\xf0\x9f\x98\xae"}, {":*", "\xf0\x9f\x98\x98"},
    {"<3", "\xf0\x9f\x92\x9a"}, {":/", "\xf0\x9f\x99\x8d"},
    {":|", "\xf0\x9f\x98\x90"}, {"B)", "\xf0\x9f\x98\x8e"},
};

/* replace ASCII patterns with Unicode emoji, longest match first */
static void emotify(char *buf, size_t cap) {
    char out[TOX_MAX_MESSAGE_LENGTH * 4 + 8];
    size_t o = 0;
    for (size_t i = 0; buf[i]; i++) {
        const char *rep = NULL;
        size_t rlen = 0;
        for (size_t k = 0; k < sizeof EMOTICONS / sizeof EMOTICONS[0]; k++) {
            size_t pl = strlen(EMOTICONS[k].pat);
            if (strncmp(buf + i, EMOTICONS[k].pat, pl) == 0 &&
                pl > rlen) {
                rlen = pl;
                rep = EMOTICONS[k].uni;
            }
        }
        if (rep) {
            size_t ul = strlen(rep);
            if (o + ul >= sizeof out) break;
            memcpy(out + o, rep, ul);
            o += ul;
            i += rlen - 1;
        } else if (o + 1 < sizeof out) {
            out[o++] = buf[i];
        }
    }
    out[o] = '\0';
    snprintf(buf, cap, "%s", out);
}

static void now_stamp(char *out, size_t cap) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(out, cap, "%H:%M", &tmv);
}

/* line format: "H:MM\x1f<1|0>\x1f<who>\x1f<text>\n" — flag 1 = own message.
   transcript + last preview live in both Contact and Group; pass them
   explicitly so one implementation serves both rosters. */
static void transcript_append(char *transcript, char *last,
                              const char *who, int me, const char *text) {
    char stamp[16];
    now_stamp(stamp, sizeof stamp);

    size_t need = strlen(stamp) + strlen(who) + strlen(text) + 8;
    size_t len = strlen(transcript);
    if (len + need >= TT_TRANSCRIPT_MAX) {
        size_t off = 0;
        while (transcript[off] && len - off + need >= TT_TRANSCRIPT_MAX) {
            const char *nl = strchr(transcript + off, '\n');
            if (!nl) { off = len; break; }
            off = (size_t)(nl - transcript) + 1;
        }
        memmove(transcript, transcript + off, len - off + 1);
    }
    size_t used = strlen(transcript);
    size_t cap = TT_TRANSCRIPT_MAX - used;
    int w = snprintf(transcript + used, cap, "%s\x1f%d\x1f%s\x1f%s\n",
                     stamp, me ? 1 : 0, who, text);
    if (w > 0 && (size_t)w >= cap && cap >= 2) {
        transcript[used + cap - 2] = '\n';
        transcript[used + cap - 1] = '\0';
    }
    snprintf(last, TT_LAST_MAX, "%s", text);
}

static void chat_append(Contact *c, const char *who, int me, const char *text) {
    transcript_append(c->transcript, c->last, who, me, text);
}

static void group_append(Group *g, const char *who, int me, const char *text) {
    transcript_append(g->transcript, g->last, who, me, text);
}

static void hist_tabs_update(Ui *ui) {
    EV("winfo", "width", ".main.chat.hf.hist");
    int wiw = atoi(Tcl_GetStringResult(ui->interp));
    if (wiw < 200) wiw = 600; /* pre-pack Configure order: width still 1 */
    /* stop is relative to the text area (widget -padx 10 excluded); right
       edge of stamp lands on the rmargin 6 */
    char buf[32];
    snprintf(buf, sizeof buf, "%d right", wiw - 26);
    EV(".main.chat.hf.hist", "tag", "configure", "stamp", "-tabs", buf);
}

static int cc_hist_resize(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    hist_tabs_update(ui);
    return TCL_OK;
}

/* system line (file transfers): no author, small gray text, own = "you" */
static void chat_append_sys(Contact *c, int me, const char *text) {
    chat_append(c, me ? "you" : "", 2 + me, text);
}

/* our sent messages vs the friend's read receipts: true once the highest
   read id reaches the last sent id */
static bool contact_all_read(const Contact *c) {
    return c->last_mid != 0 && c->last_read >= c->last_mid;
}

/* typing indicator in the chat header: "... is typing" while active */
#define TT_TYPING_TIMEOUT 5 /* seconds of keystroke silence -> stop typing */
static void chead_typing_render(Ui *ui, const Contact *c) {
    if (ui->sel_kind != TT_SEL_CHAT || ui->sel_fn != c->fn) return;
    EV(".main.chat.chead.t.smsg", "configure", "-text",
       c->peer_typing ? "is typing..." : (c->status_msg[0] ? c->status_msg
                                                           : conn_str(c->conn)));
}

/* call buttons in the chat header: state machine (emoji + side-explicit text;
   a call has two mutes and they must never be confusable: 🎤 = our mic,
   🔊/🔇 = our speaker)
   idle -> [📞 Call]; ringing -> [📵 Cancel]; incoming -> [✅ Answer][✖ Decline]
   (+ [📹 Video] when offered); active -> [📵 Hang up][⏸ Pause|▶ Resume]
   [🎤 Mute/Unmute][🔊 Mute out/🔇 Unmute out] (+ [🔄 Show …] when video);
   peer-paused -> [📵 Hang up][⏸ Peer paused (disabled)] + mutes
   Pack geometry: for -side right the FIRST-packed slave is outermost, and a
   forget+repack APPENDS to the end of the order (innermost) — so this is a
   FULL deterministic re-render: forget the whole strip (avatar included),
   pack the avatar first (outermost right), then the buttons in a fixed
   order. Partial re-packs would drift the order with every event. */
static void chead_call_render(Ui *ui, const Contact *c) {
    if (ui->sel_kind != TT_SEL_CHAT || ui->sel_fn != c->fn) return;
    bool paused = c->call_active && !(c->call_state &
        (TOXAV_FRIEND_CALL_STATE_SENDING_A | TOXAV_FRIEND_CALL_STATE_ACCEPTING_A));
    EV("pack", "forget", ".main.chat.chead.call");
    EV("pack", "forget", ".main.chat.chead.pause");
    EV("pack", "forget", ".main.chat.chead.mute");
    EV("pack", "forget", ".main.chat.chead.deaf");
    EV("pack", "forget", ".main.chat.chead.self");
    EV("pack", "forget", ".main.chat.chead.answ");
    EV("pack", "forget", ".main.chat.chead.decl");
    EV("pack", "forget", ".main.chat.chead.avatar");
    chead_avatar_render(ui, c); /* FIRST on the right = outermost */
    if (c->call_incoming) {
        EV(".main.chat.chead.self", "configure", "-text", "📹 Video");
        /* M-AV5: Video appears only when the peer offered video */
        EV(".main.chat.chead.self", "configure", "-state",
           c->call_video ? "normal" : "disabled");
        EV("pack", ".main.chat.chead.self", "-side", "right", "-padx", "2");
        EV(".main.chat.chead.answ", "configure", "-text", "✅ Answer");
        EV(".main.chat.chead.answ", "configure", "-state", "normal");
        EV("pack", ".main.chat.chead.answ", "-side", "right", "-padx", "2");
        EV(".main.chat.chead.decl", "configure", "-text", "✖ Decline");
        EV(".main.chat.chead.decl", "configure", "-state", "normal");
        EV("pack", ".main.chat.chead.decl", "-side", "right", "-padx", "2");
    } else if (c->call_active) {
        EV(".main.chat.chead.call", "configure", "-text", "📵 Hang up");
        EV("pack", ".main.chat.chead.call", "-side", "right", "-padx", "6");
        /* paused (state 0): OUR pause -> Resume; the peer's -> no resume
           from here (toxav RESUME restores only OUR OWN pause) */
        if (paused && !c->call_paused_self) {
            EV(".main.chat.chead.pause", "configure", "-text", "⏸ Peer paused");
            EV(".main.chat.chead.pause", "configure", "-state", "disabled");
        } else {
            EV(".main.chat.chead.pause", "configure",
               "-text", paused ? "▶ Resume" : "⏸ Pause");
            EV(".main.chat.chead.pause", "configure", "-state", "normal");
        }
        EV("pack", ".main.chat.chead.pause", "-side", "right", "-padx", "2");
        EV(".main.chat.chead.mute", "configure", "-text",
           c->call_muted ? "🎤 Unmute" : "🎤 Mute");
        EV("pack", ".main.chat.chead.mute", "-side", "right", "-padx", "2");
        /* output gate: independent of the mic gate (M-AV5) */
        EV(".main.chat.chead.deaf", "configure", "-text",
           c->call_deaf ? "🔇 Unmute out" : "🔊 Mute out");
        EV("pack", ".main.chat.chead.deaf", "-side", "right", "-padx", "2");
        /* M-AV5 pane swap: visible only while the call carries video */
        if (c->call_video && !paused) {
            EV(".main.chat.chead.self", "configure", "-text",
               ui->video_self ? "🔄 Show peer" : "🔄 Show self");
            EV("pack", ".main.chat.chead.self", "-side", "right", "-padx", "2");
        }
    } else if (c->call_ringing) {
        EV(".main.chat.chead.call", "configure", "-text", "📵 Cancel");
        EV("pack", ".main.chat.chead.call", "-side", "right", "-padx", "6");
    } else {
        EV(".main.chat.chead.call", "configure", "-text", "📞 Call");
        EV("pack", ".main.chat.chead.call", "-side", "right", "-padx", "6");
    }
}

/* non-chat selections have no call buttons (groups/requests/empty) */
static void chead_call_render_off(Ui *ui) {
    (void)ui;
    EV("pack", "forget", ".main.chat.chead.call");
    EV("pack", "forget", ".main.chat.chead.pause");
    EV("pack", "forget", ".main.chat.chead.mute");
    EV("pack", "forget", ".main.chat.chead.deaf");
    EV("pack", "forget", ".main.chat.chead.self");
    EV("pack", "forget", ".main.chat.chead.answ");
    EV("pack", "forget", ".main.chat.chead.decl");
}

/* AV command posts (audio-only for now; video pick-up lands with M-AV4) */
static void cc_call(Ui *ui, int type, int audio, int video) {
    if (ui->sel_kind != TT_SEL_CHAT) return;
    Contact *c = contact_by_fn(ui, ui->sel_fn);
    if (!c) return;
    tt_queue_post2(&ui->tt->in, type, ui->sel_fn, "", audio, video);
    (void)c;
}

static void group_append_sys(Group *g, int me, const char *text) {
    group_append(g, me ? "you" : "", 2 + me, text);
}

/* one rendered history line; returns the tag suffix for the author ("who_me"
   vs "who") and whether this is a system line (flag 2/3) */
static void hist_line_classify(char *f1, const char **who_tag, bool *sys) {
    char fl = f1[1];
    *sys = fl == '2' || fl == '3';
    *who_tag = *sys ? "" : (fl == '1' ? "who_me" : "who");
}

static void hist_render(Ui *ui, const char *transcript) {
    EV(".main.chat.hf.hist", "configure", "-state", "normal");
    EV(".main.chat.hf.hist", "delete", "1.0", "end");
    hist_tabs_update(ui);
    const char *p = transcript;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        size_t n = linelen < sizeof line - 1 ? linelen : sizeof line - 1;
        memcpy(line, p, n);
        line[n] = '\0';
        char *f1 = strchr(line, '\x1f');
        char *f2 = f1 ? strchr(f1 + 1, '\x1f') : NULL;
        char *f3 = f2 ? strchr(f2 + 1, '\x1f') : NULL;
        if (f1 && f2 && f3) {
            *f1 = '\0'; *f2 = '\0'; *f3 = '\0';
            const char *who = f2 + 1, *body = f3 + 1;
            const char *who_tag;
            bool sys;
            hist_line_classify(f1, &who_tag, &sys);
            if (sys) { /* no author header: one gray line */
                EV(".main.chat.hf.hist", "insert", "end", body, "sys");
                EV(".main.chat.hf.hist", "insert", "end", "\n", "gap");
            } else {
                EV(".main.chat.hf.hist", "insert", "end", who, who_tag);
                EV(".main.chat.hf.hist", "insert", "end", "\t", "stamp");
                EV(".main.chat.hf.hist", "insert", "end", line, "stamp");
                EV(".main.chat.hf.hist", "insert", "end", "\n");
                EV(".main.chat.hf.hist", "insert", "end", body, "msg");
                EV(".main.chat.hf.hist", "insert", "end", "\n", "gap");
            }
        } else {
            EV(".main.chat.hf.hist", "insert", "end", line);
            EV(".main.chat.hf.hist", "insert", "end", "\n");
        }
        if (!nl) break;
        p = nl + 1;
    }
    EV(".main.chat.hf.hist", "configure", "-state", "disabled");
    EV(".main.chat.hf.hist", "see", "end");
}

static void hist_append_live(Ui *ui, const char *who, int me, const char *text) {
    char stamp[16];
    now_stamp(stamp, sizeof stamp);
    bool sys = (me & 2) != 0; /* flag 2/3: system line, no author header */
    EV(".main.chat.hf.hist", "configure", "-state", "normal");
    if (sys) {
        EV(".main.chat.hf.hist", "insert", "end", text, "sys");
        EV(".main.chat.hf.hist", "insert", "end", "\n", "gap");
    } else {
        EV(".main.chat.hf.hist", "insert", "end", who, me ? "who_me" : "who");
        EV(".main.chat.hf.hist", "insert", "end", "\t", "stamp");
        EV(".main.chat.hf.hist", "insert", "end", stamp, "stamp");
        EV(".main.chat.hf.hist", "insert", "end", "\n");
        EV(".main.chat.hf.hist", "insert", "end", text, "msg");
        EV(".main.chat.hf.hist", "insert", "end", "\n", "gap");
    }
    EV(".main.chat.hf.hist", "configure", "-state", "disabled");
    EV(".main.chat.hf.hist", "see", "end");
}

/* ---- pane switching ---- */

/* M-AV5: 1 s duration ticker for the selected contact's active call */
static void call_tick(Ui *ui, Contact *c) {
    char ms[8];
    snprintf(ms, sizeof ms, "%d", 1000);
    EV("after", ms, "tt_call_tick"); /* re-queue first: never stall the chain */
    ui->call_timer_sched = true;
    if (!c || !c->call_active || c->call_started == 0) return;
    long s = (long)(time(NULL) - c->call_started);
    bool paused = !(c->call_state &
        (TOXAV_FRIEND_CALL_STATE_SENDING_A | TOXAV_FRIEND_CALL_STATE_ACCEPTING_A));
    char line[40];
    snprintf(line, sizeof line, paused ? "%ld:%02ld paused" : "%ld:%02ld on call",
             s / 60, s % 60);
    EV(".main.chat.chead.t.smsg", "configure", "-text", line);
}

/* queued by handle_event whenever any contact's call goes active: ticks the
   duration label while the SELECTED contact is on a call */
static int cc_call_tick(ClientData cd, Tcl_Interp *ip, int objc,
                        Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Ui *ui = &g_ui;
    ui->call_timer_sched = false;
    Contact *c = ui->sel_kind == TT_SEL_CHAT ? contact_by_fn(ui, ui->sel_fn) : NULL;
    if (c && c->call_active) {
        call_tick(ui, c);
        return TCL_OK;
    }
    /* call over: restore the peer's normal header line */
    if (ui->sel_kind == TT_SEL_CHAT && c)
        EV(".main.chat.chead.t.smsg", "configure", "-text",
           c->status_msg[0] ? c->status_msg : conn_str(c->conn));
    return TCL_OK;
}

/* start the duration chain if no timer is queued and some call is active */
static void call_timer_kick(Ui *ui) {
    if (ui->call_timer_sched) return;
    for (Contact *c = ui->contacts; c; c = c->next) {
        if (c->call_active && !c->is_request) {
            ui->call_timer_sched = true;
            EV("after", "1", "tt_call_tick");
            return;
        }
    }
}

static void show_chat_pane(Ui *ui) {
    EV("grid", "remove", ".main.req");
    EV("grid", ".main.chat", "-row", "0", "-column", "0", "-sticky", "nsew");
}

static void show_request_pane(Ui *ui) {
    EV("grid", "remove", ".main.chat");
    EV("grid", ".main.req", "-row", "0", "-column", "0", "-sticky", "nsew");
}

static void badge_render(Ui *ui) {
    static const char *const labels[] = {"online", "away", "busy", "offline"};
    /* TOR prefix proves on-screen that the engine runs TCP-only via SOCKS5 */
    snprintf(ui->badge_name, sizeof ui->badge_name, "%s%s",
             ui->tor_mode ? "\xf0\x9f\xa7\x85 " : "",
             ui->self_name[0] ? ui->self_name : "unnamed");
    EV(".sb.badge.name", "configure", "-text", ui->badge_name);
    EV(".sb.badge.smsg", "configure", "-text",
       ui->self_status_msg[0] ? ui->self_status_msg : "no status message");
    EV(".sb.badge.dot", "configure", "-foreground",
       presence_color(ui->self_presence, ui->self_conn));
    /* picker menu radio checkmark follows the picked presence; "offline"
       matches no menu value so nothing is checked */
    EV("set", "tt_status", labels[presence_dot(ui->self_presence, ui->self_conn)]);
}

static void badge_avatar_render(Ui *ui) {
    if (ui->self_avatar_img[0]) {
        EV(".sb.badge.avatar", "configure", "-image", ui->self_avatar_img,
           "-text", "");
    } else {
        EV(".sb.badge.avatar", "configure", "-image", "",
           "-text", "\xf0\x9f\x91\xa4");
    }
}

/* dialog chrome helper (defined with the group dialogs): white toplevel +
   correct-order wm transient so dialogs map above the main window */
static void dlg_theme(Ui *ui, const char *path);

/* chat-header avatar slot: shown only while a friend with an avatar is
   selected — no standing placeholder glyph. Packs to the RIGHT of the call
   buttons (pack order right→left: avatar, call buttons, name block). */
static void chead_avatar_render(Ui *ui, const Contact *c) {
    if (c && c->avatar_img[0]) {
        EV(".main.chat.chead.avatar", "configure", "-image", c->avatar_img, "-text", "");
        EV("pack", ".main.chat.chead.avatar", "-side", "right", "-fill", "y",
           "-padx", "6", "-pady", "6");
    } else {
        EV("pack", "forget", ".main.chat.chead.avatar");
    }
}

/* group controls (Members / Invite / owner settings) in the chat header:
   visible only while a group is selected, so they're never right-click-only;
   Settings is founder-only (toxcore rejects the setters for everyone else) */
static void chead_group_ctl_render(Ui *ui, const Group *g) {
    if (g) {
        EV(".main.chat.chead.gctl.settings", "configure", "-state",
           g->self_role == TOX_GROUP_ROLE_FOUNDER ? "normal" : "disabled");
        EV("pack", ".main.chat.chead.gctl", "-side", "right", "-fill", "y",
           "-pady", "8", "-padx", "6");
    } else {
        EV("pack", "forget", ".main.chat.chead.gctl");
    }
}

static void show_selected(Ui *ui) {
    if (ui->sel_kind == TT_SEL_REQUEST) {
        Contact *r = request_row(ui);
        if (r) {
            EV(".main.req.key", "configure", "-text", r->key_hex);
            EV(".main.req.msg", "configure", "-text",
               r->last[0] ? r->last : "wants to be your friend.");
            chead_group_ctl_render(ui, NULL);
            show_request_pane(ui);
            return;
        }
    }
    if (ui->sel_kind == TT_SEL_CHAT) {
        Contact *c = contact_by_fn(ui, ui->sel_fn);
        if (c) {
            c->unread = 0;
            EV(".main.chat.chead.t.name", "configure", "-text",
               c->name[0] ? c->name : "unknown");
            EV(".main.chat.chead.t.smsg", "configure", "-text",
               c->status_msg[0] ? c->status_msg : conn_str(c->conn));
            /* running transfer: a Cancel button in the header (either dir);
               packed AFTER the call strip (equal -side right: later-packed
               sits left of it, next to the name block) */
            chead_call_render(ui, c); /* also packs the avatar (outermost right) */
            if (c->xfer_running) {
                EV("pack", ".main.chat.chead.cancel", "-side", "right",
                   "-padx", "6");
            } else {
                EV("pack", "forget", ".main.chat.chead.cancel");
            }
            chead_group_ctl_render(ui, NULL);
            hist_render(ui, c->transcript);
            EV(".main.chat.in.input", "configure", "-state", "normal");
            EV(".main.chat.in.send", "configure", "-state", "normal");
            EV(".main.chat.in.file", "configure", "-state", "normal");
            show_chat_pane(ui);
            roster_render(ui);
            return;
        }
    }
    if (ui->sel_kind == TT_SEL_GROUP) {
        Group *g = group_by_gn(ui, ui->sel_fn);
        if (g) {
            g->unread = 0;
            EV(".main.chat.chead.t.name", "configure", "-text",
               g->name[0] ? g->name : "group");
            EV(".main.chat.chead.t.smsg", "configure", "-text",
               g->topic[0] ? g->topic : (g->privacy ? "private group" : "public group"));
            EV("pack", "forget", ".main.chat.chead.cancel");
            chead_call_render_off(ui);
            chead_avatar_render(ui, NULL);
            chead_group_ctl_render(ui, g);
            hist_render(ui, g->transcript);
            EV(".main.chat.in.input", "configure", "-state", "normal");
            EV(".main.chat.in.send", "configure", "-state", "normal");
            /* group chat: no file transfer button */
            EV(".main.chat.in.file", "configure", "-state", "disabled");
            show_chat_pane(ui);
            roster_render(ui);
            return;
        }
    }
    EV(".main.chat.chead.t.name", "configure", "-text", "TkTox");
    EV(".main.chat.chead.t.smsg", "configure", "-text", "");
    EV("pack", "forget", ".main.chat.chead.cancel");
    chead_call_render_off(ui);
    chead_avatar_render(ui, NULL);
    chead_group_ctl_render(ui, NULL);
    EV(".main.chat.hf.hist", "configure", "-state", "normal");
    EV(".main.chat.hf.hist", "delete", "1.0", "end");
    EV(".main.chat.hf.hist", "configure", "-state", "disabled");
    EV(".main.chat.in.input", "configure", "-state", "disabled");
    EV(".main.chat.in.send", "configure", "-state", "disabled");
    EV(".main.chat.in.file", "configure", "-state", "disabled");
    show_chat_pane(ui);
}/* ---- events (tox thread -> UI) ---- */

/* file-transfer helpers live below handle_event */
static void fmt_size(uint64_t n, char *out, size_t cap);
static void xfer_line(Ui *ui, Contact *c, bool mine, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void offer_show(Ui *ui, Contact *c);

static void handle_event(Ui *ui, TTEvent *e) {
    switch (e->type) {
    case TT_EV_TOXID:
        if (e->str) snprintf(ui->my_toxid, sizeof ui->my_toxid, "%s", e->str);
        if (ui->st_open) {
            /* live-update the Settings ToxID display (nospam may have
               changed); the widget is rebuilt on each open, so guard it */
            EV(".st.myt", "configure", "-state", "normal");
            EV(".st.myt", "delete", "1.0", "end");
            if (ui->my_toxid[0]) {
                EV(".st.myt", "insert", "end", ui->my_toxid + 0, "pk");
                EV(".st.myt", "insert", "end", ui->my_toxid + 64, "nospam");
                EV(".st.myt", "insert", "end", ui->my_toxid + 72, "checksum");
            }
            EV(".st.myt", "configure", "-state", "disabled");
        }
        break;
    case TT_EV_SELF_CONNECTION:
        ui->self_conn = e->ival;
        badge_render(ui);
        break;
    case TT_EV_SELF_NAME:
        if (e->str && e->str_len) {
            size_t n = e->str_len < sizeof ui->self_name - 1
                           ? e->str_len : sizeof ui->self_name - 1;
            memcpy(ui->self_name, e->str, n);
            ui->self_name[n] = '\0';
            badge_render(ui);
        }
        break;
    case TT_EV_SELF_STATUS_MSG:
        if (e->str) {
            size_t n = e->str_len < sizeof ui->self_status_msg - 1
                           ? e->str_len : sizeof ui->self_status_msg - 1;
            memcpy(ui->self_status_msg, e->str, n);
            ui->self_status_msg[n] = '\0';
            badge_render(ui);
        }
        break;
    case TT_EV_SELF_STATUS:
        ui->self_presence = e->ival;
        badge_render(ui);
        break;
    case TT_EV_TOR_MODE:
        ui->tor_mode = true;
        TT_LOG("tk", "engine running TCP-only via SOCKS5 (Tor mode)");
        badge_render(ui);
        break;
    case TT_EV_FRIEND_NAME: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c) break;
        if (e->str && e->str_len) {
            size_t n = e->str_len < sizeof c->name - 1 ? e->str_len : sizeof c->name - 1;
            memcpy(c->name, e->str, n);
            c->name[n] = '\0';
        }
        roster_render(ui);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            show_selected(ui);
        break;
    }
    case TT_EV_FRIEND_CONNECTION: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c) break;
        c->conn = e->ival;
        if (e->ival == TOX_CONNECTION_NONE) {
            /* offline peer cannot send typing packets; clear a stale indicator */
            c->peer_typing = false;
            chead_typing_render(ui, c);
        }
        roster_render(ui);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            show_selected(ui);
        break;
    }
    case TT_EV_FRIEND_STATUS: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c) break;
        c->presence = e->ival;
        roster_render(ui);
        break;
    }
    case TT_EV_FRIEND_STATUS_MSG: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c || !e->str) break;
        size_t n = e->str_len < sizeof c->status_msg - 1 ? e->str_len : sizeof c->status_msg - 1;
        memcpy(c->status_msg, e->str, n);
        c->status_msg[n] = '\0';
        roster_render(ui);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            show_selected(ui);
        break;
    }
    case TT_EV_FRIEND_MESSAGE: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c || !e->str) break;
        /* their message arriving ends their typing indicator */
        if (c->peer_typing) {
            c->peer_typing = false;
            chead_typing_render(ui, c);
        }
        char text[TOX_MAX_MESSAGE_LENGTH + 1];
        size_t n = e->str_len < TOX_MAX_MESSAGE_LENGTH ? e->str_len : TOX_MAX_MESSAGE_LENGTH;
        memcpy(text, e->str, n);
        text[n] = '\0';
        const char *who = c->name[0] ? c->name : "unknown";
        if (e->ival == TOX_MESSAGE_TYPE_ACTION) { /* /me style line */
            char act[TOX_MAX_MESSAGE_LENGTH + TT_NAME_MAX + 4];
            snprintf(act, sizeof act, "* %s %s", who, text);
            chat_append(c, who, 2, act);
            if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
                hist_append_live(ui, NULL, 2, act);
            else
                c->unread++;
        } else {
            chat_append(c, who, 0, text);
            if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
                hist_append_live(ui, who, 0, text);
            else
                c->unread++;
        }
        roster_render(ui);
        break;
    }
    case TT_EV_FRIEND_TYPING: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        c->peer_typing = e->ival != 0;
        chead_typing_render(ui, c);
        break;
    }
    case TT_EV_MESSAGE_SENT: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        c->last_mid = (unsigned)e->ival;
        c->last_read = 0; /* new message pending: not read yet */
        roster_render(ui);
        break;
    }
    case TT_EV_FRIEND_READ_RECEIPT: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        if ((unsigned)e->ival > c->last_read) c->last_read = (unsigned)e->ival;
        roster_render(ui); /* ✓ prefix once everything is confirmed read */
        break;
    }
    case TT_EV_OFFLINE_FLUSHED: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        char line[96];
        snprintf(line, sizeof line, "%d queued message%s delivered",
                 e->ival, e->ival == 1 ? "" : "s");
        chat_append_sys(c, 1, line);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            hist_append_live(ui, NULL, 3, line);
        roster_render(ui);
        break;
    }
    case TT_EV_AV_INCOMING: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c) break;
        c->call_incoming = true;
        c->call_active = false;
        c->call_state = 0;
        c->call_video = e->ival2 != 0; /* M-AV5: peer offers video */
        c->call_started = 0;
        c->call_paused_self = false;
        c->call_ringing = false;
        const char *who = c->name[0] ? c->name : "unknown";
        char line[TT_NAME_MAX + 32];
        snprintf(line, sizeof line, "incoming %s call from %s",
                 e->ival2 ? "audio+video" : "audio", who);
        chat_append_sys(c, 1, line);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            hist_append_live(ui, NULL, 3, line);
        chead_call_render(ui, c);
        roster_render(ui);
        break;
    }
    case TT_EV_AV_STATE: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        c->call_state = e->ival;
        if (e->ival & (TOXAV_FRIEND_CALL_STATE_SENDING_A | TOXAV_FRIEND_CALL_STATE_ACCEPTING_A)) {
            c->call_incoming = false; /* answered on the other side of a handshake */
            c->call_active = true;
            c->call_ringing = false;
            /* duration timer base: first active sighting (per contact) */
            if (c->call_started == 0) c->call_started = time(NULL);
            call_timer_kick(ui);
        }
        /* side attribution (engine tags local echoes with ival2=1): a state-0
           echo = WE paused; a real MSI callback state-0 = PEER paused.
           Non-pause echoes (resume) just drop the flag back. */
        if (e->ival2 && e->ival == 0) c->call_paused_self = true;
        else if (e->ival2 && e->ival != 0) c->call_paused_self = false;
        /* side-explicit transcript line when the PEER pauses */
        if (c->call_active && e->ival == 0 && !e->ival2) {
            chat_append_sys(c, 0, "peer paused the call");
            if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
                hist_append_live(ui, NULL, 3, "peer paused the call");
        }
        chead_call_render(ui, c);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            show_selected(ui);
        roster_render(ui); /* call indicator 📞 on the peer row */
        break;
    }
    case TT_EV_AV_ENDED: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        char line[64];
        if (e->ival2 > 0)
            snprintf(line, sizeof line, "call ended (%s) — %ld:%02ld",
                     e->ival ? "error" : "finished", (long)e->ival2 / 60, (long)e->ival2 % 60);
        else
            snprintf(line, sizeof line, "call ended (%s)",
                     e->ival ? "error" : "no connection");
        c->call_active = false;
        c->call_incoming = false;
        c->call_state = 0;
        c->call_muted = false;
        c->call_deaf = false;
        c->call_video = false;
        c->call_started = 0;
        c->call_paused_self = false;
        c->call_ringing = false;
        ui->video_self = 0; /* pane swap resets with the call */
        chat_append_sys(c, 1, line);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
            hist_append_live(ui, NULL, 3, line);
        chead_call_render(ui, c);
        roster_render(ui);
        break;
    }
    case TT_EV_AV_FRAME: /* M-AV4: latest peer frame -> after-timer pane */
        video_frame_take(ui, e);
        break;
    case TT_EV_E2EE_STATE: { /* M5: encrypted session state (🔒 badge) */
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) c = contact_add(ui, e->friend_number, false);
        if (!c) break;
        bool was = c->e2ee;
        c->e2ee = (e->ival == 1);
        if (c->e2ee && e->str && e->str_len == 32) {
            memcpy(c->e2ee_code, e->str, 32);
            c->e2ee_code[32] = '\0';
        } else if (!c->e2ee) {
            c->e2ee_code[0] = '\0';
        }
        if (c->e2ee != was) {
            roster_render(ui);
            if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number)
                show_selected(ui);
        }
        break;
    }
    case TT_EV_FRIEND_REQUEST:
        /* first event: 64-hex pubkey; a later one carries the request text */
        if (e->str && strlen(e->str) == TOX_PUBLIC_KEY_SIZE * 2) {
            if (!request_row(ui)) {
                Contact *r = contact_add(ui, 0, true);
                if (r) snprintf(r->key_hex, sizeof r->key_hex, "%s", e->str);
            }
        } else if (e->str) {
            Contact *r = request_row(ui);
            if (r) {
                size_t n = e->str_len < sizeof r->last - 1 ? e->str_len : sizeof r->last - 1;
                memcpy(r->last, e->str, n);
                r->last[n] = '\0';
            }
        }
        roster_render(ui);
        break;
    case TT_EV_FRIEND_LIST_END:
        ui->ready = true;
        break;
    case TT_EV_AVATAR_SELF:
        if (e->str && e->str_len) {
            avatar_photo_create(ui, e->str, e->str_len,
                                ui->self_avatar_img, sizeof ui->self_avatar_img);
        } else {
            ui->self_avatar_img[0] = '\0';
        }
        badge_avatar_render(ui);
        break;
    case TT_EV_AVATAR: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        if (e->str && e->str_len) {
            avatar_photo_create(ui, e->str, e->str_len,
                                c->avatar_img, sizeof c->avatar_img);
        } else {
            c->avatar_img[0] = '\0';
        }
        roster_render(ui);
        /* late-loading avatar: re-render the WHOLE call strip (a bare avatar
           re-pack would append it innermost, wedged between the buttons) */
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number) {
            chead_call_render(ui, c);
        }
        break;
    }
    case TT_EV_AVATAR_CLEARED: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        c->avatar_img[0] = '\0';
        roster_render(ui);
        if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == e->friend_number) {
            chead_call_render(ui, c); /* strip re-render unhooks the slot */
        }
        break;
    }
    case TT_EV_FILE_TX_STARTED: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        const char *nl = e->str ? strchr(e->str, '\n') : NULL;
        size_t nl_n = nl ? (size_t)(nl - e->str) : 0;
        char name[TOX_MAX_FILENAME_LENGTH + 1] = {0};
        if (nl_n) {
            memcpy(name, e->str, nl_n < sizeof name - 1 ? nl_n : sizeof name - 1);
        } else if (e->str && e->str_len) {
            memcpy(name, e->str, e->str_len < sizeof name - 1 ? e->str_len : sizeof name - 1);
        }
        c->xfer_me = true;
        c->xfer_running = true;
        c->xfer_run_id = (unsigned)e->ival;
        snprintf(c->xfer_name, sizeof c->xfer_name, "%s", name);
        char sz[32];
        fmt_size(nl ? strtoull(nl + 1, NULL, 10) : 0, sz, sizeof sz);
        xfer_line(ui, c, true, "sending file \xe2\x80\x9c%s\xe2\x80\x9d (%s)",
                  c->xfer_name, sz);
        break;
    }
    case TT_EV_FILE_PROGRESS: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        /* str: "<got>/<total>" */
        char got[32] = "?", total[32] = "?";
        const char *slash = e->str ? strchr(e->str, '/') : NULL;
        if (slash) {
            size_t gl = (size_t)(slash - e->str);
            if (gl > sizeof got - 1) gl = sizeof got - 1;
            memcpy(got, e->str, gl);
            got[gl] = '\0';
            fmt_size(strtoull(got, NULL, 10), got, sizeof got);
            fmt_size(strtoull(slash + 1, NULL, 10), total, sizeof total);
        }
        xfer_line(ui, c, c->xfer_me, "\xe2\x80\x9c%s\xe2\x80\x9d %s / %s",
                  c->xfer_name[0] ? c->xfer_name : "?", got, total);
        break;
    }
    case TT_EV_FILE_DONE: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        xfer_line(ui, c, c->xfer_me, "\xe2\x80\x9c%s\xe2\x80\x9d complete \xe2\x80\x94 %s",
                  c->xfer_name[0] ? c->xfer_name : "?",
                  e->str ? e->str : "");
        c->xfer_running = false;
        break;
    }
    case TT_EV_FILE_FAILED: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        xfer_line(ui, c, c->xfer_me, "\xe2\x80\x9c%s\xe2\x80\x9d failed",
                  c->xfer_name[0] ? c->xfer_name : "?");
        c->xfer_running = false;
        break;
    }
    case TT_EV_FILE_OFFER: {
        Contact *c = contact_by_fn(ui, e->friend_number);
        if (!c) break;
        /* str: "<name>\n<size>"; ival: xfer id */
        const char *nl = e->str ? strchr(e->str, '\n') : NULL;
        if (!nl) break;
        c->offer_pending = true;
        c->offer_id = (unsigned)e->ival;
        c->offer_size = strtoull(nl + 1, NULL, 10);
        size_t n = (size_t)(nl - e->str);
        if (n > sizeof c->offer_name - 1) n = sizeof c->offer_name - 1;
        memcpy(c->offer_name, e->str, n);
        c->offer_name[n] = '\0';
        snprintf(c->xfer_name, sizeof c->xfer_name, "%s", c->offer_name);
        c->xfer_me = false;
        c->xfer_running = true; /* accepted RX counts too: cancellable */
        c->xfer_run_id = (unsigned)e->ival;
        offer_show(ui, c);
        break;
    }
    case TT_EV_GROUP_NEW: {
        /* founder side: group object exists locally */
        Group *g = group_add(ui, e->friend_number);
        if (g) {
            if (e->str && e->str_len) {
                size_t n = e->str_len < sizeof g->name - 1 ? e->str_len : sizeof g->name - 1;
                memcpy(g->name, e->str, n);
                g->name[n] = '\0';
            }
            g->privacy = e->ival2;
            g->self_role = TOX_GROUP_ROLE_FOUNDER;
            tt_queue_post(&ui->tt->in, TT_CMD_GROUP_SYNC, e->friend_number, NULL, 0);
        }
        roster_render(ui);
        break;
    }
    case TT_EV_GROUP_JOINED: {
        /* self join (create accept path and join-by-id accept path) */
        Group *g = group_add(ui, e->friend_number);
        if (g) {
            if (e->str && e->str_len) {
                size_t n = e->str_len < sizeof g->name - 1 ? e->str_len : sizeof g->name - 1;
                memcpy(g->name, e->str, n);
                g->name[n] = '\0';
            }
            /* restore burst posts privacy here; live self-join posts 0 and
               SYNC (-10) corrects it */
            g->privacy = e->ival2 ? 1 : 0;
            tt_queue_post(&ui->tt->in, TT_CMD_GROUP_SYNC, e->friend_number, NULL, 0);
        }
        roster_render(ui);
        break;
    }
    case TT_EV_GROUP_LEFT: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (g) {
            group_append_sys(g, 0, "you left the group");
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == e->friend_number)
                ui->sel_kind = TT_SEL_NONE;
            group_remove(ui, g);
        }
        roster_render(ui);
        show_selected(ui);
        break;
    }
    case TT_EV_GROUP_MSG: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g || !e->str) break;
        GroupMember *m = group_member_upsert(ui, g, (uint32_t)e->ival);
        const char *who = (m && m->name[0]) ? m->name : "peer";
        char text[TOX_GROUP_MAX_MESSAGE_LENGTH + 1];
        size_t n = e->str_len < TOX_GROUP_MAX_MESSAGE_LENGTH
                       ? e->str_len : TOX_GROUP_MAX_MESSAGE_LENGTH;
        memcpy(text, e->str, n);
        text[n] = '\0';
        if (e->ival2 == TOX_MESSAGE_TYPE_ACTION) { /* /me style line */
            char act[TOX_GROUP_MAX_MESSAGE_LENGTH + TT_NAME_MAX + 4];
            snprintf(act, sizeof act, "* %s %s", who, text);
            group_append(g, who, 2, act);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, act);
        } else {
            group_append(g, who, 0, text);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, who, 0, text);
            else
                g->unread++;
        }
        roster_render(ui);
        break;
    }
    case TT_EV_GROUP_PRIV_MSG: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g || !e->str) break;
        GroupMember *m = group_member_upsert(ui, g, (uint32_t)e->ival);
        const char *who = (m && m->name[0]) ? m->name : "peer";
        char text[TOX_GROUP_MAX_MESSAGE_LENGTH + 64];
        size_t n = e->str_len < TOX_GROUP_MAX_MESSAGE_LENGTH
                       ? e->str_len : TOX_GROUP_MAX_MESSAGE_LENGTH;
        snprintf(text, sizeof text, "[private] %.*s", (int)n, e->str);
        group_append(g, who, 0, text);
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
            hist_append_live(ui, who, 0, text);
        else
            g->unread++;
        roster_render(ui);
        break;
    }
    case TT_EV_GROUP_TOPIC: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        if (e->str) {
            size_t n = e->str_len < sizeof g->topic - 1 ? e->str_len : sizeof g->topic - 1;
            memcpy(g->topic, e->str, n);
            g->topic[n] = '\0';
        }
        bool self_set = e->ival2 == -1; /* SYNC burst: no system line */
        if (!self_set && e->ival2 != (int)0xFFFFFFFFu) {
            /* peer-set topic: name it if known */
            GroupMember *m = group_member(g, (uint32_t)e->ival2);
            const char *who = (m && m->name[0]) ? m->name : "peer";
            char line[TT_NAME_MAX + 32];
            snprintf(line, sizeof line, "%s set the topic", who);
            group_append_sys(g, 0, line);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, line);
        }
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
            EV(".main.chat.chead.t.smsg", "configure", "-text",
               g->topic[0] ? g->topic : "no topic");
        roster_render(ui);
        break;
    }
    case TT_EV_GROUP_PEER_JOIN: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        GroupMember *m = group_member_upsert(ui, g, (uint32_t)e->ival);
        /* PEER_NAME/ROLE events follow this one (engine pushes them here);
           defer the announcement until the name is known so the line reads
           "Echo Bot joined" instead of "A peer joined" */
        if (m) m->announce = true;
        /* rebuild the dialog so a joining member gets a row at all */
        EV("winfo", "exists", ".gm");
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn &&
            Tcl_GetStringResult(ui->interp)[0] == '1')
            tt_queue_post(&ui->tt->in, TT_CMD_GROUP_SYNC, g->gn, NULL, 0);
        break;
    }
    case TT_EV_GROUP_PEER_EXIT: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        GroupMember *m = group_member(g, (uint32_t)e->ival);
        char line[TT_NAME_MAX + TT_LAST_MAX + 48];
        /* prefer live roster name, then the exit-event name */
        if (m && m->name[0])
            snprintf(line, sizeof line, "%s %s", m->name, exit_type_str(e->ival2));
        else if (e->str && e->str_len) {
            char nm2[TT_NAME_MAX];
            size_t n = e->str_len < sizeof nm2 - 1 ? e->str_len : sizeof nm2 - 1;
            memcpy(nm2, e->str, n);
            nm2[n] = '\0';
            snprintf(line, sizeof line, "%s %s", nm2, exit_type_str(e->ival2));
        } else
            snprintf(line, sizeof line, "A peer %s", exit_type_str(e->ival2));
        group_append_sys(g, 0, line);
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
            hist_append_live(ui, NULL, 2, line);
        if (m) { /* roster rebuild-free removal */
            GroupMember **pp = &g->members;
            while (*pp && *pp != m) pp = &(*pp)->next;
            if (*pp) { *pp = m->next; free(m); }
        }
        break;
    }
    case TT_EV_GROUP_PEER_NAME: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        GroupMember *m = group_member_upsert(ui, g, (uint32_t)e->ival);
        if (m && e->str) {
            size_t n = e->str_len < sizeof m->name - 1 ? e->str_len : sizeof m->name - 1;
            memcpy(m->name, e->str, n);
            m->name[n] = '\0';
        }
        /* deferred join announcement: PEER_JOIN arrives before the name */
        if (m && m->announce) {
            m->announce = false;
            char line[TT_NAME_MAX + 32];
            snprintf(line, sizeof line, "%s joined the group",
                     m->name[0] ? m->name : "A peer");
            group_append_sys(g, 0, line);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, line);
        }
        /* live-update the members dialog row label if it is open */
        EV("winfo", "exists", ".gm");
        if (Tcl_GetStringResult(ui->interp)[0] == '1') {
            char fr[24], lrow[64], who[TT_NAME_MAX + 48];
            snprintf(fr, sizeof fr, "%u", (unsigned)e->ival);
            snprintf(lrow, sizeof lrow, ".gm.r%s.l", fr);
            EV("winfo", "exists", lrow);
            if (Tcl_GetStringResult(ui->interp)[0] == '1') {
                snprintf(who, sizeof who, "%s  \xc2\xb7  %s",
                         m->name[0] ? m->name : "peer", role_str(m->role));
                EV(lrow, "configure", "-text", who);
            }
        }
        break;
    }
    case TT_EV_GROUP_PEER_STATUS: /* presence is not rendered in groups yet */
        break;
    case TT_EV_GROUP_PEER_ROLE: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        GroupMember *m = group_member_upsert(ui, g, (uint32_t)e->ival);
        if (m) m->role = e->ival2;
        /* announcement fallback: ROLE follows NAME, so if the name event
           never carried, announce here rather than never */
        if (m && m->announce) {
            m->announce = false;
            char line[TT_NAME_MAX + 32];
            snprintf(line, sizeof line, "%s joined the group",
                     m->name[0] ? m->name : "A peer");
            group_append_sys(g, 0, line);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, line);
        }
        /* live-update the members dialog role combobox (if visible) */
        EV("winfo", "exists", ".gm");
        if (Tcl_GetStringResult(ui->interp)[0] == '1') {
            char fr[24], rolerow[32];
            snprintf(fr, sizeof fr, "%u", (unsigned)e->ival);
            snprintf(rolerow, sizeof rolerow, ".gm.r%s.r", fr);
            EV("winfo", "exists", rolerow);
            if (Tcl_GetStringResult(ui->interp)[0] == '1')
                EV(rolerow, "set", role_str(e->ival2));
        }
        break;
    }
    case TT_EV_GROUP_INVITE: {
        /* modal accept/decline; ival2 = pending invite index in the engine */
        EV("winfo", "exists", ".gi");
        bool invite_open = Tcl_GetStringResult(ui->interp)[0] == '1';
        if (invite_open) break;
        EV("toplevel", ".gi", "-padx", "14", "-pady", "14");
        EV("wm", "title", ".gi", "Group Invitation");
        dlg_theme(ui, ".gi");
        EV("ttk::label", ".gi.l1", "-text",
           e->str && e->str[0] ? e->str : "A friend");
        EV("ttk::label", ".gi.l2", "-text", "invites you to a group chat",
           "-wraplength", "320", "-justify", "left");
        EV("ttk::frame", ".gi.b");
        char acc[32], dec[32];
        snprintf(acc, sizeof acc, "tt_ginv_yes %d", e->ival2);
        snprintf(dec, sizeof dec, "tt_ginv_no %d", e->ival2);
        EV("ttk::button", ".gi.yes", "-text", "Accept", "-command", acc,
           "-style", "Green.TButton");
        EV("ttk::button", ".gi.no", "-text", "Decline", "-command", dec,
           "-style", "Danger.TButton");
        EV("pack", ".gi.l1", "-side", "top", "-anchor", "w", "-font", "f_bold");
        EV("pack", ".gi.l2", "-side", "top", "-anchor", "w", "-pady", "6");
        EV("pack", ".gi.yes", "-side", "right", "-pady", "8", "-padx", "4");
        EV("pack", ".gi.no", "-side", "right", "-pady", "8");
        EV("pack", ".gi.b", "-side", "top", "-fill", "x");
        break;
    }
    case TT_EV_GROUP_MOD: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        GroupMember *m = group_member(g, (uint32_t)e->ival);
        const char *who = (m && m->name[0]) ? m->name : "A peer";
        char line[TT_NAME_MAX + 48];
        snprintf(line, sizeof line, "%s %s", who, mod_event_str(e->ival2));
        group_append_sys(g, 0, line);
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
            hist_append_live(ui, NULL, 2, line);
        if (m && e->ival2 != TOX_GROUP_MOD_EVENT_KICK) m->role = e->ival2;
        break;
    }
    case TT_EV_GROUP_MOD_SELF: {
        /* actor-side confirmation: toxcore fires no moderation callback for
           the client that issued the kick/role change, only for receivers */
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        bool failed = e->ival2 >= TT_MOD_EV_FAIL_BASE;
        int modev = failed ? e->ival2 - TT_MOD_EV_FAIL_BASE : e->ival2;
        GroupMember *m = group_member(g, (uint32_t)e->ival);
        const char *who = (m && m->name[0]) ? m->name
                          : (e->str && e->str_len ? e->str : "peer");
        char line[TT_NAME_MAX + 160];
        if (failed) {
            snprintf(line, sizeof line,
                     "could not apply %s to %s (permission denied or peer gone)",
                     mod_event_str(modev), who);
        } else {
            snprintf(line, sizeof line, "you %s %s", mod_event_str(modev), who);
            if (modev == TOX_GROUP_MOD_EVENT_KICK) {
                if (m) { /* same roster removal as PEER_EXIT */
                    GroupMember **pp = &g->members;
                    while (*pp && *pp != m) pp = &(*pp)->next;
                    if (*pp) { *pp = m->next; free(m); }
                }
            } else if (m) {
                /* MOD event mapping: 1=MODERATOR 2=USER 3=OBSERVER */
                m->role = modev == TOX_GROUP_MOD_EVENT_MODERATOR ? TOX_GROUP_ROLE_MODERATOR
                        : modev == TOX_GROUP_MOD_EVENT_USER ? TOX_GROUP_ROLE_USER
                        : TOX_GROUP_ROLE_OBSERVER;
            }
            /* role combobox in the open members dialog must reflect the new
               role; kick row removal happens via PEER_EXIT/SYNC */
            EV("winfo", "exists", ".gm");
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn &&
                strcmp(Tcl_GetStringResult(ui->interp), "1") == 0) {
                tt_queue_post(&ui->tt->in, TT_CMD_GROUP_SYNC, g->gn, NULL, 0);
            }
        }
        group_append_sys(g, 0, line);
        if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
            hist_append_live(ui, NULL, 2, line);
        break;
    }
    case TT_EV_GROUP_STATE: {
        Group *g = group_by_gn(ui, e->friend_number);
        if (!g) break;
        char line[96];
        bool announce = false;
        if (e->ival == -1) {
            g->voice = e->ival2 > 0 && e->ival2 <= 2 ? e->ival2 : 0;
            static const char *const vs[] = {"everyone may speak",
                                             "only moderators may speak",
                                             "only the founder may speak"};
            snprintf(line, sizeof line, "voice state: %s",
                     vs[g->voice]);
            announce = true;
        } else if (e->ival == -2) {
            g->topic_lock = e->ival2 ? 1 : 0;
            snprintf(line, sizeof line, "topic lock %s", e->ival2 ? "enabled" : "disabled");
            announce = true;
        } else if (e->ival == -3) {
            int pl = e->str ? atoi(e->str) : 0;
            g->peer_limit = pl > 0 ? pl : 0;
            snprintf(line, sizeof line, "peer limit set to %s",
                     e->str ? e->str : "?");
            announce = true;
        } else if (e->ival == -7) { /* SYNC burst: quiet, no transcript line */
            g->voice = e->ival2 > 0 && e->ival2 <= 2 ? e->ival2 : 0;
        } else if (e->ival == -8) {
            g->topic_lock = e->ival2 ? 1 : 0;
        } else if (e->ival == -9) {
            int pl = e->str ? atoi(e->str) : 0;
            g->peer_limit = pl > 0 ? pl : 0;
        } else if (e->ival == -10) { /* SYNC: privacy, quiet */
            g->privacy = e->ival2 ? 1 : 0;
        } else if (e->ival == -4) {
            snprintf(line, sizeof line, "password changed");
            announce = true;
        } else if (e->ival == -5) { /* SYNC: chat id hex */
            if (e->str && e->str_len == TOX_GROUP_CHAT_ID_SIZE * 2)
                memcpy(g->chat_id_hex, e->str, TOX_GROUP_CHAT_ID_SIZE * 2);
            g->chat_id_hex[TOX_GROUP_CHAT_ID_SIZE * 2] = '\0';
        } else if (e->ival == -6) { /* SYNC: self role */
            g->self_role = e->ival2;
        } else { /* 0..1: privacy state */
            g->privacy = e->ival;
            snprintf(line, sizeof line, "group is now %s",
                     e->ival ? "private" : "public");
            announce = true;
        }
        if (announce) {
            group_append_sys(g, 0, line);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, line);
        }
        break;
    }
    case TT_EV_GROUP_JOIN_FAIL: {
        Group *g = group_by_gn(ui, e->friend_number);
        static const char *const jf[] = {"peer limit reached", "wrong password", "unknown reason"};
        int fi = e->ival >= 0 && e->ival <= 2 ? e->ival : 2;
        char line[96];
        snprintf(line, sizeof line, "join failed: %s", jf[fi]);
        if (g) {
            group_append_sys(g, 0, line);
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == g->gn)
                hist_append_live(ui, NULL, 2, line);
        } else {
            EV(".main.chat.chead.t.name", "configure", "-text", "group join failed");
            EV(".main.chat.chead.t.smsg", "configure", "-text", line);
        }
        if (g) { /* engine already dropped the group object */
            if (ui->sel_kind == TT_SEL_GROUP && ui->sel_fn == e->friend_number) {
                ui->sel_kind = TT_SEL_NONE;
                chead_group_ctl_render(ui, NULL);
            }
            group_remove(ui, g);
        }
        roster_render(ui);
        show_selected(ui);
        break;
    }
    case TT_EV_SHUTDOWN:
        ui->quitting = true;
        EV("destroy", ".");
        break;
    default:
        break;
    }
}

static void poll_events(ClientData cd) {
    Ui *ui = cd;
    if (ui->quitting) return;
    for (;;) {
        TTEvent *e = tt_queue_pop_timed(&ui->tt->out, 0);
        if (!e) break;
        handle_event(ui, e);
        tt_event_free(e);
    }
    Tcl_CreateTimerHandler(80, poll_events, cd);
}

/* ---- typing indicator (outgoing, 1:1 chats only) ----
   Debounce: only post SET_TYPING 1 on the first keystroke for a friend;
   a 4s self-timer stops it after keystroke silence, and cc_send stops it
   on send. toxcore carries no auto-timeout, so the sender owns the idle
   timer; engine + m_set_usertyping dedupe same-state packets. */
static void typing_stop(Ui *ui) {
    if (ui->typing_sent && ui->typing_fn != UINT32_MAX)
        tt_queue_post(&ui->tt->in, TT_CMD_SET_TYPING, ui->typing_fn, NULL, 0);
    ui->typing_sent = false;
    ui->typing_fn = UINT32_MAX;
}

static void typing_tick(ClientData cd) {
    Ui *ui = cd;
    ui->typing_idle_sched = false;
    if (!ui->typing_sent || ui->typing_fn == UINT32_MAX) return;
    if (time(NULL) - ui->typing_last < TT_TYPING_TIMEOUT - 1) {
        Tcl_CreateTimerHandler(500, typing_tick, cd);
        ui->typing_idle_sched = true;
        return;
    }
    typing_stop(ui);
}

static void typing_keystroke(Ui *ui, uint32_t fn) {
    ui->typing_last = time(NULL);
    if (ui->typing_sent && ui->typing_fn == fn) {
        if (!ui->typing_idle_sched) {
            ui->typing_idle_sched = true;
            Tcl_CreateTimerHandler(1000, typing_tick, ui);
        }
        return;
    }
    if (ui->typing_sent && ui->typing_fn != fn) /* switched chat: stop other */
        typing_stop(ui);
    tt_queue_post(&ui->tt->in, TT_CMD_SET_TYPING, fn, NULL, 1);
    ui->typing_fn = fn;
    ui->typing_sent = true;
    if (!ui->typing_idle_sched) {
        ui->typing_idle_sched = true;
        Tcl_CreateTimerHandler(1000, typing_tick, ui);
    }
}

/* ---- C obj-commands (Tk callbacks) ---- */

/* keystroke watcher on the chat input: typing indicator driver */
static int cc_input_key(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->sel_kind == TT_SEL_CHAT)
        typing_keystroke(ui, ui->sel_fn);
    return TCL_OK;
}

/* Cancel for the contact's running transfer (either direction) */
static int cc_file_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Contact *c = ui->sel_kind == TT_SEL_CHAT ? contact_by_fn(ui, ui->sel_fn) : NULL;
    if (!c || !c->xfer_running) return TCL_OK;
    tt_queue_post(&ui->tt->in, TT_CMD_FILE_CANCEL, 0, NULL, (int)c->xfer_run_id);
    xfer_line(ui, c, c->xfer_me, "cancelling \xe2\x80\x9c%s\xe2\x80\x9d...",
              c->xfer_name[0] ? c->xfer_name : "?");
    return TCL_OK;
}

/* ---- M-AV4 video pane ----
   Peer frames land here from TT_EV_AV_FRAME; a Tk after-timer paints the
   latest frame into a photo (Tk widgets can only be touched from the Tk
   thread). YUV420 -> RGB happens in C; the photo is fed with
   Tk_PhotoPutBlock (TK_PHOTO_COMPOSITE_SET: opaque alpha 255 = plain copy). */

#define TT_VIDEO_TICK_MS 33   /* ~30 fps repaint ceiling */
#define TT_VIDEO_HIDE_SECS 3  /* frames stop -> pane closes */

/* planar YUV420 (payload layout: Y rows, then U, then V) -> RGBA */
static void video_yuv_to_rgb(const uint8_t *fr, uint8_t *rgb, int w, int h) {
    const uint8_t *yv = fr;
    const uint8_t *uv = yv + (size_t)w * h;
    const uint8_t *vv = uv + (size_t)(w / 2) * (h / 2);
    for (int j = 0; j < h; j++) {
        const uint8_t *yrow = yv + (size_t)j * w;
        uint8_t *out = rgb + (size_t)j * w * 4;
        for (int i = 0; i < w; i++) {
            int Y = yrow[i] - 16;
            int U = uv[(j / 2) * (w / 2) + i / 2] - 128;
            int V = vv[(j / 2) * (w / 2) + i / 2] - 128;
            int r = (290 * Y + 409 * V + 128) >> 8;
            int g = (290 * Y - 100 * U - 208 * V + 128) >> 8;
            int b = (290 * Y + 516 * U + 128) >> 8;
            out[i * 4] = (uint8_t)(r < 0 ? 0 : r > 255 ? 255 : r);
            out[i * 4 + 1] = (uint8_t)(g < 0 ? 0 : g > 255 ? 255 : g);
            out[i * 4 + 2] = (uint8_t)(b < 0 ? 0 : b > 255 ? 255 : b);
            out[i * 4 + 3] = 255;
        }
    }
}

/* (re)create the photo at the frame size and put the RGB block */
static void video_paint(Ui *ui) {
    int w = ui->video_w, h = ui->video_h;
    if (w < 1 || h < 1 || !ui->video_frame) return;
    if (!ui->video_img[0]) {
        snprintf(ui->video_img, sizeof ui->video_img, "vid%u", ++ui->video_seq);
        EV("image", "create", "photo", ui->video_img);
    }
    /* dimension check via the generic image command (photos have no
       width/height subcommands) */
    EV("image", "width", ui->video_img);
    int pw = atoi(Tcl_GetStringResult(ui->interp));
    if (pw != w) {
        char ws[12], hs[12];
        snprintf(ws, sizeof ws, "%d", w);
        snprintf(hs, sizeof hs, "%d", h);
        EV(ui->video_img, "configure", "-width", ws, "-height", hs);
    }
    Tk_PhotoHandle ph = Tk_FindPhoto(ui->interp, ui->video_img);
    if (!ph) return;
    if (ui->video_rgb_cap < (size_t)w * h * 4) {
        free(ui->video_rgb);
        ui->video_rgb_cap = (size_t)w * h * 4;
        ui->video_rgb = malloc(ui->video_rgb_cap);
        if (!ui->video_rgb) {
            ui->video_rgb_cap = 0;
            return;
        }
    }
    video_yuv_to_rgb(ui->video_frame, ui->video_rgb, w, h);
    Tk_PhotoImageBlock blk;
    memset(&blk, 0, sizeof blk);
    blk.pixelPtr = ui->video_rgb;
    blk.width = w;
    blk.height = h;
    blk.pitch = w * 4;
    blk.pixelSize = 4;
    blk.offset[0] = 0;
    blk.offset[1] = 1;
    blk.offset[2] = 2;
    blk.offset[3] = 3;
    Tk_PhotoPutBlock(ui->interp, ph, &blk, 0, 0, w, h, TK_PHOTO_COMPOSITE_SET);
    /* pack once (idempotent); the pane sits under the header, above history */
    EV("pack", ui->video_img, "-side", "top", "-fill", "x", "-pady", "4",
       "-before", ".main.chat.hf");
}

/* queued as a Tcl timer; paints when a fresh frame is pending and hides
   the pane again when frames stop flowing (call ended) */
static int cc_video_tick(ClientData cd, Tcl_Interp *ip, int objc,
                         Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objc; (void)objv;
    Ui *ui = &g_ui;
    ui->video_sched = false;
    if (ui->video_last && time(NULL) - ui->video_last > TT_VIDEO_HIDE_SECS) {
        ui->video_last = 0;
        if (ui->video_img[0]) {
            EV("pack", "forget", ui->video_img);
            EV("image", "delete", ui->video_img);
            ui->video_img[0] = '\0';
        }
    }
    if (ui->video_last) {
        video_paint(ui);
        char ms[8];
        snprintf(ms, sizeof ms, "%d", TT_VIDEO_TICK_MS);
        EV("after", ms, "tt_video_tick");
    }
    return TCL_OK;
}

/* TT_EV_AV_FRAME sink: keep the latest frame, (re)start the paint timer */
static void video_frame_take(Ui *ui, const TTEvent *e) {
    size_t need = (size_t)e->str_len;
    if (need < 1 || need > 460800) return;
    if (ui->video_cap < need) {
        free(ui->video_frame);
        ui->video_cap = need;
        ui->video_frame = malloc(need);
        if (!ui->video_frame) {
            ui->video_cap = 0;
            return;
        }
    }
    memcpy(ui->video_frame, e->str, need);
    ui->video_w = (uint16_t)e->ival;
    ui->video_h = (uint16_t)e->ival2;
    ui->video_last = time(NULL);
    if (!ui->video_sched) {
        ui->video_sched = true;
        EV("after", "1", "tt_video_tick"); /* start the 33 ms chain */
    }
}

/* call controls (tt_av_call / tt_av_answer / tt_av_decline): header buttons */
static int cc_av_call(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    /* one button, three roles: the label follows the contact's call state —
       📞 Call (idle) / 📵 Cancel while ringing / 📵 Hang up (active) — so
       the posted command must match (a second CALL would just fail with
       FRIEND_ALREADY_IN_CALL) */
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c) return TCL_OK;
    if (!c->call_active && !c->call_ringing && g_ui.tor_mode) {
        /* M-AV5 tor note: video QoS under SOCKS5/TCP is out of our hands */
        chat_append_sys(c, 1, "tor mode: audio ok, video may struggle");
        if (g_ui.sel_kind == TT_SEL_CHAT && g_ui.sel_fn == c->fn)
            hist_append_live(&g_ui, NULL, 3, "tor mode: audio ok, video may struggle");
    }
    if (c->call_active || c->call_ringing) {
        c->call_ringing = false; /* cancel while ringing: straight back to idle */
        cc_call(&g_ui, TT_CMD_AV_HANGUP, 1, 0);
    } else {
        c->call_ringing = true; /* until the engine confirms (AV_STATE/ENDED) */
        cc_call(&g_ui, TT_CMD_AV_CALL, 1, 0);
    }
    chead_call_render(&g_ui, c);
    return TCL_OK;
}

static int cc_av_answer(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    cc_call(&g_ui, TT_CMD_AV_ANSWER, 1, 0);
    return TCL_OK;
}

/* M-AV5: answer with video (visible only when the peer offered it) */
static int cc_av_answer_video(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c || !c->call_video) return TCL_OK;
    cc_call(&g_ui, TT_CMD_AV_ANSWER, 1, TT_AV_VIDEO_BITRATE);
    return TCL_OK;
}

static int cc_av_decline(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    cc_call(&g_ui, TT_CMD_AV_HANGUP, 0, 0);
    return TCL_OK;
}

/* M-AV3: toggle our mic gate for the selected contact's call */
static int cc_av_mute(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c || !c->call_active) return TCL_OK;
    c->call_muted = !c->call_muted;
    cc_call(&g_ui, TT_CMD_AV_MUTE, c->call_muted ? 1 : 0, 0);
    chead_call_render(&g_ui, c); /* label flips 🎤 Mute <-> 🎤 Unmute */
    return TCL_OK;
}

/* tier B1: toggle the call pause (⏸ Pause / ▶ Resume; the engine rejects
   RESUME unless WE paused — the button is disabled while the peer's pause
   is up). The engine echoes state 0 / pre-pause state back (ival2=1). */
static int cc_av_pause(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c || !c->call_active) return TCL_OK;
    bool paused = c->call_paused_self;
    c->call_paused_self = !paused;
    cc_call(&g_ui, paused ? TT_CMD_AV_RESUME : TT_CMD_AV_PAUSE, 1, 0);
    if (g_ui.sel_kind == TT_SEL_CHAT && g_ui.sel_fn == c->fn) {
        chat_append_sys(c, 1, paused ? "you resumed the call"
                                     : "you paused the call");
        hist_append_live(&g_ui, NULL, 3, paused ? "you resumed the call"
                                                : "you paused the call");
    }
    chead_call_render(&g_ui, c);
    return TCL_OK;
}

/* M-AV5: toggle the output gate for the selected contact's call */
static int cc_av_deaf(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c || !c->call_active) return TCL_OK;
    c->call_deaf = !c->call_deaf;
    cc_call(&g_ui, TT_CMD_AV_DEAF, c->call_deaf ? 1 : 0, 0);
    chead_call_render(&g_ui, c); /* label flips 🔇 Unmute out <-> 🔊 Mute out */
    return TCL_OK;
}

/* M-AV5 pane swap: mirror our own camera into the video pane (and back) */
static int cc_av_self(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)ip; (void)objv; (void)objc;
    Contact *c = g_ui.sel_kind == TT_SEL_CHAT ? contact_by_fn(&g_ui, g_ui.sel_fn) : NULL;
    if (!c || !c->call_active || !c->call_video) return TCL_OK;
    g_ui.video_self = !g_ui.video_self;
    cc_call(&g_ui, TT_CMD_AV_SELFVIEW, g_ui.video_self ? 1 : 0, 0);
    chead_call_render(&g_ui, c);
    return TCL_OK;
}

static int cc_selected(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    static int in_cb; /* re-entrant fire during programmatic selection set */
    if (in_cb) return TCL_OK;
    in_cb = 1;
    EV(".sb.rf.roster", "selection");
    const char *res = Tcl_GetStringResult(ui->interp);
    if (res && *res) {
        Contact *c = contact_by_iid(ui, res);
        Group *g = c ? NULL : group_by_iid(ui, res);
        SelKind kind = TT_SEL_NONE;
        uint32_t fn = 0;
        if (c && c->is_request) {
            kind = TT_SEL_REQUEST;
        } else if (c) {
            kind = TT_SEL_CHAT;
            fn = c->fn;
        } else if (g) {
            kind = TT_SEL_GROUP;
            fn = g->gn;
        }
        /* same selection: roster_render re-selects on every event, and the
           set queues another <<TreeviewSelect>> — acting on it again would
           ping-pong show_selected <-> roster_render forever */
        if (kind == ui->sel_kind && fn == ui->sel_fn) {
            in_cb = 0;
            return TCL_OK;
        }
        ui->sel_kind = kind;
        ui->sel_fn = fn;
        show_selected(ui);
    }
    in_cb = 0;
    return TCL_OK;
}

static int cc_send(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv;
    bool from_key = objc > 1; /* Return binding: suppress the class insert */
    if (!ui->ready) return from_key ? TCL_BREAK : TCL_OK;
    if (ui->sel_kind == TT_SEL_REQUEST) {   /* Add button on the request page */
        Contact *r = request_row(ui);
        if (r) {
            tt_queue_post(&ui->tt->in, TT_CMD_ACCEPT_FRIEND, 0, r->key_hex, 0);
            contact_remove(ui, r);
            ui->sel_kind = TT_SEL_NONE;
            roster_render(ui);
            show_selected(ui);
        }
        return TCL_OK;
    }
    if (ui->sel_kind != TT_SEL_CHAT && ui->sel_kind != TT_SEL_GROUP)
        return from_key ? TCL_BREAK : TCL_OK;
    if (ui->sel_kind == TT_SEL_GROUP) {
        Group *g = group_by_gn(ui, ui->sel_fn);
        if (!g) return from_key ? TCL_BREAK : TCL_OK;
        EV(".main.chat.in.input", "get", "1.0", "end");
        const char *text = Tcl_GetStringResult(ui->interp);
        if (!text || !*text) return from_key ? TCL_BREAK : TCL_OK;
        char buf[TOX_GROUP_MAX_MESSAGE_LENGTH + 1];
        snprintf(buf, sizeof buf, "%s", text);
        size_t bl = strlen(buf);
        if (bl && buf[bl - 1] == '\n') buf[bl - 1] = '\0';
        if (!buf[0]) return from_key ? TCL_BREAK : TCL_OK;
        /* "/me action" -> toxcore ACTION message; rendered "* you action" */
        bool action = strncmp(buf, "/me ", 4) == 0 && buf[4];
        char *body = action ? buf + 4 : buf;
        emotify(body, sizeof buf - (size_t)(body - buf));
        tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_SEND, g->gn, body, 0,
                       action ? TOX_MESSAGE_TYPE_ACTION : TOX_MESSAGE_TYPE_NORMAL);
        const char *me = ui->self_name[0] ? ui->self_name : "you";
        char line[TOX_GROUP_MAX_MESSAGE_LENGTH + TT_NAME_MAX + 4];
        if (action)
            snprintf(line, sizeof line, "* you %s", body);
        else
            snprintf(line, sizeof line, "%s", body);
        group_append(g, me, action ? 2 : 1, line);
        hist_append_live(ui, action ? NULL : me, action ? 2 : 1, line);
        EV(".main.chat.in.input", "delete", "1.0", "end");
        roster_render(ui);
        return from_key ? TCL_BREAK : TCL_OK;
    }
    Contact *c = contact_by_fn(ui, ui->sel_fn);
    if (!c) return from_key ? TCL_BREAK : TCL_OK;
    EV(".main.chat.in.input", "get", "1.0", "end");
    const char *text = Tcl_GetStringResult(ui->interp);
    if (!text || !*text) return from_key ? TCL_BREAK : TCL_OK;
    char buf[TOX_MAX_MESSAGE_LENGTH + 1];
    snprintf(buf, sizeof buf, "%s", text);
    size_t bl = strlen(buf);
    if (bl && buf[bl - 1] == '\n') buf[bl - 1] = '\0'; /* tk::text trailing \n */
    if (!buf[0]) return from_key ? TCL_BREAK : TCL_OK;
    /* "/me action" -> toxcore ACTION message; rendered "* you action" */
    bool action = strncmp(buf, "/me ", 4) == 0 && buf[4];
    char *body = action ? buf + 4 : buf;
    emotify(body, sizeof buf - (size_t)(body - buf));
    tt_queue_post2(&ui->tt->in, TT_CMD_SEND_MESSAGE, c->fn, body, 0,
                   action ? TOX_MESSAGE_TYPE_ACTION : TOX_MESSAGE_TYPE_NORMAL);
    /* our message leaves: stop the typing indicator for this friend */
    if (ui->typing_sent && ui->typing_fn == c->fn) {
        tt_queue_post(&ui->tt->in, TT_CMD_SET_TYPING, c->fn, NULL, 0);
        ui->typing_sent = false;
        ui->typing_fn = UINT32_MAX;
    }
    const char *me = ui->self_name[0] ? ui->self_name : "you";
    char line[TOX_MAX_MESSAGE_LENGTH + 8];
    if (action)
        snprintf(line, sizeof line, "* you %s", body);
    else
        snprintf(line, sizeof line, "%s", body);
    chat_append(c, me, action ? 2 : 1, line);
    hist_append_live(ui, action ? NULL : me, action ? 2 : 1, line);
    EV(".main.chat.in.input", "delete", "1.0", "end");
    roster_render(ui);
    return from_key ? TCL_BREAK : TCL_OK;
}

static int cc_ignore(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Contact *r = request_row(ui);
    if (r) {
        ui->sel_kind = TT_SEL_NONE;
        contact_remove(ui, r);
        roster_render(ui);
        show_selected(ui);
    }
    return TCL_OK;
}

static int cc_search_changed(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    const char *q = Tcl_GetVar2(ui->interp, "tt_search", NULL, TCL_GLOBAL_ONLY);
    snprintf(ui->filter, sizeof ui->filter, "%s", q ? q : "");
    roster_render(ui);
    return TCL_OK;
}

static int cc_search_enter(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    const char *q = Tcl_GetVar2(ui->interp, "tt_search", NULL, TCL_GLOBAL_ONLY);
    const char *hex = q ? toxid_span(q) : NULL;
    if (hex) {
        /* exact ToxID in the search box: send the request directly */
        tt_queue_post(&ui->tt->in, TT_CMD_ADD_FRIEND, 0, hex, 0);
        Tcl_SetVar2(ui->interp, "tt_search", NULL, "", TCL_GLOBAL_ONLY);
        ui->filter[0] = '\0';
        roster_render(ui);
    } else {
        cc_add_open(cd, ip, objc, objv);
    }
    return TCL_OK;
}

static int cc_dot(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    /* the presence dot itself is the picker (qTox: click your circle) */
    EV("winfo", "pointerxy", ".");
    int wx = 0, wy = 0;
    sscanf(Tcl_GetStringResult(ui->interp), "%d %d", &wx, &wy);
    char xs[16], ys[16];
    snprintf(xs, sizeof xs, "%d", wx);
    snprintf(ys, sizeof ys, "%d", wy);
    EV("tk_popup", ".statusmenu", xs, ys);
    return TCL_OK;
}

/* Groups button in the tool row: create/join live here (the roster
   right-click "Create/Join group..." entries were redundant paths) */
static int cc_groups_menu(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    EV("winfo", "pointerxy", ".");
    int wx = 0, wy = 0;
    sscanf(Tcl_GetStringResult(ui->interp), "%d %d", &wx, &wy);
    char xs[16], ys[16];
    snprintf(xs, sizeof xs, "%d", wx);
    snprintf(ys, sizeof ys, "%d", wy);
    EV("tk_popup", ".groupsmenu", xs, ys);
    return TCL_OK;
}

static int cc_status_set(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip;
    if (objc < 2) return TCL_OK;
    int st = atoi(Tcl_GetString(objv[1]));
    if (st < TOX_USER_STATUS_NONE || st > TOX_USER_STATUS_BUSY) return TCL_OK;
    tt_queue_post(&ui->tt->in, TT_CMD_SET_STATUS, 0, NULL, st);
    return TCL_OK;
}

static int cc_avatar_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    EV("tk_getOpenFile", "-title", "Choose avatar PNG",
       "-filetypes", "{{PNG} {.png}} {{All files} *}");
    const char *f = Tcl_GetStringResult(ui->interp);
    if (f && *f)
        tt_queue_post(&ui->tt->in, TT_CMD_SET_AVATAR, 0, f, 0);
    return TCL_OK;
}

static int cc_avatar_clear(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    tt_queue_post(&ui->tt->in, TT_CMD_CLEAR_AVATAR, 0, NULL, 0);
    return TCL_OK;
}

/* badge avatar button: identity menu (name / status message / avatar) */
static int cc_avatar_menu(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    EV("winfo", "pointerxy", ".");
    int wx = 0, wy = 0;
    sscanf(Tcl_GetStringResult(ui->interp), "%d %d", &wx, &wy);
    char xs[16], ys[16];
    snprintf(xs, sizeof xs, "%d", wx);
    snprintf(ys, sizeof ys, "%d", wy);
    EV("tk_popup", ".avatarmenu", xs, ys);
    return TCL_OK;
}

/* ---- file transfer UI ---- */

/* "File...": pick a file and send it to the selected friend */
static int cc_file_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->sel_kind != TT_SEL_CHAT || !ui->ready) return TCL_OK;
    EV("tk_getOpenFile", "-title", "Choose a file to send");
    const char *f = Tcl_GetStringResult(ui->interp);
    if (f && *f)
        tt_queue_post(&ui->tt->in, TT_CMD_SEND_FILE, ui->sel_fn, f, 0);
    return TCL_OK;
}

/* human-readable size: 123 B / 4.5 KiB / 12.0 MiB */
static void fmt_size(uint64_t n, char *out, size_t cap) {
    if (n < 1024) { snprintf(out, cap, "%llu B", (unsigned long long)n); return; }
    double v = (double)n;
    const char *unit = "KiB";
    if (v >= 1024.0 * 1024.0) { v /= 1024.0 * 1024.0; unit = "MiB"; }
    else v /= 1024.0;
    snprintf(out, cap, "%.1f %s", v, unit);
}

static void xfer_line(Ui *ui, Contact *c, bool mine, const char *fmt, ...) {
    char text[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    chat_append_sys(c, mine, text);
    if (ui->sel_kind == TT_SEL_CHAT && ui->sel_fn == c->fn)
        hist_append_live(ui, NULL, 2 + mine, text);
}

/* incoming offer: state on the contact + modal accept/decline dialog */
static void offer_show(Ui *ui, Contact *c) {
    char sz[32];
    fmt_size(c->offer_size, sz, sizeof sz);
    char text[TOX_MAX_FILENAME_LENGTH + 96];
    snprintf(text, sizeof text, "wants to send you \xe2\x80\x9c%s\xe2\x80\x9d (%s)",
             c->offer_name, sz);
    if (ui->offer_open) { /* dialog up: refresh its labels */
        EV(".fo.l2", "configure", "-text", text);
        return;
    }
    ui->offer_open = true;
    EV("toplevel", ".fo", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".fo", "Incoming File");
    dlg_theme(ui, ".fo");
    EV("ttk::label", ".fo.l1", "-text",
       c->name[0] ? c->name : "A friend");
    EV("ttk::label", ".fo.l2", "-text", text, "-wraplength", "360", "-justify", "left");
    EV("ttk::frame", ".fo.b");
    EV("ttk::button", ".fo.yes", "-text", "Save as...", "-command", "tt_file_yes",
       "-style", "Green.TButton");
    EV("ttk::button", ".fo.no", "-text", "Decline", "-command", "tt_file_no",
       "-style", "Danger.TButton");
    EV("pack", ".fo.l1", "-side", "top", "-anchor", "w", "-font", "f_bold");
    EV("pack", ".fo.l2", "-side", "top", "-anchor", "w", "-pady", "6");
    EV("pack", ".fo.yes", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".fo.no", "-side", "right", "-pady", "8");
    EV("pack", ".fo.b", "-side", "top", "-fill", "x");
    EV("wm", "protocol", ".fo", "WM_DELETE_WINDOW", "tt_file_no");
    xfer_line(ui, c, false, "wants to send you \xe2\x80\x9c%s\xe2\x80\x9d (%s)",
              c->offer_name, sz);
    roster_render(ui);
}

/* Save as... -> native save dialog -> accept with that path */
static int cc_file_yes(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Contact *c = NULL;
    for (Contact *it = ui->contacts; it; it = it->next)
        if (!it->is_request && it->offer_pending) { c = it; break; }
    if (!c) { ui->offer_open = false; EV("destroy", ".fo"); return TCL_OK; }
    EV("tk_getSaveFile", "-title", "Save incoming file",
       "-initialfile", c->offer_name);
    const char *p = Tcl_GetStringResult(ui->interp);
    if (!p || !*p) return TCL_OK; /* dialog cancelled: offer stays pending */
    tt_queue_post(&ui->tt->in, TT_CMD_FILE_ACCEPT, 0, p, (int)c->offer_id);
    xfer_line(ui, c, false, "incoming file \xe2\x80\x9c%s\xe2\x80\x9d \xe2\x80\x94 saving",
              c->offer_name);
    c->offer_pending = false;
    ui->offer_open = false;
    EV("destroy", ".fo");
    roster_render(ui);
    return TCL_OK;
}

static int cc_file_no(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Contact *c = NULL;
    for (Contact *it = ui->contacts; it; it = it->next)
        if (!it->is_request && it->offer_pending) { c = it; break; }
    if (c) {
        tt_queue_post(&ui->tt->in, TT_CMD_FILE_REJECT, 0, NULL, (int)c->offer_id);
        xfer_line(ui, c, false, "declined incoming file \xe2\x80\x9c%s\xe2\x80\x9d",
                  c->offer_name);
        c->offer_pending = false;
        roster_render(ui);
    }
    ui->offer_open = false;
    EV("destroy", ".fo");
    return TCL_OK;
}

/* live "N/76 hex chars" counter under the Add Friend ToxID field: counts
   the longest contiguous hex span (same rule the send path applies via
   toxid_span), so a truncated paste is visible BEFORE Send is hit */
static int cc_add_count(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->add_open) return TCL_OK;
    EV(".add.e1", "get");
    const char *val = Tcl_GetStringResult(ui->interp);
    size_t best = 0;
    for (const char *p = val; *p;) {
        if (!isxdigit((unsigned char)*p)) { p++; continue; }
        size_t j = 0;
        while (isxdigit((unsigned char)p[j])) j++;
        if (j > best) best = j;
        p += j;
    }
    char txt[64];
    const size_t want = TOX_ADDRESS_SIZE * 2;
    if (best >= want)
        snprintf(txt, sizeof txt, "\xe2\x9c\x93 %u hex chars \xe2\x80\x94 ready to send",
                 (unsigned)best);
    else if (best > 0)
        snprintf(txt, sizeof txt, "%u/%u hex chars \xe2\x80\x94 too short, copy the full ToxID",
                 (unsigned)best, (unsigned)want);
    else
        snprintf(txt, sizeof txt, "paste the ToxID here (%u hex chars)", (unsigned)want);
    EV(".add.count", "configure", "-text", txt,
       "-foreground", best >= want ? C_ONLINE : (best > 0 ? C_BUSY : C_HINT));
    return TCL_OK;
}

static int cc_add_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->add_open) return TCL_OK;
    ui->add_open = true;
    EV("toplevel", ".add", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".add", "Add Friend");
    dlg_theme(ui, ".add");
    EV("ttk::label", ".add.l1", "-text", "Tox ID (76 hexadecimal characters)");
    EV("ttk::entry", ".add.e1", "-width", "84");
    EV("ttk::label", ".add.count", "-text", "");
    /* qTox: auto-fill from clipboard when it holds a ToxID */
    char cb[256];
    clipboard_get(ui, cb, sizeof cb);
    if (strlen(cb) == TOX_ADDRESS_SIZE * 2)
        EV(".add.e1", "insert", "0", cb);
    EV("ttk::label", ".add.l2", "-text", "Message");
    EV("tk::text", ".add.e2", "-width", "70", "-height", "4", "-wrap", "word");
    EV(".add.e2", "insert", "1.0", "adding you on TkTox");
    EV("ttk::frame", ".add.b");
    EV("ttk::button", ".add.ok", "-text", "Send Friend Request", "-command", "tt_add_ok",
       "-style", "Green.TButton");
    EV("ttk::button", ".add.no", "-text", "Cancel", "-command", "tt_add_cancel");
    EV("pack", ".add.l1", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".add.e1", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".add.count", "-side", "top", "-anchor", "w");
    EV("pack", ".add.l2", "-side", "top", "-anchor", "w", "-pady", "6");
    EV("pack", ".add.e2", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".add.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".add.no", "-side", "right", "-pady", "8");
    EV("pack", ".add.b", "-side", "top", "-anchor", "e");
    EV("bind", ".add.e1", "<Return>", "tt_add_ok");
    /* counter updates AFTER the class bindings run (appended "+" keeps
       the paste/cut/type behavior intact); Key/Release covers manual edits */
    EV("bind", ".add.e1", "<<Paste>>", "+tt_add_count");
    EV("bind", ".add.e1", "<<PasteSelection>>", "+tt_add_count");
    EV("bind", ".add.e1", "<KeyRelease>", "+tt_add_count");
    EV("bind", ".add.e1", "<ButtonRelease-2>", "+tt_add_count");
    EV("tt_add_count"); /* initial state (covers the auto-fill case) */
    EV("wm", "protocol", ".add", "WM_DELETE_WINDOW", "tt_add_cancel");
    EV("focus", ".add.e1");
    return TCL_OK;
}

static int cc_add_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->add_open) return TCL_OK;
    EV(".add.e1", "get");
    /* copy the entry text out BEFORE the next EV call: the result buffer
       is invalidated by ".add.e2 get" below, and the request was being
       built from the dangling pointer (the recurring "bad ToxID
       (len 49)" — round-19 stale-result rule) */
    char idbuf[256];
    snprintf(idbuf, sizeof idbuf, "%s", Tcl_GetStringResult(ui->interp));
    /* pasted IDs often carry whitespace/newlines or a label prefix;
       scan for the 76-hex span instead of requiring an exact string */
    const char *hex = toxid_span(idbuf);
    if (!hex) {
        /* qTox: malformed ID turns the field pink */
        EV(".add.e1", "configure", "-background", "#FFC1C1");
        return TCL_OK;
    }
    char hexbuf[TOX_ADDRESS_SIZE * 2 + 1];
    memcpy(hexbuf, hex, TOX_ADDRESS_SIZE * 2);
    hexbuf[TOX_ADDRESS_SIZE * 2] = '\0';
    EV(".add.e2", "get", "1.0", "end");
    const char *msg = Tcl_GetStringResult(ui->interp);
    char req[TOX_ADDRESS_SIZE * 2 + 2 + TOX_MAX_FRIEND_REQUEST_LENGTH];
    if (msg && *msg) {
        snprintf(req, sizeof req, "%s\n%s", hexbuf, msg);
    } else {
        snprintf(req, sizeof req, "%s", hexbuf);
    }
    tt_queue_post(&ui->tt->in, TT_CMD_ADD_FRIEND, 0, req, 0);
    ui->add_open = false;
    EV("destroy", ".add");
    return TCL_OK;
}

static int cc_add_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->add_open = false;
    EV("destroy", ".add");
    return TCL_OK;
}

static int cc_name_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->name_open) return TCL_OK;
    ui->name_open = true;
    EV("toplevel", ".nm", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".nm", "Change Profile Name");
    dlg_theme(ui, ".nm");
    EV("ttk::label", ".nm.l", "-text", "Name (max 128 bytes)");
    EV("ttk::entry", ".nm.e", "-width", "44");
    if (ui->self_name[0]) EV(".nm.e", "insert", "0", ui->self_name);
    EV("ttk::frame", ".nm.b");
    EV("ttk::button", ".nm.ok", "-text", "Set", "-command", "tt_name_ok", "-style", "Green.TButton");
    EV("ttk::button", ".nm.no", "-text", "Cancel", "-command", "tt_name_cancel");
    EV("pack", ".nm.l", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".nm.e", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".nm.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".nm.no", "-side", "right", "-pady", "8");
    EV("pack", ".nm.b", "-side", "top", "-fill", "x");
    EV("bind", ".nm.e", "<Return>", "tt_name_ok");
    EV("wm", "protocol", ".nm", "WM_DELETE_WINDOW", "tt_name_cancel");
    EV("focus", ".nm.e");
    return TCL_OK;
}

static int cc_name_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->name_open) return TCL_OK;
    EV(".nm.e", "get");
    const char *name = Tcl_GetStringResult(ui->interp);
    if (name && *name)
        tt_queue_post(&ui->tt->in, TT_CMD_SET_NAME, 0, name, 0);
    ui->name_open = false;
    EV("destroy", ".nm");
    return TCL_OK;
}

static int cc_name_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->name_open = false;
    EV("destroy", ".nm");
    return TCL_OK;
}

static int cc_smsg_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->smsg_open) return TCL_OK;
    ui->smsg_open = true;
    EV("toplevel", ".sm", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".sm", "Change Status Message");
    dlg_theme(ui, ".sm");
    EV("ttk::label", ".sm.l", "-text", "Status message");
    EV("ttk::entry", ".sm.e", "-width", "60");
    if (ui->self_status_msg[0]) EV(".sm.e", "insert", "0", ui->self_status_msg);
    EV("ttk::frame", ".sm.b");
    EV("ttk::button", ".sm.ok", "-text", "Set", "-command", "tt_smsg_ok", "-style", "Green.TButton");
    EV("ttk::button", ".sm.no", "-text", "Cancel", "-command", "tt_smsg_cancel");
    EV("pack", ".sm.l", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".sm.e", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".sm.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".sm.no", "-side", "right", "-pady", "8");
    EV("pack", ".sm.b", "-side", "top", "-fill", "x");
    EV("bind", ".sm.e", "<Return>", "tt_smsg_ok");
    EV("wm", "protocol", ".sm", "WM_DELETE_WINDOW", "tt_smsg_cancel");
    EV("focus", ".sm.e");
    return TCL_OK;
}

static int cc_smsg_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->smsg_open) return TCL_OK;
    EV(".sm.e", "get");
    const char *msg = Tcl_GetStringResult(ui->interp);
    tt_queue_post(&ui->tt->in, TT_CMD_SET_STATUS_MSG, 0, msg ? msg : "", 0);
    ui->smsg_open = false;
    EV("destroy", ".sm");
    return TCL_OK;
}

static int cc_smsg_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->smsg_open = false;
    EV("destroy", ".sm");
    return TCL_OK;
}

/* Settings: proxy config lives in the "<profile>.tt" sidecar (engine reads
   it before tox_new), so this dialog only writes the file and says so —
   the TOR badge reflects the running session's env/engine state. */
static int cc_st_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->st_open) return TCL_OK;
    ui->st_open = true;
    EV("toplevel", ".st", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".st", "Settings");
    dlg_theme(ui, ".st");
    TTSettings set;
    tt_settings_load(&set, ui->tt->profile_path);
    /* own ToxID (public key + nospam + checksum): read-only, copyable.
       The nospam is the 4-byte anti-spam field — share this full ID so
       friends can add you. Segments are color-coded like qTox: public key
       in the main text color, nospam in blue, checksum in gray. */
    EV("ttk::label", ".st.myl", "-text", "My ToxID (share to be added)",
       "-foreground", C_HINT);
    EV("tk::text", ".st.myt", "-width", "78", "-height", "1", "-wrap", "none",
       "-state", "disabled", "-font", "f_text", "-background", C_MAIN_BG,
       "-foreground", C_MAIN_TEXT, "-borderwidth", "1", "-relief", "solid");
    EV(".st.myt", "tag", "configure", "pk", "-foreground", C_MAIN_TEXT);
    EV(".st.myt", "tag", "configure", "nospam", "-foreground", "#0000FF");
    EV(".st.myt", "tag", "configure", "checksum", "-foreground", C_HINT);
    if (ui->my_toxid[0]) {
        EV(".st.myt", "configure", "-state", "normal");
        EV(".st.myt", "insert", "end", ui->my_toxid + 0, "pk");
        EV(".st.myt", "insert", "end", ui->my_toxid + 64, "nospam");
        EV(".st.myt", "insert", "end", ui->my_toxid + 72, "checksum");
        EV(".st.myt", "configure", "-state", "disabled");
    }
    EV("ttk::label", ".st.myn", "-text",
       "Blue = NoSpam (anti-spam), gray = checksum. Randomize to stop spam.",
       "-foreground", C_HINT);
    EV("ttk::button", ".st.myc", "-text", "Copy", "-command", "tt_copy_id");
    EV("ttk::button", ".st.myr", "-text", "Randomize nospam", "-command", "tt_set_nospam");
    EV("ttk::separator", ".st.mys", "-orient", "horizontal");
    EV("ttk::label", ".st.l1", "-text", "SOCKS5 proxy host (IPv4 literal, e.g. 127.0.0.1)");
    EV("ttk::entry", ".st.e1", "-width", "44");
    if (set.proxy_set) EV(".st.e1", "insert", "0", set.proxy_host);
    EV("ttk::label", ".st.l2", "-text", "SOCKS5 proxy port");
    EV("ttk::entry", ".st.e2", "-width", "10");
    if (set.proxy_set) {
        char pb[16];
        snprintf(pb, sizeof pb, "%ld", set.proxy_port);
        EV(".st.e2", "insert", "0", pb);
    } else {
        EV(".st.e2", "insert", "0", "9050");
    }
    EV("ttk::label", ".st.note", "-text",
       "Applies after restart. TT_PROXY_* env vars override this file.",
       "-foreground", C_HINT);
    /* M5: verification code for the selected contact's encrypted session.
       The code derives from the handshake root and is identical on both
       peers — compare it out-of-band to confirm no MITM. */
    EV("ttk::separator", ".st.sep", "-orient", "horizontal");
    EV("ttk::label", ".st.vl", "-text", "E2EE verification code (selected contact)",
       "-foreground", C_HINT);
    char vcode[96];
    Contact *vc = (ui->sel_kind == TT_SEL_CHAT) ? contact_by_fn(ui, ui->sel_fn) : NULL;
    if (vc && vc->e2ee && vc->e2ee_code[0])
        snprintf(vcode, sizeof vcode, "%s", vc->e2ee_code);
    else if (vc && vc->e2ee)
        snprintf(vcode, sizeof vcode, "(session established, code pending)");
    else
        snprintf(vcode, sizeof vcode, "(no encrypted session with this contact)");
    EV("ttk::label", ".st.vc", "-text", vcode, "-foreground", C_MAIN_TEXT);
    EV("ttk::frame", ".st.b");
    EV("ttk::button", ".st.ok", "-text", "Set", "-command", "tt_st_ok", "-style", "Green.TButton");
    EV("ttk::button", ".st.clr", "-text", "Clear proxy", "-command", "tt_st_clear");
    EV("ttk::button", ".st.no", "-text", "Cancel", "-command", "tt_st_cancel");
    EV("pack", ".st.myl", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.myt", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".st.myn", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.myc", "-side", "left", "-pady", "2", "-padx", "2");
    EV("pack", ".st.myr", "-side", "left", "-pady", "2", "-padx", "2");
    EV("pack", ".st.mys", "-side", "top", "-fill", "x", "-pady", "6");
    EV("pack", ".st.l1", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.e1", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".st.l2", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.e2", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.note", "-side", "top", "-anchor", "w", "-pady", "6");
    EV("pack", ".st.sep", "-side", "top", "-fill", "x", "-pady", "6");
    EV("pack", ".st.vl", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.vc", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".st.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".st.clr", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".st.no", "-side", "right", "-pady", "8");
    EV("pack", ".st.b", "-side", "top", "-fill", "x");
    EV("bind", ".st.e2", "<Return>", "tt_st_ok");
    EV("wm", "protocol", ".st", "WM_DELETE_WINDOW", "tt_st_cancel");
    EV("focus", ".st.e1");
    const char *env_host = getenv("TT_PROXY_HOST");
    if (env_host && env_host[0])
        TT_LOG("tk", "TT_PROXY_HOST=%s is active — sidecar proxy is overridden at start", env_host);
    return TCL_OK;
}

static int cc_st_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->st_open) return TCL_OK;
    /* copy BOTH fields out before using either: the second "get" invalidates
       the first result (same stale-result rule as cc_add_ok) */
    EV(".st.e1", "get");
    char hostbuf[128];
    snprintf(hostbuf, sizeof hostbuf, "%s", Tcl_GetStringResult(ui->interp));
    EV(".st.e2", "get");
    char portbuf[16];
    snprintf(portbuf, sizeof portbuf, "%s", Tcl_GetStringResult(ui->interp));
    if (!hostbuf[0]) {
        TT_LOG("tk", "empty host — use 'Clear proxy' to remove proxy settings");
        return TCL_OK;
    }
    /* mirror the engine rule exactly: only digits and dots survive */
    for (const char *p = hostbuf; *p; p++)
        if (!isdigit((unsigned char)*p) && *p != '.') {
            EV(".st.e1", "configure", "-background", "#FFC1C1");
            return TCL_OK;
        }
    char *end = NULL;
    long port = strtol(portbuf, &end, 10);
    if (port <= 0 || port > 65535 || (end && *end)) {
        EV(".st.e2", "configure", "-background", "#FFC1C1");
        return TCL_OK;
    }
    if (tt_settings_store_proxy(ui->tt->profile_path, hostbuf, port)) {
        TT_LOG("tk", "proxy settings saved (%s:%ld) — applies after restart",
               hostbuf, port);
        ui->st_open = false;
        EV("destroy", ".st");
        EV("tk_messageBox", "-icon", "info", "-type", "ok", "-title", "Proxy set",
           "-message", "Proxy saved. Restart TkTox for it to take effect.");
    } else {
        TT_LOG("tk", "failed to write settings sidecar");
    }
    return TCL_OK;
}

static int cc_st_clear(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->st_open) return TCL_OK;
    if (tt_settings_store_proxy(ui->tt->profile_path, NULL, 0)) {
        TT_LOG("tk", "proxy settings cleared — applies after restart");
        ui->st_open = false;
        EV("destroy", ".st");
        EV("tk_messageBox", "-icon", "info", "-type", "ok", "-title", "Proxy cleared",
           "-message", "Proxy cleared. Restart TkTox for it to take effect.");
    } else {
        TT_LOG("tk", "failed to write settings sidecar");
    }
    return TCL_OK;
}

static int cc_st_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->st_open = false;
    EV("destroy", ".st");
    return TCL_OK;
}

static int cc_copy_id(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->my_toxid[0]) {
        TT_LOG("tk", "copy my ID: not available yet");
        return TCL_OK;
    }
    EV("clipboard", "clear");
    EV("clipboard", "append", ui->my_toxid);
    TT_LOG("tk", "copied my ToxID to clipboard");
    return TCL_OK;
}

static int cc_set_nospam(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    tt_queue_post(&ui->tt->in, TT_CMD_SET_NOSPAM, 0, NULL, 0);
    return TCL_OK;
}

static int cc_remove(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->sel_kind != TT_SEL_CHAT) return TCL_OK;
    Contact *c = contact_by_fn(ui, ui->sel_fn);
    if (!c) return TCL_OK;
    tt_queue_post(&ui->tt->in, TT_CMD_DELETE_FRIEND, c->fn, NULL, 0);
    contact_remove(ui, c);
    ui->sel_kind = TT_SEL_NONE;
    ui->sel_fn = 0;
    roster_render(ui);
    show_selected(ui);
    return TCL_OK;
}

/* Up on empty input recalls the last message you sent to the selected friend */
static int cc_recall(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    EV(".main.chat.in.input", "get", "1.0", "end");
    const char *cur = Tcl_GetStringResult(ui->interp);
    if (cur && *cur) return TCL_OK; /* non-empty: leave history navigation */
    if (ui->sel_kind != TT_SEL_CHAT) return TCL_OK;
    Contact *c = contact_by_fn(ui, ui->sel_fn);
    if (!c) return TCL_OK;
    /* newest own line wins: scan the \x1f-format transcript backwards */
    const char *p = c->transcript + strlen(c->transcript);
    while (p > c->transcript) {
        p--;
        const char *nl = p;
        while (nl > c->transcript && nl[-1] != '\n') nl--;
        if (p != nl && (*nl == '\n')) nl++;
        char line[TOX_MAX_MESSAGE_LENGTH + 64];
        size_t ll = strlen(nl);
        if (ll >= sizeof line) goto next;
        memcpy(line, nl, ll);
        line[ll] = '\0';
        char *f1 = strchr(line, '\x1f');
        char *f2 = f1 ? strchr(f1 + 1, '\x1f') : NULL;
        char *f3 = f2 ? strchr(f2 + 1, '\x1f') : NULL;
        if (f1 && f2 && f3 && f1[1] == '1') {
            *f3 = '\0';
            EV(".main.chat.in.input", "delete", "1.0", "end");
            EV(".main.chat.in.input", "insert", "1.0", f3 + 1);
            return TCL_BREAK;
        }
    next:;
    }
    return TCL_OK;
}

/* <Button-3> script args: %x %y %X %Y (widget- and screen-relative) */
static int cc_roster_menu(ClientData cd, Tcl_Interp *ip, int objc,
                          Tcl_Obj *const objv[]) {
    Ui *ui = cd;
    (void)ip;
    if (objc != 5) return TCL_OK;
    const char *x = Tcl_GetString(objv[1]), *y = Tcl_GetString(objv[2]);
    const char *X = Tcl_GetString(objv[3]), *Y = Tcl_GetString(objv[4]);
    /* Route the menu on the row under the cursor, NOT on ui->sel_kind:
       ttk queues <<TreeviewSelect>> asynchronously, so inside this handler
       sel_kind is still the PREVIOUS selection — the exact friend/group
       menu swap reported. tt_selected is invoked explicitly so the menu
       commands (gselected() etc.) act on the row under the cursor; the
       later queued event no-ops via cc_selected's same-selection guard.
       Identify miss (row padding): selection stays as-is. */
    char iidbuf[32] = "";
    EV(".sb.rf.roster", "identify", "item", x, y);
    const char *iid = Tcl_GetStringResult(ui->interp);
    if (iid && *iid) snprintf(iidbuf, sizeof iidbuf, "%s", iid);
    if (strcmp(iidbuf, "gheads") == 0) return TCL_OK; /* section header: no menu */
    if (iidbuf[0]) {
        EV(".sb.rf.roster", "selection", "set", iidbuf);
        EV("tt_selected");
    }
    const char *menu = ".rostermenu";
    if (iidbuf[0] == 'g')
        menu = ".groupmenu";
    else if (!iidbuf[0] && ui->sel_kind == TT_SEL_GROUP)
        menu = ".groupmenu";
    EV("tk_popup", menu, X, Y);
    return TCL_OK;
}

/* ---- group dialogs ---- */

static Group *gselected(Ui *ui) {
    return ui->sel_kind == TT_SEL_GROUP ? group_by_gn(ui, ui->sel_fn) : NULL;
}

/* "Create group...": name + public/private radio */
static int cc_gnew_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->gnew_open) return TCL_OK;
    ui->gnew_open = true;
    EV("toplevel", ".gnew", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".gnew", "Create Group");
    dlg_theme(ui, ".gnew");
    EV("ttk::label", ".gnew.l", "-text", "Group name");
    EV("ttk::entry", ".gnew.e", "-width", "44");
    EV("ttk::frame", ".gnew.priv");
    EV("ttk::radiobutton", ".gnew.pub", "-text", "Public (listed)", "-variable", "tt_gpriv",
       "-value", "public");
    EV("ttk::radiobutton", ".gnew.prv", "-text", "Private (invite only)", "-variable", "tt_gpriv",
       "-value", "private");
    EV("ttk::frame", ".gnew.b");
    EV("ttk::button", ".gnew.ok", "-text", "Create", "-command", "tt_gnew_ok",
       "-style", "Green.TButton");
    EV("ttk::button", ".gnew.no", "-text", "Cancel", "-command", "tt_gnew_cancel");
    EV("pack", ".gnew.l", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gnew.e", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".gnew.prv", "-side", "right", "-padx", "4");
    EV("pack", ".gnew.pub", "-side", "right", "-padx", "4");
    EV("pack", ".gnew.priv", "-side", "top", "-fill", "x", "-pady", "4");
    EV("pack", ".gnew.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".gnew.no", "-side", "right", "-pady", "8");
    EV("pack", ".gnew.b", "-side", "top", "-fill", "x");
    EV("set", "tt_gpriv", "private");
    EV("bind", ".gnew.e", "<Return>", "tt_gnew_ok");
    EV("wm", "protocol", ".gnew", "WM_DELETE_WINDOW", "tt_gnew_cancel");
    EV("focus", ".gnew.e");
    return TCL_OK;
}

static int cc_gnew_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->gnew_open) return TCL_OK;
    EV(".gnew.e", "get");
    const char *name = Tcl_GetStringResult(ui->interp);
    if (!name || !*name) return TCL_OK;
    const char *priv = Tcl_GetVar2(ui->interp, "tt_gpriv", NULL, TCL_GLOBAL_ONLY);
    char payload[TT_NAME_MAX + 16];
    snprintf(payload, sizeof payload, "%s\n%s", name,
             priv && strcmp(priv, "public") == 0 ? "public" : "private");
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_CREATE, 0, payload, 0);
    ui->gnew_open = false;
    EV("destroy", ".gnew");
    return TCL_OK;
}

static int cc_gnew_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->gnew_open = false;
    EV("destroy", ".gnew");
    return TCL_OK;
}

/* "Join group": chat id + optional password */
static int cc_gjoin_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (ui->gjoin_open) return TCL_OK;
    ui->gjoin_open = true;
    EV("toplevel", ".gjoin", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".gjoin", "Join Group");
    dlg_theme(ui, ".gjoin");
    EV("ttk::label", ".gjoin.l1", "-text", "Chat ID (64 hexadecimal characters)");
    EV("ttk::entry", ".gjoin.e1", "-width", "72");
    /* qTox: auto-fill from clipboard when it holds a chat id */
    char cb[256];
    clipboard_get(ui, cb, sizeof cb);
    if (strlen(cb) == TOX_GROUP_CHAT_ID_SIZE * 2)
        EV(".gjoin.e1", "insert", "0", cb);
    EV("ttk::label", ".gjoin.l2", "-text", "Password (optional)");
    EV("ttk::entry", ".gjoin.e2", "-width", "34", "-show", "\xe2\x80\xa2");
    EV("ttk::frame", ".gjoin.b");
    EV("ttk::button", ".gjoin.ok", "-text", "Join", "-command", "tt_gjoin_ok",
       "-style", "Green.TButton");
    EV("ttk::button", ".gjoin.no", "-text", "Cancel", "-command", "tt_gjoin_cancel");
    EV("pack", ".gjoin.l1", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gjoin.e1", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".gjoin.l2", "-side", "top", "-anchor", "w", "-pady", "6");
    EV("pack", ".gjoin.e2", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".gjoin.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".gjoin.no", "-side", "right", "-pady", "8");
    EV("pack", ".gjoin.b", "-side", "top", "-fill", "x");
    EV("wm", "protocol", ".gjoin", "WM_DELETE_WINDOW", "tt_gjoin_cancel");
    EV("bind", ".gjoin.e1", "<Return>", "tt_gjoin_ok");
    EV("focus", ".gjoin.e1");
    return TCL_OK;
}

static int cc_gjoin_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    if (!ui->gjoin_open) return TCL_OK;
    EV(".gjoin.e1", "get");
    /* copy out before the password "get" invalidates the result */
    char cidbuf[TOX_GROUP_CHAT_ID_SIZE * 2 + 1];
    snprintf(cidbuf, sizeof cidbuf, "%s", Tcl_GetStringResult(ui->interp));
    if (strlen(cidbuf) != TOX_GROUP_CHAT_ID_SIZE * 2) {
        EV(".gjoin.e1", "configure", "-background", "#FFC1C1");
        return TCL_OK;
    }
    EV(".gjoin.e2", "get");
    const char *pw = Tcl_GetStringResult(ui->interp);
    char payload[TOX_GROUP_CHAT_ID_SIZE * 2 + 2 + TOX_GROUP_MAX_PASSWORD_SIZE + 1];
    if (pw && pw[0])
        snprintf(payload, sizeof payload, "%s\n%s", cidbuf, pw);
    else
        snprintf(payload, sizeof payload, "%s", cidbuf);
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_JOIN, 0, payload, 0);
    ui->gjoin_open = false;
    EV("destroy", ".gjoin");
    return TCL_OK;
}

static int cc_gjoin_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->gjoin_open = false;
    EV("destroy", ".gjoin");
    return TCL_OK;
}

/* incoming group invite: Accept/Decline buttons carry the invite index */
static int cc_ginv_yes(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip;
    int idx = objc > 1 ? atoi(Tcl_GetString(objv[1])) : -1;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_INVITE_ACC, 0, NULL, 0, idx);
    EV("destroy", ".gi");
    return TCL_OK;
}

static int cc_ginv_no(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip;
    int idx = objc > 1 ? atoi(Tcl_GetString(objv[1])) : -1;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_INVITE_DEC, 0, NULL, 0, idx);
    EV("destroy", ".gi");
    return TCL_OK;
}

/* "Invite friend...": pick one of the connected friends */
static int cc_ginvite_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || ui->ginvite_open) return TCL_OK;
    ui->ginvite_open = true;
    EV("toplevel", ".ginv", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".ginv", "Invite to Group");
    dlg_theme(ui, ".ginv");
    EV("ttk::label", ".ginv.l", "-text", "Friend to invite");
    EV("ttk::combobox", ".ginv.c", "-state", "readonly", "-width", "36",
       "-values", "{}", "-textvariable", "tt_ginvite_pick");
    /* friends list into the combobox */
    EV(".ginv.c", "configure", "-values", "{}");
    Tcl_Obj *names = Tcl_NewListObj(0, NULL);
    for (Contact *c = ui->contacts; c; c = c->next) {
        if (c->is_request) continue;
        char item[TT_NAME_MAX + 16];
        snprintf(item, sizeof item, "%s (#%u)", c->name[0] ? c->name : "unknown", c->fn);
        Tcl_ListObjAppendElement(NULL, names, Tcl_NewStringObj(item, -1));
    }
    EV(".ginv.c", "configure", "-values", Tcl_GetString(names));
    EV("ttk::frame", ".ginv.b");
    EV("ttk::button", ".ginv.ok", "-text", "Invite", "-command", "tt_ginvite_ok",
       "-style", "Green.TButton");
    EV("ttk::button", ".ginv.no", "-text", "Cancel", "-command", "tt_ginvite_cancel");
    EV("pack", ".ginv.l", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".ginv.c", "-side", "top", "-fill", "x", "-pady", "4");
    EV("pack", ".ginv.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".ginv.no", "-side", "right", "-pady", "8");
    EV("pack", ".ginv.b", "-side", "top", "-fill", "x");
    EV("wm", "protocol", ".ginv", "WM_DELETE_WINDOW", "tt_ginvite_cancel");
    if (ui->self_name[0] && g->name[0]) {
        char ttl[TT_NAME_MAX * 2 + 32];
        snprintf(ttl, sizeof ttl, "Invite to Group \xe2\x80\x94 %s", g->name);
        EV("wm", "title", ".ginv", ttl);
    }
    return TCL_OK;
}

static int cc_ginvite_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->ginvite_open) return TCL_OK;
    const char *pick = Tcl_GetVar2(ui->interp, "tt_ginvite_pick", NULL, TCL_GLOBAL_ONLY);
    if (!pick || !pick[0]) return TCL_OK;
    /* item text "name (#fn)": friend number is the suffix in the parens */
    const char *hash = strrchr(pick, '#');
    if (!hash) return TCL_OK;
    uint32_t fn = (uint32_t)strtoul(hash + 1, NULL, 10);
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_INVITE, g->gn, NULL, (int)fn);
    ui->ginvite_open = false;
    EV("destroy", ".ginv");
    return TCL_OK;
}

static int cc_ginvite_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->ginvite_open = false;
    EV("destroy", ".ginv");
    return TCL_OK;
}

/* "Set topic..." */
static int cc_gtopic_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || ui->gtopic_open) return TCL_OK;
    ui->gtopic_open = true;
    EV("toplevel", ".gtopic", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".gtopic", "Set Topic");
    dlg_theme(ui, ".gtopic");
    EV("ttk::label", ".gtopic.l", "-text", "Topic (max 512 bytes)");
    EV("ttk::entry", ".gtopic.e", "-width", "60");
    if (g->topic[0]) EV(".gtopic.e", "insert", "0", g->topic);
    EV("ttk::frame", ".gtopic.b");
    EV("ttk::button", ".gtopic.ok", "-text", "Set", "-command", "tt_gtopic_ok",
       "-style", "Green.TButton");
    EV("ttk::button", ".gtopic.no", "-text", "Cancel", "-command", "tt_gtopic_cancel");
    EV("pack", ".gtopic.l", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gtopic.e", "-side", "top", "-fill", "x", "-pady", "2");
    EV("pack", ".gtopic.ok", "-side", "right", "-pady", "8", "-padx", "4");
    EV("pack", ".gtopic.no", "-side", "right", "-pady", "8");
    EV("pack", ".gtopic.b", "-side", "top", "-fill", "x");
    EV("bind", ".gtopic.e", "<Return>", "tt_gtopic_ok");
    EV("wm", "protocol", ".gtopic", "WM_DELETE_WINDOW", "tt_gtopic_cancel");
    EV("focus", ".gtopic.e");
    return TCL_OK;
}

static int cc_gtopic_ok(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gtopic_open) return TCL_OK;
    EV(".gtopic.e", "get");
    const char *topic = Tcl_GetStringResult(ui->interp);
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_TOPIC, g->gn, topic ? topic : "", 0);
    ui->gtopic_open = false;
    EV("destroy", ".gtopic");
    return TCL_OK;
}

static int cc_gtopic_cancel(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->gtopic_open = false;
    EV("destroy", ".gtopic");
    return TCL_OK;
}

/* "Settings" (group header): founder controls — password, privacy, voice
   state, topic lock, peer limit. toxcore rejects every one of these for
   non-founders, so the button is disabled unless self_role == founder. */
static int cc_gctl_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || g->self_role != TOX_GROUP_ROLE_FOUNDER || ui->gctl_open) return TCL_OK;
    ui->gctl_open = true;
    EV("toplevel", ".gctl", "-padx", "14", "-pady", "14");
    EV("wm", "title", ".gctl", "Group Settings");
    dlg_theme(ui, ".gctl");
    char hdr[TT_NAME_MAX * 2 + 32];
    snprintf(hdr, sizeof hdr, "%s \xe2\x80\x94 group settings",
             g->name[0] ? g->name : "group");
    EV("ttk::label", ".gctl.h", "-text", hdr, "-font", "f_bold");
    EV("ttk::label", ".gctl.hint", "-text",
       "Owner controls; changes apply immediately.", "-font", "f_small");
    EV("pack", ".gctl.h", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.hint", "-side", "top", "-anchor", "w", "-pady", "2");

    /* password: empty entry clears it (engine posts "" -> NULL); row
       widgets are PATH-NESTED under the row frame so pack targets the
       frame — flat -side left/right packing into the dialog turns each
       slave into a full-height column and mangles everything below */
    EV("ttk::label", ".gctl.lp", "-text", "Password (empty = remove, max 32 bytes)");
    EV("ttk::frame", ".gctl.fp");
    EV("ttk::entry", ".gctl.fp.pw", "-width", "34", "-show", "\xe2\x80\xa2");
    EV("ttk::button", ".gctl.fp.b", "-text", "Apply", "-command", "tt_gctl_pw",
       "-style", "Green.TButton");
    EV("pack", ".gctl.fp.pw", "-side", "left", "-fill", "x", "-expand", "true");
    EV("pack", ".gctl.fp.b", "-side", "right", "-padx", "4");
    EV("pack", ".gctl.lp", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.fp", "-side", "top", "-fill", "x", "-pady", "2");

    /* privacy / voice / topic lock: combobox applies on selection.
       -values must be brace-FREE ("public private"): EvalObjv passes argv
       bytes literally, so "{public private}" arrives as a one-element
       list whose item is the literal braced text */
    EV("ttk::label", ".gctl.lpr", "-text", "Privacy");
    EV("ttk::combobox", ".gctl.priv", "-state", "readonly", "-width", "12",
       "-values", "public private");
    EV(".gctl.priv", "set", g->privacy ? "private" : "public");
    EV("bind", ".gctl.priv", "<<ComboboxSelected>>", "tt_gctl_priv");
    EV("pack", ".gctl.lpr", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.priv", "-side", "top", "-fill", "x", "-pady", "2");

    EV("ttk::label", ".gctl.lv", "-text", "Voice state");
    EV("ttk::combobox", ".gctl.voice", "-state", "readonly", "-width", "12",
       "-values", "all moderators founder");
    static const char *const vstr[3] = {"all", "moderators", "founder"};
    EV(".gctl.voice", "set", vstr[g->voice >= 0 && g->voice <= 2 ? g->voice : 0]);
    EV("bind", ".gctl.voice", "<<ComboboxSelected>>", "tt_gctl_voice");
    EV("pack", ".gctl.lv", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.voice", "-side", "top", "-fill", "x", "-pady", "2");

    EV("ttk::label", ".gctl.ltl", "-text", "Topic lock");
    EV("ttk::combobox", ".gctl.tlock", "-state", "readonly", "-width", "12",
       "-values", "unlocked locked");
    EV(".gctl.tlock", "set", g->topic_lock ? "locked" : "unlocked");
    EV("bind", ".gctl.tlock", "<<ComboboxSelected>>", "tt_gctl_tlock");
    EV("pack", ".gctl.ltl", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.tlock", "-side", "top", "-fill", "x", "-pady", "2");

    /* peer limit is a hard join cap in toxcore (default 100); 0 is not
       "unlimited" — it would lock everyone out, so entries <= 0 are ignored */
    EV("ttk::label", ".gctl.lpl", "-text", "Peer limit (max members)");
    EV("ttk::frame", ".gctl.fpl");
    EV("ttk::entry", ".gctl.fpl.pl", "-width", "10");
    if (g->peer_limit > 0) {
        char pl[12];
        snprintf(pl, sizeof pl, "%d", g->peer_limit);
        EV(".gctl.fpl.pl", "insert", "0", pl);
    }
    EV("ttk::button", ".gctl.fpl.b", "-text", "Apply", "-command", "tt_gctl_pl",
       "-style", "Green.TButton");
    EV("pack", ".gctl.fpl.pl", "-side", "left");
    EV("pack", ".gctl.fpl.b", "-side", "right", "-padx", "4");
    EV("pack", ".gctl.lpl", "-side", "top", "-anchor", "w", "-pady", "2");
    EV("pack", ".gctl.fpl", "-side", "top", "-fill", "x", "-pady", "2");

    EV("ttk::button", ".gctl.done", "-text", "Done", "-command", "tt_gctl_close");
    EV("pack", ".gctl.done", "-side", "bottom", "-pady", "8");
    EV("wm", "protocol", ".gctl", "WM_DELETE_WINDOW", "tt_gctl_close");
    if (ui->self_name[0] && g->name[0]) {
        char ttl[TT_NAME_MAX * 2 + 32];
        snprintf(ttl, sizeof ttl, "Group Settings \xe2\x80\x94 %s", g->name);
        EV("wm", "title", ".gctl", ttl);
    }
    return TCL_OK;
}

static int cc_gctl_close(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    ui->gctl_open = false;
    EV("destroy", ".gctl");
    return TCL_OK;
}

static int cc_gctl_pw(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gctl_open) return TCL_OK;
    EV(".gctl.fp.pw", "get");
    const char *pw = Tcl_GetStringResult(ui->interp);
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_PASSWORD, g->gn, pw ? pw : "", 0);
    EV(".gctl.fp.pw", "delete", "0", "end");
    return TCL_OK;
}

static int cc_gctl_priv(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gctl_open) return TCL_OK;
    EV(".gctl.priv", "get");
    const char *v = Tcl_GetStringResult(ui->interp);
    int priv = (v && strcmp(v, "private") == 0) ? 1 : 0;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_PRIVACY, g->gn, NULL, 0, priv);
    return TCL_OK;
}

static int cc_gctl_voice(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gctl_open) return TCL_OK;
    EV(".gctl.voice", "get");
    const char *v = Tcl_GetStringResult(ui->interp);
    int vs = 0;
    if (v && strcmp(v, "moderators") == 0) vs = 1;
    else if (v && strcmp(v, "founder") == 0) vs = 2;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_VOICE, g->gn, NULL, 0, vs);
    return TCL_OK;
}

static int cc_gctl_tlock(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gctl_open) return TCL_OK;
    EV(".gctl.tlock", "get");
    const char *v = Tcl_GetStringResult(ui->interp);
    int lock = (v && strcmp(v, "locked") == 0) ? 1 : 0;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_TOPIC_LOCK, g->gn, NULL, 0, lock);
    return TCL_OK;
}

static int cc_gctl_pl(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !ui->gctl_open) return TCL_OK;
    EV(".gctl.fpl.pl", "get");
    const char *v = Tcl_GetStringResult(ui->interp);
    char *end = NULL;
    /* toxcore has no "unlimited" value: maxpeers is a hard join cap, so
       non-positive or non-numeric input is ignored rather than posted */
    long n = v ? strtol(v, &end, 10) : 0;
    if (n <= 0 || (end && *end)) return TCL_OK;
    if (n > 65535) n = 65535;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_PEER_LIMIT, g->gn, NULL, 0, (int)n);
    return TCL_OK;
}

/* dialog chrome helper: white toplevel (ttk TFrame/TLabel/TEntry default to
   white in this light scheme — an unstyled toplevel shows default gray
   around/between them), and correct-order wm transient so the dialog maps
   ABOVE the main window: "wm transient . <dlg>" inverts the master and
   tells the WM to keep the MAIN window on top (dialog pops underneath) */
static void dlg_theme(Ui *ui, const char *path) {
    EV(path, "configure", "-background", C_MAIN_BG);
    EV("wm", "transient", path, ".");
    (void)ui;
}

/* "Members": roster with per-peer moderation, gated by own role.
   Buttons rebuild the row; peer ids are dense so keys are stable. */
static int cc_gmembers_open(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g) return TCL_OK;
    /* rebuild the dialog each time: membership may have changed */
    EV("destroy", ".gm");
    EV("toplevel", ".gm", "-padx", "12", "-pady", "12");
    EV("wm", "title", ".gm", "Group Members");
    dlg_theme(ui, ".gm");
    char hdr[TT_NAME_MAX * 2 + 64];
    snprintf(hdr, sizeof hdr, "%s \xe2\x80\x94 you are %s",
             g->name[0] ? g->name : "group", role_str(g->self_role));
    EV("ttk::label", ".gm.h", "-text", hdr, "-font", "f_bold");
    EV("pack", ".gm.h", "-side", "top", "-anchor", "w", "-pady", "4");
    for (GroupMember *m = g->members; m; m = m->next) {
        char fr[24], rowname[48], lrow[64], krow[64];
        snprintf(fr, sizeof fr, "%u", m->pid);
        snprintf(rowname, sizeof rowname, ".gm.r%s", fr);
        EV("ttk::frame", rowname);
        char who[TT_NAME_MAX + 48];
        snprintf(who, sizeof who, "%s  \xc2\xb7  %s",
                 m->name[0] ? m->name : "peer", role_str(m->role));
        snprintf(lrow, sizeof lrow, ".gm.r%s.l", fr);
        EV("ttk::label", lrow, "-text", who);
        EV("pack", lrow, "-side", "left", "-fill", "x", "-expand", "true");
        /* kick/role only on peers below own role (founder > mod > user) */
        if (g->self_role <= m->role && g->self_role != TOX_GROUP_ROLE_OBSERVER &&
            m->role != TOX_GROUP_ROLE_FOUNDER) {
            if (g->self_role <= TOX_GROUP_ROLE_MODERATOR) {
                char kickcmd[48];
                snprintf(kickcmd, sizeof kickcmd, "tt_gkick %s", fr);
                snprintf(krow, sizeof krow, ".gm.r%s.k", fr);
                EV("ttk::button", krow, "-text", "Kick", "-command", kickcmd,
                   "-style", "Danger.TButton", "-width", "6");
                EV("pack", krow, "-side", "right", "-padx", "2");
            }
            /* role dropdown: observer/user/moderator (founder is fixed) */
            char rolerow[32], rolecmd[72];
            snprintf(rolerow, sizeof rolerow, ".gm.r%s.r", fr);
            snprintf(rolecmd, sizeof rolecmd, "tt_grole %s %s", fr, rolerow);
            EV("ttk::combobox", rolerow, "-width", "10", "-state", "readonly",
               "-values", "observer user moderator");
            EV(rolerow, "set", role_str(m->role));
            EV("bind", rolerow, "<<ComboboxSelected>>", rolecmd);
            EV("pack", rolerow, "-side", "right", "-padx", "2");
        }
        EV("pack", rowname, "-side", "top", "-fill", "x", "-pady", "2");
    }
    EV("ttk::button", ".gm.close", "-text", "Close", "-command", "destroy .gm");
    EV("pack", ".gm.close", "-side", "bottom", "-pady", "8");
    return TCL_OK;
}

/* role combobox apply: tt_grole <pid> <widget> */
static int cc_grole(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip;
    if (objc < 3) return TCL_OK;
    Group *g = gselected(ui);
    if (!g) return TCL_OK;
    uint32_t pid = (uint32_t)strtoul(Tcl_GetString(objv[1]), NULL, 10);
    const char *widget = Tcl_GetString(objv[2]);
    EV(widget, "get");
    const char *val = Tcl_GetStringResult(ui->interp);
    int role = -1;
    if (val && strcmp(val, "observer") == 0) role = TOX_GROUP_ROLE_OBSERVER;
    else if (val && strcmp(val, "user") == 0) role = TOX_GROUP_ROLE_USER;
    else if (val && strcmp(val, "moderator") == 0) role = TOX_GROUP_ROLE_MODERATOR;
    if (role < 0) return TCL_OK;
    tt_queue_post2(&ui->tt->in, TT_CMD_GROUP_ROLE, g->gn, NULL, (int)pid, role);
    return TCL_OK;
}

static int cc_gkick(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip;
    if (objc < 2) return TCL_OK;
    Group *g = gselected(ui);
    if (!g) return TCL_OK;
    uint32_t pid = (uint32_t)strtoul(Tcl_GetString(objv[1]), NULL, 10);
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_KICK, g->gn, NULL, (int)pid);
    return TCL_OK;
}

static int cc_gleave(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g) return TCL_OK;
    tt_queue_post(&ui->tt->in, TT_CMD_GROUP_LEAVE, g->gn, NULL, 0);
    return TCL_OK;
}

static int cc_gcopy_id(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    Ui *ui = cd; (void)ip; (void)objv; (void)objc;
    Group *g = gselected(ui);
    if (!g || !g->chat_id_hex[0]) return TCL_OK;
    EV("clipboard", "clear");
    EV("clipboard", "append", g->chat_id_hex);
    return TCL_OK;
}/* ---- construction ---- */

static void build_widgets(Ui *ui) {
    EV("ttk::style", "theme", "use", "clam");

    /* fonts: uTox uses Roboto; fall back to Helvetica when absent */
    EV("font", "create", "f_text", "-family", "Helvetica", "-size", "11");
    EV("font", "create", "f_bold", "-family", "Helvetica", "-size", "12", "-weight", "bold");
    EV("font", "create", "f_small", "-family", "Helvetica", "-size", "10");

    /* --- ttk style palette (uTox default theme) --- */
    EV("ttk::style", "configure", "TFrame", "-background", C_MAIN_BG);
    EV("ttk::style", "configure", "Sidebar.TFrame", "-background", C_SIDEBAR);
    EV("ttk::style", "configure", "Badge.TFrame", "-background", C_BADGE);
    EV("ttk::style", "configure", "Header.TFrame", "-background", C_BADGE);
    EV("ttk::style", "configure", "TLabel", "-background", C_MAIN_BG, "-foreground", C_MAIN_TEXT);
    EV("ttk::style", "configure", "Side.TLabel", "-background", C_SIDEBAR, "-foreground", C_LIST_TEXT);
    EV("ttk::style", "configure", "Badge.TLabel", "-background", C_BADGE, "-foreground", C_LIST_TEXT);
    EV("ttk::style", "configure", "BadgeSub.TLabel", "-background", C_BADGE, "-foreground", C_LIST_SUBTEXT);
    EV("ttk::style", "configure", "Head.TLabel", "-background", C_BADGE, "-foreground", C_MAIN_TEXT);
    EV("ttk::style", "configure", "HeadSub.TLabel", "-background", C_BADGE, "-foreground", C_SUBTEXT);
    EV("ttk::style", "configure", "Treeview", "-background", C_SIDEBAR,
       "-foreground", C_LIST_TEXT, "-fieldbackground", C_SIDEBAR,
       "-rowheight", "40", "-borderwidth", "0");
    EV("ttk::style", "map", "Treeview",
       "-background", "selected #FFFFFF", "-foreground", "selected #1C1C1C");
    EV("ttk::style", "configure", "Green.TButton", "-background", C_ONLINE, "-foreground", C_MAIN_BG);
    EV("ttk::style", "map", "Green.TButton",
       "-background", "disabled #D1D1D1 pressed #76D56A");
    EV("ttk::style", "configure", "Danger.TButton", "-background", C_BUSY, "-foreground", C_MAIN_BG);
    EV("ttk::style", "map", "Danger.TButton", "-background", "pressed #DC5656");
    EV("ttk::style", "configure", "TButton", "-padding", "6");

    /* ============ sidebar ============ */
    EV("ttk::frame", ".sb", "-style", "Sidebar.TFrame");

    /* self badge */
    EV("ttk::frame", ".sb.badge", "-style", "Badge.TFrame", "-height", "64");
    EV("ttk::button", ".sb.badge.avatar", "-text", "\xf0\x9f\x91\xa4", "-width", "3",
       "-command", "tt_avatar_menu");
    EV("ttk::label", ".sb.badge.name", "-style", "Badge.TLabel",
       "-text", "unnamed", "-font", "f_bold");
    EV("ttk::label", ".sb.badge.smsg", "-style", "BadgeSub.TLabel",
       "-text", "no status message", "-font", "f_small");
    EV("ttk::label", ".sb.badge.dot", "-style", "Badge.TLabel",
       "-text", "\xe2\x97\x8f", "-foreground", C_OFFLINE_DOT, "-font", "f_small",
       "-cursor", "hand2");
    EV("bind", ".sb.badge.dot", "<Button-1>", "tt_dot");
    EV("grid", ".sb.badge.avatar", "-row", "0", "-column", "0", "-rowspan", "2",
       "-padx", "6", "-pady", "8");
    EV("grid", ".sb.badge.name", "-row", "0", "-column", "1", "-sticky", "w", "-padx", "2");
    EV("grid", ".sb.badge.smsg", "-row", "1", "-column", "1", "-sticky", "w", "-padx", "2");
    EV("grid", ".sb.badge.dot", "-row", "0", "-column", "2", "-rowspan", "2",
       "-padx", "6", "-sticky", "e");
    EV("grid", "columnconfigure", ".sb.badge", "1", "-weight", "1");
    EV("grid", ".sb.badge", "-row", "0", "-column", "0", "-sticky", "ew");
    EV("grid", "rowconfigure", ".sb.badge", "0", "-weight", "0");
    (void)ui;
    EV("bind", ".sb.badge.smsg", "<Double-Button-1>", "tt_smsg_open");
    EV("bind", ".sb.badge.name", "<Double-Button-1>", "tt_name_open");

    /* roster */
    EV("ttk::frame", ".sb.rf");
    EV("ttk::scrollbar", ".sb.rf.sb2", "-orient", "vertical", "-command", ".sb.rf.roster yview");
    EV("ttk::treeview", ".sb.rf.roster", "-columns", "0", "-show", "tree",
       "-yscrollcommand", ".sb.rf.sb2 set", "-selectmode", "browse");
    EV("bind", ".sb.rf.roster", "<<TreeviewSelect>>", "tt_selected");
    EV("pack", ".sb.rf.sb2", "-side", "right", "-fill", "y");
    EV("pack", ".sb.rf.roster", "-side", "left", "-fill", "both", "-expand", "true");

    /* search bar: qTox places it between badge and list */
    EV("ttk::frame", ".sb.bottom", "-style", "Badge.TFrame", "-height", "30");
    EV("ttk::entry", ".sb.bottom.search", "-font", "f_small", "-textvariable", "tt_search",
       "-style", "Badge.TEntry");
    EV("ttk::style", "configure", "Badge.TEntry",
       "-fieldbackground", "#313131", "-foreground", C_LIST_TEXT, "-insertcolor", C_LIST_TEXT);
    EV("pack", ".sb.bottom.search", "-side", "left", "-fill", "both", "-expand", "true",
       "-padx", "4", "-pady", "2");
    EV("grid", ".sb.bottom", "-row", "1", "-column", "0", "-sticky", "ew");

    EV("grid", ".sb.rf", "-row", "2", "-column", "0", "-sticky", "nsew");

    /* roster context menu (right-click): remove friend */
    EV("menu", ".rostermenu", "-tearoff", "0");
    EV(".rostermenu", "add", "command", "-label", "Remove friend", "-command", "tt_remove");
    EV("bind", ".sb.rf.roster", "<Button-3>", "tt_roster_menu %x %y %X %Y");

    /* group context menu (right-click on a group row) */
    EV("menu", ".groupmenu", "-tearoff", "0");
    EV(".groupmenu", "add", "command", "-label", "Invite friend...", "-command", "tt_ginvite_open");
    EV(".groupmenu", "add", "command", "-label", "Set topic...", "-command", "tt_gtopic_open");
    EV(".groupmenu", "add", "command", "-label", "Members", "-command", "tt_gmembers_open");
    EV(".groupmenu", "add", "separator");
    EV(".groupmenu", "add", "command", "-label", "Copy chat ID", "-command", "tt_gcopy_id");
    EV(".groupmenu", "add", "command", "-label", "Leave group", "-command", "tt_gleave");

    /* Groups tool-row menu: the create/join entry points */
    EV("menu", ".groupsmenu", "-tearoff", "0");
    EV(".groupsmenu", "add", "command", "-label", "Create group...", "-command", "tt_gnew_open");
    EV(".groupsmenu", "add", "command", "-label", "Join group (chat ID)...", "-command", "tt_gjoin_open");

    /* presence picker (qTox radio pattern); identity editing (status
       message / avatar) lives in the badge avatar button menu */
    EV("menu", ".statusmenu", "-tearoff", "0");
    EV(".statusmenu", "add", "radiobutton", "-label", "Online", "-variable", "tt_status",
       "-value", "online", "-command", "tt_status_set 0");
    EV(".statusmenu", "add", "radiobutton", "-label", "Away", "-variable", "tt_status",
       "-value", "away", "-command", "tt_status_set 1");
    EV(".statusmenu", "add", "radiobutton", "-label", "Busy", "-variable", "tt_status",
       "-value", "busy", "-command", "tt_status_set 2");

    /* badge avatar button menu: the identity edit surface */
    EV("menu", ".avatarmenu", "-tearoff", "0");
    EV(".avatarmenu", "add", "command", "-label", "Change nickname...", "-command", "tt_name_open");
    EV(".avatarmenu", "add", "command", "-label", "Set status message...", "-command", "tt_smsg_open");
    EV(".avatarmenu", "add", "command", "-label", "Copy my ID", "-command", "tt_copy_id");
    EV(".avatarmenu", "add", "separator");
    EV(".avatarmenu", "add", "command", "-label", "Settings (proxy)...", "-command", "tt_st_open");
    EV(".avatarmenu", "add", "separator");
    EV(".avatarmenu", "add", "command", "-label", "Set avatar (PNG)...", "-command", "tt_avatar_open");
    EV(".avatarmenu", "add", "command", "-label", "Clear avatar", "-command", "tt_avatar_clear");

    /* bottom tool row: qTox tooliconsZone — flat full-width action buttons */
    EV("ttk::frame", ".sb.tools", "-style", "Badge.TFrame", "-height", "35");
    EV("ttk::button", ".sb.tools.add", "-text", "+ Add Friend", "-command", "tt_add_open",
       "-style", "Tool.TButton");
    EV("ttk::button", ".sb.tools.groups", "-text", "Groups \xe2\x96\xbe", "-command",
       "tt_groups_menu", "-style", "Tool.TButton");
    EV("ttk::style", "configure", "Tool.TButton",
       "-background", C_BADGE, "-foreground", C_LIST_TEXT, "-borderwidth", "0");
    EV("ttk::style", "map", "Tool.TButton", "-background", "active #4E4E4E");
    EV("pack", ".sb.tools.add", "-side", "left", "-fill", "both", "-expand", "true",
       "-padx", "2", "-pady", "2");
    EV("pack", ".sb.tools.groups", "-side", "left", "-fill", "both", "-padx", "2", "-pady", "2");
    EV("grid", ".sb.tools", "-row", "3", "-column", "0", "-sticky", "ew");

    EV("grid", "rowconfigure", ".sb", "2", "-weight", "1");
    EV("grid", "columnconfigure", ".sb", "0", "-weight", "1");

    /* ============ main pane ============ */
    EV("ttk::frame", ".main");

    /* chat subpane */
    EV("ttk::frame", ".main.chat");
    EV("ttk::frame", ".main.chat.chead", "-style", "Badge.TFrame", "-height", "56");
    EV("ttk::button", ".main.chat.chead.avatar", "-text", "\xf0\x9f\x91\xa4", "-width", "3",
       "-state", "disabled", "-cursor", "");
    EV("ttk::frame", ".main.chat.chead.t", "-style", "Badge.TFrame");
    EV("ttk::label", ".main.chat.chead.t.name", "-style", "Head.TLabel", "-text", "TkTox",
       "-font", "f_bold");
    EV("ttk::label", ".main.chat.chead.t.smsg", "-style", "HeadSub.TLabel", "-text", "", "-font", "f_small");
    EV("pack", ".main.chat.chead.t.name", "-side", "top", "-anchor", "w");
    EV("pack", ".main.chat.chead.t.smsg", "-side", "top", "-anchor", "w");
    EV("pack", ".main.chat.chead.t", "-side", "left", "-fill", "both", "-expand", "true");
    /* group controls: visible only while a group is selected
       (chead_group_ctl_render packs/unpacks on demand) */
    EV("ttk::frame", ".main.chat.chead.gctl", "-style", "Badge.TFrame");
    EV("ttk::button", ".main.chat.chead.gctl.members", "-text", "Members",
       "-command", "tt_gmembers_open", "-width", "8");
    EV("ttk::button", ".main.chat.chead.gctl.invite", "-text", "Invite...",
       "-command", "tt_ginvite_open", "-width", "8");
    EV("ttk::button", ".main.chat.chead.gctl.settings", "-text", "Settings",
       "-command", "tt_gctl_open", "-width", "8");
    EV("pack", ".main.chat.chead.gctl.members", "-side", "left", "-padx", "2");
    EV("pack", ".main.chat.chead.gctl.invite", "-side", "left", "-padx", "2");
    EV("pack", ".main.chat.chead.gctl.settings", "-side", "left", "-padx", "2");
    /* active-transfer cancel: stays unpacked here; show_selected packs it
       for friends with a running transfer only */
    EV("ttk::button", ".main.chat.chead.cancel", "-text", "Cancel",
       "-command", "tt_file_cancel", "-style", "Danger.TButton", "-width", "7");
    /* call controls: stay unpacked; chead_call_render packs per call state */
    EV("ttk::button", ".main.chat.chead.call", "-text", "Call",
       "-command", "tt_av_call", "-width", "7");
    EV("ttk::button", ".main.chat.chead.answ", "-text", "Answer",
       "-command", "tt_av_answer", "-style", "Green.TButton", "-width", "7");
    EV("ttk::button", ".main.chat.chead.decl", "-text", "Decline",
       "-command", "tt_av_decline", "-style", "Danger.TButton", "-width", "7");
    /* mic mute + output gate: side-explicit (🎤 = our mic, 🔊/🔇 = our
       speaker) — pack order right→left is mute, pause, hang up */
    EV("ttk::button", ".main.chat.chead.mute", "-text", "🎤 Mute",
       "-command", "tt_av_mute", "-width", "7");
    EV("ttk::button", ".main.chat.chead.pause", "-text", "⏸ Pause",
       "-command", "tt_av_pause", "-width", "8");
    EV("ttk::button", ".main.chat.chead.self", "-text", "📹 Video",
       "-command", "tt_av_self", "-width", "7");
    /* M-AV5: toggle our output gate for the selected contact's call */
    EV("ttk::button", ".main.chat.chead.deaf", "-text", "Mute out",
       "-command", "tt_av_deaf", "-width", "7");
    /* avatar slot stays unpacked until a friend with an avatar is selected
       (chead_avatar_render packs it on demand) */
    EV("pack", ".main.chat.chead", "-side", "top", "-fill", "x");

    EV("ttk::frame", ".main.chat.hf");
    EV("tk::text", ".main.chat.hf.hist", "-wrap", "word", "-font", "f_text",
       "-state", "disabled", "-highlightthickness", "0", "-padx", "10", "-pady", "6",
       "-foreground", C_CHAT_TEXT, "-background", C_MAIN_BG, "-spacing1", "2",
       "-height", "8"); /* small request: pack expands it to fill anyway;
                           default 24 lines crops the input strip at 560px */
    EV(".main.chat.hf.hist", "tag", "configure", "stamp", "-foreground", C_HINT, "-font", "f_small",
       "-tabs", "94 left"); /* no braces: EvalObjv passes argv bytes literally */
    EV(".main.chat.hf.hist", "tag", "configure", "who", "-foreground", C_SUBTEXT, "-font", "f_text",
       "-lmargin1", "2", "-lmargin2", "2");
    EV(".main.chat.hf.hist", "tag", "configure", "who_me", "-foreground", C_SUBTEXT, "-font", "f_bold",
       "-lmargin1", "2", "-lmargin2", "2"); /* qTox bolds own author */
    EV(".main.chat.hf.hist", "tag", "configure", "msg", "-foreground", C_CHAT_TEXT,
       "-lmargin1", "20", "-lmargin2", "6", "-rmargin", "6"); /* wraps flush */
    EV(".main.chat.hf.hist", "tag", "configure", "sys", "-foreground", C_HINT,
       "-font", "f_small", "-lmargin1", "20", "-lmargin2", "6"); /* file-transfer system lines */
    EV(".main.chat.hf.hist", "tag", "configure", "day", "-foreground", C_HINT, "-font", "f_small",
       "-justify", "center", "-spacing1", "6", "-spacing3", "6");
    EV(".main.chat.hf.hist", "tag", "configure", "gap", "-spacing3", "10"); /* trailing \n of each message: last-char rule puts the space after the message, not between author and body */
    EV("ttk::scrollbar", ".main.chat.hf.sb3", "-orient", "vertical", "-command", ".main.chat.hf.hist yview");
    EV(".main.chat.hf.hist", "configure", "-yscrollcommand", ".main.chat.hf.sb3 set");
    EV("pack", ".main.chat.hf.sb3", "-side", "right", "-fill", "y");
    EV("pack", ".main.chat.hf.hist", "-side", "left", "-fill", "both", "-expand", "true");
    /* pixel-stable right tab stop for timestamps on any window size;
       must come after the widget exists */
    EV("bind", ".main.chat.hf.hist", "<Configure>", "+tt_hist_resize");
    EV("pack", ".main.chat.hf", "-side", "top", "-fill", "both", "-expand", "true");

    EV("ttk::frame", ".main.chat.in", "-height", "46");
    EV("tk::text", ".main.chat.in.input", "-font", "f_text", "-height", "2", "-width", "40",
       "-wrap", "word",
       "-highlightthickness", "1", "-highlightbackground", C_EDGE, "-state", "disabled");
    EV("ttk::button", ".main.chat.in.send", "-text", "Send", "-command", "tt_send",
       "-style", "Green.TButton", "-state", "disabled", "-width", "7");
    EV("ttk::button", ".main.chat.in.file", "-text", "\xf0\x9f\x93\x8e", "-command", "tt_file_open",
       "-state", "disabled", "-width", "3", "-cursor", "hand2");
    EV("pack", ".main.chat.in.input", "-side", "left", "-fill", "both", "-expand", "true",
       "-padx", "8", "-pady", "6");
    EV("pack", ".main.chat.in.file", "-side", "left", "-pady", "6", "-anchor", "e");
    EV("pack", ".main.chat.in.send", "-side", "left", "-padx", "8", "-pady", "6", "-anchor", "e");
    EV("pack", ".main.chat.in", "-side", "top", "-fill", "x");
    EV("bind", ".main.chat.in.input", "<Return>", "+tt_send");
    EV("bind", ".main.chat.in.input", "<Up>", "tt_recall");
    EV("bind", ".main.chat.in.input", "<Shift-Up>", "break");
    EV("bind", ".main.chat.in.input", "<Key>", "+tt_input_key");

    /* request subpane */
    EV("ttk::frame", ".main.req");
    EV("ttk::label", ".main.req.title", "-text", "Friend Request", "-font", "f_bold");
    EV("ttk::label", ".main.req.key", "-text", "", "-foreground", C_SUBTEXT, "-font", "f_small");
    EV("ttk::label", ".main.req.msg", "-text", "", "-font", "f_text", "-wraplength", "420",
       "-justify", "left");
    EV("ttk::frame", ".main.req.b");
    EV("ttk::button", ".main.req.add", "-text", "Add", "-command", "tt_send",
       "-style", "Green.TButton", "-width", "8");
    EV("ttk::button", ".main.req.no", "-text", "Ignore", "-command", "tt_ignore",
       "-style", "Danger.TButton", "-width", "8");
    EV("pack", ".main.req.title", "-side", "top", "-anchor", "w", "-padx", "12", "-pady", "14");
    EV("pack", ".main.req.key", "-side", "top", "-anchor", "w", "-padx", "12", "-pady", "2");
    EV("pack", ".main.req.msg", "-side", "top", "-anchor", "w", "-padx", "12", "-pady", "8");
    EV("pack", ".main.req.no", "-side", "right", "-padx", "8", "-pady", "12");
    EV("pack", ".main.req.add", "-side", "right", "-pady", "12");
    EV("pack", ".main.req.b", "-side", "bottom", "-anchor", "e", "-fill", "x");

    EV("grid", ".main.chat", "-row", "0", "-column", "0", "-sticky", "nsew");
    EV("grid", ".main.req", "-row", "0", "-column", "0", "-sticky", "nsew");
    EV("grid", "rowconfigure", ".main", "0", "-weight", "1");
    EV("grid", "columnconfigure", ".main", "0", "-weight", "1");
    EV("grid", "remove", ".main.req");

    /* ============ root layout ============ */
    EV("grid", ".sb", "-row", "0", "-column", "0", "-sticky", "ns");
    EV("grid", ".main", "-row", "0", "-column", "1", "-sticky", "nsew");
    EV("grid", "rowconfigure", ".", "0", "-weight", "1");
    EV("grid", "columnconfigure", ".", "0", "-weight", "0");
    EV("grid", "columnconfigure", ".", "1", "-weight", "1");

    EV("wm", "title", ".", "TkTox");
    EV("wm", "geometry", ".", "880x560");
    EV("wm", "minsize", ".", "720", "460");
}

int ui_run(TTToxThread *tt) {
    memset(&g_ui, 0, sizeof g_ui);
    g_ui.tt = tt;
    g_ui.sel_kind = TT_SEL_NONE;
    g_ui.self_presence = TOX_USER_STATUS_NONE;
    g_ui.self_conn = TOX_CONNECTION_NONE;
    g_ui.typing_fn = UINT32_MAX;

    Tcl_FindExecutable("TkTox");
    /* The vendored libtcl8.6.so has Debian's script path (/usr/share/tcltk/tcl8.6)
       compiled in; a mismatched system script version there fails Tcl_Init with
       "version conflict for package Tcl". Point both interpreters at the vendored
       8.6.18 script trees via the documented env overrides before init. */
    setenv("TCL_LIBRARY",
           TT_TCL_SCRIPT_DIR, 1);
    setenv("TK_LIBRARY",
           TT_TK_SCRIPT_DIR, 1);
    g_ui.interp = Tcl_CreateInterp();
    if (!g_ui.interp) {
        TT_LOG("tk", "Tcl_CreateInterp failed");
        tt_tox_thread_stop(tt);
        return 1;
    }
    if (Tcl_Init(g_ui.interp) != TCL_OK) {
        TT_LOG("tk", "Tcl_Init failed: %s", Tcl_GetStringResult(g_ui.interp));
        tt_tox_thread_stop(tt);
        return 1;
    }
    if (Tk_Init(g_ui.interp) != TCL_OK) {
        TT_LOG("tk", "Tk_Init failed: %s", Tcl_GetStringResult(g_ui.interp));
        tt_tox_thread_stop(tt);
        return 1;
    }

    bind_cmd(&g_ui, "tt_selected", cc_selected);
    bind_cmd(&g_ui, "tt_send", cc_send);
    bind_cmd(&g_ui, "tt_input_key", cc_input_key);
    bind_cmd(&g_ui, "tt_file_cancel", cc_file_cancel);
    bind_cmd(&g_ui, "tt_ignore", cc_ignore);
    bind_cmd(&g_ui, "tt_search_changed", cc_search_changed);
    bind_cmd(&g_ui, "tt_search_enter", cc_search_enter);
    bind_cmd(&g_ui, "tt_add_open", cc_add_open);
    bind_cmd(&g_ui, "tt_add_ok", cc_add_ok);
    bind_cmd(&g_ui, "tt_add_cancel", cc_add_cancel);
    bind_cmd(&g_ui, "tt_add_count", cc_add_count);
    bind_cmd(&g_ui, "tt_name_open", cc_name_open);
    bind_cmd(&g_ui, "tt_name_ok", cc_name_ok);
    bind_cmd(&g_ui, "tt_name_cancel", cc_name_cancel);
    bind_cmd(&g_ui, "tt_smsg_open", cc_smsg_open);
    bind_cmd(&g_ui, "tt_smsg_ok", cc_smsg_ok);
    bind_cmd(&g_ui, "tt_smsg_cancel", cc_smsg_cancel);
    bind_cmd(&g_ui, "tt_st_open", cc_st_open);
    bind_cmd(&g_ui, "tt_st_ok", cc_st_ok);
    bind_cmd(&g_ui, "tt_st_clear", cc_st_clear);
    bind_cmd(&g_ui, "tt_st_cancel", cc_st_cancel);
    bind_cmd(&g_ui, "tt_copy_id", cc_copy_id);
    bind_cmd(&g_ui, "tt_set_nospam", cc_set_nospam);
    bind_cmd(&g_ui, "tt_remove", cc_remove);
    bind_cmd(&g_ui, "tt_roster_menu", cc_roster_menu);
    bind_cmd(&g_ui, "tt_recall", cc_recall);
    bind_cmd(&g_ui, "tt_hist_resize", cc_hist_resize);
    bind_cmd(&g_ui, "tt_dot", cc_dot);
    bind_cmd(&g_ui, "tt_groups_menu", cc_groups_menu);
    bind_cmd(&g_ui, "tt_status_set", cc_status_set);
    bind_cmd(&g_ui, "tt_avatar_open", cc_avatar_open);
    bind_cmd(&g_ui, "tt_avatar_clear", cc_avatar_clear);
    bind_cmd(&g_ui, "tt_avatar_menu", cc_avatar_menu);
    bind_cmd(&g_ui, "tt_file_open", cc_file_open);
    bind_cmd(&g_ui, "tt_file_yes", cc_file_yes);
    bind_cmd(&g_ui, "tt_file_no", cc_file_no);
    bind_cmd(&g_ui, "tt_av_call", cc_av_call);
    bind_cmd(&g_ui, "tt_av_answer", cc_av_answer);
    bind_cmd(&g_ui, "tt_av_decline", cc_av_decline);
    bind_cmd(&g_ui, "tt_av_mute", cc_av_mute);
    bind_cmd(&g_ui, "tt_av_pause", cc_av_pause);
    bind_cmd(&g_ui, "tt_av_video", cc_av_answer_video);
    bind_cmd(&g_ui, "tt_av_deaf", cc_av_deaf);
    bind_cmd(&g_ui, "tt_av_self", cc_av_self);
    bind_cmd(&g_ui, "tt_video_tick", cc_video_tick);
    bind_cmd(&g_ui, "tt_call_tick", cc_call_tick);
    bind_cmd(&g_ui, "tt_gnew_open", cc_gnew_open);
    bind_cmd(&g_ui, "tt_gnew_ok", cc_gnew_ok);
    bind_cmd(&g_ui, "tt_gnew_cancel", cc_gnew_cancel);
    bind_cmd(&g_ui, "tt_gjoin_open", cc_gjoin_open);
    bind_cmd(&g_ui, "tt_gjoin_ok", cc_gjoin_ok);
    bind_cmd(&g_ui, "tt_gjoin_cancel", cc_gjoin_cancel);
    bind_cmd(&g_ui, "tt_ginv_yes", cc_ginv_yes);
    bind_cmd(&g_ui, "tt_ginv_no", cc_ginv_no);
    bind_cmd(&g_ui, "tt_ginvite_open", cc_ginvite_open);
    bind_cmd(&g_ui, "tt_ginvite_ok", cc_ginvite_ok);
    bind_cmd(&g_ui, "tt_ginvite_cancel", cc_ginvite_cancel);
    bind_cmd(&g_ui, "tt_gtopic_open", cc_gtopic_open);
    bind_cmd(&g_ui, "tt_gtopic_ok", cc_gtopic_ok);
    bind_cmd(&g_ui, "tt_gtopic_cancel", cc_gtopic_cancel);
    bind_cmd(&g_ui, "tt_gctl_open", cc_gctl_open);
    bind_cmd(&g_ui, "tt_gctl_close", cc_gctl_close);
    bind_cmd(&g_ui, "tt_gctl_pw", cc_gctl_pw);
    bind_cmd(&g_ui, "tt_gctl_priv", cc_gctl_priv);
    bind_cmd(&g_ui, "tt_gctl_voice", cc_gctl_voice);
    bind_cmd(&g_ui, "tt_gctl_tlock", cc_gctl_tlock);
    bind_cmd(&g_ui, "tt_gctl_pl", cc_gctl_pl);
    bind_cmd(&g_ui, "tt_gmembers_open", cc_gmembers_open);
    bind_cmd(&g_ui, "tt_grole", cc_grole);
    bind_cmd(&g_ui, "tt_gkick", cc_gkick);
    bind_cmd(&g_ui, "tt_gleave", cc_gleave);
    bind_cmd(&g_ui, "tt_gcopy_id", cc_gcopy_id);

    TT_LOG("tk", "phase: init ok, building widgets");
    build_widgets(&g_ui);
    roster_colors(&g_ui);
    TT_LOG("tk", "phase: widgets built, draining initial events");

    /* initial events pushed before the loop: ToxID, self name/status */
    for (int i = 0; i < 5; i++) {
        TTEvent *e0 = tt_queue_pop_timed(&tt->out, 0);
        if (!e0) break;
        handle_event(&g_ui, e0);
        tt_event_free(e0);
    }
    badge_render(&g_ui);
    TT_LOG("tk", "phase: entering main loop");

    poll_events(&g_ui);
    Tk_MainLoop();

    TT_LOG("tk", "phase: main loop exited, cleaning up");
    while (g_ui.contacts) contact_remove(&g_ui, g_ui.contacts);
    Tcl_DeleteInterp(g_ui.interp);
    TT_LOG("tk", "phase: cleanup done");
    tt_tox_thread_stop(tt);
    return 0;
}