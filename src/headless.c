#include "tox_thread.h"
#include "headless.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <tox/toxav.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* Headless mode: no GTK. Runs the tox thread, prints lifecycle events.
   Used for CI, M3 loopback tests, and display-less environments.
   Exits 0 after self comes online, 2 on timeout, 1 on tox failure. */
int headless_main(const char *profile) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    int rc = 2;
    while (!g_stop) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (!ev) continue;
        switch (ev->type) {
        case TT_EV_TOXID:
            TT_LOG("main", "ToxID: %s", ev->str ? ev->str : "?");
            break;
        case TT_EV_SELF_CONNECTION:
            TT_LOG("main", "self connection: %d", ev->ival);
            if (ev->ival != 0) { /* connected: success for test harnesses */
                rc = 0;
                g_stop = 1;
            }
            break;
        case TT_EV_FRIEND_REQUEST:
            TT_LOG("main", "friend request from %s", ev->str ? ev->str : "?");
            break;
        case TT_EV_SHUTDOWN:
            g_stop = 1;
            rc = 1;
            break;
        default:
            break;
        }
        tt_event_free(ev);
    }
    tt_tox_thread_stop(&tt);
    return rc;
}

/* ---- bot mode: automated two-instance M2 test ----
   Responder (no peer ToxID): accepts any friend request, echoes
   "pong-m2" for a "ping-m2" message, exits 0 after replying.
   Initiator (peer ToxID given): adds the peer, sends "ping-m2" on
   first online event, exits 0 when the expected reply arrives. */

static bool str_contains(const char *hay, size_t hay_len, const char *needle) {
    char buf[TOX_MAX_MESSAGE_LENGTH + 1];
    size_t n = hay_len < TOX_MAX_MESSAGE_LENGTH ? hay_len : TOX_MAX_MESSAGE_LENGTH;
    memcpy(buf, hay, n);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

/* ---- Echo Bot test avatar: 96x96 RGBA smiley, minimal PNG writer ----
   Stored-deflate blocks only (no zlib), same spirit as the GIF dot
   generator in ui_tk.c: enough of the format to produce a valid,
   human-checkable image without pulling in a compression library. */

static uint32_t tt_crc32(const unsigned char *b, size_t n) {
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; i++) {
        c ^= b[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

static uint32_t tt_adler32(const unsigned char *b, size_t n) {
    uint32_t a = 1, s = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + b[i]) % 65521;
        s = (s + a) % 65521;
    }
    return (s << 16) | a;
}

static void tt_png_chunk(unsigned char *p, size_t *pos,
                         const char *type, const unsigned char *data, uint32_t len) {
    p[(*pos)++] = (unsigned char)(len >> 24);
    p[(*pos)++] = (unsigned char)(len >> 16);
    p[(*pos)++] = (unsigned char)(len >> 8);
    p[(*pos)++] = (unsigned char)len;
    size_t start = *pos;
    for (int i = 0; i < 4; i++) p[(*pos)++] = (unsigned char)type[i];
    if (len) memcpy(p + *pos, data, len);
    *pos += len;
    uint32_t crc = tt_crc32(p + start, *pos - start);
    p[(*pos)++] = (unsigned char)(crc >> 24);
    p[(*pos)++] = (unsigned char)(crc >> 16);
    p[(*pos)++] = (unsigned char)(crc >> 8);
    p[(*pos)++] = (unsigned char)crc;
}

static void tt_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[2 + 1] = (unsigned char)v;
}

static unsigned char *echo_avatar_png(uint32_t *out_len) {
    enum { W = 96, H = 96 };
    size_t raw_len = (size_t)H * (1 + W * 4); /* filter byte + RGBA row */
    unsigned char *raw = malloc(raw_len);
    if (!raw) return NULL;
    unsigned char *r = raw;
    for (int y = 0; y < H; y++) {
        *r++ = 0; /* filter: none */
        for (int x = 0; x < W; x++) {
            int dx = x - 48, dy = y - 48;
            int d2 = dx * dx + dy * dy;
            unsigned char px[4] = {0, 0, 0, 0}; /* transparent corner */
            if (d2 <= 45 * 45) {                /* face disc, online green */
                px[0] = 0x6B; px[1] = 0xC2; px[2] = 0x60; px[3] = 0xFF;
                int e2 = (dx - 14) * (dx - 14) + (dy + 10) * (dy + 10);
                int e1 = (dx + 14) * (dx + 14) + (dy + 10) * (dy + 10);
                if (e2 <= 36 || e1 <= 36) {     /* eyes */
                    px[0] = 0x1C; px[1] = 0x1C; px[2] = 0x1C;
                } else {
                    int m2 = dx * dx + (dy - 4) * (dy - 4);
                    if ((dy - 4) > 0 && m2 >= 24 * 24 && m2 <= 28 * 28) {
                        px[0] = 0x1C; px[1] = 0x1C; px[2] = 0x1C; /* smile */
                    }
                }
            }
            memcpy(r, px, 4);
            r += 4;
        }
    }

    /* zlib stream: header + one stored block + adler32 */
    size_t zlen = 2 + 5 + raw_len + 4;
    unsigned char *z = malloc(zlen);
    if (!z) { free(raw); return NULL; }
    z[0] = 0x78; z[1] = 0x01;
    z[2] = 0x01; /* BFINAL | BTYPE=00 stored */
    z[3] = (unsigned char)(raw_len & 0xFF);
    z[4] = (unsigned char)(raw_len >> 8);
    z[5] = (unsigned char)(~raw_len & 0xFF);
    z[6] = (unsigned char)((~raw_len >> 8) & 0xFF);
    memcpy(z + 7, raw, raw_len);
    tt_be32(z + 2 + 5 + raw_len, tt_adler32(raw, raw_len));
    free(raw);

    size_t total = 8 + (12 + 13) + (12 + zlen) + 12;
    unsigned char *png = malloc(total);
    if (!png) { free(z); return NULL; }
    static const unsigned char sig[8] =
        {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    memcpy(png, sig, 8);
    size_t pos = 8;
    unsigned char ihdr[13];
    tt_be32(ihdr, 96); tt_be32(ihdr + 4, 96);
    ihdr[8] = 8;  /* bit depth */
    ihdr[9] = 6;  /* color type RGBA */
    ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    tt_png_chunk(png, &pos, "IHDR", ihdr, 13);
    tt_png_chunk(png, &pos, "IDAT", z, (uint32_t)zlen);
    tt_png_chunk(png, &pos, "IEND", NULL, 0);
    free(z);
    *out_len = (uint32_t)total;
    return png;
}

#define ECHO_BOT_AVATAR_PATH "/tmp/TkTox-echo-bot-avatar.png"

static void echo_bot_set_avatar(void) {
    uint32_t alen = 0;
    unsigned char *png = echo_avatar_png(&alen);
    if (!png) return;
    FILE *fp = fopen(ECHO_BOT_AVATAR_PATH, "wb");
    if (fp) {
        fwrite(png, 1, alen, fp);
        fclose(fp);
    }
    free(png);
}

/* ---- file roundtrip test: deterministic pattern file ----
   Content is a pure function of the offset, so the receiver verifies the
   downloaded copy byte-for-byte by regenerating the pattern (1.5 MiB:
   exercises multi-chunk serving and the 256KiB progress events). */
#define TT_TEST_FILE_PATH "/tmp/TkTox-testfile.bin"
#define TT_TEST_FILE_RX_PATH "/tmp/TkTox-testfile-rx.bin"
#define TT_TEST_FILE_SIZE (1536u * 1024u)

/* round 25: TT_BOT_CANCEL=1 turns the file phase into a mid-transfer
   cancel test — an 8 MiB staged file leaves the initiator time to see
   progress events before it cancels; both sides must see FILE_FAILED */
#define TT_TEST_FILE_BIG_PATH "/tmp/TkTox-testfile-big.bin"
#define TT_TEST_FILE_BIG_SIZE (8u * 1024u * 1024u)

/* round 14: NGC private-group roundtrip constants */
#define TT_NGC_TOPIC "ngc round 14 topic"

static unsigned char test_file_byte(uint64_t i) {
    return (unsigned char)(i * 131u + (i >> 9) * 7u);
}

static bool test_file_write(const char *path, uint64_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    unsigned char block[65536];
    for (uint64_t off = 0; off < size; off += sizeof block) {
        size_t n = sizeof block;
        if (off + n > size) n = size - (size_t)off;
        for (size_t i = 0; i < n; i++) block[i] = test_file_byte(off + i);
        if (fwrite(block, 1, n, fp) != n) { fclose(fp); return false; }
    }
    fclose(fp);
    return true;
}

static bool echo_test_file_write(void) {
    return test_file_write(TT_TEST_FILE_PATH, TT_TEST_FILE_SIZE);
}

static bool echo_test_file_verify(void) {
    FILE *fp = fopen(TT_TEST_FILE_RX_PATH, "rb");
    if (!fp) return false;
    unsigned char block[65536], want[65536];
    bool ok = true;
    uint64_t off = 0;
    while (ok) {
        size_t n = fread(block, 1, sizeof block, fp);
        if (n == 0) break;
        for (size_t i = 0; i < n; i++) want[i] = test_file_byte(off + i);
        if (memcmp(block, want, n) != 0) ok = false;
        off += n;
    }
    fclose(fp);
    return ok && off == TT_TEST_FILE_SIZE;
}

int bot_main(const char *profile, const char *peer_toxid) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    bool initiator = peer_toxid != NULL;
    bool ping_sent = false, pong_sent = false;
    bool file_sent = false, file_offered = false, file_done = false, file_ok = false;
    bool file_failed = false;
    /* round 25: typing indicator + read receipts + mid-transfer cancel */
    bool cancel_mode = getenv("TT_BOT_CANCEL") != NULL;
    bool typing_got = false, receipt_got = false, cancel_test = false;
    bool tx_failed = false, cancel_sent = false;
    unsigned xfer_run = 0;
    time_t typing_at = 0;
    time_t start = time(NULL);
    time_t pong_at = 0, file_at = 0;
    int rc = 2;
    /* round 14: NGC private-group roundtrip
       initiator: pong-m2 -> GROUP_CREATE -> GROUP_INVITE -> on peer join:
       promote to moderator + set topic + send "ngc-ping" -> expects
       "ngc-pong-m2" back + PEER_EXIT when the responder leaves.
       responder: GROUP_INVITE -> auto-accept -> sees promotion + topic +
       "ngc-ping" -> sends "ngc-pong-m2" -> leaves 2s later. */
    int group_gn = -1;
    uint32_t pong_fn = UINT32_MAX;
    /* round 25: friend number the ping arrived from + typing-dance state */
    uint32_t ping_fn = UINT32_MAX;
    bool typing_shown = false;
    bool group_want = false, group_created = false, peer_joined = false, group_pong = false;
    bool peer_gone = false, gpong_sent = false, gleft_seen = false;
    bool role_seen = false, gtopic_seen = false, kick_posted = false;
    unsigned last_mid = 0; /* round 25: initiator's last sent tox message id */
    int peer_pid = -1; /* responder's group peer id (from PEER_JOIN) */
    time_t ngc_at = 0, gpong_at = 0, file_done_at = 0;
    /* M-AV1/M-AV2: TT_BOT_CALL=1 runs a call-signaling phase (audio call ->
       peer auto-answers -> ACTIVE states seen both sides -> hangup -> ENDED
       FINISHED both sides). Media flows but is dropped by the engine stubs
       (device layer is M-AV3); this verifies signaling + state machine. */
    bool call_mode = getenv("TT_BOT_CALL") != NULL;
    /* M-AV2: TT_BOT_CALL_SOLO skips the file/group phases entirely — a
       focused call-only regression (av-test.sh). Call cycles are timing-
       fragile next to the file/group phases (the responder can complete
       them and exit before the peer's CANCEL→FINISHED lands). */
    bool call_solo = getenv("TT_BOT_CALL_SOLO") != NULL;
    /* M-AV4: TT_BOT_CALL_VTEST (implies SOLO) adds a video exchange: the
       call negotiates video (2500 kbps), the initiator pumps TT_AV_VTEST
       synthetic frames, both sides count TT_EV_AV_FRAME rx. */
    bool call_vtest = getenv("TT_BOT_CALL_VTEST") != NULL;
    if (call_vtest) call_solo = true;
    bool call_initiated = false, call_answered = false, call_hangup = false;
    bool call_state_seen = false, call_ended_ok = false, call_finished_rx = false;
    bool video_sent = false, video_rx = false; /* M-AV4 evidence */
    bool video_pump_on = false; /* responder echo pump started */
    uint32_t video_rx_w = 0, video_rx_h = 0, video_rx_n = 0;
    uint32_t call_fn = UINT32_MAX; /* friend number of the active call */
    time_t call_at = 0;
    /* tier B1: TT_BOT_CALL_PAUSE adds a mid-call pause/resume cycle before
       the callee hangup (initiator pauses -> state 0 both ends -> initiator
       resumes -> pre-pause states seen both ends). */
    bool call_pause_test = getenv("TT_BOT_CALL_PAUSE") != NULL;
    bool pause_sent = false, paused_seen = false, resumed_seen = false;
    bool resume_posted = false;
    uint32_t pre_pause_state = 0, g_last_active_state = 0;
    /* tier B2: mid-call video bit-rate change (vtest calls only — on an
       audio-only call a rate set would flip the S_VIDEO capability). */
    bool br_sent = false;
    /* tier B3 negative paths (av-test.sh): TT_BOT_CALL_DECLINE = the peer
       CANCELs on arrival (caller expects FINISHED + ENDED, never an ACTIVE
       state); TT_BOT_CALL_OFFLINE = solo call to an unreachable friend ->
       toxav rejects (NOT_CONNECTED), no crash. */
    bool call_decline_test = getenv("TT_BOT_CALL_DECLINE") != NULL;
    bool call_offline_test = getenv("TT_BOT_CALL_OFFLINE") != NULL;
    bool offline_call_posted = false;
    /* M3: TT_BOT_E2EE exercises the encrypted layer end-to-end (the script
       sets TT_E2EE=1 to enable it): engine handshakes on friend-online,
       the ping stashes until the session is live, then flows as DATA;
       both sides log their 32-hex verify code for the script to compare.
       Solo mode: no file/group phases. */
    bool e2ee_mode = getenv("TT_BOT_E2EE") != NULL;
    bool e2ee_established = false;
    char e2ee_code[33] = {0};
    if (e2ee_mode) call_solo = true;
    /* M4 harness modes (e2ee-test.sh reorder/replay): the initiator drives
       the ratchet edge cases over the wire after the session establishes.
       reorder: deliver DATA frames seq 2,1,3 out of order — the responder
       recovers 1,2 via the skipped-key store and echoes all three back.
       replay: re-inject the last incoming DATA frame into the local session
       — must reject as TT_E2EE_REPLAY (never crash, never consume state). */
    bool e2ee_reorder = getenv("TT_BOT_E2EE_REORDER") != NULL;
    bool e2ee_replay = getenv("TT_BOT_E2EE_REPLAY") != NULL;
    bool reorder_posted = false;
    int reorder_rx = 0;   /* responder: m1/m2/m3 received (recovered) */
    int reorder_echo = 0; /* initiator: m1/m2/m3 echoes received back */
    bool replay_posted = false;
    /* tier B3 offline test: valid-checksum ToxID for a key nobody owns
       (key 0xa0..0xbe,0x7f — last byte < 128 per public_key_valid — plus
       nospam 0xffffffff; data_checksum XOR-fold over the 36 bytes =
       00c0). The ADD succeeds, the friend never connects, toxav rejects
       the call. */
    const char *offline_toxid =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe7fffffffff00c0";
    time_t offline_call_at = 0;
    if (call_decline_test || call_offline_test) call_solo = true;
    if (call_offline_test) offline_call_at = start + 1;

    if (initiator) {
        /* tier B3 offline mode: the peer arg only flips the initiator role —
           the real friend is NOT added; the unreachable fake friend (fn 0)
           below is the only one */
        if (!call_offline_test)
            tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, peer_toxid, 0);
        tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "Trench Bot", 0);
        if (cancel_mode) test_file_write(TT_TEST_FILE_BIG_PATH, TT_TEST_FILE_BIG_SIZE);
    } else {
        tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "Echo Bot", 0);
        /* test avatar for manual UI checks: green smiley, ~37KB PNG */
        echo_bot_set_avatar();
        tt_queue_post(&tt.in, TT_CMD_SET_AVATAR, 0, ECHO_BOT_AVATAR_PATH, 0);
        /* known-content file for the transfer roundtrip test */
        echo_test_file_write();
    }

    while (!g_stop && time(NULL) - start < 180) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (!ev) {
            /* tier B3 offline test: post add (unreachable friend -> fn 0) +
               call; toxav must reject with NOT_CONNECTED (4), no crash */
            if (initiator && call_offline_test && !offline_call_posted &&
                offline_call_at != 0 && time(NULL) - offline_call_at >= 5) {
                offline_call_posted = true;
                offline_call_at = time(NULL);
                TT_LOG("bot", "offline test: adding unreachable friend %s",
                       offline_toxid);
                tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, offline_toxid, 0);
                tt_queue_post2(&tt.in, TT_CMD_AV_CALL, 0, NULL, 32, 0);
            }
            /* tier B3 decline test: call the peer ~2 s after connect (the
               FRIEND_CONNECTION trigger is the primary path) */
            if (initiator && call_decline_test && !call_initiated &&
                pong_sent && time(NULL) - pong_at >= 2) {
                call_initiated = true;
                call_fn = 0;
                call_at = time(NULL);
                TT_LOG("bot", "decline test: calling friend 0 (audio 32k) [timer]");
                tt_queue_post2(&tt.in, TT_CMD_AV_CALL, 0, NULL, 32, 0);
            }
            /* tier B3: negative-path runs exit once the assertion evidence
               exists — the offline instance right after its add+call settle,
               the decline caller once the peer's CANCEL landed */
            if (initiator && call_offline_test && offline_call_posted &&
                time(NULL) - offline_call_at >= 3) {
                TT_LOG("bot", "offline test: no crash after rejection — done");
                rc = 0;
                break;
            }
            if (initiator && call_decline_test && call_ended_ok &&
                call_finished_rx) {
                TT_LOG("bot", "decline test: FINISHED + ENDED after peer CANCEL");
                rc = 0;
                break;
            }
            /* round 25: hold the pong 2s after the typing signal so toxcore
               flushes the typing packet before the engine's auto reset */
            if (!initiator && typing_shown && !pong_sent &&
                time(NULL) - typing_at >= 2) {
                TT_LOG("bot", "typing shown 2s — sending pong-m2");
                tt_queue_post(&tt.in, TT_CMD_SEND_MESSAGE, ping_fn, "pong-m2", 0);
                pong_sent = true;
                pong_at = time(NULL);
            }
            /* M3 e2ee: responder exits ~3s after its pong (the initiator's
               ping receipt already flowed; nothing else to wait for). M4
               reorder: hold until all three out-of-order frames (m2/m3/m4)
               were recovered through the skipped-key store and echoed. */
            if (e2ee_mode && !initiator && pong_sent &&
                time(NULL) - pong_at >= 3) {
                if (e2ee_reorder && reorder_rx < 3) continue;
                rc = 0;
                break;
            }
            /* M3 e2ee: fail fast when the in-band handshake never lands */
            if (e2ee_mode && initiator && !e2ee_established &&
                time(NULL) - start >= 60) {
                TT_LOG("bot", "e2ee: no session within 60s");
                rc = 3;
                break;
            }
            /* M4 harness: once the session is live, the initiator drives the
               ratchet edge cases. reorder: post the out-of-order delivery
               (seq 3,2,4) and wait for the responder's m2/m3/m4 echoes.
               replay: post the re-inject after the pong arrives (pong_at set
               on the initiator when it receives "pong-m2", so last_in holds
               a real DATA frame) and wait for the reject log. */
            if (e2ee_mode && initiator && e2ee_established) {
                if (e2ee_reorder && !reorder_posted) {
                    reorder_posted = true;
                    TT_LOG("bot", "reorder: posting out-of-order delivery");
                    tt_queue_post(&tt.in, TT_CMD_E2EE_REORDER, 0, NULL, 0);
                }
                if (e2ee_replay && !replay_posted && pong_at != 0) {
                    replay_posted = true;
                    TT_LOG("bot", "replay: posting re-inject");
                    tt_queue_post(&tt.in, TT_CMD_E2EE_REPLAY, 0, NULL, 0);
                }
            }
            /* M-AV2: the CALLEE hangs up ~2s (solo) / 10s (full, past the
               file transfer — a mid-file MSI POP can be dropped by the
               saturated lossless queue) after answering. msi semantics: the
               hangup side's CANCEL is silent for itself; only the PEER gets
               a FINISHED callback (msi.c handle_pop -> MSI_ON_END). So the
               caller observes the full cycle; the callee's evidence is its
               own CANCEL. (Above the phase branches: the group branch keeps
               polling until gleft_seen, so a timer below it never fires.) */
            if (call_mode && !initiator && call_answered && !call_hangup &&
                time(NULL) - call_at >= (call_solo ? (call_pause_test ? 8 :
                                          call_vtest ? 12 : 2) : 10)) {
                call_hangup = true;
                TT_LOG("bot", "hanging up (callee) friend %u", call_fn);
                tt_queue_post(&tt.in, TT_CMD_AV_HANGUP, call_fn, NULL, 0);
            }
            if (pong_sent && !initiator && !group_want && !call_solo) {
                if (file_failed) { /* round 25: FAILED is success in cancel mode */
                    rc = cancel_mode ? 0 : 3;
                    break;
                }
                if (file_done && file_ok) {
                    /* stay up ~15s: the founder may still invite us to a group */
                    if (time(NULL) - file_done_at < 15) continue;
                    break; /* reply + file flushed, no invite came */
                }
                if (file_offered && !file_done && time(NULL) - file_at >= 45) {
                    TT_LOG("bot", "file transfer stalled");
                    break; /* rc stays 2 */
                }
                continue; /* still waiting for the file to arrive */
            }
            if (!initiator && group_want) {
                /* joined: wait for promotion/topic/ping, pong; then instead of
                   self-leaving, wait to be kicked by the founder (exercises the
                   kick path end-to-end: MV_KICK moderation event on self +
                   disconnect). Fallback self-leave at +10s. */
                if (gpong_sent && gleft_seen) {
                    /* M-AV2 full mode: stay alive until our callee hangup has
                       been posted AND the initiator got its FINISHED (the
                       hangup lands after the group phases; the exit check
                       below verifies it was sent) */
                    if (call_mode && !call_hangup) continue;
                    rc = 0;
                    break;
                }
                if (gpong_sent && time(NULL) - gpong_at >= 10) {
                    TT_LOG("bot", "no kick received — self-leaving (fallback)");
                    tt_queue_post(&tt.in, TT_CMD_GROUP_LEAVE, (uint32_t)group_gn, NULL, 0);
                    continue;
                }
                if (!gpong_sent && time(NULL) - ngc_at >= 20) {
                    TT_LOG("bot", "NGC side: no group traffic (timeout)");
                    rc = 2;
                    break;
                }
                continue;
            }
            /* M-AV2: the CALLEE hangs up ~2s (solo) / 10s (full, past the
               file transfer — a mid-file MSI POP can be dropped by the
               saturated lossless queue) after answering. msi semantics: the
               hangup side's CANCEL is silent for itself; only the PEER gets
               a FINISHED callback (msi.c handle_pop -> MSI_ON_END). So the
               caller observes the full cycle; the callee's evidence is its
               own CANCEL. */
            if (call_mode && !initiator && call_answered && !call_hangup &&
                time(NULL) - call_at >= (call_solo ? (call_pause_test ? 8 :
                                          call_vtest ? 12 : 2) : 10)) {
                call_hangup = true;
                TT_LOG("bot", "hanging up (callee) friend %u", call_fn);
                tt_queue_post(&tt.in, TT_CMD_AV_HANGUP, call_fn, NULL, 0);
            }
            /* M-AV2 solo: hold the scripted exit until the call cycle is
               done — the caller until its FINISHED+ENDED (from the callee's
               CANCEL), the callee a few seconds past its own hangup. In full
               mode the file/group phases govern exit; assertions run at the
               end. M-AV4 vtest: the initiator additionally waits for video
               frames to flow back before it hangs up (the callee pumps its
               own echo frames after SENDING_V lights up). */
            if (call_mode && call_solo && (call_initiated || call_answered)) {
                if (initiator && call_vtest && !video_sent && !call_ended_ok &&
                    time(NULL) - call_at >= 2) {
                    /* SENDING_V never lit (peer did not accept video): stop
                       the pump so the call can still finish cleanly */
                    tt_queue_post2(&tt.in, TT_CMD_AV_VTEST, call_fn, NULL, 0, 0);
                }
                /* tier B2: mid-call video bit-rate change (3 s into a vtest
                   call; the engine must accept it and keep frames flowing) */
                if (initiator && call_vtest && !br_sent &&
                    time(NULL) - call_at >= 3) {
                    br_sent = true;
                    TT_LOG("bot", "br set: video 1800 kbit/s mid-call");
                    tt_queue_post2(&tt.in, TT_CMD_AV_SET_VIDEO_BR, call_fn,
                                   NULL, 1800, 0);
                }
                /* tier B1: pause 2 s after the call is ACTIVE; RESUME goes
                   out 2 s after the pause (the callee holds the call ~8 s),
                   and resumed_seen is set by the real restore-state events */
                if (initiator && call_pause_test && call_state_seen &&
                    !pause_sent && time(NULL) - call_at >= 2) {
                    pause_sent = true;
                    call_at = time(NULL); /* pause-window restart */
                    TT_LOG("bot", "pause cycle: sending PAUSE to %u", call_fn);
                    tt_queue_post(&tt.in, TT_CMD_AV_PAUSE, call_fn, NULL, 0);
                }
                if (initiator && call_pause_test && paused_seen &&
                    !resume_posted && time(NULL) - call_at >= 2) {
                    resume_posted = true;
                    TT_LOG("bot", "pause cycle: sending RESUME to %u", call_fn);
                    tt_queue_post(&tt.in, TT_CMD_AV_RESUME, call_fn, NULL, 0);
                }
                bool call_done = initiator ?
                    (call_ended_ok && call_finished_rx &&
                     (!call_vtest || video_rx) &&
                     (!call_pause_test || resumed_seen)) :
                    (call_hangup && time(NULL) - call_at >= (call_decline_test ? 1 : 5));
                if (call_done) {
                    TT_LOG("bot", "call phase complete");
                    if (!initiator) rc = 0; /* exit assertion verifies below */
                    break;
                }
                if (time(NULL) - call_at >= 25) {
                    TT_LOG("bot", "call phase timed out (state=%d ended=%d rx=%d hangup=%d vrx=%d paused=%d)",
                           call_state_seen, call_ended_ok, call_finished_rx,
                           call_hangup, video_rx, paused_seen);
                    rc = 3;
                    break;
                }
                continue;
            }
            if (initiator) {
                if (group_created) {
                    if (!peer_joined && time(NULL) - ngc_at >= 20) {
                        TT_LOG("bot", "NGC: peer join timed out");
                        rc = 2;
                        break;
                    }
                    if (peer_joined && !peer_gone && !kick_posted &&
                        gpong_at && time(NULL) - gpong_at >= 2) {
                        /* kick the responder instead of waiting for its own
                           leave: exercises the kick path (MOD_SELF on the
                           actor, MV_KICK-on-self + disconnect on the target) */
                        TT_LOG("bot", "kicking peer %d from group %d", peer_pid, group_gn);
                        tt_queue_post(&tt.in, TT_CMD_GROUP_KICK, (uint32_t)group_gn,
                                      NULL, peer_pid);
                        kick_posted = true;
                    }
                    if (peer_joined && !peer_gone && kick_posted &&
                        time(NULL) - gpong_at >= 15) {
                        TT_LOG("bot", "kick did not remove peer (timed out) — leaving");
                        tt_queue_post(&tt.in, TT_CMD_GROUP_LEAVE, (uint32_t)group_gn, NULL, 0);
                        peer_gone = true; /* do not retry */
                        ngc_at = time(NULL);
                    }
                    if (peer_gone) {
                        /* M-AV2 full mode: hold the drain exit until the
                           callee's CANCEL produced our FINISHED+ENDED (its
                           hangup fires ~10s after answer; bounded by the 25s
                           phase timeout below) */
                        if (call_mode && !(call_ended_ok && call_finished_rx)) {
                            if (time(NULL) - call_at >= 25) {
                                TT_LOG("bot", "call phase timed out (state=%d ended=%d rx=%d hangup=%d)",
                                       call_state_seen, call_ended_ok,
                                       call_finished_rx, call_hangup);
                                rc = 3;
                                break;
                            }
                            continue;
                        }
                        if (time(NULL) - ngc_at >= 2)
                            break; /* drain exit-event tail */
                    }
                } else if (group_want) {
                    if (time(NULL) - ngc_at >= 20) { /* GROUP_CREATE never took */
                        TT_LOG("bot", "NGC: group creation timed out");
                        rc = 2;
                        break;
                    }
                } else if (rc == 0 && !cancel_mode &&
                           time(NULL) - pong_at >= 5) {
                    /* M-AV2 solo: the call hold above breaks out instead —
                       never take the round-13 file-phase exit mid-call */
                    if (call_mode && call_solo) continue;
                    /* M4 harness: hold the exit until the ratchet edge cases
                       settle. reorder: all three out-of-order echoes must
                       come back. replay: the re-inject must have been posted
                       (its reject is verified from the engine log). */
                    if (e2ee_reorder && reorder_echo < 3) continue;
                    if (e2ee_replay && !replay_posted) continue;
                    /* round 25 assertions: typing packet + receipt for our
                       message id (both fire before the round can pass) */
                    if (!typing_got || !receipt_got) {
                        TT_LOG("bot", "round 25 assertions failed: typing=%d receipt=%d",
                               typing_got, receipt_got);
                        rc = 3;
                        break;
                    }
                    /* round 13 contract: file phase done, nothing pending */
                    break;
                } else if (cancel_mode && rc == 0 && time(NULL) - pong_at >= 8) {
                    /* cancel mode: cancel already passed (rc=0 via FILE_FAILED)
                       or it never fired in time — keep waiting for the cancel
                       branch below instead of taking the NGC downgrade */
                    if (tx_failed) break;
                    if (cancel_test && !cancel_sent) {
                        /* fallback: cancel by timer even if progress events
                           were somehow lost (decouples the cancel-path check
                           from the progress-emit fix being verified) */
                        TT_LOG("bot", "cancel mode: cancelling xfer %u by timer", xfer_run);
                        tt_queue_post(&tt.in, TT_CMD_FILE_CANCEL, 0, NULL, (int)xfer_run);
                        cancel_sent = true;
                    }
                    if (time(NULL) - pong_at >= 30) {
                        TT_LOG("bot", "cancel mode: no cancel window (timed out)");
                        rc = 3;
                        break;
                    }
                }
                continue;
            }
            /* responder still waiting for ping-m2: keep polling until timeout */
            continue;
        }
        switch (ev->type) {
        case TT_EV_TOXID:
            TT_LOG("bot", "self ToxID: %s", ev->str ? ev->str : "?");
            break;
        case TT_EV_AVATAR:
            if (initiator)
                TT_LOG("bot", "avatar received: %u bytes", (unsigned)ev->str_len);
            break;
        case TT_EV_FILE_TX_STARTED:
            if (initiator) {
                TT_LOG("bot", "file tx started: %s", ev->str ? ev->str : "?");
                file_sent = true;
                xfer_run = (unsigned)ev->ival;
                if (cancel_mode) {
                    cancel_test = true;
                    TT_LOG("bot", "cancel mode: will cancel xfer %u at first progress", xfer_run);
                }
            }
            break;
        case TT_EV_FILE_OFFER: {
            if (initiator) break;
            /* str "<name>\n<size>", ival xfer id: auto-accept to /tmp */
            file_offered = true;
            file_at = time(NULL);
            TT_LOG("bot", "file offer: %s (xfer id %d) — accepting",
                   ev->str ? ev->str : "?", ev->ival);
            tt_queue_post(&tt.in, TT_CMD_FILE_ACCEPT, 0, TT_TEST_FILE_RX_PATH, ev->ival);
            break;
        }
        case TT_EV_FILE_PROGRESS:
            if (initiator) {
                TT_LOG("bot", "file progress: %s", ev->str ? ev->str : "?");
                if (cancel_mode && cancel_test && !cancel_sent) {
                    /* mid-transfer cancel: engine posts SET_TYPING 0 + CANCEL
                       and frees the transfer on both ends */
                    TT_LOG("bot", "cancelling xfer %u mid-transfer", xfer_run);
                    tt_queue_post(&tt.in, TT_CMD_FILE_CANCEL, 0, NULL, (int)xfer_run);
                    cancel_sent = true; /* don't re-cancel on a later progress event */
                }
            } else {
                TT_LOG("bot", "file progress: %s", ev->str ? ev->str : "?");
            }
            break;
        case TT_EV_FILE_DONE:
            if (!initiator) {
                file_done = true;
                file_ok = echo_test_file_verify();
                file_done_at = time(NULL);
                TT_LOG("bot", "file done: %s — %s", ev->str ? ev->str : "?",
                       file_ok ? "content matches pattern" : "CONTENT MISMATCH");
                if (file_ok) rc = 0;
            }
            break;
        case TT_EV_FILE_FAILED:
            if (initiator) {
                tx_failed = true;
                TT_LOG("bot", "file transfer FAILED (tx side) — cancel path green");
                if (cancel_mode && cancel_test) rc = 0; /* cancel test passed */
            } else {
                file_failed = true;
                TT_LOG("bot", "file transfer FAILED (rx side)");
            }
            break;
        case TT_EV_FRIEND_TYPING:
            /* round 25: peer typing indicator reached the initiator */
            TT_LOG("bot", "friend %u typing: %d", ev->friend_number, ev->ival);
            if (initiator && ev->ival == 1) typing_got = true;
            break;
        case TT_EV_FRIEND_READ_RECEIPT:
            /* round 25: highest read message id reported by the friend */
            TT_LOG("bot", "friend %u read receipt: mid=%d", ev->friend_number, ev->ival);
            if (initiator && (unsigned)ev->ival == last_mid && last_mid != 0) {
                receipt_got = true;
                TT_LOG("bot", "receipt matches sent message id %u", last_mid);
            }
            break;
        case TT_EV_MESSAGE_SENT:
            /* round 25: tox message id our send got (receipt key) */
            TT_LOG("bot", "message sent to friend %u (id %d)", ev->friend_number, ev->ival);
            if (initiator && (unsigned)ev->ival != 0) last_mid = (unsigned)ev->ival;
            break;
        case TT_EV_SELF_CONNECTION:
            TT_LOG("bot", "self connection: %d", ev->ival);
            break;
        case TT_EV_OFFLINE_FLUSHED:
            TT_LOG("bot", "offline queue flushed to friend %u (%d message%s)",
                   ev->friend_number, ev->ival, ev->ival == 1 ? "" : "s");
            break;
        case TT_EV_FRIEND_REQUEST:
            if (ev->str && strlen(ev->str) == TOX_PUBLIC_KEY_SIZE * 2) {
                TT_LOG("bot", "accepting request from %s", ev->str);
                tt_queue_post(&tt.in, TT_CMD_ACCEPT_FRIEND, 0, ev->str, 0);
            }
            break;
        case TT_EV_FRIEND_CONNECTION:
            TT_LOG("bot", "friend %u connection: %d", ev->friend_number, ev->ival);
            if (initiator && !ping_sent && ev->ival != 0) {
                ping_sent = true;
                tt_queue_post(&tt.in, TT_CMD_SEND_MESSAGE, ev->friend_number, "ping-m2", 0);
                TT_LOG("bot", "sent ping to %u", ev->friend_number);
            }
            /* tier B3 decline test: call the real peer the moment it is
               connected; it CANCELs on arrival instead of answering */
            if (initiator && call_decline_test && !call_initiated &&
                ev->friend_number == 0 && ev->ival != 0) {
                call_initiated = true;
                call_fn = ev->friend_number;
                call_at = time(NULL);
                TT_LOG("bot", "decline test: calling friend %u (audio 32k)", ev->friend_number);
                tt_queue_post2(&tt.in, TT_CMD_AV_CALL, ev->friend_number, NULL, 32, 0);
            }
            break;
        case TT_EV_FRIEND_MESSAGE:
            if (ev->str) {
                TT_LOG("bot", "friend %u message: %.*s", ev->friend_number,
                       (int)(ev->str_len > 64 ? 64 : ev->str_len), ev->str);
                if (initiator && str_contains(ev->str, ev->str_len, "pong-m2")) {
                    rc = 0;
                    pong_at = time(NULL);
                    if (call_mode && !call_initiated) { /* M-AV2: call phase first */
                        call_initiated = true;
                        call_fn = ev->friend_number;
                        call_at = time(NULL);
                        /* M-AV4 vtest: negotiate video too (audio 32k, video 2500k) */
                        int video_br = call_vtest ? 2500 : 0;
                        TT_LOG("bot", "calling friend %u (audio 32k, video %dk)",
                               ev->friend_number, video_br);
                        tt_queue_post2(&tt.in, TT_CMD_AV_CALL, ev->friend_number, NULL, 32, video_br);
                        if (call_vtest)
                            tt_queue_post2(&tt.in, TT_CMD_AV_VTEST, ev->friend_number, NULL, 1, 0);
                    }
                    if (!file_sent && !call_solo) { /* solo mode: no file phase */
                        /* cancel mode: the small file transfers too fast to
                           cancel mid-flight — send the staged 8 MiB file and
                           stop after the cancel (no group phase) */
                        const char *fpath = TT_TEST_FILE_PATH;
                        unsigned fsize = TT_TEST_FILE_SIZE;
                        if (cancel_mode) {
                            fpath = TT_TEST_FILE_BIG_PATH;
                            fsize = TT_TEST_FILE_BIG_SIZE;
                        }
                        TT_LOG("bot", "sending test file %s (%u bytes)", fpath, fsize);
                        tt_queue_post(&tt.in, TT_CMD_SEND_FILE, ev->friend_number, fpath, 0);
                    }
                    if (cancel_mode) break; /* round 25: cancel test exits on FILE_FAILED */
                    if (!group_want && !call_solo) { /* solo mode: no group phase */
                        group_want = true;
                        pong_fn = ev->friend_number;
                        ngc_at = time(NULL); /* create wait starts */
                        TT_LOG("bot", "creating private group \"test\"");
                        tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "test\nprivate", 0);
                    }
                } else if (!initiator && str_contains(ev->str, ev->str_len, "ping-m2")) {
                    /* round 25: signal typing first, send the pong on the
                       2s tick above so the typing packet flushes first */
                    ping_fn = ev->friend_number;
                    typing_shown = true;
                    typing_at = time(NULL);
                    TT_LOG("bot", "ping received — signalling typing");
                    tt_queue_post(&tt.in, TT_CMD_SET_TYPING, ev->friend_number, NULL, 1);
                } else if (!initiator && !str_contains(ev->str, ev->str_len, "ping-m2")) {
                    /* M4 reorder: the responder counts the out-of-order
                       frames it recovered (m2/m3/m4) — the skipped-key store
                       must deliver all three despite the 3,2,4 wire order */
                    if (e2ee_reorder &&
                        (str_contains(ev->str, ev->str_len, "m2") ||
                         str_contains(ev->str, ev->str_len, "m3") ||
                         str_contains(ev->str, ev->str_len, "m4")))
                        reorder_rx++;
                    /* generic echo so manual UI testing gets a reply for any text */
                    tt_queue_post(&tt.in, TT_CMD_SEND_MESSAGE, ev->friend_number, ev->str, 0);
                } else if (initiator && e2ee_reorder &&
                           (str_contains(ev->str, ev->str_len, "m2") ||
                            str_contains(ev->str, ev->str_len, "m3") ||
                            str_contains(ev->str, ev->str_len, "m4"))) {
                    /* M4 reorder: the initiator counts the echoes of the
                       out-of-order frames it sent — all three must come back */
                    reorder_echo++;
                }
            }
            break;
        /* ---- round 14: NGC private-group roundtrip ----
           (group number lives in friend_number for every group event) */
        case TT_EV_GROUP_NEW:
            if (initiator && !group_created) {
                group_created = true;
                group_want = true;
                group_gn = (int)ev->friend_number;
                ngc_at = time(NULL); /* peer-join wait starts */
                TT_LOG("bot", "group created: gn=%d name=%s privacy=%d",
                       ev->friend_number, ev->str ? ev->str : "?", ev->ival2);
                tt_queue_post(&tt.in, TT_CMD_GROUP_INVITE, ev->friend_number,
                              NULL, (int)pong_fn);
                TT_LOG("bot", "invited friend %u to group %d", pong_fn, ev->friend_number);
            }
            break;
        case TT_EV_GROUP_JOINED:
            if (!initiator && !group_want) {
                group_gn = (int)ev->friend_number;
                group_want = true;
                ngc_at = time(NULL); /* waiting for promotion/topic/ping */
                TT_LOG("bot", "joined group gn=%d name=%s (invited by founder)",
                       ev->friend_number, ev->str ? ev->str : "?");
            }
            break;
        case TT_EV_GROUP_INVITE:
            if (!initiator && ev->ival2 >= 0 && !gpong_sent) {
                TT_LOG("bot", "group invite \"%s\" (idx %d) — accepting",
                       ev->str ? ev->str : "?", ev->ival2);
                tt_queue_post2(&tt.in, TT_CMD_GROUP_INVITE_ACC, 0, NULL, 0, ev->ival2);
            }
            break;
        case TT_EV_GROUP_PEER_JOIN:
            if (initiator && (int)ev->friend_number == group_gn && !peer_joined) {
                peer_joined = true;
                peer_pid = (int)ev->ival; /* group peer id (NOT friend number) */
                ngc_at = time(NULL);
                TT_LOG("bot", "peer %u joined group %d — promoting + topic",
                       ev->ival, group_gn);
                tt_queue_post2(&tt.in, TT_CMD_GROUP_ROLE, ev->friend_number,
                               NULL, (int)ev->ival, (int)TOX_GROUP_ROLE_MODERATOR);
                tt_queue_post(&tt.in, TT_CMD_GROUP_TOPIC, ev->friend_number,
                              TT_NGC_TOPIC, 0);
                tt_queue_post(&tt.in, TT_CMD_GROUP_SEND, ev->friend_number,
                              "ngc-ping", 0);
                TT_LOG("bot", "sent \"ngc-ping\" to group %d", group_gn);
            }
            break;
        case TT_EV_GROUP_MOD:
            if (!initiator && (int)ev->friend_number == group_gn) {
                if (ev->ival2 == (int)TOX_GROUP_MOD_EVENT_KICK && gpong_sent) {
                    /* kicked client: toxcore fires MV_KICK with self as the
                       target and disconnects us — treat as group exit */
                    gleft_seen = true;
                    TT_LOG("bot", "kicked from group %d (peer %u)", group_gn, ev->ival);
                } else {
                    role_seen = true;
                    TT_LOG("bot", "moderation event: peer %u %s (event %d)",
                           ev->ival, ev->ival2 == (int)TOX_GROUP_MOD_EVENT_OBSERVER ? "role->observer"
                           : ev->ival2 == (int)TOX_GROUP_MOD_EVENT_USER ? "role->user"
                           : ev->ival2 == (int)TOX_GROUP_MOD_EVENT_MODERATOR ? "role->moderator"
                           : "kick", ev->ival2);
                }
            }
            break;
        case TT_EV_GROUP_MOD_SELF:
            if (initiator && (int)ev->friend_number == group_gn) {
                bool faild = (int)ev->ival2 >= TT_MOD_EV_FAIL_BASE;
                int mev = faild ? (int)ev->ival2 - TT_MOD_EV_FAIL_BASE : (int)ev->ival2;
                TT_LOG("bot", "actor feedback: peer %u %s%s",
                       ev->ival, faild ? "FAILED " : "",
                       mev == (int)TOX_GROUP_MOD_EVENT_MODERATOR ? "promoted to moderator"
                       : mev == (int)TOX_GROUP_MOD_EVENT_USER ? "set to user"
                       : mev == (int)TOX_GROUP_MOD_EVENT_OBSERVER ? "demoted to observer"
                       : mev == (int)TOX_GROUP_MOD_EVENT_KICK ? "kicked" : "moderated");
                if (!faild && mev == (int)TOX_GROUP_MOD_EVENT_MODERATOR)
                    role_seen = true; /* actor-side confirmation of the promote */
            }
            break;
        case TT_EV_GROUP_TOPIC:
            if (!initiator && (int)ev->friend_number == group_gn && ev->str) {
                char tbuf[TOX_GROUP_MAX_TOPIC_LENGTH + 1];
                size_t tn = ev->str_len < sizeof tbuf - 1 ? ev->str_len : sizeof tbuf - 1;
                memcpy(tbuf, ev->str, tn);
                tbuf[tn] = '\0';
                TT_LOG("bot", "group %d topic set to \"%s\"", ev->friend_number, tbuf);
                if (strcmp(tbuf, TT_NGC_TOPIC) == 0) gtopic_seen = true;
            }
            break;
        case TT_EV_GROUP_MSG:
            if (ev->str) {
                if (initiator && (int)ev->friend_number == group_gn &&
                    str_contains(ev->str, ev->str_len, "ngc-pong-m2") && !group_pong) {
                    group_pong = true;
                    gpong_at = time(NULL);
                    rc = 0;
                    TT_LOG("bot", "received \"ngc-pong-m2\" from peer %u -> rc=0", ev->ival);
                } else if (!initiator && (int)ev->friend_number == group_gn &&
                           str_contains(ev->str, ev->str_len, "ngc-ping") && !gpong_sent) {
                    TT_LOG("bot", "received \"ngc-ping\" from peer %u (role %s, topic %s) — replying",
                           ev->ival, role_seen ? "moderator" : "user",
                           gtopic_seen ? TT_NGC_TOPIC : "?");
                    tt_queue_post(&tt.in, TT_CMD_GROUP_SEND, ev->friend_number, "ngc-pong-m2", 0);
                    gpong_sent = true;
                    gpong_at = time(NULL);
                } else {
                    TT_LOG("bot", "group %d msg: %.*s", ev->friend_number,
                           (int)(ev->str_len > 48 ? 48 : ev->str_len), ev->str);
                }
            }
            break;
        case TT_EV_GROUP_PEER_EXIT:
            if (initiator && (int)ev->friend_number == group_gn) {
                peer_gone = true;
                TT_LOG("bot", "peer %u left group %d (exit type %d)", ev->ival,
                       ev->friend_number, ev->ival2);
            }
            break;
        case TT_EV_GROUP_LEFT:
            if (!initiator && (int)ev->friend_number == group_gn) {
                gleft_seen = true;
                TT_LOG("bot", "left group %d", ev->friend_number);
            }
            break;
        case TT_EV_GROUP_STATE:
            if ((int)ev->ival == -5 || (int)ev->ival == -6)
                TT_LOG("bot", "group %d sync: %s%s", ev->friend_number,
                       (int)ev->ival == -5 ? (ev->str ? "chat id " : "chat id ?") : "",
                       (int)ev->ival == -5 && ev->str ? ev->str : "");
            break;
        case TT_EV_GROUP_PEER_NAME:
            TT_LOG("bot", "group %d peer %u name: %s", ev->friend_number,
                   (unsigned)ev->ival, ev->str ? ev->str : "?");
            break;
        case TT_EV_GROUP_PEER_ROLE:
            TT_LOG("bot", "group %d peer %u role now %d", ev->friend_number,
                   (unsigned)ev->ival, ev->ival2);
            break;
        case TT_EV_GROUP_PRIV_MSG:
            TT_LOG("bot", "group %d private msg from peer %u: %.*s", ev->friend_number,
                   (unsigned)ev->ival,
                   (int)(ev->str_len > 48 ? 48 : ev->str_len), ev->str ? ev->str : "");
            break;
        case TT_EV_GROUP_JOIN_FAIL:
            TT_LOG("bot", "group %d join FAILED (type %d)", ev->friend_number, ev->ival);
            rc = 3;
            break;
        /* ---- M3: encrypted-layer state (verify code) ---- */
        case TT_EV_E2EE_STATE:
            TT_LOG("bot", "e2ee state friend %u: %d code=%s",
                   ev->friend_number, ev->ival, ev->str ? ev->str : "?");
            if (ev->ival == 1 && ev->str && ev->str_len == 32) {
                memcpy(e2ee_code, ev->str, 33);
                e2ee_established = true;
            }
            break;
        /* ---- M-AV2: call-signaling phase ---- */
        case TT_EV_AV_INCOMING:
            if (!initiator && call_mode) {
                TT_LOG("bot", "incoming call from %u (a=%d v=%d) — %s",
                       ev->friend_number, ev->ival, ev->ival2,
                       call_decline_test ? "declining (CANCEL)" : "answering");
                call_answered = true;
                call_fn = ev->friend_number;
                call_at = time(NULL); /* start the call-hold timeout window */
                if (call_decline_test) {
                    /* tier B3 decline = CANCEL before answer: the caller must
                       observe FINISHED + ENDED, never an ACTIVE state */
                    call_hangup = true;
                    tt_queue_post(&tt.in, TT_CMD_AV_HANGUP, ev->friend_number, NULL, 0);
                } else {
                    /* M-AV4 vtest: accept video too (audio 32k, video 2500k) */
                    tt_queue_post2(&tt.in, TT_CMD_AV_ANSWER, ev->friend_number, NULL,
                                   32, call_vtest ? 2500 : 0);
                }
            }
            break;
        case TT_EV_AV_STATE:
            TT_LOG("bot", "call state %u: 0x%x%s", ev->friend_number, (unsigned)ev->ival,
                   (ev->ival & TOXAV_FRIEND_CALL_STATE_SENDING_A) ? " (sending audio)" : "");
            if (ev->ival & TOXAV_FRIEND_CALL_STATE_SENDING_A) call_state_seen = true;
            if (ev->ival & TOXAV_FRIEND_CALL_STATE_SENDING_V) {
                video_sent = true;
                /* (M-AV4 vtest echo moved to TT_EV_AV_FRAME: the callee's
                   state callback never shows SENDING_V — MSI keeps it at
                   0x14 for the whole call — so frames are the only reliable
                   "peer is sending video" signal on the answering side) */
            }
            if (ev->ival & (TOXAV_FRIEND_CALL_STATE_FINISHED |
                            TOXAV_FRIEND_CALL_STATE_ERROR)) {
                call_finished_rx = true;
                if (!initiator) call_at = time(NULL); /* linger window starts */
            }
            /* tier B1 pause/resume: the initiator's PAUSE echo and the
               peer's MSI capabilities callback both arrive as state 0; the
               RESUME restores the pre-pause state on both ends (the local
               echo is synthesized; the peer gets the real MSI callback). */
            if (call_pause_test) {
                if (ev->ival == 0 && !paused_seen) {
                    paused_seen = true;
                    pre_pause_state = g_last_active_state; /* restore reference */
                    TT_LOG("bot", "pause cycle: state 0 seen (pre=%u)", pre_pause_state);
                } else if (ev->ival != 0 && paused_seen &&
                           (ev->ival & (TOXAV_FRIEND_CALL_STATE_SENDING_A |
                                        TOXAV_FRIEND_CALL_STATE_ACCEPTING_A))) {
                    resumed_seen = true;
                    TT_LOG("bot", "pause cycle: resumed (state 0x%x)", (unsigned)ev->ival);
                }
                if (ev->ival != 0 &&
                    (ev->ival & (TOXAV_FRIEND_CALL_STATE_SENDING_A |
                                 TOXAV_FRIEND_CALL_STATE_ACCEPTING_A)))
                    g_last_active_state = (uint32_t)ev->ival;
            }
            break;
        case TT_EV_AV_ENDED:
            TT_LOG("bot", "call with %u ended (rc=%d dur=%ds)", ev->friend_number,
                   ev->ival, ev->ival2);
            if (!ev->ival) call_ended_ok = true;
            break;
        case TT_EV_AV_FRAME: /* M-AV4: peer video frames flowing */
            video_rx = true;
            video_rx_w = (uint32_t)ev->ival;
            video_rx_h = (uint32_t)ev->ival2;
            video_rx_n++;
            /* vtest echo: receiving frames proves the peer sends video —
               pump our own synthetic frames back (proves both directions).
               This must key off FRAMES, not SENDING_V: the callee's state
               callback never shows that bit (verified in the vtest logs). */
            if (call_vtest && !initiator && !video_pump_on) {
                video_pump_on = true;
                TT_LOG("bot", "vtest: echoing video back to %u", ev->friend_number);
                tt_queue_post2(&tt.in, TT_CMD_AV_VTEST, ev->friend_number, NULL, 1, 0);
            }
            break;
        case TT_EV_SHUTDOWN:
            g_stop = 1;
            rc = 1;
            break;
        default:
            break;
        }
        tt_event_free(ev);
    }
    tt_tox_thread_stop(&tt);
    if (initiator && rc == 0 && !cancel_mode && !call_solo) {
        /* solo call mode skips the NGC assertion — no group phase ran */
        TT_LOG("bot", "NGC roundtrip: %s%s%s%s",
               group_created ? "create ok, " : "CREATE MISSING, ",
               group_pong ? "ngc-pong received, " : "NGC-PONG MISSING, ",
               peer_joined ? "peer join ok, " : "PEER JOIN MISSING, ",
               peer_gone ? (gleft_seen ? "" : "peer exit seen") : "peer exit not seen (sync race)");
        if (!group_created || !group_pong || !peer_joined)
            rc = 2; /* core assertions failed after all */
    } else if (initiator && rc == 0 && cancel_mode) {
        TT_LOG("bot", "round 25: typing=%d receipt=%d cancel(passed via FILE_FAILED)",
               typing_got, receipt_got);
        if (!typing_got || !receipt_got || !tx_failed) rc = 3; /* verify at exit too */
    }
    if (initiator && call_mode && rc == 0 && !call_decline_test &&
            !call_offline_test) {
        /* caller: call sent, ACTIVE state seen, and the callee's CANCEL
           produced a FINISHED state + our own ENDED event */
        TT_LOG("bot", "M-AV2: initiated=%d answered_peer=%d state_seen=%d finished_rx=%d ended_ok=%d",
               call_initiated, call_answered, call_state_seen, call_finished_rx, call_ended_ok);
        if (!call_initiated || !call_state_seen || !call_finished_rx ||
                !call_ended_ok) rc = 3;
        if (call_vtest && rc == 0) {
            TT_LOG("bot", "M-AV4: vrx=%u (%ux%u frames)", video_rx_n, video_rx_w, video_rx_h);
            if (!video_rx || video_rx_n == 0) rc = 3; /* no video frames received */
        }
        if (call_pause_test && rc == 0) {
            /* tier B1 caller: PAUSE -> state 0 both ends, RESUME -> restore */
            TT_LOG("bot", "pause cycle: paused=%d resumed=%d pre_state=0x%x",
                   paused_seen, resumed_seen, pre_pause_state);
            if (!paused_seen || !resumed_seen || pre_pause_state == 0) rc = 3;
        }
    }
    if (initiator && call_mode && call_decline_test && rc == 0) {
        /* tier B3 decline: the peer's CANCEL must produce FINISHED + ENDED
           and NEVER an ACTIVE state (no answer happened) */
        TT_LOG("bot", "decline: finished_rx=%d ended_ok=%d active_state=%d",
               call_finished_rx, call_ended_ok, call_state_seen);
        if (!call_finished_rx || !call_ended_ok || call_state_seen) rc = 3;
    }
    if (!initiator && call_mode && rc == 0) {
        /* callee: answer posted + our own CANCEL posted (state_seen is not
           required — the callee gets no state callback until FINISHED, which
           only arrives when the CALLER hangs up, which never happens here) */
        TT_LOG("bot", "M-AV2 rx: answered=%d hangup=%d", call_answered, call_hangup);
        if (!call_answered || !call_hangup) rc = 3;
        if (call_vtest && rc == 0) {
            TT_LOG("bot", "M-AV4 rx: vrx=%u (%ux%u frames)", video_rx_n, video_rx_w, video_rx_h);
            if (!video_rx || video_rx_n == 0) rc = 3; /* no video frames received */
        }
        if (call_pause_test && rc == 0) {
            /* tier B1 callee: the PAUSE must have produced a state-0 (its
               own capabilities callback) and the RESUME a restore back */
            TT_LOG("bot", "pause cycle rx: paused=%d resumed=%d pre_state=0x%x",
                   paused_seen, resumed_seen, pre_pause_state);
            if (!paused_seen || !resumed_seen) rc = 3;
        }
    }
    if (!initiator && gpong_sent) {
        TT_LOG("bot", "NGC side: %s%s",
               role_seen ? "promotion observed, " : "PROMOTION NOT OBSERVED, ",
               gtopic_seen ? "topic observed" : "TOPIC NOT OBSERVED");
        if (!role_seen || !gtopic_seen) rc = 0; /* soft checks: log-only */
    }
    if (e2ee_mode && rc == 0) {
        /* M3: the session must be established on both peers, with the
           initiator additionally holding a read receipt for its encrypted
           ping (MESSAGE_SENT + FRIEND_READ_RECEIPT roundtrip) */
        TT_LOG("bot", "M3 e2ee: established=%d code=%s receipt=%d",
               e2ee_established, e2ee_code, receipt_got);
        if (!e2ee_established) rc = 3;
        if (initiator && !receipt_got) rc = 3;
        /* M4 harness: reorder — the responder must have recovered all three
           out-of-order frames (m2/m3/m4) and the initiator must have gotten
           all three echoes back. replay — the re-inject must have been
           posted (its TT_E2EE_REPLAY reject is verified from the engine log
           by e2ee-test.sh). */
        if (e2ee_reorder) {
            TT_LOG("bot", "M4 reorder: rx=%d echo=%d", reorder_rx, reorder_echo);
            if (!initiator && reorder_rx < 3) rc = 3;
            if (initiator && reorder_echo < 3) rc = 3;
        }
        if (e2ee_replay) {
            TT_LOG("bot", "M4 replay: posted=%d", replay_posted);
            if (initiator && !replay_posted) rc = 3;
        }
    }
    return rc;
}

/* Long-lived echo responder (--echo <profile>): the manual-testing peer.
   Unlike bot_main's scripted 180s run this never self-exits — no inactivity
   timeout, no NGC no-traffic timeout (round 21: those timers killed the bot
   mid-conversation, which looked like "invite goes offline" — invites then
   hit a dead friend and fail with TOX_ERR_GROUP_INVITE_FRIEND_FAIL). Accepts
   friend requests and group invites, echoes 1:1 messages, echoes group
   messages back to the group, tracks group joins. Ctrl-C to stop. */
int echo_main(const char *profile) {
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint); /* test-ui.sh kills the bot with SIGTERM */
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "Echo Bot", 0);
    echo_bot_set_avatar();
    tt_queue_post(&tt.in, TT_CMD_SET_AVATAR, 0, ECHO_BOT_AVATAR_PATH, 0);
    TT_LOG("echo", "echo bot running (long-lived; Ctrl-C to stop)");
    while (!g_stop) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (!ev) continue;
        switch (ev->type) {
        case TT_EV_TOXID:
            TT_LOG("echo", "self ToxID: %s", ev->str ? ev->str : "?");
            break;
        case TT_EV_SELF_CONNECTION:
            TT_LOG("echo", "self connection: %d", ev->ival);
            break;
        case TT_EV_FRIEND_CONNECTION:
            TT_LOG("echo", "friend %u connection: %d", ev->friend_number, ev->ival);
            break;
        case TT_EV_FRIEND_REQUEST:
            if (ev->str && strlen(ev->str) == TOX_PUBLIC_KEY_SIZE * 2) {
                TT_LOG("echo", "accepting request from %s", ev->str);
                tt_queue_post(&tt.in, TT_CMD_ACCEPT_FRIEND, 0, ev->str, 0);
            }
            break;
        case TT_EV_FRIEND_MESSAGE:
            if (ev->str) {
                TT_LOG("echo", "friend %u message: %.*s", ev->friend_number,
                       (int)(ev->str_len > 64 ? 64 : ev->str_len), ev->str);
                tt_queue_post(&tt.in, TT_CMD_SEND_MESSAGE, ev->friend_number, ev->str, 0);
            }
            break;
        /* M-AV1: answer calls so manual UI testing exercises real audio */
        case TT_EV_AV_INCOMING:
            TT_LOG("echo", "incoming call from %u (a=%d v=%d) — answering",
                   ev->friend_number, ev->ival, ev->ival2);
            tt_queue_post2(&tt.in, TT_CMD_AV_ANSWER, ev->friend_number, NULL, 1, 0);
            break;
        case TT_EV_AV_STATE:
            TT_LOG("echo", "call state %u: 0x%x", ev->friend_number, (unsigned)ev->ival);
            break;
        case TT_EV_AV_ENDED:
            TT_LOG("echo", "call with %u ended (rc=%d dur=%ds)",
                   ev->friend_number, ev->ival, ev->ival2);
            break;
        case TT_EV_GROUP_INVITE:
            TT_LOG("echo", "group invite \"%s\" (idx %d) from friend %u — accepting",
                   ev->str ? ev->str : "?", ev->ival2, ev->friend_number);
            tt_queue_post2(&tt.in, TT_CMD_GROUP_INVITE_ACC, 0, NULL, 0, ev->ival2);
            break;
        case TT_EV_GROUP_JOINED:
            TT_LOG("echo", "joined group gn=%u name=%s",
                   ev->friend_number, ev->str ? ev->str : "?");
            break;
        case TT_EV_GROUP_PEER_JOIN:
            TT_LOG("echo", "PEER %u joined gn=%u", ev->ival, ev->friend_number);
            break;
        case TT_EV_GROUP_MSG:
            if (ev->str) {
                TT_LOG("echo", "group %u msg from peer %u: %.*s", ev->friend_number,
                       (unsigned)ev->ival, (int)(ev->str_len > 64 ? 64 : ev->str_len), ev->str);
                tt_queue_post(&tt.in, TT_CMD_GROUP_SEND, ev->friend_number, ev->str, 0);
            }
            break;
        case TT_EV_GROUP_PEER_EXIT:
            TT_LOG("echo", "peer %u left gn=%u (exit %d)", ev->ival,
                   ev->friend_number, ev->ival2);
            break;
        case TT_EV_GROUP_JOIN_FAIL:
            TT_LOG("echo", "group %u join FAILED (type %d)", ev->friend_number, ev->ival);
            break;
        case TT_EV_SHUTDOWN:
            g_stop = 1;
            break;
        default:
            break;
        }
        tt_event_free(ev);
    }
    tt_tox_thread_stop(&tt);
    return 0;
}

/* Group persistence probe (--persist-test <profile> [B]):
   phase A (no arg): fresh profile -> create private group "persist-probe"
   -> wait for self-join -> exit WITHOUT leaving (shutdown saves the live
   group into savedata STATE_TYPE_GROUPS).
   phase B (arg "B"): same profile -> engine restore burst must log
   "restored group" and a GROUP_JOINED arrives (toxcore self-reconnects;
   self-join fires on first sync response from a saved peer). rc=0 when the
   group came back, 2 on timeout, 3 if phase A saw no self-join. */
int persist_test_main(const char *profile, bool phase_b) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    const time_t start = time(NULL);
    int rc = 2;
    if (!phase_b) {
        /* founder side: create fires GROUP_NEW immediately (founder is
           connected at once — time_connected is set in gc_group_add, so
           the self-join callback never fires on the create path) */
        bool created = false, joined = false;
        tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "persist-probe\nprivate", 0);
        while (!g_stop && time(NULL) - start < 60) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            if (ev->type == TT_EV_GROUP_JOINED) joined = true;
            else if (ev->type == TT_EV_GROUP_NEW) created = true;
            tt_event_free(ev);
            if (created || joined) break;
        }
        if (!created && !joined) {
            TT_LOG("bot", "persist phase A: group create never fired");
            rc = 3;
        } else {
            TT_LOG("bot", "persist phase A: %s; exiting WITHOUT leave (save)",
                   joined ? "group joined" : "group created (founder connected)");
            rc = 0;
        }
    } else {
        bool joined = false;
        /* phase B: the restore burst logs "restored group" (tox side) and
           the reconnect self-join fires GROUP_JOINED; either proves reload */
        while (!g_stop && time(NULL) - start < 90) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            if (ev->type == TT_EV_GROUP_JOINED) {
                TT_LOG("bot", "persist phase B: GROUP_JOINED gn=%u name=%s",
                       ev->friend_number, ev->str ? ev->str : "?");
                joined = true;
                break;
            }
            tt_event_free(ev);
        }
        if (joined) {
            TT_LOG("bot", "persist phase B: restored group rejoined OK");
            rc = 0;
        } else {
            TT_LOG("bot", "persist phase B: no GROUP_JOINED within 90s");
            rc = 2;
        }
    }
    tt_tox_thread_stop(&tt);
    return rc;
}

/* Faux offline messaging probe (--offline-test <profile> <peer_toxid> [B]):
   phase A: add the peer (fresh profile), post SEND_MESSAGE while the peer
   is NOT running — toxcore fails with FRIEND_NOT_CONNECTED, the engine
   queues it, we exit (rc=0) once the .oq sidecar exists. The script then
   checks the sidecar and starts phase B.
   phase B: restart on the same profile — the queue restores from disk;
   when the peer accepts the request and comes online, the queued message
   flushes; the peer's echo reply proves end-to-end delivery. rc=0 on echo. */
int offline_test_main(const char *profile, const char *peer_toxid, bool phase_b) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    const time_t start = time(NULL);
    int rc = 2;
    if (!phase_b) {
        bool added = false;
        tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, peer_toxid, 0);
        tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "Offline Bot", 0);
        while (!g_stop && time(NULL) - start < 30) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            if (ev->type == TT_EV_SELF_CONNECTION && ev->ival != 0 && !added) {
                /* self online, peer dead: post the message directly */
                TT_LOG("bot", "phase A: self online, posting message to offline peer");
                tt_queue_post(&tt.in, TT_CMD_SEND_MESSAGE, 0, "offline-probe-hello", 0);
                added = true;
            }
            tt_event_free(ev);
            if (added) break;
        }
        /* poll for the sidecar the engine writes on queue */
        char oqpath[1100];
        snprintf(oqpath, sizeof oqpath, "%s.oq", profile);
        for (int i = 0; i < 20 && access(oqpath, F_OK) != 0; i++)
            usleep(100 * 1000);
        if (access(oqpath, F_OK) == 0) {
            TT_LOG("bot", "phase A: message queued, sidecar %s exists", oqpath);
            rc = 0;
        } else {
            TT_LOG("bot", "phase A: sidecar never appeared");
        }
    } else {
        bool flushed = false, echoed = false;
        while (!g_stop && time(NULL) - start < 120) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            switch (ev->type) {
            case TT_EV_TOXID:
                TT_LOG("bot", "phase B self ToxID: %s", ev->str ? ev->str : "?");
                break;
            case TT_EV_OFFLINE_FLUSHED:
                flushed = true;
                TT_LOG("bot", "phase B: offline queue flushed (%d message%s)",
                       ev->ival, ev->ival == 1 ? "" : "s");
                break;
            case TT_EV_FRIEND_MESSAGE:
                if (ev->str && str_contains(ev->str, ev->str_len, "offline-probe-hello")) {
                    echoed = true;
                    TT_LOG("bot", "phase B: echo received — end-to-end OK");
                }
                break;
            default:
                break;
            }
            tt_event_free(ev);
            if (flushed && echoed) { rc = 0; break; }
        }
        if (!(flushed && echoed)) {
            TT_LOG("bot", "phase B: %s%s",
                   flushed ? "" : "NO FLUSH ", echoed ? "" : "NO ECHO");
        }
    }
    tt_tox_thread_stop(&tt);
    return rc;
}

/* Flap reproduction (--flap-test <profile> [<peer_toxid>]), two-sided:
   responder (no peer): accept friend requests + group invites, stay alive,
   log every connection/group event — the silent second client.
   initiator (peer given): add friend; on both online: create group1 +
   invite; on peer join: leave group1, create group2 (proxy for a
   pre-existing group) + invite the same friend; logs every self/friend
   connection transition. rc=0 when the friend joined round 2; rc=3 if
   self ever dropped; rc=2 on timeout. */
int flap_test_main(const char *profile, const char *peer_toxid) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    const time_t start = time(NULL);
    int rc = 2;
    bool initiator = peer_toxid != NULL;
    if (!initiator) {
        /* silent responder: accept everything, log, stay alive */
        while (!g_stop && time(NULL) - start < 300) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            switch (ev->type) {
            case TT_EV_TOXID:
                TT_LOG("flap-r", "self ToxID: %s", ev->str ? ev->str : "?");
                break;
            case TT_EV_SELF_CONNECTION:
                TT_LOG("flap-r", "SELF conn -> %d", ev->ival);
                break;
            case TT_EV_FRIEND_CONNECTION:
                TT_LOG("flap-r", "FRIEND %u conn -> %d", ev->friend_number, ev->ival);
                break;
            case TT_EV_FRIEND_REQUEST:
                TT_LOG("flap-r", "accepting request");
                tt_queue_post(&tt.in, TT_CMD_ACCEPT_FRIEND, 0, ev->str, 0);
                break;
            case TT_EV_GROUP_INVITE:
                TT_LOG("flap-r", "invite \"%s\" — accepting", ev->str ? ev->str : "?");
                tt_queue_post2(&tt.in, TT_CMD_GROUP_INVITE_ACC, 0, NULL, 0, ev->ival2);
                break;
            case TT_EV_GROUP_JOINED:
                TT_LOG("flap-r", "JOINED gn=%u", ev->friend_number);
                break;
            case TT_EV_GROUP_PEER_JOIN:
                TT_LOG("flap-r", "PEER %u joined gn=%u", ev->ival, ev->friend_number);
                break;
            default:
                break;
            }
            tt_event_free(ev);
        }
        tt_tox_thread_stop(&tt);
        return 0;
    }
    enum { F_WAIT_ONLINE, F_CREATE1, F_WAIT_JOIN1, F_CREATE2, F_WAIT_JOIN2, F_DONE } st = F_WAIT_ONLINE;
    uint32_t fn = UINT32_MAX;
    int gn1 = -1, gn2 = -1;
    bool self_dropped = false;
    tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "Flap Bot", 0);
    tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, peer_toxid, 0);
    while (!g_stop && time(NULL) - start < 150) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (!ev) continue;
        switch (ev->type) {
        case TT_EV_SELF_CONNECTION:
            TT_LOG("flap", "SELF conn -> %d", ev->ival);
            if (ev->ival == 0 && st != F_WAIT_ONLINE) {
                self_dropped = true;
                rc = 3;
            }
            if (ev->ival != 0 && st == F_WAIT_ONLINE) {
                if (fn == UINT32_MAX) break; /* wait for the friend first */
                st = F_CREATE1;
                TT_LOG("flap", "creating group1 (round 1)");
                tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "flap1\nprivate", 0);
            }
            break;
        case TT_EV_FRIEND_CONNECTION:
            TT_LOG("flap", "FRIEND %u conn -> %d", ev->friend_number, ev->ival);
            if (ev->ival != 0 && fn == UINT32_MAX) {
                fn = ev->friend_number;
                if (st == F_WAIT_ONLINE) { /* self was already up */
                    st = F_CREATE1;
                    TT_LOG("flap", "creating group1 (round 1)");
                    tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "flap1\nprivate", 0);
                }
            }
            break;
        case TT_EV_GROUP_NEW:
            if (st == F_CREATE1) {
                gn1 = (int)ev->friend_number;
                TT_LOG("flap", "group1 gn=%d — inviting friend %u", gn1, fn);
                tt_queue_post(&tt.in, TT_CMD_GROUP_INVITE, (uint32_t)gn1, NULL, (int)fn);
                st = F_WAIT_JOIN1;
            } else if (st == F_CREATE2) {
                gn2 = (int)ev->friend_number;
                TT_LOG("flap", "group2 gn=%d — inviting friend %u (THE REPRO STEP)", gn2, fn);
                tt_queue_post(&tt.in, TT_CMD_GROUP_INVITE, (uint32_t)gn2, NULL, (int)fn);
                st = F_WAIT_JOIN2;
            }
            break;
        case TT_EV_GROUP_PEER_JOIN:
            if ((int)ev->friend_number == gn1 && st == F_WAIT_JOIN1) {
                TT_LOG("flap", "peer joined group1 — leaving group1, creating group2");
                tt_queue_post(&tt.in, TT_CMD_GROUP_LEAVE, (uint32_t)gn1, NULL, 0);
                tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "flap2\nprivate", 0);
                st = F_CREATE2;
            } else if ((int)ev->friend_number == gn2 && st == F_WAIT_JOIN2) {
                TT_LOG("flap", "peer joined group2 — REPRO COMPLETE, self conn stable");
                rc = self_dropped ? 3 : 0;
                st = F_DONE;
            }
            break;
        default:
            break;
        }
        tt_event_free(ev);
    }
    if (rc == 2) TT_LOG("flap", "timeout in state %d (gn1=%d gn2=%d fn=%u)", st, gn1, gn2, fn);
    tt_tox_thread_stop(&tt);
    return rc;
}

/* Connectivity soak (--soak-test <profile> [minutes]): connect and hold,
   logging every self connection change with timestamps; exits 0 if self
   stayed connected the whole window, 3 if it ever dropped. */
int soak_test_main(const char *profile, int minutes) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    const time_t end = time(NULL) + (minutes > 0 ? minutes : 2) * 60;
    int rc = 0, drops = 0, changes = 0;
    TT_LOG("soak", "holding connection for %d minute(s)", minutes > 0 ? minutes : 2);
    while (!g_stop && time(NULL) < end) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (!ev) continue;
        if (ev->type == TT_EV_SELF_CONNECTION) {
            changes++;
            if (ev->ival == 0) { drops++; rc = 3; TT_LOG("soak", "DROP #%d", drops); }
            else TT_LOG("soak", "up (%d)", ev->ival);
        }
        tt_event_free(ev);
    }
    TT_LOG("soak", "done: %d connection change(s), %d drop(s) — %s",
           changes, drops, rc == 0 ? "STABLE" : "FLAPPED");
    tt_tox_thread_stop(&tt);
    return rc;
}

/* Invite-into-RESTORED-group probe (--invrest-test <profile> <peer_toxid> [B]):
   the exact round-21 user trigger — inviting a friend into a group that came
   back from savedata restore. Phase A (fresh profile): add friend, create
   "invrest" (private), invite the peer, wait for the peer to join, then exit
   WITHOUT leaving (shutdown saves the group). Phase B (same profile): the
   engine restores the group from savedata; when the peer is connected again,
   re-invite into the RESTORED group and watch self connection for 120s —
   rc=0 when the peer joins with no self drop, 3 on a self drop, 2 on timeout. */
int invrest_test_main(const char *profile, const char *peer_toxid, bool phase_b) {
    signal(SIGINT, on_sigint);
    TTToxThread tt;
    if (!tt_tox_thread_start(&tt, profile)) {
        TT_LOG("main", "failed to start tox thread");
        return 1;
    }
    tt_queue_post(&tt.in, TT_CMD_SET_NAME, 0, "InvRest Bot", 0);
    const time_t start = time(NULL);
    int rc = 2;
    if (!phase_b) {
        if (peer_toxid) tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, peer_toxid, 0);
        bool created = false, peer_in = false, self_up = false;
        uint32_t fn = UINT32_MAX;
        int gn = -1;
        while (!g_stop && time(NULL) - start < 90) {
            TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
            if (!ev) continue;
            switch (ev->type) {
            case TT_EV_FRIEND_CONNECTION:
                if (ev->ival != 0 && fn == UINT32_MAX) {
                    fn = ev->friend_number;
                    TT_LOG("invrest", "phase A: friend %u connected", fn);
                    if (self_up && !created) {
                        TT_LOG("invrest", "phase A: creating group");
                        tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "invrest\nprivate", 0);
                        created = true;
                    }
                }
                break;
            case TT_EV_SELF_CONNECTION:
                if (ev->ival != 0) self_up = true;
                if (ev->ival != 0 && !created && fn != UINT32_MAX) {
                    TT_LOG("invrest", "phase A: creating group");
                    tt_queue_post(&tt.in, TT_CMD_GROUP_CREATE, 0, "invrest\nprivate", 0);
                    created = true;
                }
                break;
            case TT_EV_GROUP_NEW:
                gn = (int)ev->friend_number;
                TT_LOG("invrest", "phase A: group gn=%d — inviting friend %u", gn, fn);
                tt_queue_post(&tt.in, TT_CMD_GROUP_INVITE, (uint32_t)gn, NULL, (int)fn);
                break;
            case TT_EV_GROUP_PEER_JOIN:
                TT_LOG("invrest", "phase A: peer joined gn=%d — exiting WITHOUT leave (save)",
                       ev->friend_number);
                peer_in = true;
                break;
            default:
                break;
            }
            tt_event_free(ev);
            if (peer_in) break;
        }
        if (peer_in) {
            TT_LOG("invrest", "phase A complete: group gn=%d saved with peer inside", gn);
            rc = 0;
        } else {
            TT_LOG("invrest", "phase A incomplete (created=%d peer_in=%d)", created, peer_in);
            rc = 3;
        }
        tt_tox_thread_stop(&tt);
        return rc;
    }
    /* phase B: profile restored (group comes back via savedata), re-invite
       the peer into the RESTORED group; rc=3 if self ever drops. */
    if (peer_toxid) tt_queue_post(&tt.in, TT_CMD_ADD_FRIEND, 0, peer_toxid, 0);
    bool invited = false, peer_in = false, self_dropped = false;
    uint32_t fn = UINT32_MAX;
    int gn = -1;
    time_t last_ping = 0;
    while (!g_stop && time(NULL) - start < 120) {
        TTEvent *ev = tt_queue_pop_timed(&tt.out, 500);
        if (ev) {
        switch (ev->type) {
        case TT_EV_SELF_CONNECTION:
            if (ev->ival == 0 && invited) {
                TT_LOG("invrest", "phase B: SELF DROPPED after invite (THE BUG)");
                self_dropped = true;
                rc = 3;
            }
            break;
        case TT_EV_FRIEND_CONNECTION:
            if (ev->ival != 0 && fn == UINT32_MAX) {
                fn = ev->friend_number;
                TT_LOG("invrest", "phase B: friend %u connected", fn);
            }
            break;
        case TT_EV_GROUP_JOINED:
            if (gn < 0) {
                gn = (int)ev->friend_number;
                TT_LOG("invrest", "phase B: restored group gn=%d name=%s",
                       gn, ev->str ? ev->str : "?");
            }
            break;
        case TT_EV_GROUP_NEW:
            /* restore must NOT fire GROUP_NEW (that's create-only) — if it
               does, log it loudly: that would re-found a second group */
            TT_LOG("invrest", "phase B: UNEXPECTED GROUP_NEW gn=%u — restore re-founded?",
                   ev->friend_number);
            break;
        case TT_EV_GROUP_PEER_JOIN:
            if (invited && (int)ev->friend_number == gn) {
                TT_LOG("invrest", "phase B: peer joined restored group — SUCCESS");
                peer_in = true;
            }
            break;
        case TT_EV_GROUP_MSG:
            /* the restored group carries traffic: our ping came back echoed */
            if (invited && (int)ev->friend_number == gn && ev->str &&
                str_contains(ev->str, ev->str_len, "invrest-ping")) {
                TT_LOG("invrest", "phase B: group message roundtrip OK — restored group fully functional");
                peer_in = true;
            }
            break;
        default:
            break;
        }
        tt_event_free(ev);
        }
        if (!invited && gn >= 0 && fn != UINT32_MAX && time(NULL) - start > 15) {
            TT_LOG("invrest", "phase B: RE-INVITING friend %u into restored group %d (THE REPRO STEP)",
                   fn, gn);
            tt_queue_post(&tt.in, TT_CMD_GROUP_INVITE, (uint32_t)gn, NULL, (int)fn);
            /* the peer may already be a member (they never left; only our
               connection did) — toxcore ignores the re-invite then. Prove
               the restored group works by a message roundtrip instead. */
            tt_queue_post(&tt.in, TT_CMD_GROUP_SEND, (uint32_t)gn, "invrest-ping", 0);
            invited = true;
            last_ping = time(NULL);
        } else if (invited && !peer_in && time(NULL) - last_ping >= 20) {
            tt_queue_post(&tt.in, TT_CMD_GROUP_SEND, (uint32_t)gn, "invrest-ping", 0);
            last_ping = time(NULL);
        }
        if (peer_in) break;
    }
    if (!invited) {
        TT_LOG("invrest", "phase B: never got both self+friend online and group restored");
        rc = 2;
    } else if (!peer_in && !self_dropped) {
        TT_LOG("invrest", "phase B: invite posted but peer never joined within 120s");
        rc = 2;
    }
    if (!self_dropped) rc = peer_in ? 0 : rc;
    TT_LOG("invrest", "phase B result: rc=%d (peer_in=%d self_dropped=%d)",
           rc, peer_in, self_dropped);
    tt_tox_thread_stop(&tt);
    return rc;
}