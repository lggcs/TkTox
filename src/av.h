/* AV engine layer (M-AV1) + audio device layer (M-AV3): toxav lifecycle,
   call events, and ALSA ring plumbing on the tox thread.
   Threading (toxav.h contract): only toxav_iterate is thread-safe; every other
   toxav call must run on the tox thread. Call-state events fire from the tox
   thread (during toxav_iterate / toxav callbacks invoked there), so we post
   TT_EV_AV_* exactly like the other toxcore callbacks do.
   Audio NEVER crosses the TT event queue: the ALSA capture worker pushes PCM
   into a ring that the tox loop drains straight into toxav_audio_send_frame;
   received frames go into the playback ring from the toxav rx callback. */
#ifndef TT_AV_H
#define TT_AV_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "tox_thread.h"
#include <tox/toxav.h>

#define TT_AV_AUDIO_BITRATE 32 /* kbit/s */
#define TT_AV_VIDEO_BITRATE 2500 /* kbit/s */

/* M-AV4 harness frame pump: 15 frames/s is plenty to prove the wire path */
#define TT_AV_VTEST_INTERVAL_MS 66
#define TT_AV_VTEST_SIZE 160 /* 160x90 -> 80x45 chroma */
#define TT_AV_VTEST_COUNT 150

struct TTAudio;

/* per-friend call state we track (toxav holds the real session state) */
typedef struct TTAvg {
    bool mic_muted; /* TT_CMD_AV_MUTE: capture gate in the ALSA worker */
    bool deaf;      /* M-AV5: output gate — pushed PCM is dropped */
    bool selfview_on; /* M-AV5: post local V4L2 frames to the UI pane */
    time_t started; /* call start (for duration lines) */
    uint32_t state; /* last toxav call state bitmask */
    uint32_t paused_state; /* tier B1: state remembered across PAUSE (g->state is 0 while paused) */
    uint32_t call_fn; /* friend number of the active call (send_frame key) */
    struct TTAudio *audio;        /* M-AV3 device layer (NULL until started) */
    pthread_t audio_cap_thread;   /* mic -> cap ring worker */
    pthread_t audio_play_thread;  /* play ring -> speaker worker */
    struct TTVideo *video;        /* M-AV4 V4L2 layer (NULL until started) */
    pthread_t video_thread;       /* V4L2 capture worker */
    /* M-AV4 harness pump (TT_BOT_CALL_VTEST): moving pattern send */
    bool vtest_on;
    uint32_t vtest_sent;
    time_t vtest_at;
    uint32_t vtest_fn;
    uint64_t video_last_seq; /* V4L2 slot seq already sent (dedupe) */
} TTAvg;

bool tt_av_init(TTToxThread *t);
void tt_av_kill(TTToxThread *t);

/* Fold into the tox loop right after tox_iterate (single-thread mode). */
void tt_av_iterate(TTToxThread *t, ToxAV *av);

/* command handlers (run on the tox thread from handle_cmd) */
void tt_av_cmd_call(TTToxThread *t, uint32_t fn, int audio_br, int video_br);
void tt_av_cmd_answer(TTToxThread *t, uint32_t fn, int audio_br, int video_br);
void tt_av_cmd_hangup(TTToxThread *t, uint32_t fn);
void tt_av_cmd_pause(TTToxThread *t, uint32_t fn);
void tt_av_cmd_resume(TTToxThread *t, uint32_t fn);
void tt_av_cmd_mute(TTToxThread *t, uint32_t fn, bool muted);
void tt_av_cmd_deaf(TTToxThread *t, uint32_t fn, bool deaf);
void tt_av_cmd_selfview(TTToxThread *t, uint32_t fn, int on);
void tt_av_cmd_vtest(TTToxThread *t, uint32_t fn, int on);
void tt_av_cmd_video_br(TTToxThread *t, uint32_t fn, int br);

#endif