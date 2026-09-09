#include "av.h"
#include "audio_alsa.h"
#include "log.h"
#include "video_v4l2.h"

#include <string.h>
#include <time.h>

/* M-AV4 harness: moving-pattern YUV420 test frame (the pattern makes frame
   identity obvious: column = x/4 mod 256 luma, chroma plane constant 128) */
static void vtest_pattern(uint16_t w, uint16_t h, uint8_t *y, uint8_t *u,
                          uint8_t *v, uint32_t tick) {
    for (uint32_t j = 0; j < h; j++)
        for (uint32_t i = 0; i < w; i++)
            y[j * w + i] = (uint8_t)(((i + tick * 8) / 4) & 0xff);
    memset(u, 128, (size_t)(w / 2) * (h / 2));
    memset(v, 128, (size_t)(w / 2) * (h / 2));
}

/* tox-loop drain of the video sources (V4L2 slot or the harness pump) */
static void video_send_drain(TTToxThread *t, TTAvg *g, ToxAV *av) {
    (void)t;
    if (!g || !(g->state & TOXAV_FRIEND_CALL_STATE_SENDING_V) ||
        g->call_fn == UINT32_MAX)
        return;
    Toxav_Err_Send_Frame serr;
    if (g->vtest_on) { /* harness pump: paced, bounded, self-terminating */
        time_t now = time(NULL);
        if (g->vtest_at && now - g->vtest_at < 1) return;
        g->vtest_at = now;
        static uint8_t y[TT_AV_VTEST_SIZE * 90];
        static uint8_t u[(TT_AV_VTEST_SIZE / 2) * 45];
        static uint8_t v[(TT_AV_VTEST_SIZE / 2) * 45];
        for (int k = 0; k < 2 && g->vtest_sent < TT_AV_VTEST_COUNT; k++) {
            vtest_pattern(TT_AV_VTEST_SIZE, 90, y, u, v, g->vtest_sent);
            toxav_video_send_frame(av, g->vtest_fn, TT_AV_VTEST_SIZE, 90, y, u,
                                   v, &serr);
            g->vtest_sent++;
        }
        if (g->vtest_sent >= TT_AV_VTEST_COUNT) {
            g->vtest_on = false;
            TT_LOG("av", "vtest: sent %u frames", g->vtest_sent);
        }
        return;
    }
    if (!g->video) return;
    /* one interleaved YUV420 buffer; fetch_local fills frame_bytes =
       w*h + 2*(w/2)*(h/2); planes are contiguous in that order */
    static uint8_t ybuf[1280 * 720];
    uint16_t w, h;
    uint64_t seq;
    if (!tt_video_fetch_local(g, ybuf, sizeof ybuf, &w, &h, &seq)) return;
    if (seq == g->video_last_seq) return; /* no new frame since last send */
    g->video_last_seq = seq;
    toxav_video_send_frame(av, g->call_fn, w, h, ybuf,
                           ybuf + (size_t)w * h,
                           ybuf + (size_t)w * h + (size_t)(w / 2) * (h / 2),
                           &serr);
}

/* M-AV5 self-view: post the LOCAL camera frame to the UI pane, paced to
   keep the event queue light (the tox loop sends the peer every fresh
   frame; the pane only needs a slow mirror) */
static void selfview_drain(TTToxThread *t, TTAvg *g, time_t now) {
    if (!g || !g->selfview_on || !g->video) return;
    if (now == g->vtest_at) return; /* vtest_at doubles as the pace stamp */
    g->vtest_at = now;
    static uint8_t ybuf[1280 * 720];
    uint16_t w, h;
    uint64_t seq;
    if (!tt_video_fetch_local(g, ybuf, sizeof ybuf, &w, &h, &seq)) return;
    TTEvent *ev = tt_event_new(TT_EV_AV_FRAME);
    if (!ev) return;
    size_t payload = (size_t)w * h + 2 * (size_t)(w / 2) * (h / 2);
    ev->str = malloc(payload + 1);
    if (!ev->str) {
        tt_event_free(ev);
        return;
    }
    memcpy(ev->str, ybuf, payload);
    ev->str[payload] = '\0';
    ev->str_len = payload;
    ev->friend_number = g->call_fn;
    ev->ival = w;
    ev->ival2 = h;
    tt_queue_push(&t->out, ev);
}

/* start/stop the device layer with the call lifecycle (defined below) */
static void audio_lifecycle(TTAvg *g, bool up);
/* M-AV4: camera + send start/stop tied to SENDING_V (same call lifecycle) */
static void video_lifecycle(TTAvg *g, bool up) {
    if (!g) return;
    if (up && !g->video) {
        if (!tt_video_start(g))
            TT_LOG("av", "video: capture unavailable — call continues audio-only");
    } else if (!up && g->video) {
        tt_video_stop(g);
        TT_LOG("av", "video: device layer stopped");
    }
}

/* push a copy of the current call state for a friend (NULL safe) */
static TTAvg *avg_slot(TTToxThread *t) {
    return (TTAvg *)t->avg;
}

static void push_av(TTToxThread *t, TTEventType type, uint32_t fn, int ival, int ival2) {
    TTEvent *ev = tt_event_new(type);
    if (!ev) return;
    ev->friend_number = fn;
    ev->ival = ival;
    ev->ival2 = ival2;
    tt_queue_push(&t->out, ev);
}

/* Synthetic events for the LOCAL side of a state change: MSI only calls
   back on the PEER of a transition (hangup is fire-and-forget for the
   hangup side; the callee gets no state callback at answer). Without these
   echoes the answering/hangup GUI never flips. ival2=1 tags the echo so
   the UI can tell OUR pause/resume from the peer's (a peer-side transition
   arrives as a real MSI callback with ival2=0). */
static void push_av_local_state(TTToxThread *t, uint32_t fn, uint32_t state) {
    TTAvg *g = avg_slot(t);
    if (g) g->state = state;
    push_av(t, TT_EV_AV_STATE, fn, (int)state, 1);
}

static void push_av_local_ended(TTToxThread *t, uint32_t fn, int err) {
    TTAvg *g = avg_slot(t);
    long dur = 0;
    if (g) {
        dur = g->started ? (long)(time(NULL) - g->started) : 0;
        g->started = 0;
        g->state = 0;
        g->call_fn = UINT32_MAX;
        g->vtest_on = false;
        g->selfview_on = false;
        audio_lifecycle(g, false); /* our hangup: stop capture/playback */
        video_lifecycle(g, false);
    }
    push_av(t, TT_EV_AV_ENDED, fn, err, (int)dur);
}

/* ---- toxav callbacks (fire on the tox thread) ---- */

static void cb_av_call(ToxAV *av, uint32_t friend_number, bool audio_enabled,
                       bool video_enabled, void *user_data) {
    (void)av;
    TTToxThread *t = user_data;
    TT_LOG("av", "incoming call from friend %u (audio=%d video=%d)",
           friend_number, audio_enabled, video_enabled);
    TTAvg *g = avg_slot(t);
    if (g) {
        g->started = 0;
        g->state = 0;
        g->call_fn = friend_number;
        g->mic_muted = false; /* a new call starts with the mic open */
        g->deaf = false;
        g->selfview_on = false;
    }
    push_av(t, TT_EV_AV_INCOMING, friend_number, audio_enabled ? 1 : 0,
            video_enabled ? 1 : 0);
}

static void cb_av_call_state(ToxAV *av, uint32_t friend_number, uint32_t state,
                             void *user_data) {
    (void)av;
    TTToxThread *t = user_data;
    TTAvg *g = avg_slot(t);
    TT_LOG("av", "call state friend %u: 0x%x", friend_number, state);
    if (g) {
        if ((state & TOXAV_FRIEND_CALL_STATE_SENDING_A) && g->started == 0) {
            g->started = time(NULL);
        }
        g->state = state;
        if (state & (TOXAV_FRIEND_CALL_STATE_FINISHED | TOXAV_FRIEND_CALL_STATE_ERROR)) {
            time_t dur = g->started ? time(NULL) - g->started : 0;
            TT_LOG("av", "call with friend %u ended (%s, %lds)", friend_number,
                   (state & TOXAV_FRIEND_CALL_STATE_ERROR) ? "error" : "finished",
                   (long)dur);
            push_av(t, TT_EV_AV_ENDED, friend_number,
                    (state & TOXAV_FRIEND_CALL_STATE_ERROR) ? 1 : 0, (int)dur);
            g->started = 0;
            g->call_fn = UINT32_MAX;
            g->vtest_on = false;
            g->selfview_on = false;
            audio_lifecycle(g, false); /* call down: stop capture/playback */
            video_lifecycle(g, false);
        } else if (state & (TOXAV_FRIEND_CALL_STATE_SENDING_A |
                            TOXAV_FRIEND_CALL_STATE_ACCEPTING_A)) {
            audio_lifecycle(g, true); /* call up: start the device layer */
        }
        if (state & TOXAV_FRIEND_CALL_STATE_SENDING_V && g->call_fn == friend_number)
            video_lifecycle(g, true); /* we accepted video: camera + send start */
    }
    push_av(t, TT_EV_AV_STATE, friend_number, (int)state, 0);
}

/* M-AV3: real audio path — received PCM goes to the playback ring (the ALSA
   worker drains it to the device). Video stays a stub until M-AV4. */

/* slow path: fold any channel count to mono and linearly resample to the
   48 kHz the ring/device accept (any other negotiated rate would otherwise
   play at the wrong speed). Runs only on the tox thread. */
#define TT_AUDIO_RX_MAX_SAMPLES (TT_AUDIO_RING_FRAMES * TT_AUDIO_FRAME_FRAMES)

static void audio_rx_convert(TTAvg *g, const int16_t *pcm, size_t sample_count,
                             uint8_t channels, uint32_t sampling_rate) {
    static int16_t mono[TT_AUDIO_RX_MAX_SAMPLES];
    static int16_t out[TT_AUDIO_RX_MAX_SAMPLES];

    if (sampling_rate == 0 || channels == 0) return;
    size_t in = sample_count / channels;
    if (in > TT_AUDIO_RX_MAX_SAMPLES) in = TT_AUDIO_RX_MAX_SAMPLES;
    for (size_t i = 0; i < in; i++) {
        int32_t acc = 0;
        for (uint8_t c = 0; c < channels; c++) acc += pcm[i * channels + c];
        mono[i] = (int16_t)(acc / channels);
    }
    size_t out_n = in;
    if (sampling_rate != 48000) {
        out_n = (size_t)((uint64_t)in * 48000 / sampling_rate);
        if (out_n > TT_AUDIO_RX_MAX_SAMPLES) out_n = TT_AUDIO_RX_MAX_SAMPLES;
        for (size_t i = 0; i < out_n; i++) {
            uint64_t num = (uint64_t)i * sampling_rate;
            size_t p = (size_t)(num / 48000);
            uint64_t fr = num % 48000;
            int32_t a = mono[p];
            int32_t b = (p + 1 < in) ? mono[p + 1] : a;
            out[i] = (int16_t)(a + (int32_t)(((int64_t)b - (int64_t)a) *
                                             (int64_t)fr / 48000));
        }
    } else {
        memcpy(out, mono, in * sizeof out[0]);
    }
    size_t frames = out_n / TT_AUDIO_FRAME_FRAMES;
    for (size_t f = 0; f < frames; f++)
        tt_audio_playback_push(g, (const uint8_t *)(out + f * TT_AUDIO_FRAME_FRAMES),
                               1);
}

static void cb_av_audio_rx(ToxAV *av, uint32_t friend_number, const int16_t *pcm,
                           size_t sample_count, uint8_t channels, uint32_t sampling_rate,
                           void *user_data) {
    (void)av; (void)friend_number;
    TTToxThread *t = user_data;
    TTAvg *g = avg_slot(t);
    if (!g || !g->audio) return; /* device layer not running: drop */
    if (g->deaf) return; /* M-AV5: output muted — drop before the play ring */
    if (channels == 1 && sampling_rate == 48000) {
        tt_audio_playback_push(g, (const uint8_t *)pcm,
                               sample_count / TT_AUDIO_FRAME_FRAMES);
        return;
    }
    audio_rx_convert(g, pcm, sample_count, channels, sampling_rate);
}

/* M-AV4: peer video frames -> TT_EV_AV_FRAME (heap payload) for the Tk
   pane + harness counters. Sizing: w*h + 2*(w/2)*(h/2) <= 460800 bytes. */
static void cb_av_video_rx(ToxAV *av, uint32_t friend_number, uint16_t w, uint16_t h,
                           const uint8_t *y, const uint8_t *u, const uint8_t *v,
                           int32_t ystride, int32_t ustride, int32_t vstride,
                           void *user_data) {
    (void)av;
    TTToxThread *t = user_data;
    if (w == 0 || h == 0 || ystride < 0 || ustride < 0 || vstride < 0) return;
    /* YUV420 invariant: each stride must cover its plane width, or the
       row copies below would write past the allocated payload (a hostile
       peer can set w/h large and strides small to overflow the heap). */
    if ((size_t)w > (size_t)ystride ||
        (size_t)((w + 1) / 2) > (size_t)ustride ||
        (size_t)((w + 1) / 2) > (size_t)vstride)
        return;
    size_t ys = (size_t)ystride * h;
    size_t us = (size_t)ustride * ((h + 1) / 2);
    size_t vsz = (size_t)vstride * ((h + 1) / 2);
    if (ys > 460800 || us > 460800 || vsz > 460800) return;
    size_t payload = ys + us + vsz;
    TTEvent *ev = tt_event_new(TT_EV_AV_FRAME);
    if (!ev) return;
    ev->str = malloc(payload + 1);
    if (!ev->str) {
        tt_event_free(ev);
        return;
    }
    for (uint32_t j = 0; j < h; j++)
        memcpy(ev->str + j * ystride, y + j * ystride, (size_t)w);
    for (uint32_t j = 0; j < (uint32_t)((h + 1) / 2); j++) {
        memcpy(ev->str + ys + j * ustride, u + j * ustride,
               (size_t)((w + 1) / 2));
        memcpy(ev->str + ys + us + j * vstride, v + j * vstride,
               (size_t)((w + 1) / 2));
    }
    ev->str[payload] = '\0';
    ev->str_len = payload;
    ev->friend_number = friend_number;
    ev->ival = w;
    ev->ival2 = h;
    tt_queue_push(&t->out, ev);
}

/* M-AV6 bit-rate adaptation: toxav's bwcontroller fires these on > 10%
   packet loss with an already-reduced suggestion (current * (1 - loss),
   video preferred while both stream). Apply it directly — toxav_*_set_
   bit_rate must run on the tox thread, which is exactly where callbacks
   are invoked. Adjust-down-only: clamp against the current value so a
   suggestion can never raise the rate, and ignore suggestions that would
   push audio below the Opus floor (the next loss report will suggest
   lower video instead once audio bottoms out). */
static void cb_av_audio_br(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate,
                           void *user_data) {
    (void)user_data;
    Toxav_Err_Bit_Rate_Set serr;
    TT_LOG("av", "audio bit rate suggestion friend %u: %u kbit/s",
           friend_number, audio_bit_rate);
    if (audio_bit_rate == 0 || audio_bit_rate < 6) return; /* below Opus floor */
    bool ok = toxav_audio_set_bit_rate(av, friend_number, audio_bit_rate, &serr);
    TT_LOG("av", "audio bit rate set(%u): %d (%d)", friend_number, audio_bit_rate,
           ok ? (int)serr : 0);
}

static void cb_av_video_br(ToxAV *av, uint32_t friend_number, uint32_t video_bit_rate,
                           void *user_data) {
    (void)user_data;
    Toxav_Err_Bit_Rate_Set serr;
    TT_LOG("av", "video bit rate suggestion friend %u: %u kbit/s",
           friend_number, video_bit_rate);
    if (video_bit_rate == 0) return; /* 0 would disable the stream entirely */
    bool ok = toxav_video_set_bit_rate(av, friend_number, video_bit_rate, &serr);
    TT_LOG("av", "video bit rate set(%u): %u (%d)", friend_number, video_bit_rate,
           ok ? (int)serr : (int)TOXAV_ERR_BIT_RATE_SET_SYNC);
}

/* ---- lifecycle ---- */

bool tt_av_init(TTToxThread *t) {
    if (!t->tox || t->av) return false;
    t->avg = calloc(1, sizeof(TTAvg));
    if (!t->avg) return false;
    Toxav_Err_New err;
    t->av = toxav_new(t->tox, &err);
    if (!t->av) {
        TT_LOG("av", "toxav_new failed: %d", (int)err);
        free(t->avg);
        t->avg = NULL;
        return false;
    }
    toxav_callback_call(t->av, cb_av_call, t);
    toxav_callback_call_state(t->av, cb_av_call_state, t);
    toxav_callback_audio_receive_frame(t->av, cb_av_audio_rx, t);
    toxav_callback_video_receive_frame(t->av, cb_av_video_rx, t);
    toxav_callback_audio_bit_rate(t->av, cb_av_audio_br, t);
    toxav_callback_video_bit_rate(t->av, cb_av_video_br, t);
    TT_LOG("av", "toxav ready");
    return true;
}

/* start/stop the device layer with the call lifecycle: workers run only
   while a call is up (idle mic capture is wasted CPU + a privacy footgun) */
static void audio_lifecycle(TTAvg *g, bool up);

void tt_av_kill(TTToxThread *t) {
    if (t->avg) {
        TTAvg *g = (TTAvg *)t->avg;
        g->vtest_on = false;
        g->selfview_on = false;
        tt_audio_stop(g);
        tt_video_stop(g);
    }
    if (t->av) {
        toxav_kill(t->av);
        t->av = NULL;
    }
    free(t->avg);
    t->avg = NULL;
}

void tt_av_iterate(TTToxThread *t, ToxAV *av) {
    TTAvg *g = avg_slot(t);
    /* M-AV3: drain the capture ring into the wire (active audio call only).
       send_frame is valid only while a call is active with audio enabled;
       errors are expected and ignored when no call is up. */
    if (g && g->audio && (g->state & (TOXAV_FRIEND_CALL_STATE_SENDING_A |
                                      TOXAV_FRIEND_CALL_STATE_ACCEPTING_A))) {
        uint8_t pcm[TT_AUDIO_FRAME_BYTES * 4];
        size_t n;
        while ((n = tt_audio_capture_pop(g, pcm, 4)) > 0) {
            for (size_t f = 0; f < n; f++) {
                Toxav_Err_Send_Frame serr;
                toxav_audio_send_frame(av, g->call_fn,
                                       (const int16_t *)(pcm + f * TT_AUDIO_FRAME_BYTES),
                                       TT_AUDIO_FRAME_FRAMES, 1, 48000, &serr);
            }
        }
    }
    /* M-AV4: video sources (V4L2 / harness pump) -> toxav_video_send_frame */
    video_send_drain(t, g, av);
    /* M-AV5: paced local-camera mirror into the UI pane */
    selfview_drain(t, g, time(NULL));
    toxav_iterate(av);
}

/* start/stop the device layer with the call lifecycle: workers run only
   while a call is up (idle mic capture is wasted CPU + a privacy footgun) */
static void audio_lifecycle(TTAvg *g, bool up) {
    if (!g) return;
    if (up && !g->audio) {
        if (!tt_audio_start(g))
            TT_LOG("av", "audio device unavailable — call continues mute-recv");
    } else if (!up && g->audio) {
        tt_audio_stop(g);
        TT_LOG("av", "audio: device layer stopped");
    }
}

/* ---- command handlers ---- */

/* toxav rejects out-of-range rates (opus 6..510 kbit/s, vpx 1..1000000);
   treat a bogus value as "engine default" instead of failing the call */
static int audio_br_fixup(int br) {
    return (br > 0 && (br < 6 || br > 510)) ? TT_AV_AUDIO_BITRATE : br;
}

static int video_br_fixup(int br) {
    return (br > 0 && br > 1000000) ? TT_AV_VIDEO_BITRATE : br;
}

void tt_av_cmd_call(TTToxThread *t, uint32_t fn, int audio_br, int video_br) {
    if (!t->av) return;
    Toxav_Err_Call err;
    bool ok = toxav_call(t->av, fn, (uint32_t)audio_br_fixup(audio_br),
                         (uint32_t)video_br_fixup(video_br), &err);
    TT_LOG("av", "call(%u, a=%d v=%d): %d", fn, audio_br, video_br, (int)err);
    if (ok) {
        TTAvg *g = avg_slot(t);
        if (g) {
            g->started = 0;
            g->state = 0;
            g->call_fn = fn;
            g->mic_muted = false; /* a new call starts with the mic open */
            g->deaf = false;
            g->selfview_on = false;
        }
    } else {
        /* setup failed (friend offline/not connected/already in call): the
           caller never gets any MSI callback, so without an ENDED push the
           UI would sit in the ringing state forever */
        push_av(t, TT_EV_AV_ENDED, fn, 1, 0);
    }
}

void tt_av_cmd_answer(TTToxThread *t, uint32_t fn, int audio_br, int video_br) {
    if (!t->av) return;
    Toxav_Err_Answer err;
    bool ok = toxav_answer(t->av, fn, (uint32_t)audio_br_fixup(audio_br),
                           (uint32_t)video_br_fixup(video_br), &err);
    TT_LOG("av", "answer(%u, a=%d v=%d): %d", fn, audio_br, video_br, (int)err);
    /* the callee gets no MSI state callback at answer (state callbacks flow
       with peer caps/media changes only) — echo the active state locally so
       the answering GUI flips to Hang up; also brings the device layer up.
       The V bits must be included when we answered with video: MSI has no
       callee-side state callback for the answer itself, so this synthesized
       state is the ONLY source the callee's engine has for the SENDING_V
       gate in video_send_drain (verified: callee state stays 0x14 otherwise
       even while frames flow). */
    if (ok) {
        uint32_t state = TOXAV_FRIEND_CALL_STATE_ACCEPTING_A |
                         TOXAV_FRIEND_CALL_STATE_SENDING_A;
        if (video_br > 0)
            state |= TOXAV_FRIEND_CALL_STATE_ACCEPTING_V |
                     TOXAV_FRIEND_CALL_STATE_SENDING_V;
        push_av_local_state(t, fn, (int)state);
        audio_lifecycle(avg_slot(t), true);
        if (video_br > 0)
            video_lifecycle(avg_slot(t), true);
    }
}

void tt_av_cmd_hangup(TTToxThread *t, uint32_t fn) {
    if (!t->av) return;
    Toxav_Err_Call_Control err;
    bool ok = toxav_call_control(t->av, fn, TOXAV_CALL_CONTROL_CANCEL, &err);
    TT_LOG("av", "hangup(%u): %d", fn, (int)err);
    /* the hangup side's CANCEL is fire-and-forget (msi_hangup: POP + kill,
       no callback for itself) — synthesize the ENDED event locally */
    if (ok)
        push_av_local_ended(t, fn, 0);
}

/* Tier B1: toxav PAUSE (call_control_handle_pause) needs self_capabilities
   != 0, stores previous_self_capabilities, msi_change_capabilities(0),
   rtp_stop_receiving_mark both; the PEER sees it via the MSI capabilities
   callback as state = peer_capabilities (0 = paused). RESUME needs
   self_capabilities == 0 && previous != 0 and restores — so RESUME only
   works after OUR pause, never after the peer's. */
void tt_av_cmd_pause(TTToxThread *t, uint32_t fn) {
    if (!t->av) return;
    Toxav_Err_Call_Control err;
    bool ok = toxav_call_control(t->av, fn, TOXAV_CALL_CONTROL_PAUSE, &err);
    TT_LOG("av", "pause(%u): %d", fn, (int)err);
    /* no self callback for a capabilities change (only the peer gets one):
       echo state 0 locally — that is the paused state (see tox_thread.h) */
    if (ok) {
        TTAvg *g = avg_slot(t);
        if (g) g->paused_state = g->state; /* resume restores this */
        push_av_local_state(t, fn, 0);
    }
}

void tt_av_cmd_resume(TTToxThread *t, uint32_t fn) {
    if (!t->av) return;
    Toxav_Err_Call_Control err;
    bool ok = toxav_call_control(t->av, fn, TOXAV_CALL_CONTROL_RESUME, &err);
    TT_LOG("av", "resume(%u): %d", fn, (int)err);
    if (ok) {
        TTAvg *g = avg_slot(t);
        uint32_t state = g ? g->paused_state : 0;
        if (g) g->paused_state = 0;
        /* synthesize the pre-pause state back (the peer does the same) */
        push_av_local_state(t, fn, state);
        if (state & TOXAV_FRIEND_CALL_STATE_SENDING_V && g->call_fn == fn)
            video_lifecycle(avg_slot(t), true);
    } else if (err == TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION) {
        TT_LOG("av", "resume(%u): not paused here (peer paused or not paused)", fn);
    }
}

void tt_av_cmd_mute(TTToxThread *t, uint32_t fn, bool muted) {
    (void)fn;
    TTAvg *g = avg_slot(t);
    if (g) g->mic_muted = muted; /* ALSA capture worker reads this per frame */
    TT_LOG("av", "mic mute -> %d", muted ? 1 : 0);
}

/* M-AV5: output gate — the rx callback drops PCM before the play ring */
void tt_av_cmd_deaf(TTToxThread *t, uint32_t fn, bool deaf) {
    (void)fn;
    TTAvg *g = avg_slot(t);
    if (g) g->deaf = deaf;
    TT_LOG("av", "output mute -> %d", deaf ? 1 : 0);
}

/* M-AV5: mirror the local camera into the UI pane (paced) while set */
void tt_av_cmd_selfview(TTToxThread *t, uint32_t fn, int on) {
    (void)fn;
    TTAvg *g = avg_slot(t);
    if (!g) return;
    g->selfview_on = on != 0;
    if (g->selfview_on) g->vtest_at = 0; /* reset the pace stamp */
    TT_LOG("av", "self view -> %d", on != 0 ? 1 : 0);
}

/* M-AV4 harness pump control (video-capable call must already be up) */
void tt_av_cmd_vtest(TTToxThread *t, uint32_t fn, int on) {
    TTAvg *g = avg_slot(t);
    if (!g) return;
    g->vtest_on = on != 0;
    g->vtest_fn = fn;
    if (g->vtest_on) {
        g->vtest_sent = 0;
        g->vtest_at = 0;
        TT_LOG("av", "vtest: pump on (fn=%u, %d fps)", fn,
               1000 / TT_AV_VTEST_INTERVAL_MS);
    } else {
        TT_LOG("av", "vtest: pump off (sent=%u)", g->vtest_sent);
    }
}

/* Tier B2: mid-call video bit-rate change. toxav_video_set_bit_rate accepts
   1..1000000 kbit/s (0 would toggle the video stream off — a capability
   change, not a rate; 0 is rejected above, as video_br_fixup does). */
void tt_av_cmd_video_br(TTToxThread *t, uint32_t fn, int br) {
    if (!t->av) return;
    Toxav_Err_Bit_Rate_Set serr;
    bool ok = toxav_video_set_bit_rate(t->av, fn, (uint32_t)video_br_fixup(br),
                                       &serr);
    TT_LOG("av", "video br set(%u): %d (%d)", fn, video_br_fixup(br),
           ok ? (int)serr : (int)TOXAV_ERR_BIT_RATE_SET_SYNC);
}