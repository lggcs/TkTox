#include "audio_alsa.h"
#include "log.h"

#include <alsa/asoundlib.h>
#include <pthread.h>
#include <string.h>

/* M-AV3 device layer. Workers use blocking ALSA I/O with a modest buffer
   (4 x 20 ms) so a stalled peer never accumulates latency on our side;
   the rings drop instead of blocking the tox thread. */

#define TT_ALSA_PERIOD_FRAMES TT_AUDIO_FRAME_FRAMES /* 20 ms */
#define TT_ALSA_BUFFER_PERIODS 4

static void ring_reset(TTAudioRing *r) {
    r->head = 0;
    r->tail = 0;
}

/* single-producer/single-consumer cursor rings; on full, drop the OLDEST
   frames so the new push fits (readers keep a consistent, if older, stream) */
static void ring_push(TTAudioRing *r, const uint8_t *pcm, size_t frames) {
    if (frames > TT_AUDIO_RING_FRAMES) {
        pcm += (frames - TT_AUDIO_RING_FRAMES) * TT_AUDIO_FRAME_BYTES;
        frames = TT_AUDIO_RING_FRAMES;
    }
    unsigned used = r->head - r->tail; /* unsigned wrap arithmetic */
    if (used + frames > TT_AUDIO_RING_FRAMES)
        r->tail += (used + frames) - TT_AUDIO_RING_FRAMES;
    size_t off = (r->head % TT_AUDIO_RING_FRAMES) * TT_AUDIO_FRAME_BYTES;
    if (off + frames * TT_AUDIO_FRAME_BYTES <= sizeof r->buf) {
        memcpy(r->buf + off, pcm, frames * TT_AUDIO_FRAME_BYTES);
    } else {
        size_t first = sizeof r->buf - off;
        memcpy(r->buf + off, pcm, first);
        memcpy(r->buf, pcm + first, frames * TT_AUDIO_FRAME_BYTES - first);
    }
    r->head += (unsigned)frames;
}

static size_t ring_pop(TTAudioRing *r, uint8_t *out, size_t max_frames) {
    unsigned used = r->head - r->tail;
    if (used > TT_AUDIO_RING_FRAMES) used = TT_AUDIO_RING_FRAMES;
    size_t n = used < max_frames ? used : max_frames;
    size_t off = (r->tail % TT_AUDIO_RING_FRAMES) * TT_AUDIO_FRAME_BYTES;
    if (off + n * TT_AUDIO_FRAME_BYTES <= sizeof r->buf) {
        memcpy(out, r->buf + off, n * TT_AUDIO_FRAME_BYTES);
    } else {
        size_t first = sizeof r->buf - off;
        memcpy(out, r->buf + off, first);
        memcpy(out + first, r->buf, n * TT_AUDIO_FRAME_BYTES - first);
    }
    r->tail += (unsigned)n;
    return n;
}

/* ---- ALSA helpers ---- */

static snd_pcm_t *open_pcm(const char *dev, bool capture) {
    snd_pcm_t *h = NULL;
    int rc = snd_pcm_open(&h, dev, capture ? SND_PCM_STREAM_CAPTURE
                                           : SND_PCM_STREAM_PLAYBACK, 0);
    if (rc < 0) return NULL;
    rc = snd_pcm_set_params(h, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED,
                            1 /* mono */, 48000, 1 /* soft resample */,
                            TT_ALSA_BUFFER_PERIODS * 20000 /* 80 ms latency us */);
    if (rc < 0) {
        snd_pcm_close(h);
        return NULL;
    }
    return h;
}

static void *capture_worker(void *arg) {
    TTAvg *g = arg;
    snd_pcm_t *h = g->audio->cap;
    uint8_t pcm[TT_AUDIO_FRAME_BYTES];
    while (g->audio->run) {
        snd_pcm_sframes_t n = snd_pcm_readi(h, pcm, TT_AUDIO_FRAME_FRAMES);
        if (n == -EPIPE) { /* overrun */
            snd_pcm_prepare(h);
            continue;
        }
        if (n < 0) break;
        /* mic mute gate: muted bytes never reach the network path */
        if (g->mic_muted) continue;
        ring_push(&g->audio->cap_ring, pcm, (size_t)n);
    }
    return NULL;
}

static void *playback_worker(void *arg) {
    TTAvg *g = arg;
    snd_pcm_t *h = g->audio->play;
    uint8_t pcm[TT_AUDIO_FRAME_BYTES];
    while (g->audio->run) {
        size_t n = ring_pop(&g->audio->play_ring, pcm, 1);
        if (n == 0) {
            /* underrun-safe idle: 10 ms sleep keeps latency bounded */
            struct timespec ts = {0, 10 * 1000 * 1000};
            nanosleep(&ts, NULL);
            continue;
        }
        snd_pcm_sframes_t wrote = snd_pcm_writei(h, pcm, n * TT_AUDIO_FRAME_FRAMES);
        if (wrote == -EPIPE) { /* underrun */
            snd_pcm_prepare(h);
            continue;
        }
        if (wrote < 0) break;
    }
    return 0;
}

bool tt_audio_start(TTAvg *g) {
    if (!g || g->audio) return false;
    g->audio = calloc(1, sizeof(struct TTAudio));
    if (!g->audio) return false;
    ring_reset(&g->audio->cap_ring);
    ring_reset(&g->audio->play_ring);
    g->audio->cap = open_pcm("default", true);
    g->audio->play = open_pcm("default", false);
    if (!g->audio->cap || !g->audio->play) {
        TT_LOG("av", "audio: ALSA device open failed (cap=%d play=%d)",
               g->audio->cap != NULL, g->audio->play != NULL);
        tt_audio_stop(g);
        return false;
    }
    g->audio->run = true;
    if (pthread_create(&g->audio_cap_thread, NULL, capture_worker, g) == 0) {
        g->audio->cap_created = true;
    } else {
        TT_LOG("av", "audio: worker threads failed to start");
        tt_audio_stop(g);
        return false;
    }
    if (pthread_create(&g->audio_play_thread, NULL, playback_worker, g) != 0) {
        TT_LOG("av", "audio: worker threads failed to start");
        tt_audio_stop(g);
        return false;
    }
    g->audio->play_created = true;
    TT_LOG("av", "audio: ALSA started (48kHz mono, 20ms frames)");
    return true;
}

void tt_audio_stop(TTAvg *g) {
    if (!g || !g->audio) return;
    g->audio->run = false;
    /* unblock the readers/writers */
    if (g->audio->cap) snd_pcm_drop(g->audio->cap);
    if (g->audio->play) snd_pcm_drop(g->audio->play);
    if (g->audio->cap_created)
        pthread_join(g->audio_cap_thread, NULL);
    if (g->audio->play_created)
        pthread_join(g->audio_play_thread, NULL);
    if (g->audio->cap) snd_pcm_close(g->audio->cap);
    if (g->audio->play) snd_pcm_close(g->audio->play);
    free(g->audio);
    g->audio = NULL;
}

size_t tt_audio_capture_pop(TTAvg *g, uint8_t *out, size_t max_frames) {
    if (!g || !g->audio) return 0;
    return ring_pop(&g->audio->cap_ring, out, max_frames);
}

void tt_audio_playback_push(TTAvg *g, const uint8_t *pcm, size_t frames) {
    if (!g || !g->audio) return;
    ring_push(&g->audio->play_ring, pcm, frames);
}