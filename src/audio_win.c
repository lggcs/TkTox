#include "audio_alsa.h"
#include "log.h"

#include <windows.h>
#include <mmsystem.h>
#include <string.h>

/* M-AV3 device layer, Windows port. Same contract as audio_alsa.c: blocking
   waveIn/waveOut workers with 4 x 20 ms device buffering so a stalled peer
   never accumulates latency on our side; the rings drop instead of blocking
   the tox thread. 48 kHz mono S16 (little-endian is the native byte order
   on Windows, so the wire format maps 1:1). */

#define TT_WIN_AUDIO_PERIOD_FRAMES TT_AUDIO_FRAME_FRAMES /* 20 ms */
#define TT_WIN_AUDIO_BUFFERS 4

/* one queued device block per worker buffer */
typedef struct WAVEBUF {
    WAVEHDR hdr;
    uint8_t pcm[TT_AUDIO_FRAME_BYTES];
} WAVEBUF;

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

static WAVEFORMATEX audio_fmt(void) {
    WAVEFORMATEX f;
    memset(&f, 0, sizeof f);
    f.wFormatTag = WAVE_FORMAT_PCM;
    f.nChannels = 1;
    f.nSamplesPerSec = 48000;
    f.wBitsPerSample = 16;
    f.nBlockAlign = 2;
    f.nAvgBytesPerSec = 48000 * 2;
    return f;
}

/* ---- capture worker (mic -> cap ring) ---- */

static void *capture_worker(void *arg) {
    TTAvg *g = arg;
    struct TTAudio *a = g->audio;
    HWAVEIN h = (HWAVEIN)a->cap;
    WAVEBUF bufs[TT_WIN_AUDIO_BUFFERS];
    memset(bufs, 0, sizeof bufs);
    for (int i = 0; i < TT_WIN_AUDIO_BUFFERS; i++) {
        bufs[i].hdr.lpData = (LPSTR)bufs[i].pcm;
        bufs[i].hdr.dwBufferLength = TT_AUDIO_FRAME_BYTES;
        waveInPrepareHeader(h, &bufs[i].hdr, sizeof bufs[i].hdr);
        waveInAddBuffer(h, &bufs[i].hdr, sizeof bufs[i].hdr);
    }
    waveInStart(h);
    while (a->run) {
        WAVEHDR *w = NULL;
        for (int i = 0; i < TT_WIN_AUDIO_BUFFERS && !w; i++)
            if ((bufs[i].hdr.dwFlags & WHDR_DONE)) w = &bufs[i].hdr;
        if (!w) {
            Sleep(5); /* device runs at 20 ms granularity; 5 ms poll is fine */
            continue;
        }
        /* mic mute gate: muted bytes never reach the network path */
        if (!g->mic_muted)
            ring_push(&a->cap_ring, (const uint8_t *)w->lpData, 1);
        waveInUnprepareHeader(h, w, sizeof *w);
        w->dwBufferLength = TT_AUDIO_FRAME_BYTES;
        w->dwFlags = 0;
        waveInPrepareHeader(h, w, sizeof *w);
        waveInAddBuffer(h, w, sizeof *w);
    }
    waveInReset(h);
    for (int i = 0; i < TT_WIN_AUDIO_BUFFERS; i++)
        waveInUnprepareHeader(h, &bufs[i].hdr, sizeof bufs[i].hdr);
    return NULL;
}

/* ---- playback worker (play ring -> speaker) ---- */

static void *playback_worker(void *arg) {
    TTAvg *g = arg;
    struct TTAudio *a = g->audio;
    HWAVEOUT h = (HWAVEOUT)a->play;
    WAVEBUF bufs[TT_WIN_AUDIO_BUFFERS];
    memset(bufs, 0, sizeof bufs);
    for (int i = 0; i < TT_WIN_AUDIO_BUFFERS; i++) {
        bufs[i].hdr.lpData = (LPSTR)bufs[i].pcm;
        bufs[i].hdr.dwBufferLength = TT_AUDIO_FRAME_BYTES;
        waveOutPrepareHeader(h, &bufs[i].hdr, sizeof bufs[i].hdr);
    }
    unsigned next = 0;
    while (a->run) {
        WAVEHDR *w = &bufs[next % TT_WIN_AUDIO_BUFFERS].hdr;
        if (!(w->dwFlags & WHDR_DONE)) {
            /* underrun-safe idle: 5 ms sleep keeps latency bounded */
            Sleep(5);
            continue;
        }
        size_t n = ring_pop(&a->play_ring, (uint8_t *)w->lpData, 1);
        if (n == 0) {
            Sleep(5);
            continue;
        }
        w->dwBufferLength = TT_AUDIO_FRAME_BYTES;
        w->dwFlags &= ~(WHDR_DONE | WHDR_PREPARED);
        waveOutPrepareHeader(h, w, sizeof *w);
        waveOutWrite(h, w, sizeof *w);
        next++;
    }
    waveOutReset(h);
    for (int i = 0; i < TT_WIN_AUDIO_BUFFERS; i++)
        waveOutUnprepareHeader(h, &bufs[i].hdr, sizeof bufs[i].hdr);
    return 0;
}

bool tt_audio_start(TTAvg *g) {
    if (!g || g->audio) return false;
    g->audio = calloc(1, sizeof(struct TTAudio));
    if (!g->audio) return false;
    ring_reset(&g->audio->cap_ring);
    ring_reset(&g->audio->play_ring);
    WAVEFORMATEX f = audio_fmt();
    UINT dev_in = WAVE_MAPPER, dev_out = WAVE_MAPPER;
    MMRESULT rci = waveInOpen((LPHWAVEIN)&g->audio->cap, dev_in, &f,
                              0, 0, CALLBACK_NULL);
    MMRESULT rco = waveOutOpen((LPHWAVEOUT)&g->audio->play, dev_out, &f,
                               0, 0, CALLBACK_NULL);
    if (rci != MMSYSERR_NOERROR || rco != MMSYSERR_NOERROR) {
        TT_LOG("av", "audio: wave device open failed (in=%u out=%u)",
               (unsigned)rci, (unsigned)rco);
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
    TT_LOG("av", "audio: waveIn/waveOut started (48kHz mono, 20ms frames)");
    return true;
}

void tt_audio_stop(TTAvg *g) {
    if (!g || !g->audio) return;
    g->audio->run = false;
    if (g->audio->cap_created)
        pthread_join(g->audio_cap_thread, NULL);
    if (g->audio->play_created)
        pthread_join(g->audio_play_thread, NULL);
    if (g->audio->cap) waveInClose((HWAVEIN)g->audio->cap);
    if (g->audio->play) waveOutClose((HWAVEOUT)g->audio->play);
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