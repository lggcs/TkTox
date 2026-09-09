#ifndef TT_AUDIO_ALSA_H
#define TT_AUDIO_ALSA_H

/* M-AV3 audio device layer: tiny ALSA wrapper around 20 ms / 48 kHz / mono
   S16_LE capture + playback. Two background workers move bytes between the
   device and the lock-guarded rings owned by av.c:
     capture thread: mic -> tt_audio->cap ring   (drained by the tox loop)
     playback thread: drains the play ring -> device
   Rings drop-newest on overflow (audio tolerates loss; blocking the tox
   thread does not). The mic-mute flag is honored at the capture source so
   muted bytes never enter the network path. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "av.h"

/* ring capacity in frames (20 ms = 960 frames @48k); ~1 s of audio */
#define TT_AUDIO_RING_FRAMES 50

/* toxav default frame: 20 ms @ 48 kHz mono, S16_LE */
#define TT_AUDIO_FRAME_FRAMES 960
#define TT_AUDIO_FRAME_BYTES (TT_AUDIO_FRAME_FRAMES * 2)

typedef struct TTAudioRing {
    uint8_t buf[TT_AUDIO_RING_FRAMES * TT_AUDIO_FRAME_BYTES];
    volatile unsigned head; /* writer cursor (frames) */
    volatile unsigned tail; /* reader cursor (frames) */
} TTAudioRing;

/* both rings live in TTAvg so av.c owns the lifetime */
struct TTAudio {
    volatile bool run;
    bool cap_created;  /* per-thread join guard (start may fail part-way) */
    bool play_created;
    void *cap;    /* snd_pcm_t * */
    void *play;   /* snd_pcm_t * */
    TTAudioRing cap_ring;
    TTAudioRing play_ring;
};

bool tt_audio_start(TTAvg *g);
void tt_audio_stop(TTAvg *g);

/* tox-loop side (single consumer / single producer, no locks needed):
   drain captured PCM for sending (returns frames*2 bytes), feed playback */
size_t tt_audio_capture_pop(TTAvg *g, uint8_t *out, size_t max_frames);
void tt_audio_playback_push(TTAvg *g, const uint8_t *pcm, size_t frames);

#endif