#ifndef TT_VIDEO_V4L2_H
#define TT_VIDEO_V4L2_H

/* M-AV4 video device layer: V4L2 MMAP capture (kernel headers only, no new
   lib). One capture thread converts YUYV frames to planar YUV420 (the toxav
   wire format) into a lock-guarded latest-frame slot; the tox loop drains it
   into toxav_video_send_frame and the UI after-timer reads it for the
   self-view. Frames NEVER cross the TT event queue. Size fallback chain
   1280x720 -> 640x480 -> 320x240 (first size the driver accepts wins). */

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "av.h"

#define TT_V4L2_NBUFS 4

/* latest captured frame (shared; the lock holds only a memcpy) */
struct TTVideo {
    pthread_mutex_t lock;
    volatile bool run;
    volatile bool ready;
    bool thread_created;
    int fd;                      /* -1 until open succeeds */
    uint16_t w, h;               /* negotiated capture size */
    uint32_t stride;             /* YUYV row bytes (v4l2 bytesperline) */
    uint32_t frame_bytes;        /* w * h * 3 / 2 */
    uint8_t *yuv;                /* latest converted frame */
    uint8_t *back;               /* conversion scratch (thread-private) */
    void *bufs[TT_V4L2_NBUFS];   /* MMAP buffers */
    size_t lens[TT_V4L2_NBUFS];
    uint64_t seq;                /* produced frames (drain gating) */
};

bool tt_video_start(TTAvg *g);
void tt_video_stop(TTAvg *g);

/* UI/tox-loop fetch of the latest local frame (YUV420 planar). Returns
   false when the device layer is down or no frame has arrived yet. */
bool tt_video_fetch_local(TTAvg *g, uint8_t *out, size_t cap,
                          uint16_t *w, uint16_t *h, uint64_t *seq);

#endif