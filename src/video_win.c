#include "video_v4l2.h"
#include "log.h"

#include <string.h>

/* M-AV4 video device layer, Windows port: capture is disabled (the Linux
   layer reads V4L2 mmap devices, which have no direct Windows counterpart).
   tt_video_start fails exactly like the Linux build on a machine without
   /dev/video0, so every consumer keeps its existing no-camera degrade
   path. The struct keeps its full shape (lock, seq, buffers) so av.c and
   ui_tk.c compile unchanged against either device file. */

bool tt_video_start(TTAvg *g) {
    if (!g || g->video) return false;
    struct TTVideo *v = calloc(1, sizeof *v);
    if (!v) return false;
    pthread_mutex_init(&v->lock, NULL);
    v->fd = -1;
    g->video = v;
    TT_LOG("av", "video: capture unavailable on this platform — disabled");
    /* fail like the Linux layer does when /dev/video0 is missing: clear
       the slot so a later call re-attempts the (future) device layer */
    tt_video_stop(g);
    return false;
}

void tt_video_stop(TTAvg *g) {
    if (!g || !g->video) return;
    struct TTVideo *v = g->video;
    free(v->yuv);
    free(v->back);
    pthread_mutex_destroy(&v->lock);
    free(v);
    g->video = NULL;
}

bool tt_video_fetch_local(TTAvg *g, uint8_t *out, size_t cap,
                          uint16_t *w, uint16_t *h, uint64_t *seq) {
    (void)out; (void)cap; (void)w; (void)h; (void)seq;
    if (!g || !g->video) return false;
    return false; /* no frames ever: capture disabled */
}