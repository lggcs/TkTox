#include "video_v4l2.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

/* M-AV4 capture worker: DQBUF -> YUYV -> YUV420 -> swap into the shared
   slot. Never blocks the drain side; a call sends ~30 fps while the tox
   loop iterates at its own pace. */

#define TT_V4L2_DEV "/dev/video0"

static int xioctl(int fd, unsigned long req, void *arg) {
    int rc;
    do rc = ioctl(fd, req, arg);
    while (rc < 0 && errno == EINTR);
    return rc;
}

/* negotiate size+format; first size the driver accepts wins (falling
   through the chain: 1280x720 -> 640x480 -> 320x240) */
static bool set_format(struct TTVideo *v, int fd) {
    static const uint32_t widths[] = {1280, 640, 320};
    static const uint32_t heights[] = {720, 480, 240};
    for (size_t i = 0; i < 3; i++) {
        struct v4l2_format fmt = {0};
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.width = widths[i];
        fmt.fmt.pix.height = heights[i];
        fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
        fmt.fmt.pix.field = V4L2_FIELD_NONE;
        if (xioctl(fd, VIDIOC_S_FMT, &fmt) < 0) continue;
        if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) continue;
        v->w = (uint16_t)fmt.fmt.pix.width;
        v->h = (uint16_t)fmt.fmt.pix.height;
        v->stride = fmt.fmt.pix.bytesperline >= fmt.fmt.pix.width * 2
                        ? fmt.fmt.pix.bytesperline
                        : fmt.fmt.pix.width * 2;
        return true;
    }
    return false;
}

/* one YUYV row -> one Y row (+ one U/V half-row pair when du/dv are
   non-NULL; chroma is packed 4:2:2: every second byte pair is Cb/Cr for
   two pixels) */
static void convert_row_yuyv(const uint8_t *src, uint32_t w, uint8_t *dy,
                             uint8_t *du, uint8_t *dv, uint32_t uw) {
    for (uint32_t x = 0; x < w; x += 2) {
        dy[x] = src[2 * x];
        dy[x + 1] = src[2 * x + 2];
        if (du && x / 2 < uw) {
            du[x / 2] = src[2 * x + 1];
            dv[x / 2] = src[2 * x + 3];
        }
    }
}

static void yuyv_to_yuv420(const struct TTVideo *v, const uint8_t *src,
                           uint8_t *dst) {
    uint8_t *dy = dst;
    uint8_t *du = dst + (size_t)v->w * v->h;
    uint8_t *dv = du + (size_t)(v->w / 2) * (v->h / 2);
    uint32_t uw = v->w / 2;
    for (uint32_t y = 0; y < v->h; y++) {
        const uint8_t *row = (const uint8_t *)src + (size_t)y * v->stride;
        /* chroma planes carry half the rows: source them from even rows;
           odd rows must NOT write chroma at all (passing the base pointer
           would clobber chroma row 0) */
        convert_row_yuyv(row, v->w, dy + (size_t)y * v->w,
                         y % 2 == 0 ? du + (y / 2) * uw : NULL,
                         y % 2 == 0 ? dv + (y / 2) * uw : NULL, uw);
    }
}

static void frame_publish(struct TTVideo *v, const uint8_t *yuv) {
    pthread_mutex_lock(&v->lock);
    memcpy(v->yuv, yuv, v->frame_bytes);
    v->seq++;
    v->ready = true;
    pthread_mutex_unlock(&v->lock);
}

static void *video_worker(void *arg) {
    struct TTVideo *v = arg;
    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(v->fd, VIDIOC_STREAMON, &type) < 0) return NULL;
    while (v->run) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(v->fd, &fds);
        struct timeval tv = {1, 0}; /* 1 s poll so stop stays responsive */
        if (select(v->fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        struct v4l2_buffer buf = {0};
        buf.type = type;
        buf.memory = V4L2_MEMORY_MMAP;
        if (xioctl(v->fd, VIDIOC_DQBUF, &buf) < 0) {
            if (errno == EAGAIN) continue;
            break;
        }
        if (buf.index < TT_V4L2_NBUFS && v->lens[buf.index] >= v->stride * v->h) {
            yuyv_to_yuv420(v, v->bufs[buf.index], v->back);
            frame_publish(v, v->back);
        }
        xioctl(v->fd, VIDIOC_QBUF, &buf);
    }
    xioctl(v->fd, VIDIOC_STREAMOFF, &type);
    return NULL;
}

static void video_free(struct TTVideo *v, pthread_t thread) {
    if (v->thread_created) pthread_join(thread, NULL);
    if (v->fd >= 0) {
        for (int i = 0; i < TT_V4L2_NBUFS; i++)
            if (v->bufs[i] && v->bufs[i] != MAP_FAILED)
                munmap(v->bufs[i], v->lens[i]);
        close(v->fd);
    }
    free(v->yuv);
    free(v->back);
    pthread_mutex_destroy(&v->lock);
    free(v);
}

bool tt_video_start(TTAvg *g) {
    if (!g || g->video) return false;
    g->video = calloc(1, sizeof(struct TTVideo));
    struct TTVideo *v = g->video;
    if (!v) return false;
    pthread_mutex_init(&v->lock, NULL);
    v->fd = -1;

    v->fd = open(TT_V4L2_DEV, O_RDWR | O_NONBLOCK, 0);
    if (v->fd < 0) {
        TT_LOG("av", "video: %s unavailable — capture disabled", TT_V4L2_DEV);
        tt_video_stop(g);
        return false;
    }
    struct v4l2_capability cap;
    if (xioctl(v->fd, VIDIOC_QUERYCAP, &cap) < 0 ||
        !(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) ||
        !(cap.capabilities & V4L2_CAP_STREAMING)) {
        TT_LOG("av", "video: device lacks MMAP capture");
        tt_video_stop(g);
        return false;
    }
    if (!set_format(v, v->fd)) {
        TT_LOG("av", "video: no supported YUYV size (1280x720/640x480/320x240 tried)");
        tt_video_stop(g);
        return false;
    }
    v->frame_bytes = (size_t)v->w * v->h * 3 / 2;
    v->yuv = malloc(v->frame_bytes);
    v->back = malloc(v->frame_bytes);
    if (!v->yuv || !v->back) {
        tt_video_stop(g);
        return false;
    }
    struct v4l2_requestbuffers req = {0};
    req.count = TT_V4L2_NBUFS;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(v->fd, VIDIOC_REQBUFS, &req) < 0 || req.count < 2) {
        TT_LOG("av", "video: REQBUFS failed");
        tt_video_stop(g);
        return false;
    }
    for (unsigned i = 0; i < req.count; i++) {
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;
        if (xioctl(v->fd, VIDIOC_QUERYBUF, &buf) < 0) {
            tt_video_stop(g);
            return false;
        }
        v->bufs[i] = mmap(NULL, buf.length, PROT_READ | PROT_WRITE,
                          MAP_SHARED, v->fd, buf.m.offset);
        v->lens[i] = buf.length;
        if (v->bufs[i] == MAP_FAILED) {
            tt_video_stop(g);
            return false;
        }
        xioctl(v->fd, VIDIOC_QBUF, &buf);
    }
    v->run = true;
    if (pthread_create(&g->video_thread, NULL, video_worker, v) == 0) {
        v->thread_created = true;
        TT_LOG("av", "video: V4L2 started (%ux%u YUYV -> YUV420)", v->w, v->h);
        return true;
    }
    TT_LOG("av", "video: capture thread failed to start");
    tt_video_stop(g);
    return false;
}

void tt_video_stop(TTAvg *g) {
    if (!g || !g->video) return;
    struct TTVideo *v = g->video;
    v->run = false;
    video_free(v, g->video_thread);
    g->video = NULL;
}

bool tt_video_fetch_local(TTAvg *g, uint8_t *out, size_t cap,
                          uint16_t *w, uint16_t *h, uint64_t *seq) {
    if (!g || !g->video) return false;
    struct TTVideo *v = g->video;
    if (cap < v->frame_bytes) return false;
    pthread_mutex_lock(&v->lock);
    bool ok = v->ready;
    if (ok) {
        memcpy(out, v->yuv, v->frame_bytes);
        *w = v->w;
        *h = v->h;
        *seq = v->seq;
    }
    pthread_mutex_unlock(&v->lock);
    return ok;
}