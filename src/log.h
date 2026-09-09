#ifndef TT_LOG_H
#define TT_LOG_H
#include <stdio.h>
#include <time.h>

/* Central logging: format is always a literal at the call site; variadic args
   are checked with -Wformat=2. Never route peer-controlled bytes through a
   non-literal format. */
#define TT_LOG(component, fmt, ...)                                     \
    do {                                                                \
        struct timespec tt_log_ts;                                      \
        clock_gettime(CLOCK_REALTIME, &tt_log_ts);                      \
        struct tm tt_log_tm;                                            \
        localtime_r(&tt_log_ts.tv_sec, &tt_log_tm);                     \
        fprintf(stderr, "[%02d:%02d:%02d][%-9s] " fmt "\n",             \
                tt_log_tm.tm_hour, tt_log_tm.tm_min, tt_log_tm.tm_sec,  \
                component, ##__VA_ARGS__);                              \
    } while (0)

#endif