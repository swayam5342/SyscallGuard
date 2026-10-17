#ifndef SG_COMMON_H
#define SG_COMMON_H

#include <stdint.h>
#include <time.h>

/* Tokens are kept in milli-units so slow refill rates do not round to zero. */
#define SG_MILLI 1000

static inline int64_t sg_now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

#endif
