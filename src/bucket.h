#ifndef SG_BUCKET_H
#define SG_BUCKET_H

#include <stdint.h>

/*
 * tokens and capacity are milli-units, rate is units per second. Refill is
 * computed from elapsed time, so calling it often never double counts.
 */
struct sg_bucket {
    int64_t tokens;
    int64_t capacity;
    int64_t rate;
    int64_t rem;     /* sub-milli-unit remainder carried between refills */
    int64_t last_us;
};

void sg_bucket_init(struct sg_bucket *b, int64_t rate, int64_t capacity, int64_t now_us);
/* Returns the gross amount credited before clamping to capacity. */
int64_t sg_bucket_refill(struct sg_bucket *b, int64_t now_us);
void sg_bucket_set_rate(struct sg_bucket *b, int64_t rate, int64_t capacity);

static inline int sg_bucket_can(const struct sg_bucket *b, int64_t cost)
{
    return b->tokens >= cost;
}

static inline void sg_bucket_take(struct sg_bucket *b, int64_t cost)
{
    b->tokens -= cost;
}

#endif
