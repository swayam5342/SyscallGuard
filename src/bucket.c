#include "bucket.h"

/* Longest gap credited at once, so a long idle period cannot overflow. */
#define MAX_REFILL_US (60LL * 1000000)

void sg_bucket_init(struct sg_bucket *b, int64_t rate, int64_t capacity, int64_t now_us)
{
    b->tokens = 0;
    b->capacity = capacity;
    b->rate = rate;
    b->rem = 0;
    b->last_us = now_us;
}

int64_t sg_bucket_refill(struct sg_bucket *b, int64_t now_us)
{
    int64_t dt = now_us - b->last_us, acc, gross;

    if (dt <= 0)
        return 0;
    b->last_us = now_us;
    if (dt > MAX_REFILL_US)
        dt = MAX_REFILL_US;

    /* units/s * us / 1000 = milli-units */
    acc = b->rate * dt + b->rem;
    gross = acc / 1000;
    b->tokens += gross;
    b->rem = acc % 1000;
    if (b->tokens >= b->capacity) {
        b->tokens = b->capacity;
        b->rem = 0;
    }
    return gross;
}

void sg_bucket_set_rate(struct sg_bucket *b, int64_t rate, int64_t capacity)
{
    b->rate = rate;
    b->capacity = capacity;
    if (b->tokens > capacity)
        b->tokens = capacity;
}
