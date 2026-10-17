#ifndef SG_WAITQ_H
#define SG_WAITQ_H

#include <stddef.h>
#include <stdint.h>

/*
 * Max-heap of held notifications. Effective priority prio + wait/q grows at
 * the same rate for every waiter, so the fixed key prio*q - arrival gives the
 * same order at any time and the heap never needs re-keying.
 */
struct sg_waiter {
    int64_t key;
    uint64_t seq;
    uint64_t id;          /* seccomp notification id */
    int64_t arrive_us;
    int64_t deadline_us;
    int64_t cost;         /* milli-units */
    void *owner;          /* job */
    void *aux;            /* per-process stats */
    int pid;
    int nr;
    int cls;
};

struct sg_waitq {
    struct sg_waiter *v;
    size_t n, cap;
};

int sg_waitq_push(struct sg_waitq *q, const struct sg_waiter *w);
int sg_waitq_pop(struct sg_waitq *q, struct sg_waiter *out);
void sg_waitq_free(struct sg_waitq *q);

#endif
