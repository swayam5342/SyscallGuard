#include "waitq.h"

#include <stdlib.h>

static int before(const struct sg_waiter *a, const struct sg_waiter *b)
{
    return a->key > b->key || (a->key == b->key && a->seq < b->seq);
}

static void swap(struct sg_waiter *a, struct sg_waiter *b)
{
    struct sg_waiter t = *a;

    *a = *b;
    *b = t;
}

int sg_waitq_push(struct sg_waitq *q, const struct sg_waiter *w)
{
    size_t i;

    if (q->n == q->cap) {
        size_t cap = q->cap ? q->cap * 2 : 64;
        struct sg_waiter *v = realloc(q->v, cap * sizeof *v);

        if (!v)
            return -1;
        q->v = v;
        q->cap = cap;
    }
    i = q->n++;
    q->v[i] = *w;
    while (i > 0 && before(&q->v[i], &q->v[(i - 1) / 2])) {
        swap(&q->v[i], &q->v[(i - 1) / 2]);
        i = (i - 1) / 2;
    }
    return 0;
}

int sg_waitq_pop(struct sg_waitq *q, struct sg_waiter *out)
{
    size_t i = 0;

    if (q->n == 0)
        return 0;
    *out = q->v[0];
    q->v[0] = q->v[--q->n];
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, best = i;

        if (l < q->n && before(&q->v[l], &q->v[best]))
            best = l;
        if (r < q->n && before(&q->v[r], &q->v[best]))
            best = r;
        if (best == i)
            break;
        swap(&q->v[i], &q->v[best]);
        i = best;
    }
    return 1;
}

void sg_waitq_free(struct sg_waitq *q)
{
    free(q->v);
    q->v = NULL;
    q->n = q->cap = 0;
}
