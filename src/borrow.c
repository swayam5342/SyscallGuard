#include "borrow.h"

#include <stdlib.h>

static void loan_close(struct sg_ledger *lg, enum sg_loan_event ev, struct sg_loan *l)
{
    int64_t left = l->amount - l->repaid;

    l->borrower->owed -= left;
    l->lender->lent_out -= left;
    if (ev == SG_LOAN_REPAID)
        lg->repaid++;
    else
        lg->written_off++;
    if (lg->log)
        lg->log(lg->ctx, ev, l);
    free(l);
}

void sg_acct_refill(struct sg_acct *a, int64_t now_us, const struct sg_borrow_params *p,
                    struct sg_ledger *lg)
{
    int64_t gross = sg_bucket_refill(&a->bucket, now_us);
    /* Use the gross refill so a borrower sitting at full capacity still repays. */
    int64_t budget = gross * p->repay_pct / 100;

    a->entitled_total += gross;

    while (a->loans && budget > 0) {
        struct sg_loan *l = a->loans;
        struct sg_acct *lender = l->lender;
        int64_t amt = l->amount - l->repaid;

        if (amt > budget)
            amt = budget;
        if (amt > a->bucket.tokens)
            amt = a->bucket.tokens;
        if (amt <= 0)
            break;
        a->bucket.tokens -= amt;
        budget -= amt;
        /* Credit beyond the lender's capacity is dropped: tokens are never created. */
        lender->bucket.tokens += amt;
        if (lender->bucket.tokens > lender->bucket.capacity)
            lender->bucket.tokens = lender->bucket.capacity;
        l->repaid += amt;
        a->owed -= amt;
        lender->lent_out -= amt;
        if (l->repaid == l->amount) {
            a->loans = l->next;
            loan_close(lg, SG_LOAN_REPAID, l);
        }
    }
}

struct sg_acct *sg_pick_lender(struct sg_acct *const *all, size_t n, const struct sg_acct *b,
                               int64_t need, int64_t now_us, const struct sg_borrow_params *p)
{
    struct sg_acct *best = NULL;
    int64_t best_surplus = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        struct sg_acct *a = all[i];
        int64_t surplus;
        int idle;

        if (a == b || a->owed > 0 || a->nwaiting > 0)
            continue;
        a->entitled_total += sg_bucket_refill(&a->bucket, now_us);
        idle = now_us - a->last_active_us >= p->idle_us;
        /* Lending only upwards avoids priority inversion through the budget. */
        if (a->prio > b->prio && !idle)
            continue;
        surplus = a->bucket.tokens - a->bucket.capacity * p->reserve_pct / 100;
        if (surplus < need)
            continue;
        if (!best || surplus > best_surplus || (surplus == best_surplus && a->prio < best->prio)) {
            best = a;
            best_surplus = surplus;
        }
    }
    return best;
}

int sg_borrow(struct sg_acct *const *all, size_t n, struct sg_acct *b, int64_t cost, int64_t now_us,
              const struct sg_borrow_params *p, struct sg_ledger *lg)
{
    int64_t need = cost - b->bucket.tokens, room, amount;
    struct sg_acct *lender;
    struct sg_loan *l, **tail;

    if (need <= 0)
        return 1;
    room = b->bucket.capacity * p->cap_pct / 100 - b->owed;
    if (!p->enabled || need > room)
        return 0;

    amount = need;
    if (p->chunk_pct > 0) {
        int64_t chunk = b->bucket.capacity * p->chunk_pct / 100;
        int64_t spare = b->bucket.capacity - cost;

        /* Round up to a chunk, but leave no more after the call than fits under capacity. */
        if (chunk > amount)
            amount = chunk;
        if (amount > room)
            amount = room;
        if (amount > need + (spare > 0 ? spare : 0))
            amount = need + (spare > 0 ? spare : 0);
    }
    lender = sg_pick_lender(all, n, b, amount, now_us, p);
    if (!lender && amount > need) {
        amount = need;
        lender = sg_pick_lender(all, n, b, amount, now_us, p);
    }
    if (!lender)
        return 0;
    l = calloc(1, sizeof *l);
    if (!l)
        return 0;

    l->id = ++lg->next_id;
    l->lender = lender;
    l->borrower = b;
    l->amount = amount;
    l->t_start_us = now_us;
    for (tail = &b->loans; *tail; tail = &(*tail)->next)
        ;
    *tail = l;

    lender->bucket.tokens -= amount;
    b->bucket.tokens += amount;
    b->owed += amount;
    lender->lent_out += amount;
    b->borrowed_total += amount;
    lender->lent_total += amount;
    b->loans_taken++;
    lender->loans_given++;
    lg->opened++;
    if (lg->log)
        lg->log(lg->ctx, SG_LOAN_OPEN, l);
    return 1;
}

void sg_acct_close(struct sg_acct *const *all, size_t n, struct sg_acct *gone, struct sg_ledger *lg)
{
    size_t i;

    while (gone->loans) {
        struct sg_loan *l = gone->loans;

        gone->loans = l->next;
        loan_close(lg, SG_LOAN_WRITTEN_OFF, l);
    }
    for (i = 0; i < n; i++) {
        struct sg_loan **pp;

        if (all[i] == gone)
            continue;
        pp = &all[i]->loans;
        while (*pp) {
            if ((*pp)->lender == gone) {
                struct sg_loan *l = *pp;

                *pp = l->next;
                loan_close(lg, SG_LOAN_WRITTEN_OFF, l);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}
