#ifndef SG_BORROW_H
#define SG_BORROW_H

#include <stddef.h>
#include <stdint.h>

#include "bucket.h"

/*
 * Budget borrowing and the loan ledger. A lender must owe nothing, have no
 * waiting calls, keep a reserve and have equal or lower priority (unless it
 * is idle). Tokens move between jobs and are never created; loans are repaid
 * from the borrower's later refills. All amounts are milli-units.
 */

struct sg_borrow_params {
    int enabled;
    int64_t reserve_pct;   /* share of capacity a lender keeps */
    int64_t cap_pct;       /* most a borrower may owe, % of its capacity */
    int64_t repay_pct;     /* share of each refill that repays */
    int64_t idle_us;
    int64_t chunk_pct;     /* minimum loan, % of borrower capacity; 0 = exact deficit */
};

struct sg_acct;

struct sg_loan {
    uint32_t id;
    struct sg_acct *lender, *borrower;
    int64_t amount, repaid;
    int64_t t_start_us;
    struct sg_loan *next;  /* the borrower's loans, oldest first */
};

struct sg_acct {
    uint32_t id;
    int prio;
    struct sg_bucket bucket;
    int64_t last_active_us;
    unsigned nwaiting;
    struct sg_loan *loans; /* outstanding as borrower, oldest first */
    int64_t owed;          /* outstanding as borrower */
    int64_t lent_out;      /* outstanding as lender */
    int64_t borrowed_total, lent_total;
    int64_t entitled_total;   /* all refill credited so far */
    unsigned loans_taken, loans_given;
};

enum sg_loan_event { SG_LOAN_OPEN, SG_LOAN_REPAID, SG_LOAN_WRITTEN_OFF };

struct sg_ledger {
    uint32_t next_id;
    unsigned long long opened, repaid, written_off;
    void (*log)(void *ctx, enum sg_loan_event ev, const struct sg_loan *loan);
    void *ctx;
};

/* Refill the bucket and repay the oldest loan from the refill. */
void sg_acct_refill(struct sg_acct *a, int64_t now_us, const struct sg_borrow_params *p,
                    struct sg_ledger *lg);

struct sg_acct *sg_pick_lender(struct sg_acct *const *all, size_t n, const struct sg_acct *b,
                               int64_t need, int64_t now_us, const struct sg_borrow_params *p);

/* Returns 1 if b holds at least cost tokens afterwards. */
int sg_borrow(struct sg_acct *const *all, size_t n, struct sg_acct *b, int64_t cost, int64_t now_us,
              const struct sg_borrow_params *p, struct sg_ledger *lg);

/* Write off gone's loans in both directions; call before it leaves all[]. */
void sg_acct_close(struct sg_acct *const *all, size_t n, struct sg_acct *gone, struct sg_ledger *lg);

#endif
