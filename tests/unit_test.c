/* Unit tests for the token bucket, waiting queue and cost table. */
#define _GNU_SOURCE
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "borrow.h"
#include "bucket.h"
#include "common.h"
#include "costs.h"
#include "waitq.h"

static int checks, failures;

#define CHECK(cond)                                                              \
    do {                                                                         \
        checks++;                                                                \
        if (!(cond)) {                                                           \
            printf("FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
            failures++;                                                          \
        }                                                                        \
    } while (0)

static void test_bucket(void)
{
    struct sg_bucket b;
    int i;

    /* 1000 units/s, capacity 2000 units */
    sg_bucket_init(&b, 1000, 2000 * SG_MILLI, 0);
    CHECK(b.tokens == 0);
    CHECK(sg_bucket_refill(&b, 10000) == 10 * SG_MILLI);   /* 10 ms -> 10 units */
    CHECK(b.tokens == 10 * SG_MILLI);
    sg_bucket_refill(&b, 10000);                 /* no time passed */
    CHECK(b.tokens == 10 * SG_MILLI);
    sg_bucket_refill(&b, 9000000);               /* far more than capacity */
    CHECK(b.tokens == 2000 * SG_MILLI);
    CHECK(sg_bucket_can(&b, 2000 * SG_MILLI));
    CHECK(!sg_bucket_can(&b, 2000 * SG_MILLI + 1));
    sg_bucket_take(&b, 2000 * SG_MILLI);
    CHECK(b.tokens == 0);

    /* Lowering capacity clamps the tokens. */
    sg_bucket_refill(&b, 9500000);               /* +500 units */
    sg_bucket_set_rate(&b, 1000, 100 * SG_MILLI);
    CHECK(b.tokens == 100 * SG_MILLI);

    /* Slow rate in small steps: the remainder must carry, not round away. */
    sg_bucket_init(&b, 7, 1000000 * SG_MILLI, 0);
    for (i = 1; i <= 3000; i++)
        sg_bucket_refill(&b, (int64_t)i * 333);
    CHECK(b.tokens == 7LL * 3000 * 333 / 1000);  /* 6993 milli-units */
}

static void test_waitq(void)
{
    struct sg_waitq q = { 0 };
    struct sg_waiter w = { 0 }, out;
    int64_t keys[] = { 5, 9, 1, 9, 3 };
    int64_t want_key[] = { 9, 9, 5, 3, 1 };
    uint64_t want_seq[] = { 1, 3, 0, 4, 2 };
    size_t i;

    for (i = 0; i < 5; i++) {
        w.key = keys[i];
        w.seq = i;
        CHECK(sg_waitq_push(&q, &w) == 0);
    }
    for (i = 0; i < 5; i++) {
        CHECK(sg_waitq_pop(&q, &out) == 1);
        CHECK(out.key == want_key[i]);
        CHECK(out.seq == want_seq[i]);           /* equal keys pop in arrival order */
    }
    CHECK(sg_waitq_pop(&q, &out) == 0);

    /* Many entries stay ordered after growth. */
    for (i = 0; i < 1000; i++) {
        w.key = (int64_t)((i * 7919) % 1000);
        w.seq = i;
        sg_waitq_push(&q, &w);
    }
    {
        int64_t last = 1000;
        int ordered = 1;

        while (sg_waitq_pop(&q, &out)) {
            if (out.key > last)
                ordered = 0;
            last = out.key;
        }
        CHECK(ordered);
    }
    sg_waitq_free(&q);
}

static void test_aging_key(void)
{
    /* key = prio*q - arrive: a low-priority call that waited long enough overtakes. */
    const int64_t q = 500000;   /* 500 ms in us */
    int64_t old_low = 2 * q - 0;            /* prio 2, arrived at t=0 */
    int64_t new_high = 8 * q - 3500000;     /* prio 8, arrived at t=3.5 s */
    int64_t fresh_high = 8 * q - 2000000;   /* prio 8, arrived at t=2 s */

    CHECK(old_low > new_high);
    CHECK(fresh_high > old_low);
}

static void test_costs(void)
{
    __u64 args[6] = { 0 };
    const struct sg_syscall *s;
    struct sock_fprog prog;
    enum sg_class cls;

    CHECK(sg_lookup(__NR_getpid) == NULL);       /* fast path */
    CHECK(sg_lookup(-1) == NULL);
    CHECK(sg_lookup(100000) == NULL);

    s = sg_lookup(__NR_read);
    CHECK(s != NULL);
    args[2] = 100;
    CHECK(sg_cost(s, args, &cls) == 1 && cls == SG_C_DATA);
    args[2] = 128 * 1024;                        /* +1 per 64 KiB */
    CHECK(sg_cost(s, args, &cls) == 3);

    s = sg_lookup(__NR_mmap);
    args[1] = 3u << 20;                          /* +1 per MiB */
    CHECK(s && sg_cost(s, args, &cls) == 5 && cls == SG_C_MMAP);

    s = sg_lookup(__NR_clone);
    args[0] = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND;
    CHECK(s && sg_cost(s, args, &cls) == 10 && cls == SG_C_THREAD);
    CHECK(sg_classes[cls].policy == SG_WAIT);
    args[0] = SIGCHLD;
    CHECK(sg_cost(s, args, &cls) == 30 && cls == SG_C_PROC);
    CHECK(sg_classes[cls].policy == SG_REJECT);

    s = sg_lookup(__NR_execve);
    CHECK(s && sg_cost(s, args, &cls) == 40);

    CHECK(sg_build_filter(&prog) == 0);
    CHECK(prog.len > 10);
    CHECK(prog.filter[prog.len - 1].k == SECCOMP_RET_USER_NOTIF);
    CHECK(prog.filter[prog.len - 2].k == SECCOMP_RET_ALLOW);
    free(prog.filter);
}

static void acct_init(struct sg_acct *a, uint32_t id, int prio, int64_t cap, int64_t tokens, int64_t rate,
                      int64_t now);

static void test_borrow_chunks(void)
{
    const int64_t M = SG_MILLI, now = 0;
    struct sg_borrow_params p = { .enabled = 1, .reserve_pct = 30, .cap_pct = 50, .repay_pct = 50,
                                  .idle_us = 1000000, .chunk_pct = 10 };
    struct sg_ledger lg = { 0 };
    struct sg_acct b, rich, poor, *all[2] = { &b, &rich };
    int64_t total;

    acct_init(&b, 1, 8, 1000, 0, 0, now);
    acct_init(&rich, 2, 2, 10000, 10000, 0, now);
    total = b.bucket.tokens + rich.bucket.tokens;

    /* Deficit 30 is rounded up to a chunk of 10% x 1000 = 100. */
    CHECK(sg_borrow(all, 2, &b, 30 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 100 * M && b.bucket.tokens == 100 * M);
    CHECK(b.bucket.tokens + rich.bucket.tokens == total);
    sg_bucket_take(&b.bucket, 30 * M);             /* 70 left: no new loan for the next calls */
    CHECK(sg_borrow(all, 2, &b, 50 * M, now, &p, &lg) == 1 && lg.opened == 1);
    sg_bucket_take(&b.bucket, 50 * M);

    /* A deficit larger than a chunk is borrowed exactly. */
    CHECK(sg_borrow(all, 2, &b, 300 * M, now, &p, &lg) == 1);
    CHECK(b.owed == (100 + 280) * M);
    sg_bucket_take(&b.bucket, 300 * M);

    /* The chunk never exceeds the borrower cap (500): room left is 120. */
    CHECK(sg_borrow(all, 2, &b, 10 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 480 * M);                       /* chunk 100 still fits */
    sg_bucket_take(&b.bucket, 10 * M);

    /* What is left after the call must fit under capacity: cost 960 with 900 held. */
    acct_init(&b, 1, 8, 1000, 900, 0, now);
    CHECK(sg_borrow(all, 2, &b, 960 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 100 * M);                       /* chunk 100 = deficit 60 + spare 40 */
    acct_init(&b, 1, 8, 1000, 980, 0, now);
    CHECK(sg_borrow(all, 2, &b, 990 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 20 * M);                        /* deficit 10 + spare 10 */

    /* A lender that cannot spare a chunk still covers the exact deficit. */
    acct_init(&b, 1, 8, 1000, 0, 0, now);
    acct_init(&poor, 3, 2, 1000, 350, 0, now);      /* surplus 350 - 300 = 50 */
    all[1] = &poor;
    CHECK(sg_borrow(all, 2, &b, 40 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 40 * M && poor.bucket.tokens == 310 * M);

    sg_acct_close(all, 2, &b, &lg);
    all[1] = &rich;
    sg_acct_close(all, 2, &b, &lg);
}

/* Runs last: calibrated costs are process-wide. */
static void test_calibrated_costs(void)
{
    char path[] = "/tmp/sg-unit-costs-XXXXXX", err[256];
    __u64 args[6] = { 0 };
    enum sg_class cls;
    FILE *f;
    int fd;

    CHECK(sg_set_cost("nosuchcall", 5) == -1);
    CHECK(sg_set_cost("execve", 0) == -1);

    fd = mkstemp(path);
    CHECK(fd >= 0);
    f = fdopen(fd, "w");
    fputs("# calibrated\n\nexecve 111  110750 489 40   # trailing columns ignored\n"
          "clone_thread 44\nread 2\n", f);
    fclose(f);
    CHECK(sg_load_costs(path, err, sizeof err) == 3);

    CHECK(sg_cost(sg_lookup(__NR_execve), args, &cls) == 111);
    args[2] = 128 * 1024;                        /* size term still applies */
    CHECK(sg_cost(sg_lookup(__NR_read), args, &cls) == 4);
    args[0] = CLONE_VM | CLONE_THREAD;
    CHECK(sg_cost(sg_lookup(__NR_clone), args, &cls) == 44 && cls == SG_C_THREAD);
    args[0] = SIGCHLD;
    CHECK(sg_cost(sg_lookup(__NR_clone), args, &cls) == 30);   /* not calibrated: seed */

    f = fopen(path, "w");
    fputs("execve 111\nbogus 3\n", f);
    fclose(f);
    CHECK(sg_load_costs(path, err, sizeof err) == -1);
    CHECK(strstr(err, ":2:") != NULL);           /* reports the bad line */
    unlink(path);
    CHECK(sg_load_costs(path, err, sizeof err) == -1);
}

static int loan_events[3];

static void count_loan(void *ctx, enum sg_loan_event ev, const struct sg_loan *l)
{
    (void)ctx;
    (void)l;
    loan_events[ev]++;
}

static void acct_init(struct sg_acct *a, uint32_t id, int prio, int64_t cap, int64_t tokens, int64_t rate,
                      int64_t now)
{
    memset(a, 0, sizeof *a);
    a->id = id;
    a->prio = prio;
    sg_bucket_init(&a->bucket, rate, cap * SG_MILLI, now);
    a->bucket.tokens = tokens * SG_MILLI;
    a->last_active_us = now;
}

static void test_borrow(void)
{
    const int64_t M = SG_MILLI, now = 500000, later = now + 2000000;
    struct sg_borrow_params p = { .enabled = 1, .reserve_pct = 30, .cap_pct = 50, .repay_pct = 50,
                                  .idle_us = 1000000 };
    struct sg_ledger lg = { .log = count_loan };
    struct sg_acct b, low, high, *all[3] = { &b, &low, &high };
    int64_t total;

    acct_init(&b, 1, 8, 1000, 900, 1000, now);      /* borrower, refills 1000/s */
    acct_init(&low, 2, 2, 2000, 1900, 0, now);      /* lower priority, may lend */
    acct_init(&high, 3, 9, 5000, 5000, 0, now);     /* higher priority, busy */
    total = b.bucket.tokens + low.bucket.tokens + high.bucket.tokens;

    /* Deficit 300: only the lower-priority job may lend. */
    CHECK(sg_borrow(all, 3, &b, 1200 * M, now, &p, &lg) == 1);
    CHECK(b.bucket.tokens == 1200 * M);
    CHECK(low.bucket.tokens == 1600 * M);
    CHECK(high.bucket.tokens == 5000 * M);
    CHECK(b.bucket.tokens + low.bucket.tokens + high.bucket.tokens == total);   /* conserved */
    CHECK(b.owed == 300 * M && low.lent_out == 300 * M);
    CHECK(loan_events[SG_LOAN_OPEN] == 1);
    sg_bucket_take(&b.bucket, 1200 * M);

    /* Borrower cap beta = 50% of 1000: 300 + 300 is too much, 300 + 200 is not. */
    CHECK(sg_borrow(all, 3, &b, 300 * M, now, &p, &lg) == 0);
    CHECK(sg_borrow(all, 3, &b, 200 * M, now, &p, &lg) == 1);
    CHECK(b.owed == 500 * M && low.bucket.tokens == 1400 * M);
    sg_bucket_take(&b.bucket, 200 * M);

    /* Reserve rho = 30%: low's surplus is 1400 - 600 = 800 < 900. */
    CHECK(sg_pick_lender(all, 3, &b, 900 * M, now, &p) == NULL);
    /* Idle tax: once idle, the higher-priority job lends, and has the largest surplus. */
    CHECK(sg_pick_lender(all, 3, &b, 100 * M, later, &p) == &high);
    /* A job that owes never lends, even when idle. */
    CHECK(sg_pick_lender(all, 3, &low, 1 * M, later, &p) == &high);

    /* Repayment: gamma = 50% of each refill goes to the oldest loan first. */
    sg_acct_refill(&b, now + 400000, &p, &lg);      /* +400, repays 200 of loan 1 */
    CHECK(b.bucket.tokens == 200 * M && b.owed == 300 * M);
    CHECK(low.bucket.tokens == 1600 * M && low.lent_out == 300 * M);
    CHECK(loan_events[SG_LOAN_REPAID] == 0);
    sg_acct_refill(&b, now + 800000, &p, &lg);      /* closes loan 1, 100 into loan 2 */
    CHECK(loan_events[SG_LOAN_REPAID] == 1);
    CHECK(b.bucket.tokens == 400 * M && b.owed == 100 * M);

    /* Borrower exits: the rest is written off on both sides. */
    sg_acct_close(all, 3, &b, &lg);
    CHECK(b.loans == NULL && b.owed == 0 && low.lent_out == 0);
    CHECK(loan_events[SG_LOAN_WRITTEN_OFF] == 1);

    /* Lender exits: the borrower's debt to it is written off. */
    CHECK(sg_borrow(all, 3, &high, 5100 * M, now, &p, &lg) == 1);
    CHECK(high.owed == 100 * M && high.loans->lender == &low);
    sg_acct_close(all, 3, &low, &lg);
    CHECK(high.loans == NULL && high.owed == 0);
    CHECK(loan_events[SG_LOAN_WRITTEN_OFF] == 2);

    /* Disabled borrowing never lends. */
    p.enabled = 0;
    high.bucket.tokens = 0;
    CHECK(sg_borrow(all, 3, &high, 1 * M, now, &p, &lg) == 0);
}

int main(void)
{
    test_bucket();
    test_waitq();
    test_aging_key();
    test_costs();
    test_borrow();
    test_borrow_chunks();
    test_calibrated_costs();
    printf("%s  unit tests: %d checks, %d failed\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
