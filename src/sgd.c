/*
 * sgd: the SyscallGuard supervisor.
 *
 * Each job registered by sg-launch brings a seccomp listener fd. Every
 * costed call arrives on it as a notification and is allowed (CONTINUE),
 * held until budget is available (the reply is deferred), or rejected with
 * an errno.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"
#include "costs.h"
#include "sgd.h"

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SET_FLAGS
#define SECCOMP_IOCTL_NOTIF_SET_FLAGS SECCOMP_IOW(4, __u64)
#endif
#ifndef SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP
#define SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (1UL << 0)
#endif

struct sgd_config cfg = {
    .global_rate = 200000,
    .burst_ms = 1000,
    .tmax_ms = 2000,
    .fork_wait_ms = 500,
    .aging_ms = 500,
    .qmax = 256,
    .reject_delay_ms = 10,
    .spin_us = 0,
    .sync_wake = 1,
    .borrow = {
        .enabled = 1,
        .reserve_pct = 30,
        .cap_pct = 50,
        .repay_pct = 50,
        .idle_us = 1000000,
        .chunk_pct = 10,
    },
};

struct sgd_state S;

const int64_t sg_wait_bounds_us[WAIT_BUCKETS] = {
    1000, 5000, 10000, 50000, 100000, 500000, 1000000, 2000000,
};

static enum ep_kind tag_listen = EP_LISTEN, tag_timer = EP_TIMER, tag_signal = EP_SIGNAL,
                    tag_http = EP_HTTP_LISTEN;

void die(const char *what)
{
    perror(what);
    exit(1);
}

void ep_add(int fd, void *tag)
{
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = tag };

    if (epoll_ctl(S.ep, EPOLL_CTL_ADD, fd, &ev) < 0)
        die("epoll_ctl");
}

double units(int64_t milli)
{
    return (double)milli / SG_MILLI;
}

struct job *find_job(uint32_t id)
{
    struct job *j;

    for (j = S.jobs; j; j = j->next)
        if (j->acct.id == id)
            return j;
    return NULL;
}

static const char *sys_name(int nr)
{
    const struct sg_syscall *s = sg_lookup(nr);

    return s ? s->name : "?";
}

static void log_call(const struct job *j, int pid, int nr, int cls, int64_t cost, const char *dec,
                     int64_t wait_us)
{
    if (!cfg.log)
        return;
    fprintf(cfg.log,
            "{\"t_us\":%lld,\"ev\":\"call\",\"job\":%u,\"pid\":%d,\"sys\":\"%s\",\"cls\":\"%s\","
            "\"cost\":%.3f,\"dec\":\"%s\",\"wait_us\":%lld}\n",
            (long long)sg_now_us(), j->acct.id, pid, sys_name(nr), sg_classes[cls].name, units(cost), dec,
            (long long)wait_us);
}

static void log_stats(const char *ev, const struct job *j, int pid, const struct stats *st)
{
    if (!cfg.log)
        return;
    fprintf(cfg.log,
            "{\"t_us\":%lld,\"ev\":\"%s\",\"job\":%u,\"name\":\"%s\",\"pid\":%d,\"prio\":%d,"
            "\"calls\":%llu,\"allowed\":%llu,\"waited\":%llu,\"rejected\":%llu,\"dropped\":%llu,"
            "\"charged\":%.3f,\"wait_us_total\":%lld,\"wait_us_max\":%lld",
            (long long)sg_now_us(), ev, j->acct.id, j->name, pid, j->acct.prio, st->calls, st->allowed,
            st->waited, st->rejected, st->dropped, units(st->charged), st->wait_us_total, st->wait_us_max);
    if (pid == 0)
        fprintf(cfg.log,
                ",\"rate\":%lld,\"fixed\":%d,\"fork_policy\":\"%s\",\"capacity\":%.3f,\"entitled\":%.3f,"
                "\"loans_taken\":%u,\"borrowed\":%.3f,\"loans_given\":%u,\"lent\":%.3f",
                (long long)j->acct.bucket.rate, j->fixed_rate != 0, sg_fork_policy_name(j->fork_policy),
                units(j->acct.bucket.capacity),
                units(j->acct.entitled_total), j->acct.loans_taken, units(j->acct.borrowed_total),
                j->acct.loans_given, units(j->acct.lent_total));
    fputs("}\n", cfg.log);
}

static void log_loan(void *ctx, enum sg_loan_event ev, const struct sg_loan *l)
{
    static const char *const names[] = { "loan_open", "loan_repaid", "loan_written_off" };
    int64_t now = sg_now_us();

    (void)ctx;
    if (!cfg.log)
        return;
    fprintf(cfg.log,
            "{\"t_us\":%lld,\"ev\":\"%s\",\"loan\":%u,\"from\":%u,\"to\":%u,\"amount\":%.3f,"
            "\"repaid\":%.3f,\"age_us\":%lld}\n",
            (long long)now, names[ev], l->id, l->lender->id, l->borrower->id, units(l->amount),
            units(l->repaid), (long long)(now - l->t_start_us));
}

static void log_sgd(const char *ev)
{
    if (!cfg.log)
        return;
    fprintf(cfg.log,
            "{\"t_us\":%lld,\"ev\":\"%s\",\"global_rate\":%lld,\"burst_ms\":%lld,\"tmax_ms\":%lld,"
            "\"fork_wait_ms\":%lld,\"aging_ms\":%lld,\"borrowing\":%d,\"loan_chunk_pct\":%lld,"
            "\"reject_delay_ms\":%lld,\"spin_us\":%lld,\"sync_wake\":%d,\"costs\":\"%s\","
            "\"global_entitled\":%.3f,\"charged\":%.3f}\n",
            (long long)sg_now_us(), ev, (long long)cfg.global_rate, (long long)cfg.burst_ms,
            (long long)cfg.tmax_ms, (long long)cfg.fork_wait_ms, (long long)cfg.aging_ms, cfg.borrow.enabled,
            (long long)cfg.borrow.chunk_pct, (long long)cfg.reject_delay_ms, (long long)cfg.spin_us,
            cfg.sync_wake, cfg.cost_file ? "calibrated" : "seed", units(S.global_entitled),
            units(S.total.charged));
}

static struct pcb *pcb_get(struct job *j, pid_t pid)
{
    struct pcb **head = &S.pcb[(unsigned)pid % PCB_BUCKETS], *p;

    for (p = *head; p; p = p->next)
        if (p->pid == pid && p->job == j)
            return p;
    p = calloc(1, sizeof *p);
    if (!p)
        die("calloc");
    p->pid = pid;
    p->job = j;
    p->next = *head;
    *head = p;
    return p;
}

static void pcb_drop_job(struct job *j)
{
    size_t i;

    for (i = 0; i < PCB_BUCKETS; i++) {
        struct pcb **pp = &S.pcb[i];

        while (*pp) {
            if ((*pp)->job == j) {
                struct pcb *dead = *pp;

                log_stats("pcb", j, dead->pid, &dead->st);
                *pp = dead->next;
                free(dead);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

#define NOTE(j, p, field) ((j)->st.field++, (p)->st.field++, S.total.field++)

static void note_wait_time(struct job *j, struct pcb *p, int64_t wait_us)
{
    j->st.wait_us_total += wait_us;
    p->st.wait_us_total += wait_us;
    S.total.wait_us_total += wait_us;
    if (wait_us > j->st.wait_us_max)
        j->st.wait_us_max = wait_us;
    if (wait_us > p->st.wait_us_max)
        p->st.wait_us_max = wait_us;
    if (wait_us > S.total.wait_us_max)
        S.total.wait_us_max = wait_us;
}

static void refill(struct job *j, int64_t now)
{
    sg_acct_refill(&j->acct, now, &cfg.borrow, &S.ledger);
}

static void global_refill(int64_t now)
{
    S.global_entitled += sg_bucket_refill(&S.global, now);
}

static void rebuild_accts(void)
{
    size_t n = 0;
    struct job *j;

    for (j = S.jobs; j; j = j->next)
        n++;
    if (n > S.accts_cap) {
        struct sg_acct **v = realloc(S.accts, n * 2 * sizeof *v);

        if (!v)
            die("realloc");
        S.accts = v;
        S.accts_cap = n * 2;
    }
    S.naccts = 0;
    for (j = S.jobs; j; j = j->next)
        S.accts[S.naccts++] = &j->acct;
}

/* Share jobs get R_g * prio / sum(prio); capacity is rate * burst. */
void recompute_rates(int64_t now)
{
    int64_t sumw = 0, rate;
    struct job *j;

    for (j = S.jobs; j; j = j->next)
        if (!j->fixed_rate)
            sumw += j->acct.prio;
    for (j = S.jobs; j; j = j->next) {
        rate = j->fixed_rate ? j->fixed_rate : cfg.global_rate * j->acct.prio / sumw;
        if (rate < 1)
            rate = 1;
        refill(j, now);
        /* units/s * ms = milli-units */
        sg_bucket_set_rate(&j->acct.bucket, rate, rate * cfg.burst_ms);
    }
}

static int job_can(struct job *j, int64_t cost, int64_t now)
{
    return sg_bucket_can(&j->acct.bucket, cost) ||
           sg_borrow(S.accts, S.naccts, &j->acct, cost, now, &cfg.borrow, &S.ledger);
}

static void reply(int lfd, uint64_t id, int err)
{
    memset(S.resp, 0, S.sz.seccomp_notif_resp);
    S.resp->id = id;
    if (err)
        S.resp->error = -err;
    else
        S.resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    /* ENOENT: the thread died while we were deciding. */
    if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, S.resp) < 0 && errno != ENOENT)
        perror("sgd: NOTIF_SEND");
}

/*
 * Rejections are answered after reject_delay_ms so that a job retrying in a
 * loop (fork after EAGAIN) cannot keep sgd busy; the thread sleeps meanwhile.
 */
static void reject(struct job *j, uint64_t id, int err, int64_t now)
{
    if (cfg.reject_delay_ms == 0) {
        reply(j->lfd, id, err);
        return;
    }
    if (S.nrejects == S.rejects_cap) {
        size_t cap = S.rejects_cap ? S.rejects_cap * 2 : 64;
        struct held_reject *v = realloc(S.rejects, cap * sizeof *v);

        if (!v)
            die("realloc");
        S.rejects = v;
        S.rejects_cap = cap;
    }
    S.rejects[S.nrejects++] = (struct held_reject){ j, id, err, now + cfg.reject_delay_ms * 1000 };
}

static void flush_rejects(int64_t now, int force, const struct job *gone)
{
    size_t i = 0;

    while (i < S.nrejects) {
        struct held_reject *r = &S.rejects[i];

        if (r->job == gone || force || r->due_us <= now) {
            if (r->job != gone)
                reply(r->job->lfd, r->id, r->err);
            S.rejects[i] = S.rejects[--S.nrejects];
        } else {
            i++;
        }
    }
}

/* See waitq.h for why this key implements aging. */
static int64_t wait_key(const struct job *j, int64_t arrive_us)
{
    return (int64_t)j->acct.prio * cfg.aging_ms * 1000 - arrive_us;
}

static void admit(struct job *j, struct pcb *p, const struct sg_waiter *w, int64_t wait_us)
{
    int b = 0;

    sg_bucket_take(&j->acct.bucket, w->cost);
    sg_bucket_take(&S.global, w->cost);
    reply(j->lfd, w->id, 0);
    NOTE(j, p, allowed);
    j->st.charged += w->cost;
    p->st.charged += w->cost;
    S.total.charged += w->cost;
    note_wait_time(j, p, wait_us);
    while (b < WAIT_BUCKETS && wait_us > sg_wait_bounds_us[b])
        b++;
    S.wait_hist[b]++;
    S.wait_hist_sum_us += wait_us;
    log_call(j, w->pid, w->nr, w->cls, w->cost, "ALLOW", wait_us);
}

static void on_notify(struct job *j)
{
    const struct sg_syscall *s;
    struct sg_waiter w;
    enum sg_class cls;
    enum sg_policy policy;
    int64_t now, burst_limit, max_wait_ms;
    struct pcb *p;
    int err = 0;

    memset(S.req, 0, S.sz.seccomp_notif);
    if (ioctl(j->lfd, SECCOMP_IOCTL_NOTIF_RECV, S.req) < 0) {
        if (errno == EINTR || errno == ENOENT)
            return;
        die("sgd: NOTIF_RECV");
    }
    now = sg_now_us();
    j->acct.last_active_us = now;
    S.last_notify_us = now;
    s = sg_lookup(S.req->data.nr);
    if (!s) {
        reply(j->lfd, S.req->id, 0);
        return;
    }
    p = pcb_get(j, (pid_t)S.req->pid);
    w = (struct sg_waiter){
        .key = wait_key(j, now),
        .id = S.req->id,
        .arrive_us = now,
        .cost = sg_cost(s, S.req->data.args, &cls) * SG_MILLI,
        .owner = j,
        .aux = p,
        .pid = (int)S.req->pid,
        .nr = S.req->data.nr,
    };
    w.cls = cls;
    NOTE(j, p, calls);
    refill(j, now);
    global_refill(now);

    /* Keep per-job FIFO order, and do not overtake a waiter held for the global bucket. */
    if (j->acct.nwaiting == 0 && !(S.g_blocked && w.key <= S.g_blocked_key) &&
        sg_bucket_can(&S.global, w.cost) && job_can(j, w.cost, now)) {
        admit(j, p, &w, 0);
        return;
    }

    policy = sg_classes[cls].policy;
    max_wait_ms = cfg.tmax_ms;
    if (cls == SG_C_PROC) {
        policy = j->fork_policy == SG_FORK_REJECT ? SG_REJECT : SG_WAIT;
        if (j->fork_policy == SG_FORK_BRIEF && cfg.fork_wait_ms < max_wait_ms)
            max_wait_ms = cfg.fork_wait_ms;
    }

    burst_limit = j->acct.bucket.capacity;
    if (cfg.borrow.enabled)
        burst_limit += j->acct.bucket.capacity * cfg.borrow.cap_pct / 100;
    if (policy == SG_REJECT)
        err = sg_classes[cls].reject_errno;
    else if (w.cost > burst_limit || w.cost > S.global.capacity)
        err = EAGAIN;   /* could never be admitted */
    else if (j->acct.nwaiting >= cfg.qmax)
        err = EAGAIN;
    if (err) {
        reject(j, w.id, err, now);
        NOTE(j, p, rejected);
        log_call(j, w.pid, w.nr, w.cls, w.cost, "REJECT", 0);
        return;
    }

    w.seq = S.seq++;
    w.deadline_us = now + max_wait_ms * 1000;
    if (sg_waitq_push(&S.wq, &w) < 0)
        die("sgd: waitq");
    j->acct.nwaiting++;
    NOTE(j, p, waited);
    log_call(j, w.pid, w.nr, w.cls, w.cost, "WAIT", 0);
}

/* Pop every waiter into S.scratch, in priority order. */
static size_t drain_waiters(void)
{
    struct sg_waiter w;
    size_t n = 0;

    if (S.wq.n > S.scratch_cap) {
        size_t cap = S.wq.n * 2;
        struct sg_waiter *v = realloc(S.scratch, cap * sizeof *v);

        if (!v)
            die("realloc");
        S.scratch = v;
        S.scratch_cap = cap;
    }
    while (sg_waitq_pop(&S.wq, &w))
        S.scratch[n++] = w;
    return n;
}

static void requeue(const struct sg_waiter *w)
{
    if (sg_waitq_push(&S.wq, w) < 0)
        die("sgd: waitq");
}

void rekey_job(struct job *j)
{
    size_t n = drain_waiters(), i;

    for (i = 0; i < n; i++) {
        if (S.scratch[i].owner == j)
            S.scratch[i].key = wait_key(j, S.scratch[i].arrive_us);
        requeue(&S.scratch[i]);
    }
}

static void on_tick(void)
{
    uint64_t expirations;
    struct job *jb;
    int64_t now;
    size_t n, i;

    if (read(S.timer_fd, &expirations, sizeof expirations) < 0 && errno != EAGAIN)
        die("sgd: timerfd");
    now = sg_now_us();
    flush_rejects(now, 0, NULL);
    global_refill(now);
    for (jb = S.jobs; jb; jb = jb->next)
        refill(jb, now);
    S.gen++;
    S.g_blocked = 0;

    n = drain_waiters();
    for (i = 0; i < n; i++) {
        struct sg_waiter *e = &S.scratch[i];
        struct job *j = e->owner;
        struct pcb *p = e->aux;
        int64_t waited = now - e->arrive_us;

        /* The thread may have been killed while it waited. */
        if (ioctl(j->lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &e->id) < 0) {
            j->acct.nwaiting--;
            NOTE(j, p, dropped);
            log_call(j, e->pid, e->nr, e->cls, e->cost, "DROP", waited);
            continue;
        }
        if (now > e->deadline_us) {
            reply(j->lfd, e->id, EAGAIN);
            j->acct.nwaiting--;
            NOTE(j, p, rejected);
            note_wait_time(j, p, waited);
            log_call(j, e->pid, e->nr, e->cls, e->cost, "REJECT", waited);
            continue;
        }
        if (j->blocked_gen == S.gen || S.g_blocked) {
            requeue(e);
            continue;
        }
        /* Borrowing is pointless if the global bucket could not admit the call anyway. */
        if (!sg_bucket_can(&j->acct.bucket, e->cost) &&
            !(sg_bucket_can(&S.global, e->cost) && job_can(j, e->cost, now))) {
            j->blocked_gen = S.gen;
            requeue(e);
            continue;
        }
        if (!sg_bucket_can(&S.global, e->cost)) {
            /* Hold everything behind it, or small low-priority calls would drain the global bucket first. */
            S.g_blocked = 1;
            S.g_blocked_key = e->key;
            requeue(e);
            continue;
        }
        j->acct.nwaiting--;
        admit(j, p, e, waited);
    }
    if (cfg.log)
        fflush(cfg.log);
}

static struct job *job_new(const struct sg_register *reg, int lfd)
{
    struct job *j = calloc(1, sizeof *j);
    int64_t now = sg_now_us();
    char *c;

    if (!j)
        die("calloc");
    j->kind = EP_JOB;
    j->lfd = lfd;
    j->fixed_rate = reg->rate;
    j->fork_policy = reg->fork_policy;
    j->acct.id = ++S.next_id;
    j->acct.prio = reg->prio;
    j->acct.last_active_us = now;
    memcpy(j->name, reg->name, sizeof j->name);
    j->name[sizeof j->name - 1] = '\0';
    for (c = j->name; *c; c++)   /* keep the JSON log and metric labels valid */
        if (*c == '"' || *c == '\\' || (unsigned char)*c < 0x20)
            *c = '_';
    j->start_us = now;
    sg_bucket_init(&j->acct.bucket, 1, 0, now);
    j->next = S.jobs;
    S.jobs = j;
    rebuild_accts();
    recompute_rates(now);
    j->acct.bucket.tokens = j->acct.bucket.capacity;
    j->acct.entitled_total = j->acct.bucket.capacity;
    ep_add(lfd, j);
    if (cfg.sync_wake &&
        ioctl(lfd, SECCOMP_IOCTL_NOTIF_SET_FLAGS, SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP) < 0) {
        fprintf(stderr, "[sgd] note: synchronous wake-up unavailable (%s; needs Linux 6.6), continuing without\n",
                strerror(errno));
        cfg.sync_wake = 0;
    }

    fprintf(stderr, "[sgd] job %u (%s) started: prio %d, %s %lld units/s, fork policy %s\n", j->acct.id,
            j->name, j->acct.prio, j->fixed_rate ? "fixed" : "share", (long long)j->acct.bucket.rate,
            sg_fork_policy_name(j->fork_policy));
    log_stats("job_start", j, 0, &j->st);
    return j;
}

static void job_free(struct job *j)
{
    struct job **pp;

    sg_acct_close(S.accts, S.naccts, &j->acct, &S.ledger);
    for (pp = &S.jobs; *pp; pp = &(*pp)->next)
        if (*pp == j) {
            *pp = j->next;
            break;
        }
    rebuild_accts();
    pcb_drop_job(j);
    epoll_ctl(S.ep, EPOLL_CTL_DEL, j->lfd, NULL);
    close(j->lfd);
    free(j);
}

/* The listener reports POLLHUP only once every task of the job has exited and been reaped. */
static void end_job(struct job *j)
{
    int64_t now = sg_now_us();
    size_t n = drain_waiters(), i;

    for (i = 0; i < n; i++)
        if (S.scratch[i].owner != j)
            requeue(&S.scratch[i]);
    flush_rejects(now, 0, j);

    refill(j, now);
    fprintf(stderr,
            "[sgd] job %u (%s) ended after %.3fs: calls=%llu allowed=%llu waited=%llu rejected=%llu "
            "dropped=%llu charged=%lld max_wait_ms=%.1f loans=%u borrowed=%lld lent=%lld\n",
            j->acct.id, j->name, (double)(now - j->start_us) / 1e6, j->st.calls, j->st.allowed,
            j->st.waited, j->st.rejected, j->st.dropped, j->st.charged / SG_MILLI,
            (double)j->st.wait_us_max / 1000, j->acct.loans_taken,
            (long long)(j->acct.borrowed_total / SG_MILLI), (long long)(j->acct.lent_total / SG_MILLI));
    log_stats("job_end", j, 0, &j->st);
    job_free(j);
    recompute_rates(now);
    if (cfg.log)
        fflush(cfg.log);
}

static void on_listen(void)
{
    struct conn *c;
    int fd = accept4(S.listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

    if (fd < 0)
        return;
    c = calloc(1, sizeof *c);
    if (!c)
        die("calloc");
    c->kind = EP_CONN;
    c->fd = fd;
    ep_add(fd, c);
}

static void on_conn(struct conn *c)
{
    union {
        struct sg_register reg;
        struct sg_ctl ctl;
    } msg;
    struct sg_ack ack = { 0, 0 };
    int lfd;
    ssize_t n = sg_recv_fd(c->fd, &msg, sizeof msg, &lfd);

    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return;

    if (n == (ssize_t)sizeof msg.ctl && msg.ctl.magic == SG_CTL_MAGIC) {
        if (lfd >= 0)
            close(lfd);
        ctl_handle(c->fd, &msg.ctl);
        goto done;
    }

    if (n != (ssize_t)sizeof msg.reg || msg.reg.magic != SG_PROTO_MAGIC || lfd < 0)
        ack.status = -EPROTO;
    else if (msg.reg.prio < SG_PRIO_MIN || msg.reg.prio > SG_PRIO_MAX || msg.reg.rate < 0 ||
             msg.reg.fork_policy < 0 || msg.reg.fork_policy >= SG_FORK_COUNT)
        ack.status = -EINVAL;

    if (ack.status == 0)
        ack.job_id = job_new(&msg.reg, lfd)->acct.id;
    else if (lfd >= 0)
        close(lfd);   /* the launcher's costed calls now fail with ENOSYS */

    if (write(c->fd, &ack, sizeof ack) < 0)
        perror("sgd: ack");
done:
    close(c->fd);
    free(c);
}

static int open_listener(const char *path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    mode_t old_mask;
    int fd;

    if (strlen(path) >= sizeof addr.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(addr.sun_path, path);

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
        fprintf(stderr, "sgd: another sgd is already listening on %s\n", path);
        exit(1);
    }
    close(fd);
    unlink(path);

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    old_mask = umask(077);   /* only this user may register jobs or send commands */
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        umask(old_mask);
        return -1;
    }
    umask(old_mask);
    if (listen(fd, 64) < 0)
        return -1;
    return fd;
}

static void shutdown_all(void)
{
    size_t n = drain_waiters(), i;

    /* A filter cannot be removed, so let held calls run rather than fail. */
    for (i = 0; i < n; i++)
        reply(((struct job *)S.scratch[i].owner)->lfd, S.scratch[i].id, 0);
    flush_rejects(sg_now_us(), 1, NULL);
    while (S.jobs) {
        fprintf(stderr, "[sgd] warning: job %u (%s) is still running; its costed calls will now fail with ENOSYS\n",
                S.jobs->acct.id, S.jobs->name);
        job_free(S.jobs);
    }
    close(S.listen_fd);
    if (S.http_fd >= 0)
        close(S.http_fd);
    unlink(cfg.sock);
    global_refill(sg_now_us());
    log_sgd("sgd_stop");
    fprintf(stderr, "[sgd] stopped: loans opened=%llu repaid=%llu written_off=%llu\n", S.ledger.opened,
            S.ledger.repaid, S.ledger.written_off);
    if (cfg.log)
        fclose(cfg.log);
    sg_waitq_free(&S.wq);
    free(S.scratch);
    free(S.rejects);
    free(S.accts);
    free(S.req);
    free(S.resp);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-s sock] [-r rate] [-H burst_ms] [-T tmax_ms] [-F fork_wait_ms] [-a aging_ms] [-q qmax]\n"
            "          [-I idle_ms] [-B] [-k chunk_pct] [-R delay_ms] [-S spin_us] [-W]\n"
            "          [-m port] [-c costs] [-L] [-l log]\n"
            "  -s sock      listening socket (default /tmp/syscallguard-<uid>.sock)\n"
            "  -r rate      global budget R_g in cost units/s (default 200000)\n"
            "  -H burst_ms  burst horizon H: capacity = rate * H (default 1000)\n"
            "  -T tmax_ms   reject a call that has waited this long (default 2000)\n"
            "  -F ms        process creation of a job with fork policy \"brief\" waits at most this\n"
            "               long, then fails with EAGAIN (default 500; see sg-launch -f)\n"
            "  -a aging_ms  waiting this long raises effective priority by 1 (default 500)\n"
            "  -q qmax      max waiting calls per job (default 256)\n"
            "  -I idle_ms   a job idle this long may lend to any priority (default 1000)\n"
            "  -B           disable borrowing (baseline for evaluation)\n"
            "  -k pct       borrow at least pct%% of the borrower's capacity per loan (default 10; 0 = deficit)\n"
            "  -R delay_ms  hold budget rejections this long before replying (default 10; 0 = at once)\n"
            "  -S spin_us   keep polling this long after a notification before sleeping (default 0;\n"
            "               fastest round trip but burns CPU; turns synchronous wake-up off)\n"
            "  -W           do not request synchronous wake-ups (Linux 6.6+)\n"
            "  -m port      serve Prometheus metrics on http://127.0.0.1:port/metrics\n"
            "  -c costs     load calibrated syscall costs (from tools/sg_calibrate.py)\n"
            "  -L           print the cost table in effect and exit\n"
            "  -l log       write a JSON-lines event log\n",
            argv0);
    exit(2);
}

static int64_t parse_min(const char *s, long long min, const char *argv0)
{
    char *end;
    long long v;

    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno || *s == '\0' || *end != '\0' || v < min)
        usage(argv0);
    return v;
}

static int64_t parse_pos(const char *s, const char *argv0)
{
    return parse_min(s, 1, argv0);
}

int main(int argc, char **argv)
{
    struct itimerspec tick = {
        .it_interval = { 0, TICK_MS * 1000000L },
        .it_value = { 0, TICK_MS * 1000000L },
    };
    sigset_t sigs;
    char err[256];
    int opt, list_costs = 0;

    S.http_fd = -1;
    sg_default_sock(cfg.sock, sizeof cfg.sock);
    while ((opt = getopt(argc, argv, "s:r:H:T:F:a:q:I:Bk:R:S:Wm:c:Ll:h")) != -1) {
        switch (opt) {
        case 's': snprintf(cfg.sock, sizeof cfg.sock, "%s", optarg); break;
        case 'r': cfg.global_rate = parse_pos(optarg, argv[0]); break;
        case 'H': cfg.burst_ms = parse_pos(optarg, argv[0]); break;
        case 'T': cfg.tmax_ms = parse_pos(optarg, argv[0]); break;
        case 'F': cfg.fork_wait_ms = parse_pos(optarg, argv[0]); break;
        case 'a': cfg.aging_ms = parse_pos(optarg, argv[0]); break;
        case 'q': cfg.qmax = (unsigned)parse_pos(optarg, argv[0]); break;
        case 'I': cfg.borrow.idle_us = parse_pos(optarg, argv[0]) * 1000; break;
        case 'B': cfg.borrow.enabled = 0; break;
        case 'k':
            cfg.borrow.chunk_pct = parse_min(optarg, 0, argv[0]);
            if (cfg.borrow.chunk_pct > 100)
                usage(argv[0]);
            break;
        case 'R': cfg.reject_delay_ms = parse_min(optarg, 0, argv[0]); break;
        case 'S': cfg.spin_us = parse_min(optarg, 0, argv[0]); break;
        case 'W': cfg.sync_wake = 0; break;
        case 'm':
            cfg.metrics_port = (int)parse_pos(optarg, argv[0]);
            if (cfg.metrics_port > 65535)
                usage(argv[0]);
            break;
        case 'c':
            if (sg_load_costs(optarg, err, sizeof err) < 0) {
                fprintf(stderr, "sgd: %s\n", err);
                return 2;
            }
            cfg.cost_file = optarg;
            break;
        case 'L':
            list_costs = 1;
            break;
        case 'l':
            cfg.log = fopen(optarg, "w");
            if (!cfg.log)
                die(optarg);
            break;
        default: usage(argv[0]);
        }
    }
    if (optind != argc)
        usage(argv[0]);
    if (list_costs) {
        sg_dump_costs(stdout);
        return 0;
    }
    /* Synchronous wake-up moves threads onto sgd's CPU, where a spinning sgd never yields. */
    if (cfg.spin_us && cfg.sync_wake) {
        fprintf(stderr, "[sgd] note: spinning (-S) and synchronous wake-up compete for one CPU; "
                        "turning synchronous wake-up off\n");
        cfg.sync_wake = 0;
    }

    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &S.sz) < 0)
        die("sgd: SECCOMP_GET_NOTIF_SIZES");
    S.req = malloc(S.sz.seccomp_notif);
    S.resp = malloc(S.sz.seccomp_notif_resp);
    if (!S.req || !S.resp)
        die("malloc");
    S.ledger.log = log_loan;

    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
        die("sigprocmask");
    S.signal_fd = signalfd(-1, &sigs, SFD_CLOEXEC);
    S.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    S.ep = epoll_create1(EPOLL_CLOEXEC);
    if (S.signal_fd < 0 || S.timer_fd < 0 || S.ep < 0)
        die("sgd: setup");
    if (timerfd_settime(S.timer_fd, 0, &tick, NULL) < 0)
        die("timerfd_settime");
    S.listen_fd = open_listener(cfg.sock);
    if (S.listen_fd < 0)
        die(cfg.sock);
    if (cfg.metrics_port) {
        S.http_fd = http_open(cfg.metrics_port);
        if (S.http_fd < 0)
            die("sgd: metrics port");
        ep_add(S.http_fd, &tag_http);
    }

    S.start_us = sg_now_us();
    sg_bucket_init(&S.global, cfg.global_rate, cfg.global_rate * cfg.burst_ms, S.start_us);
    S.global.tokens = S.global.capacity;
    S.global_entitled = S.global.capacity;

    ep_add(S.listen_fd, &tag_listen);
    ep_add(S.timer_fd, &tag_timer);
    ep_add(S.signal_fd, &tag_signal);
    log_sgd("sgd_start");
    fprintf(stderr,
            "[sgd] listening on %s: global %lld units/s, burst %lld ms, T_max %lld ms, borrowing %s, %s costs\n",
            cfg.sock, (long long)cfg.global_rate, (long long)cfg.burst_ms, (long long)cfg.tmax_ms,
            cfg.borrow.enabled ? "on" : "off", cfg.cost_file ? cfg.cost_file : "seed");
    if (cfg.metrics_port)
        fprintf(stderr, "[sgd] metrics on http://127.0.0.1:%d/metrics\n", cfg.metrics_port);
    fprintf(stderr,
            "[sgd] brief fork wait %lld ms, reject delay %lld ms, loan chunk %lld%%, spin %lld us, "
            "synchronous wake-up %s\n",
            (long long)cfg.fork_wait_ms, (long long)cfg.reject_delay_ms, (long long)cfg.borrow.chunk_pct,
            (long long)cfg.spin_us, cfg.sync_wake ? "requested" : "off");

    for (;;) {
        struct epoll_event evs[64];
        int timeout = cfg.spin_us && sg_now_us() - S.last_notify_us < cfg.spin_us ? 0 : -1;
        int n = epoll_wait(S.ep, evs, 64, timeout), i;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("epoll_wait");
        }
        for (i = 0; i < n; i++) {
            void *tag = evs[i].data.ptr;

            switch (*(enum ep_kind *)tag) {
            case EP_LISTEN:
                on_listen();
                break;
            case EP_CONN:
                on_conn(tag);
                break;
            case EP_HTTP_LISTEN:
                http_on_accept();
                break;
            case EP_HTTP:
                http_on_request(tag);
                break;
            case EP_TIMER:
                on_tick();
                break;
            case EP_SIGNAL:
                shutdown_all();
                return 0;
            case EP_JOB:
                if (evs[i].events & EPOLLIN)
                    on_notify(tag);
                else if (evs[i].events & (EPOLLHUP | EPOLLERR))
                    end_job(tag);
                break;
            }
        }
    }
}
