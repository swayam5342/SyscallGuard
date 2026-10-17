#ifndef SG_SGD_H
#define SG_SGD_H

/* Internal state of the sgd supervisor, shared by sgd.c and sgd_ctl.c. */

#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "borrow.h"
#include "bucket.h"
#include "proto.h"
#include "waitq.h"

#define TICK_MS 10
#define PCB_BUCKETS 1024
#define WAIT_BUCKETS 8

enum ep_kind { EP_LISTEN, EP_CONN, EP_TIMER, EP_SIGNAL, EP_JOB, EP_HTTP_LISTEN, EP_HTTP };

struct stats {
    unsigned long long calls, allowed, waited, rejected, dropped;
    long long charged, wait_us_total, wait_us_max;   /* charged in milli-units */
};

/* Per-process statistics within a job. */
struct pcb {
    pid_t pid;
    struct job *job;
    struct stats st;
    struct pcb *next;
};

struct job {
    enum ep_kind kind;          /* EP_JOB; first member, used as the epoll tag */
    int lfd;
    int64_t fixed_rate;         /* 0 = proportional share */
    int fork_policy;            /* enum sg_fork_policy */
    char name[64];
    struct sg_acct acct;
    uint64_t blocked_gen;       /* tick in which its oldest waiter could not be paid */
    int64_t start_us;
    struct stats st;
    struct job *next;
};

struct held_reject {
    struct job *job;
    uint64_t id;
    int err;
    int64_t due_us;
};

struct conn {
    enum ep_kind kind;
    int fd;
};

struct sgd_config {
    char sock[SG_SOCK_MAX];
    int64_t global_rate;        /* units/s */
    int64_t burst_ms;
    int64_t tmax_ms;
    int64_t fork_wait_ms;
    int64_t aging_ms;           /* waiting this long gains one priority level */
    unsigned qmax;
    int metrics_port;
    const char *cost_file;
    int64_t reject_delay_ms;
    int64_t spin_us;
    int sync_wake;
    struct sg_borrow_params borrow;
    FILE *log;
};

struct sgd_state {
    int ep, listen_fd, timer_fd, signal_fd, http_fd;
    int64_t start_us;
    struct sg_bucket global;
    int64_t global_entitled;
    struct job *jobs;
    struct sg_acct **accts;     /* every job's acct, for lender search */
    size_t naccts, accts_cap;
    uint32_t next_id;
    struct sg_ledger ledger;
    struct sg_waitq wq;
    struct sg_waiter *scratch;
    size_t scratch_cap;
    uint64_t gen, seq;
    int g_blocked;              /* a waiter was held back by the global bucket this tick */
    int64_t g_blocked_key;
    struct held_reject *rejects;
    size_t nrejects, rejects_cap;
    int64_t last_notify_us;
    struct stats total;         /* including jobs that have ended */
    unsigned long long wait_hist[WAIT_BUCKETS + 1];   /* admitted calls by wait time */
    long long wait_hist_sum_us;
    struct seccomp_notif_sizes sz;
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct pcb *pcb[PCB_BUCKETS];
};

extern struct sgd_config cfg;
extern struct sgd_state S;
extern const int64_t sg_wait_bounds_us[WAIT_BUCKETS];

/* sgd.c */
void die(const char *what);
void ep_add(int fd, void *tag);
double units(int64_t milli);
struct job *find_job(uint32_t id);
void recompute_rates(int64_t now);
void rekey_job(struct job *j);

/* sgd_ctl.c */
void ctl_handle(int fd, const struct sg_ctl *ctl);
int http_open(int port);
void http_on_accept(void);
void http_on_request(struct conn *c);

#endif
