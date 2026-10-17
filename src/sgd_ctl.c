/* sgctl commands over the Unix socket, and Prometheus metrics over HTTP on 127.0.0.1. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "sgd.h"

/* Blocking write with a 1 s timeout, so a stuck client cannot stall sgd for long. */
static void send_all(int fd, const char *buf, size_t len)
{
    struct timeval tv = { .tv_sec = 1 };
    int flags = fcntl(fd, F_GETFL);

    if (flags >= 0)
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        buf += n;
        len -= (size_t)n;
    }
}

/* Jobs oldest first (S.jobs is newest first); caller frees. */
static struct job **jobs_by_id(size_t *count)
{
    struct job **v, *j;
    size_t n = 0;

    for (j = S.jobs; j; j = j->next)
        n++;
    v = calloc(n ? n : 1, sizeof *v);
    if (!v)
        die("calloc");
    *count = n;
    for (j = S.jobs; j; j = j->next)
        v[--n] = j;
    return v;
}

static void write_status(FILE *out)
{
    size_t n, i;
    struct job **v = jobs_by_id(&n);

    fprintf(out, "global: %.1f / %.1f units, refill %lld units/s, borrowing %s, up %.1f s\n",
            units(S.global.tokens), units(S.global.capacity), (long long)cfg.global_rate,
            cfg.borrow.enabled ? "on" : "off", (double)(sg_now_us() - S.start_us) / 1e6);
    fprintf(out, "totals: calls=%llu allowed=%llu waited=%llu rejected=%llu dropped=%llu charged=%.0f\n",
            S.total.calls, S.total.allowed, S.total.waited, S.total.rejected, S.total.dropped,
            units(S.total.charged));
    fprintf(out, "loans:  opened=%llu repaid=%llu written_off=%llu\n\n", S.ledger.opened, S.ledger.repaid,
            S.ledger.written_off);
    fprintf(out, "%-4s %-14s %4s %5s %8s %10s %10s %4s %8s %8s %7s %8s %8s %8s %6s\n", "JOB", "NAME", "PRIO",
            "MODE", "RATE/S", "TOKENS", "CAPACITY", "WAIT", "CALLS", "ALLOWED", "WAITED", "REJECTED", "OWED",
            "LENT", "FORK");
    for (i = 0; i < n; i++) {
        const struct job *j = v[i];

        fprintf(out,
                "%-4u %-14.14s %4d %5s %8lld %10.1f %10.1f %4u %8llu %8llu %7llu %8llu %8.1f %8.1f %6s\n",
                j->acct.id, j->name, j->acct.prio, j->fixed_rate ? "fixed" : "share",
                (long long)j->acct.bucket.rate, units(j->acct.bucket.tokens), units(j->acct.bucket.capacity),
                j->acct.nwaiting, j->st.calls, j->st.allowed, j->st.waited, j->st.rejected,
                units(j->acct.owed), units(j->acct.lent_out), sg_fork_policy_name(j->fork_policy));
    }
    if (n == 0)
        fprintf(out, "(no jobs)\n");
    free(v);
}

static void write_loans(FILE *out)
{
    int64_t now = sg_now_us();
    size_t n, i, rows = 0;
    struct job **v = jobs_by_id(&n);
    const struct sg_loan *l;

    fprintf(out, "%-5s %5s %5s %10s %10s %8s\n", "LOAN", "FROM", "TO", "AMOUNT", "REPAID", "AGE_S");
    for (i = 0; i < n; i++)
        for (l = v[i]->acct.loans; l; l = l->next, rows++)
            fprintf(out, "%-5u %5u %5u %10.1f %10.1f %8.2f\n", l->id, l->lender->id, l->borrower->id,
                    units(l->amount), units(l->repaid), (double)(now - l->t_start_us) / 1e6);
    if (rows == 0)
        fprintf(out, "(no outstanding loans)\n");
    free(v);
}

static void header(FILE *out, const char *name, const char *type, const char *help)
{
    fprintf(out, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, type);
}

static void scalar(FILE *out, const char *name, const char *type, const char *help, double value)
{
    header(out, name, type, help);
    fprintf(out, "%s %.17g\n", name, value);
}

enum job_metric {
    JM_PRIORITY, JM_RATE, JM_TOKENS, JM_CAPACITY, JM_WAITING, JM_OWED, JM_LENT_OUT,
    JM_CALLS, JM_ALLOWED, JM_WAITED, JM_REJECTED, JM_DROPPED, JM_CHARGED, JM_ENTITLED,
    JM_BORROWED, JM_LENT, JM_WAIT_SECONDS, JM_COUNT
};

static const struct {
    const char *name, *type, *help;
} job_metrics[JM_COUNT] = {
    [JM_PRIORITY]     = { "sg_job_priority", "gauge", "Job priority (1 lowest, 10 highest)" },
    [JM_RATE]         = { "sg_job_rate_units", "gauge", "Job refill rate in cost units per second" },
    [JM_TOKENS]       = { "sg_job_tokens_units", "gauge", "Tokens in the job bucket" },
    [JM_CAPACITY]     = { "sg_job_capacity_units", "gauge", "Job bucket capacity" },
    [JM_WAITING]      = { "sg_job_waiting_calls", "gauge", "Calls of the job currently held (WAIT)" },
    [JM_OWED]         = { "sg_job_owed_units", "gauge", "Outstanding debt of the job as borrower" },
    [JM_LENT_OUT]     = { "sg_job_lent_out_units", "gauge", "Outstanding loans the job has made" },
    [JM_CALLS]        = { "sg_job_calls_total", "counter", "Costed calls received" },
    [JM_ALLOWED]      = { "sg_job_allowed_total", "counter", "Calls admitted (immediately or after waiting)" },
    [JM_WAITED]       = { "sg_job_waited_total", "counter", "Calls that had to wait" },
    [JM_REJECTED]     = { "sg_job_rejected_total", "counter", "Calls rejected" },
    [JM_DROPPED]      = { "sg_job_dropped_total", "counter", "Waiting calls whose thread died" },
    [JM_CHARGED]      = { "sg_job_charged_units_total", "counter", "Cost units charged" },
    [JM_ENTITLED]     = { "sg_job_entitled_units_total", "counter", "Cost units credited by refills" },
    [JM_BORROWED]     = { "sg_job_borrowed_units_total", "counter", "Cost units borrowed" },
    [JM_LENT]         = { "sg_job_lent_units_total", "counter", "Cost units lent" },
    [JM_WAIT_SECONDS] = { "sg_job_wait_seconds_total", "counter", "Total time calls spent waiting" },
};

static double job_value(const struct job *j, enum job_metric m)
{
    switch (m) {
    case JM_PRIORITY:     return j->acct.prio;
    case JM_RATE:         return (double)j->acct.bucket.rate;
    case JM_TOKENS:       return units(j->acct.bucket.tokens);
    case JM_CAPACITY:     return units(j->acct.bucket.capacity);
    case JM_WAITING:      return j->acct.nwaiting;
    case JM_OWED:         return units(j->acct.owed);
    case JM_LENT_OUT:     return units(j->acct.lent_out);
    case JM_CALLS:        return (double)j->st.calls;
    case JM_ALLOWED:      return (double)j->st.allowed;
    case JM_WAITED:       return (double)j->st.waited;
    case JM_REJECTED:     return (double)j->st.rejected;
    case JM_DROPPED:      return (double)j->st.dropped;
    case JM_CHARGED:      return units(j->st.charged);
    case JM_ENTITLED:     return units(j->acct.entitled_total);
    case JM_BORROWED:     return units(j->acct.borrowed_total);
    case JM_LENT:         return units(j->acct.lent_total);
    case JM_WAIT_SECONDS: return (double)j->st.wait_us_total / 1e6;
    case JM_COUNT:        break;
    }
    return 0;
}

static void write_metrics(FILE *out)
{
    unsigned long long cumulative = 0;
    size_t n, i;
    struct job **v = jobs_by_id(&n);
    int b, m;

    scalar(out, "sg_up_seconds", "gauge", "Seconds since sgd started", (double)(sg_now_us() - S.start_us) / 1e6);
    scalar(out, "sg_borrowing_enabled", "gauge", "1 if budget borrowing is enabled", cfg.borrow.enabled);
    scalar(out, "sg_global_rate_units", "gauge", "Global refill rate R_g in cost units per second",
           (double)cfg.global_rate);
    scalar(out, "sg_global_tokens_units", "gauge", "Tokens in the global bucket", units(S.global.tokens));
    scalar(out, "sg_global_capacity_units", "gauge", "Global bucket capacity", units(S.global.capacity));
    scalar(out, "sg_global_entitled_units_total", "counter", "Cost units credited to the global bucket",
           units(S.global_entitled));
    scalar(out, "sg_jobs", "gauge", "Jobs currently governed", (double)n);
    scalar(out, "sg_waiting_calls", "gauge", "Calls currently held (WAIT)", (double)S.wq.n);
    scalar(out, "sg_calls_total", "counter", "Costed calls received by all jobs", (double)S.total.calls);
    scalar(out, "sg_allowed_total", "counter", "Calls admitted", (double)S.total.allowed);
    scalar(out, "sg_waited_total", "counter", "Calls that had to wait", (double)S.total.waited);
    scalar(out, "sg_rejected_total", "counter", "Calls rejected", (double)S.total.rejected);
    scalar(out, "sg_dropped_total", "counter", "Waiting calls whose thread died", (double)S.total.dropped);
    scalar(out, "sg_charged_units_total", "counter", "Cost units charged to all jobs", units(S.total.charged));
    scalar(out, "sg_loans_opened_total", "counter", "Loans opened", (double)S.ledger.opened);
    scalar(out, "sg_loans_repaid_total", "counter", "Loans fully repaid", (double)S.ledger.repaid);
    scalar(out, "sg_loans_written_off_total", "counter", "Loans written off because a party exited",
           (double)S.ledger.written_off);

    header(out, "sg_admission_wait_seconds", "histogram", "Time from arrival to admission of allowed calls");
    for (b = 0; b < WAIT_BUCKETS; b++) {
        cumulative += S.wait_hist[b];
        fprintf(out, "sg_admission_wait_seconds_bucket{le=\"%g\"} %llu\n", (double)sg_wait_bounds_us[b] / 1e6,
                cumulative);
    }
    cumulative += S.wait_hist[WAIT_BUCKETS];
    fprintf(out, "sg_admission_wait_seconds_bucket{le=\"+Inf\"} %llu\n", cumulative);
    fprintf(out, "sg_admission_wait_seconds_sum %.6f\n", (double)S.wait_hist_sum_us / 1e6);
    fprintf(out, "sg_admission_wait_seconds_count %llu\n", cumulative);

    for (m = 0; m < JM_COUNT; m++) {
        header(out, job_metrics[m].name, job_metrics[m].type, job_metrics[m].help);
        for (i = 0; i < n; i++)
            fprintf(out, "%s{job=\"%u\",name=\"%s\"} %.17g\n", job_metrics[m].name, v[i]->acct.id, v[i]->name,
                    job_value(v[i], (enum job_metric)m));
    }
    free(v);
}

static void log_change(const char *ev, const struct job *j, long long value)
{
    if (!cfg.log)
        return;
    fprintf(cfg.log, "{\"t_us\":%lld,\"ev\":\"%s\",\"job\":%u,\"value\":%lld,\"rate\":%lld}\n",
            (long long)sg_now_us(), ev, j->acct.id, value, (long long)j->acct.bucket.rate);
    fflush(cfg.log);
}

void ctl_handle(int fd, const struct sg_ctl *ctl)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&buf, &len);
    struct job *j = NULL;

    if (!out)
        return;
    if (ctl->cmd == SG_CTL_SET_PRIO || ctl->cmd == SG_CTL_SET_RATE) {
        j = find_job(ctl->job);
        if (!j) {
            fprintf(out, "error: no job %u\n", ctl->job);
            goto send;
        }
    }

    switch (ctl->cmd) {
    case SG_CTL_STATUS:
        write_status(out);
        break;
    case SG_CTL_LOANS:
        write_loans(out);
        break;
    case SG_CTL_METRICS:
        write_metrics(out);
        break;
    case SG_CTL_SET_PRIO:
        if (ctl->value < SG_PRIO_MIN || ctl->value > SG_PRIO_MAX) {
            fprintf(out, "error: priority must be %d..%d\n", SG_PRIO_MIN, SG_PRIO_MAX);
            break;
        }
        j->acct.prio = (int)ctl->value;
        rekey_job(j);
        recompute_rates(sg_now_us());
        log_change("set_prio", j, ctl->value);
        fprintf(out, "ok: job %u (%s) priority %d, rate %lld units/s\n", j->acct.id, j->name, j->acct.prio,
                (long long)j->acct.bucket.rate);
        break;
    case SG_CTL_SET_RATE:
        if (ctl->value < 0) {
            fprintf(out, "error: rate must be >= 0 (0 = priority share)\n");
            break;
        }
        j->fixed_rate = ctl->value;
        recompute_rates(sg_now_us());
        log_change("set_rate", j, ctl->value);
        fprintf(out, "ok: job %u (%s) %s rate %lld units/s\n", j->acct.id, j->name,
                j->fixed_rate ? "fixed" : "share", (long long)j->acct.bucket.rate);
        break;
    default:
        fprintf(out, "error: unknown command %d\n", ctl->cmd);
    }
send:
    fclose(out);
    send_all(fd, buf, len);
    free(buf);
}

int http_open(int port)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int one = 1, fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void http_on_accept(void)
{
    struct conn *c;
    int fd = accept4(S.http_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

    if (fd < 0)
        return;
    c = calloc(1, sizeof *c);
    if (!c)
        die("calloc");
    c->kind = EP_HTTP;
    c->fd = fd;
    ep_add(fd, c);
}

void http_on_request(struct conn *c)
{
    char req[1024], head[256], *body = NULL;
    size_t blen = 0;
    ssize_t n = read(c->fd, req, sizeof req - 1);
    FILE *out;
    int ok, hlen;

    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return;
    if (n > 0) {
        req[n] = '\0';
        ok = strncmp(req, "GET /metrics ", 13) == 0 || strncmp(req, "GET /metrics?", 13) == 0;
        out = open_memstream(&body, &blen);
        if (out) {
            if (ok)
                write_metrics(out);
            else
                fputs("not found; try /metrics\n", out);
            fclose(out);
            hlen = snprintf(head, sizeof head,
                            "HTTP/1.0 %s\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                            "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                            ok ? "200 OK" : "404 Not Found", blen);
            send_all(c->fd, head, (size_t)hlen);
            send_all(c->fd, body, blen);
            free(body);
        }
    }
    close(c->fd);
    free(c);
}
