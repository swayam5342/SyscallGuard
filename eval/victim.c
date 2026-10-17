/*
 * Victim probe: an interactive, latency-sensitive job. Every INTERVAL_MS it
 * appends a 64-byte record to FILE (and fsyncs it in "sync" mode), and
 * records how long the whole open/write/[fsync]/close took. Prints latency
 * percentiles as JSON.
 *
 *   victim FILE DURATION_S INTERVAL_MS [sync|nosync]
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;

    return (x > y) - (x < y);
}

/*
 * Time this process spent runnable but waiting for a CPU, from
 * /proc/self/schedstat ("run_ns wait_ns timeslices"); -1 if unavailable.
 */
static long long rq_wait_ns(void)
{
    unsigned long long run, wait;
    FILE *f = fopen("/proc/self/schedstat", "r");
    int n;

    if (!f)
        return -1;
    n = fscanf(f, "%llu %llu", &run, &wait);
    fclose(f);
    return n == 2 ? (long long)wait : -1;
}

/* Nearest-rank percentile of a sorted array. */
static long long pct(const int64_t *v, size_t n, unsigned p)
{
    size_t rank = (p * n + 99) / 100;

    if (n == 0)
        return 0;
    return (long long)v[rank ? rank - 1 : 0];
}

int main(int argc, char **argv)
{
    int64_t start, end, next, *lat, sum = 0;
    long long rq0, rq1;
    size_t n = 0, cap;
    long interval_ms;
    char rec[64];
    int errors = 0, sync_mode;

    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s FILE DURATION_S INTERVAL_MS [sync|nosync]\n", argv[0]);
        return 2;
    }
    sync_mode = argc == 4 || strcmp(argv[4], "nosync") != 0;
    interval_ms = atol(argv[3]);
    if (interval_ms < 1)
        return 2;
    cap = (size_t)(atof(argv[2]) * 1000 / interval_ms) + 16;
    lat = malloc(cap * sizeof *lat);
    if (!lat)
        return 1;
    memset(rec, 'v', sizeof rec - 1);
    rec[sizeof rec - 1] = '\n';

    rq0 = rq_wait_ns();
    start = now_ns();
    end = start + (int64_t)(atof(argv[2]) * 1e9);
    next = start;
    while (next < end) {
        int64_t t0 = now_ns(), t1;
        int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600), ok = fd >= 0;

        if (ok && (write(fd, rec, sizeof rec) != (ssize_t)sizeof rec || (sync_mode && fsync(fd) < 0)))
            ok = 0;
        if (fd >= 0)
            close(fd);
        t1 = now_ns();
        if (ok && n < cap) {
            lat[n++] = (t1 - t0) / 1000;
            sum += (t1 - t0) / 1000;
        } else if (!ok) {
            errors++;
        }
        next += interval_ms * 1000000;
        if (next > t1) {
            struct timespec ts = { .tv_sec = next / 1000000000, .tv_nsec = next % 1000000000 };

            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
        } else {
            next = t1;   /* fell behind: do not burst to catch up */
        }
    }

    rq1 = rq_wait_ns();
    qsort(lat, n, sizeof *lat, cmp_i64);
    printf("{\"ops\":%zu,\"errors\":%d,\"p50_us\":%lld,\"p95_us\":%lld,\"p99_us\":%lld,\"max_us\":%lld,"
           "\"mean_us\":%.1f,\"rq_wait_us\":%lld}\n",
           n, errors, pct(lat, n, 50), pct(lat, n, 95), pct(lat, n, 99), n ? (long long)lat[n - 1] : 0,
           n ? (double)sum / (double)n : 0.0, rq0 >= 0 && rq1 >= 0 ? (rq1 - rq0) / 1000 : -1);
    free(lat);
    return 0;
}
