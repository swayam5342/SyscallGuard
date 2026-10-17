/*
 * Bounded fork pressure: PROCS workers each fork a child that exits at once
 * and reap it, in a loop, for DURATION_S seconds. At most 2*PROCS+1
 * processes exist at any time, so this is safe to run on a shared machine
 * (unlike an unbounded fork bomb). Prints totals as JSON.
 *
 *   fork_pressure DURATION_S PROCS
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct result {
    long long forks, eagain, other;
};

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Kernel CPU time of this process and its reaped workers (and theirs). */
static double sys_seconds(void)
{
    struct rusage self, kids;

    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &kids);
    return (double)(self.ru_stime.tv_sec + kids.ru_stime.tv_sec) +
           (double)(self.ru_stime.tv_usec + kids.ru_stime.tv_usec) / 1e6;
}

static void worker(double end, int out)
{
    struct result r = { 0, 0, 0 };

    while (now_s() < end) {
        pid_t pid = fork();

        if (pid == 0)
            _exit(0);
        if (pid > 0) {
            r.forks++;
            waitpid(pid, NULL, 0);
        } else if (errno == EAGAIN) {
            r.eagain++;
        } else {
            r.other++;
        }
    }
    if (write(out, &r, sizeof r) != (ssize_t)sizeof r)
        _exit(1);
    _exit(0);
}

int main(int argc, char **argv)
{
    struct result total = { 0, 0, 0 }, r;
    int procs, started = 0, i, p[2];
    double start, end, elapsed;

    if (argc != 3) {
        fprintf(stderr, "usage: %s DURATION_S PROCS\n", argv[0]);
        return 2;
    }
    procs = atoi(argv[2]);
    if (procs < 1 || procs > 64 || pipe(p) < 0)
        return 2;
    start = now_s();
    end = start + atof(argv[1]);
    for (i = 0; i < procs; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            close(p[0]);
            worker(end, p[1]);
        }
        if (pid > 0)
            started++;
    }
    close(p[1]);
    while (read(p[0], &r, sizeof r) == (ssize_t)sizeof r) {
        total.forks += r.forks;
        total.eagain += r.eagain;
        total.other += r.other;
    }
    while (wait(NULL) > 0)
        ;
    elapsed = now_s() - start;
    printf("{\"workers\":%d,\"forks\":%lld,\"forks_per_s\":%.1f,\"eagain\":%lld,\"other_errors\":%lld,"
           "\"sys_s\":%.3f}\n",
           started, total.forks, (double)total.forks / elapsed, total.eagain, total.other, sys_seconds());
    return 0;
}
