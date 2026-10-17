/*
 * Metadata storm: PROCS workers create, write, close and unlink files in
 * DIR as fast as they can for DURATION_S seconds. Every operation takes the
 * directory's inode lock, so a victim working in the same directory has to
 * queue behind them. Prints totals as JSON.
 *
 *   meta_storm DIR DURATION_S PROCS
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct result {
    long long ops, errors;
};

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Kernel CPU time of this process and its reaped workers. */
static double sys_seconds(void)
{
    struct rusage self, kids;

    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &kids);
    return (double)(self.ru_stime.tv_sec + kids.ru_stime.tv_sec) +
           (double)(self.ru_stime.tv_usec + kids.ru_stime.tv_usec) / 1e6;
}

static void worker(const char *dir, int id, double end, int out)
{
    struct result r = { 0, 0 };
    char path[4096];

    while (now_s() < end) {
        int fd;

        snprintf(path, sizeof path, "%s/storm-%d-%lld", dir, id, r.ops % 64);
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0 && unlink(path) == 0)
            r.ops++;
        else
            r.errors++;
    }
    if (write(out, &r, sizeof r) != (ssize_t)sizeof r)
        _exit(1);
    _exit(0);
}

int main(int argc, char **argv)
{
    struct result total = { 0, 0 }, r;
    int procs, started = 0, i, p[2];
    double start, end, elapsed;

    if (argc != 4) {
        fprintf(stderr, "usage: %s DIR DURATION_S PROCS\n", argv[0]);
        return 2;
    }
    procs = atoi(argv[3]);
    if (procs < 1 || procs > 64 || pipe(p) < 0)
        return 2;
    start = now_s();
    end = start + atof(argv[2]);
    for (i = 0; i < procs; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            close(p[0]);
            worker(argv[1], i, end, p[1]);
        }
        if (pid > 0)
            started++;
    }
    close(p[1]);
    while (read(p[0], &r, sizeof r) == (ssize_t)sizeof r) {
        total.ops += r.ops;
        total.errors += r.errors;
    }
    while (wait(NULL) > 0)
        ;
    elapsed = now_s() - start;
    printf("{\"workers\":%d,\"ops\":%lld,\"ops_per_s\":%.1f,\"errors\":%lld,\"sys_s\":%.3f}\n", started, total.ops,
           (double)total.ops / elapsed, total.errors, sys_seconds());
    return 0;
}
