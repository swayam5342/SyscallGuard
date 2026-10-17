/*
 * Noisy neighbour: PROCS workers each overwrite a BLOCK-byte block of their
 * own file and fsync it, as fast as they can, for DURATION_S seconds.
 * Durability calls are the most expensive class, so this is cheap to issue
 * and expensive for the kernel and the disk. Prints totals as JSON.
 *
 *   fsync_flood DIR DURATION_S PROCS BLOCK_BYTES
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static void worker(const char *dir, int id, double end, size_t block, int out)
{
    struct result r = { 0, 0 };
    char path[4096], *buf = malloc(block);
    int fd;

    snprintf(path, sizeof path, "%s/flood-%d", dir, id);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || !buf)
        _exit(1);
    memset(buf, 'f', block);
    while (now_s() < end) {
        off_t off = (off_t)(r.ops % 256) * (off_t)block;

        if (pwrite(fd, buf, block, off) == (ssize_t)block && fsync(fd) == 0)
            r.ops++;
        else
            r.errors++;
    }
    close(fd);
    if (write(out, &r, sizeof r) != (ssize_t)sizeof r)
        _exit(1);
    _exit(0);
}

int main(int argc, char **argv)
{
    struct result total = { 0, 0 }, r;
    int procs, started = 0, fork_failed = 0, i, p[2];
    double start, end, elapsed;
    size_t block;

    if (argc != 5) {
        fprintf(stderr, "usage: %s DIR DURATION_S PROCS BLOCK_BYTES\n", argv[0]);
        return 2;
    }
    procs = atoi(argv[3]);
    block = (size_t)atol(argv[4]);
    if (procs < 1 || block < 1 || pipe(p) < 0)
        return 2;
    start = now_s();
    end = start + atof(argv[2]);
    for (i = 0; i < procs; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            close(p[0]);
            worker(argv[1], i, end, block, p[1]);
        }
        if (pid > 0)
            started++;
        else
            fork_failed++;
    }
    close(p[1]);
    while (read(p[0], &r, sizeof r) == (ssize_t)sizeof r) {
        total.ops += r.ops;
        total.errors += r.errors;
    }
    while (wait(NULL) > 0)
        ;
    elapsed = now_s() - start;
    printf("{\"workers\":%d,\"fork_failed\":%d,\"ops\":%lld,\"ops_per_s\":%.1f,\"errors\":%lld,\"sys_s\":%.3f}\n",
           started, fork_failed, total.ops, (double)total.ops / elapsed, total.errors, sys_seconds());
    return 0;
}
