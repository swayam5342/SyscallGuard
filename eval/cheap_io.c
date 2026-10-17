/*
 * Well-behaved busy job: tiny reads and writes that are cheap for the
 * kernel (read 64 B from /dev/zero, write it to /dev/null) for DURATION_S
 * seconds. A call-counting limiter cannot tell these apart from fsync.
 *
 *   cheap_io DURATION_S
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    long long ops = 0, errors = 0, i;
    double start, end, elapsed;
    struct rusage ru;
    char buf[64];
    int in, out;

    if (argc != 2) {
        fprintf(stderr, "usage: %s DURATION_S\n", argv[0]);
        return 2;
    }
    in = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    out = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (in < 0 || out < 0)
        return 1;
    start = now_s();
    end = start + atof(argv[1]);
    while (now_s() < end) {
        for (i = 0; i < 64; i++) {   /* check the clock every 64 ops */
            if (read(in, buf, sizeof buf) == (ssize_t)sizeof buf && write(out, buf, sizeof buf) == (ssize_t)sizeof buf)
                ops++;
            else
                errors++;
        }
    }
    elapsed = now_s() - start;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"ops\":%lld,\"ops_per_s\":%.1f,\"errors\":%lld,\"sys_s\":%.3f}\n", ops, (double)ops / elapsed, errors,
           (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6);
    return 0;
}
