/*
 * Per-call overhead microbenchmark. Times getppid() (never costed: under
 * SyscallGuard it only pays for the in-kernel seccomp filter) and a 1-byte
 * read() from /dev/zero (costed: under SyscallGuard it makes a round trip
 * to sgd). Run it natively and under sg-launch and compare.
 *
 *   bench_syscall FAST_ITERS SLOW_ITERS
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    long fast, slow, i;
    int64_t t0, t_fast, t_slow;
    char c;
    int fd;

    if (argc != 3) {
        fprintf(stderr, "usage: %s FAST_ITERS SLOW_ITERS\n", argv[0]);
        return 2;
    }
    fast = atol(argv[1]);
    slow = atol(argv[2]);
    fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fast < 1 || slow < 1)
        return 1;

    t0 = now_ns();
    for (i = 0; i < fast; i++)
        syscall(SYS_getppid);   /* bypass any libc caching */
    t_fast = now_ns() - t0;

    t0 = now_ns();
    for (i = 0; i < slow; i++)
        if (read(fd, &c, 1) != 1)
            return 1;
    t_slow = now_ns() - t0;

    printf("{\"getppid_ns\":%.1f,\"read_ns\":%.1f}\n", (double)t_fast / (double)fast,
           (double)t_slow / (double)slow);
    return 0;
}
