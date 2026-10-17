/*
 * sgctl: inspect and adjust a running sgd.
 *
 *   sgctl [-s sock] status
 *   sgctl [-s sock] loans
 *   sgctl [-s sock] metrics
 *   sgctl [-s sock] set-prio JOB PRIO
 *   sgctl [-s sock] set-rate JOB RATE     (RATE 0 = back to priority share)
 *
 * Exit status: 0 ok, 1 sgd reported an error, 2 usage, 3 sgd unreachable.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "proto.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-s sock] status | loans | metrics | set-prio JOB PRIO | set-rate JOB RATE\n",
            argv0);
    exit(2);
}

static long long parse_num(const char *s, const char *argv0)
{
    char *end;
    long long v;

    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno || *s == '\0' || *end != '\0')
        usage(argv0);
    return v;
}

int main(int argc, char **argv)
{
    struct sg_ctl ctl = { .magic = SG_CTL_MAGIC };
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    char sock_path[SG_SOCK_MAX], *buf = NULL;
    size_t len = 0, cap = 0;
    const char *cmd;
    int opt, fd, nargs;

    sg_default_sock(sock_path, sizeof sock_path);
    while ((opt = getopt(argc, argv, "s:h")) != -1) {
        if (opt != 's')
            usage(argv[0]);
        snprintf(sock_path, sizeof sock_path, "%s", optarg);
    }
    if (optind >= argc)
        usage(argv[0]);
    cmd = argv[optind];
    nargs = argc - optind - 1;

    if (strcmp(cmd, "status") == 0 && nargs == 0) {
        ctl.cmd = SG_CTL_STATUS;
    } else if (strcmp(cmd, "loans") == 0 && nargs == 0) {
        ctl.cmd = SG_CTL_LOANS;
    } else if (strcmp(cmd, "metrics") == 0 && nargs == 0) {
        ctl.cmd = SG_CTL_METRICS;
    } else if ((strcmp(cmd, "set-prio") == 0 || strcmp(cmd, "set-rate") == 0) && nargs == 2) {
        long long job = parse_num(argv[optind + 1], argv[0]);

        if (job < 1 || job > UINT32_MAX)
            usage(argv[0]);
        ctl.cmd = cmd[4] == 'p' ? SG_CTL_SET_PRIO : SG_CTL_SET_RATE;
        ctl.job = (uint32_t)job;
        ctl.value = parse_num(argv[optind + 2], argv[0]);
    } else {
        usage(argv[0]);
    }

    strcpy(addr.sun_path, sock_path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        fprintf(stderr, "sgctl: cannot reach sgd at %s: %s\n", sock_path, strerror(errno));
        return 3;
    }
    if (write(fd, &ctl, sizeof ctl) != (ssize_t)sizeof ctl) {
        perror("sgctl: write");
        return 3;
    }
    for (;;) {
        ssize_t n;

        if (len == cap) {
            cap = cap ? cap * 2 : 4096;
            buf = realloc(buf, cap);
            if (!buf) {
                perror("sgctl");
                return 3;
            }
        }
        n = read(fd, buf + len, cap - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        len += (size_t)n;
    }
    close(fd);

    if (len >= 6 && memcmp(buf, "error:", 6) == 0) {
        fwrite(buf, 1, len, stderr);
        free(buf);
        return 1;
    }
    fwrite(buf, 1, len, stdout);
    free(buf);
    return 0;
}
