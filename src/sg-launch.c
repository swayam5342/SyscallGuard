/*
 * sg-launch: run a command as a SyscallGuard job.
 *
 *   sg-launch [-s sock] [-p prio] [-r rate] [-n name] [-f brief|wait|reject] -- command [args...]
 *
 * Installs the SyscallGuard seccomp filter on itself, hands the listener fd
 * to sgd, then execs the command. Every process and thread the command
 * creates inherits the filter, so the whole tree is one job with one budget.
 *
 * Exit status: the command's own status, 125 if sg-launch itself failed,
 * 126 if the command could not be executed, 127 if it was not found.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#include "costs.h"
#include "proto.h"

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-s sock] [-p prio] [-r rate] [-n name] [-f policy] -- command [args...]\n"
            "  -s sock   sgd socket (default /tmp/syscallguard-<uid>.sock)\n"
            "  -p prio   priority %d (lowest) .. %d (highest), default 5\n"
            "  -r rate   fixed budget in cost units/s instead of a priority share\n"
            "  -n name   job name shown in sgd's log\n"
            "  -f, --fork-policy brief|wait|reject\n"
            "            when process creation is short of budget: wait up to sgd's bound then\n"
            "            fail (brief, default), wait like other calls (wait), or fail at once (reject)\n",
            argv0, SG_PRIO_MIN, SG_PRIO_MAX);
    exit(125);
}

static long parse_long(const char *s, const char *argv0)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *s == '\0' || *end != '\0')
        usage(argv0);
    return v;
}

static int connect_sgd(const char *path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int fd;

    if (strlen(path) >= sizeof addr.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(addr.sun_path, path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    static const struct option longopts[] = {
        { "fork-policy", required_argument, NULL, 'f' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    struct sg_register reg = { .magic = SG_PROTO_MAGIC, .prio = 5, .fork_policy = SG_FORK_BRIEF };
    char sock_path[SG_SOCK_MAX];
    const char *name = NULL, *slash;
    struct sock_fprog prog;
    struct sg_ack ack;
    int opt, sock, lfd;
    ssize_t n;

    sg_default_sock(sock_path, sizeof sock_path);
    while ((opt = getopt_long(argc, argv, "+s:p:r:n:f:h", longopts, NULL)) != -1) {
        switch (opt) {
        case 's':
            snprintf(sock_path, sizeof sock_path, "%s", optarg);
            break;
        case 'p':
            reg.prio = (int32_t)parse_long(optarg, argv[0]);
            if (reg.prio < SG_PRIO_MIN || reg.prio > SG_PRIO_MAX)
                usage(argv[0]);
            break;
        case 'r':
            reg.rate = parse_long(optarg, argv[0]);
            if (reg.rate < 1)
                usage(argv[0]);
            break;
        case 'n':
            name = optarg;
            break;
        case 'f':
            reg.fork_policy = sg_fork_policy_parse(optarg);
            if (reg.fork_policy < 0)
                usage(argv[0]);
            break;
        default:
            usage(argv[0]);
        }
    }
    if (optind >= argc)
        usage(argv[0]);
    if (!name) {
        slash = strrchr(argv[optind], '/');
        name = slash ? slash + 1 : argv[optind];
    }
    snprintf(reg.name, sizeof reg.name, "%s", name);

    sock = connect_sgd(sock_path);
    if (sock < 0) {
        fprintf(stderr, "sg-launch: cannot reach sgd at %s: %s\n", sock_path, strerror(errno));
        return 125;
    }
    if (sg_build_filter(&prog) < 0) {
        perror("sg-launch: building filter");
        return 125;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("sg-launch: PR_SET_NO_NEW_PRIVS");
        return 125;
    }
    /* WAIT_KILLABLE_RECV (5.19+): a held call is not disturbed by non-fatal signals. */
    lfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, &prog);
    if (lfd < 0 && errno == EINVAL)
        lfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (lfd < 0) {
        perror("sg-launch: seccomp");
        return 125;
    }

    /*
     * From here on a costed call blocks until someone reads the listener, so
     * it must reach sgd first (sendmsg and close are not costed). On failure,
     * closing our copy turns costed calls into ENOSYS instead of a hang.
     */
    if (sg_send_fd(sock, &reg, sizeof reg, lfd) < 0) {
        close(lfd);
        _exit(125);
    }
    close(lfd);

    /* This read is itself costed; sgd already holds the listener and answers it. */
    n = read(sock, &ack, sizeof ack);
    if (n != (ssize_t)sizeof ack) {
        fprintf(stderr, "sg-launch: sgd did not accept the job: %s\n",
                n < 0 ? strerror(errno) : "short reply");
        return 125;
    }
    if (ack.status) {
        fprintf(stderr, "sg-launch: sgd rejected the job: %s\n", strerror(-ack.status));
        return 125;
    }
    close(sock);

    execvp(argv[optind], argv + optind);
    fprintf(stderr, "sg-launch: %s: %s\n", argv[optind], strerror(errno));
    return errno == ENOENT ? 127 : 126;
}
