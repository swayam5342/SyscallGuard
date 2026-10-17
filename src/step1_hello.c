/*
 * step1_hello: run a command and log every openat() it makes, using seccomp
 * user notification. Each call is let through with CONTINUE.
 *
 *   ./build/step1_hello ls /
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define SG_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "SyscallGuard supports x86-64 and aarch64 only"
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

static void die(const char *what)
{
    perror(what);
    exit(1);
}

static int sys_seccomp(unsigned int op, unsigned int flags, void *args)
{
    return (int)syscall(SYS_seccomp, op, flags, args);
}

/* Kill on a foreign architecture, notify on openat, allow the rest. Returns the listener fd. */
static int install_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SG_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof filter / sizeof filter[0],
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return sys_seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

static int send_fd(int sock, int fd)
{
    char byte = 'x';
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } ctrl;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl.buf,
        .msg_controllen = sizeof ctrl.buf,
    };
    struct cmsghdr *c;

    memset(&ctrl, 0, sizeof ctrl);
    c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int recv_fd(int sock)
{
    char byte;
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } ctrl;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl.buf,
        .msg_controllen = sizeof ctrl.buf,
    };
    struct cmsghdr *c;
    int fd;

    if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != 1)
        return -1;
    c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
        return -1;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

/* For the log only; sgd decides from register arguments alone. */
static void read_path(pid_t pid, unsigned long long addr, char *out, size_t len)
{
    char mem[64];
    ssize_t n;
    int fd;

    snprintf(mem, sizeof mem, "/proc/%d/mem", pid);
    fd = open(mem, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(out, len, "?");
        return;
    }
    n = pread(fd, out, len - 1, (off_t)addr);
    close(fd);
    if (n <= 0) {
        snprintf(out, len, "?");
        return;
    }
    out[n] = '\0';
}

int main(int argc, char **argv)
{
    struct seccomp_notif_sizes sizes;
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    long intercepted = 0;
    int sv[2], lfd, pidfd, status = 0;
    pid_t child;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 2;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
        die("socketpair");

    child = fork();
    if (child < 0)
        die("fork");

    if (child == 0) {
        /*
         * Once the filter is installed, an openat blocks until someone reads
         * the listener, so the fd must be handed over before any openat.
         */
        close(sv[0]);
        lfd = install_filter();
        if (lfd < 0) {
            perror("seccomp");
            _exit(127);
        }
        if (send_fd(sv[1], lfd) < 0) {
            perror("send_fd");
            _exit(127);
        }
        close(lfd);
        close(sv[1]);
        execvp(argv[1], argv + 1);
        perror("execvp");
        _exit(127);
    }

    close(sv[1]);
    lfd = recv_fd(sv[0]);
    close(sv[0]);
    if (lfd < 0)
        die("recv_fd");

    /*
     * The kernel drops a task's filter only when the task is reaped, so the
     * listener never reports POLLHUP while our child is a zombie.
     */
    pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (pidfd < 0)
        die("pidfd_open");

    if (sys_seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
        die("SECCOMP_GET_NOTIF_SIZES");
    req = malloc(sizes.seccomp_notif);
    resp = malloc(sizes.seccomp_notif_resp);
    if (!req || !resp)
        die("malloc");

    for (;;) {
        struct pollfd pfds[2] = {
            { .fd = lfd, .events = POLLIN },
            { .fd = pidfd, .events = POLLIN },
        };
        struct pollfd *pfd = &pfds[0];
        char path[256];

        if (poll(pfds, pidfd >= 0 ? 2 : 1, -1) < 0) {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        if (pidfd >= 0 && (pfds[1].revents & POLLIN)) {
            if (waitpid(child, &status, 0) < 0)
                die("waitpid");
            close(pidfd);
            pidfd = -1;
        }

        if (pfd->revents & POLLIN) {
            memset(req, 0, sizes.seccomp_notif);
            if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
                /* ENOENT: the thread was killed before we received it */
                if (errno == EINTR || errno == ENOENT)
                    continue;
                die("NOTIF_RECV");
            }

            read_path(req->pid, req->data.args[1], path, sizeof path);
            /* The path is only meaningful if the thread is still waiting. */
            if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0)
                fprintf(stderr, "[sg] pid=%-6d openat(\"%s\", flags=0x%llx)\n",
                        req->pid, path, (unsigned long long)req->data.args[2]);

            memset(resp, 0, sizes.seccomp_notif_resp);
            resp->id = req->id;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT)
                die("NOTIF_SEND");
            intercepted++;
            continue;
        }

        /* POLLHUP: every process using the filter has exited and been reaped. */
        if (pfd->revents & (POLLHUP | POLLERR))
            break;
    }

    if (pidfd >= 0 && waitpid(child, &status, 0) < 0)
        die("waitpid");
    fprintf(stderr, "[sg] intercepted %ld openat call(s)\n", intercepted);
    free(req);
    free(resp);
    close(lfd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
