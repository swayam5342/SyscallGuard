#define _GNU_SOURCE
#include "proto.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

void sg_default_sock(char *buf, size_t len)
{
    snprintf(buf, len, "/tmp/syscallguard-%u.sock", (unsigned)getuid());
}

static const char *const fork_policy_names[SG_FORK_COUNT] = { "brief", "wait", "reject" };

const char *sg_fork_policy_name(int policy)
{
    return policy >= 0 && policy < SG_FORK_COUNT ? fork_policy_names[policy] : "?";
}

int sg_fork_policy_parse(const char *s)
{
    int i;

    for (i = 0; i < SG_FORK_COUNT; i++)
        if (strcmp(s, fork_policy_names[i]) == 0)
            return i;
    return -1;
}

int sg_send_fd(int sock, const void *buf, size_t len, int fd)
{
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
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
    return sendmsg(sock, &msg, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

ssize_t sg_recv_fd(int sock, void *buf, size_t len, int *fd)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len };
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
    ssize_t n;

    *fd = -1;
    n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0)
        return n;
    for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
            memcpy(fd, CMSG_DATA(c), sizeof(int));
    return n;
}
