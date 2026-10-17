#define _GNU_SOURCE
#include "costs.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#define SG_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "SyscallGuard supports x86-64 and aarch64 only"
#endif

/* Seed costs; tools/sg_calibrate.py measures real ones for a given machine. */
const struct sg_class_info sg_classes[SG_C_COUNT] = {
    [SG_C_DATA]    = { "data_io",    1,  1u << 16, SG_WAIT,   0 },
    [SG_C_META]    = { "metadata",   3,  0,        SG_WAIT,   0 },
    [SG_C_DURABLE] = { "durability", 20, 0,        SG_WAIT,   0 },
    [SG_C_MMAP]    = { "memory_map", 2,  1u << 20, SG_WAIT,   0 },
    [SG_C_PROC]    = { "process",    30, 0,        SG_REJECT, EAGAIN },
    /* Threads wait rather than fail: many programs abort if pthread_create fails. */
    [SG_C_THREAD]  = { "thread",     10, 0,        SG_WAIT,   0 },
    [SG_C_EXEC]    = { "exec",       40, 0,        SG_WAIT,   0 },
    [SG_C_NET]     = { "net_setup",  4,  0,        SG_WAIT,   0 },
};

#define E(sys, cls, size_arg) { __NR_##sys, #sys, cls, size_arg }

static const struct sg_syscall table[] = {
    E(read, SG_C_DATA, 2),
    E(write, SG_C_DATA, 2),
    E(pread64, SG_C_DATA, 2),
    E(pwrite64, SG_C_DATA, 2),
    E(readv, SG_C_DATA, -1),
    E(writev, SG_C_DATA, -1),
    E(preadv, SG_C_DATA, -1),
    E(pwritev, SG_C_DATA, -1),
    E(sendto, SG_C_DATA, 2),
    E(recvfrom, SG_C_DATA, 2),

    E(openat, SG_C_META, -1),
#ifdef __NR_openat2
    E(openat2, SG_C_META, -1),
#endif
#ifdef __NR_open
    E(open, SG_C_META, -1),
#endif
#ifdef __NR_creat
    E(creat, SG_C_META, -1),
#endif
    E(unlinkat, SG_C_META, -1),
#ifdef __NR_unlink
    E(unlink, SG_C_META, -1),
#endif
#ifdef __NR_rmdir
    E(rmdir, SG_C_META, -1),
#endif
    E(renameat2, SG_C_META, -1),
#ifdef __NR_renameat
    E(renameat, SG_C_META, -1),
#endif
#ifdef __NR_rename
    E(rename, SG_C_META, -1),
#endif
    E(mkdirat, SG_C_META, -1),
#ifdef __NR_mkdir
    E(mkdir, SG_C_META, -1),
#endif

    E(fsync, SG_C_DURABLE, -1),
    E(fdatasync, SG_C_DURABLE, -1),
    E(sync, SG_C_DURABLE, -1),
    E(syncfs, SG_C_DURABLE, -1),

    E(mmap, SG_C_MMAP, 1),
    E(munmap, SG_C_MMAP, 1),
    E(mremap, SG_C_MMAP, 2),
    E(brk, SG_C_MMAP, -1),

#ifdef __NR_fork
    E(fork, SG_C_PROC, -1),
#endif
#ifdef __NR_vfork
    E(vfork, SG_C_PROC, -1),
#endif
    E(clone, SG_C_PROC, -1),   /* reclassified as THREAD when CLONE_THREAD is set */

    E(execve, SG_C_EXEC, -1),
    E(execveat, SG_C_EXEC, -1),

    E(socket, SG_C_NET, -1),
    E(connect, SG_C_NET, -1),
    E(bind, SG_C_NET, -1),
    E(accept4, SG_C_NET, -1),
#ifdef __NR_accept
    E(accept, SG_C_NET, -1),
#endif
};

#define NTABLE (sizeof table / sizeof table[0])

/* Calls answered inside the kernel without a supervisor round trip. */
static const struct { int nr; int err; } denied[] = {
#ifdef __NR_clone3
    /* clone3 passes its flags in memory; ENOSYS makes glibc fall back to clone(). */
    { __NR_clone3, ENOSYS },
#endif
#ifdef __NR_io_uring_setup
    /* One io_uring_enter can submit many operations, bypassing per-call accounting. */
    { __NR_io_uring_setup, EPERM },
#endif
};

#define NDENIED (sizeof denied / sizeof denied[0])

#define MAX_NR 1024
static const struct sg_syscall *index_by_nr[MAX_NR];
static int index_ready;

/* Calibrated base costs; 0 = use the class seed. */
static int64_t calibrated[MAX_NR];
static int64_t calibrated_thread;

const struct sg_syscall *sg_lookup(int nr)
{
    size_t i;

    if (!index_ready) {
        for (i = 0; i < NTABLE; i++)
            if (table[i].nr >= 0 && table[i].nr < MAX_NR)
                index_by_nr[table[i].nr] = &table[i];
        index_ready = 1;
    }
    if (nr < 0 || nr >= MAX_NR)
        return NULL;
    return index_by_nr[nr];
}

int64_t sg_cost(const struct sg_syscall *s, const __u64 args[6], enum sg_class *cls_out)
{
    enum sg_class cls = s->cls;
    const struct sg_class_info *ci;
    int64_t cost;

    if (s->nr == __NR_clone && (args[0] & CLONE_THREAD))
        cls = SG_C_THREAD;
    ci = &sg_classes[cls];
    if (cls == SG_C_THREAD)
        cost = calibrated_thread ? calibrated_thread : ci->base;
    else
        cost = calibrated[s->nr] ? calibrated[s->nr] : ci->base;
    if (ci->size_unit && s->size_arg >= 0) {
        __u64 extra = args[s->size_arg] / ci->size_unit;

        if (extra > (1u << 30))
            extra = 1u << 30;
        cost += (int64_t)extra;
    }
    if (cls_out)
        *cls_out = cls;
    return cost;
}

int sg_set_cost(const char *name, int64_t units)
{
    size_t i;

    if (units < 1)
        return -1;
    if (strcmp(name, "clone_thread") == 0) {
        calibrated_thread = units;
        return 0;
    }
    for (i = 0; i < NTABLE; i++)
        if (strcmp(table[i].name, name) == 0) {
            calibrated[table[i].nr] = units;
            return 0;
        }
    return -1;
}

int sg_load_costs(const char *path, char *err, size_t errlen)
{
    char line[512];
    int lineno = 0, loaded = 0;
    FILE *f = fopen(path, "r");

    if (!f) {
        snprintf(err, errlen, "%s: %s", path, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char name[64], *hash = strchr(line, '#');
        long long cost;
        int n;

        lineno++;
        if (hash)
            *hash = '\0';
        n = sscanf(line, "%63s %lld", name, &cost);
        if (n <= 0)
            continue;
        if (n != 2 || sg_set_cost(name, cost) < 0) {
            snprintf(err, errlen, "%s:%d: expected \"<costed syscall> <cost >= 1>\"", path, lineno);
            fclose(f);
            return -1;
        }
        loaded++;
    }
    fclose(f);
    return loaded;
}

void sg_dump_costs(FILE *out)
{
    __u64 args[6] = { 0 };
    size_t i;

    fprintf(out, "%-4s %-12s %-10s %5s %6s\n", "NR", "NAME", "CLASS", "SEED", "COST");
    for (i = 0; i < NTABLE; i++) {
        enum sg_class cls;
        int64_t cost = sg_cost(&table[i], args, &cls);

        fprintf(out, "%-4d %-12s %-10s %5lld %6lld\n", table[i].nr, table[i].name, sg_classes[cls].name,
                (long long)sg_classes[table[i].cls].base, (long long)cost);
    }
    args[0] = CLONE_THREAD;
    fprintf(out, "%-4d %-12s %-10s %5lld %6lld\n", __NR_clone, "clone_thread", sg_classes[SG_C_THREAD].name,
            (long long)sg_classes[SG_C_THREAD].base, (long long)sg_cost(sg_lookup(__NR_clone), args, NULL));
}

int sg_build_filter(struct sock_fprog *prog)
{
#ifdef __x86_64__
    const size_t x32_insns = 2;
#else
    const size_t x32_insns = 0;
#endif
    size_t len = 4 + x32_insns + 2 * NDENIED + NTABLE + 2, i;
    struct sock_filter *f, *p;

    if (NTABLE > 255) {
        errno = E2BIG;
        return -1;
    }
    f = calloc(len, sizeof *f);
    if (!f)
        return -1;
    p = f;

    *p++ = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    *p++ = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SG_AUDIT_ARCH, 1, 0);
    *p++ = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    *p++ = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    /* x32 ABI numbers would bypass the table below. */
    *p++ = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
    *p++ = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
#endif
    for (i = 0; i < NDENIED; i++) {
        *p++ = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)denied[i].nr, 0, 1);
        *p++ = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                            SECCOMP_RET_ERRNO | ((unsigned)denied[i].err & SECCOMP_RET_DATA));
    }
    /* Costed calls jump past the remaining checks and RET_ALLOW to RET_USER_NOTIF. */
    for (i = 0; i < NTABLE; i++)
        *p++ = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)table[i].nr,
                                            (unsigned char)(NTABLE - i), 0);
    *p++ = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    *p++ = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

    prog->len = (unsigned short)len;
    prog->filter = f;
    return 0;
}
