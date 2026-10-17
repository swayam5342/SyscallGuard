#ifndef SG_COSTS_H
#define SG_COSTS_H

#include <linux/filter.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>

/* Syscall cost table and seccomp filter generator. */

enum sg_policy { SG_WAIT, SG_REJECT };

enum sg_class {
    SG_C_DATA,      /* read/write family */
    SG_C_META,      /* open, unlink, rename, mkdir */
    SG_C_DURABLE,   /* fsync family */
    SG_C_MMAP,      /* mmap, munmap, mremap, brk */
    SG_C_PROC,      /* fork, vfork, clone without CLONE_THREAD */
    SG_C_THREAD,    /* clone with CLONE_THREAD */
    SG_C_EXEC,      /* execve, execveat */
    SG_C_NET,       /* socket, connect, accept, bind */
    SG_C_COUNT
};

struct sg_class_info {
    const char *name;
    int64_t base;          /* cost units */
    uint64_t size_unit;    /* +1 unit per this many bytes of the size arg; 0 = none */
    enum sg_policy policy;
    int reject_errno;
};

struct sg_syscall {
    int nr;
    const char *name;
    enum sg_class cls;
    int size_arg;          /* index of the byte-count argument, -1 = none */
};

extern const struct sg_class_info sg_classes[SG_C_COUNT];

/* NULL if the call is not costed. */
const struct sg_syscall *sg_lookup(int nr);

/* Cost in whole units; *cls_out gets the effective class (clone may be a thread). */
int64_t sg_cost(const struct sg_syscall *s, const __u64 args[6], enum sg_class *cls_out);

/* prog->filter is malloc'd. */
int sg_build_filter(struct sock_fprog *prog);

/* Override a syscall's seed cost; "clone_thread" is clone with CLONE_THREAD. */
int sg_set_cost(const char *name, int64_t units);

/* "name cost" per line, '#' comments, extra columns ignored. Returns the count, or -1 and err. */
int sg_load_costs(const char *path, char *err, size_t errlen);

void sg_dump_costs(FILE *out);

#endif
