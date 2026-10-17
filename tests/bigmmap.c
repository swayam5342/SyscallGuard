/*
 * Test helper: one large costed call. mmap of N MiB costs 2 + N units but
 * reserves no memory (PROT_NONE, MAP_NORESERVE). Optionally stays alive for
 * a few seconds so loans can be repaid. Exits 1 if the mmap was refused.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    size_t mib = argc > 1 ? strtoul(argv[1], NULL, 10) : 1;
    unsigned hold = argc > 2 ? (unsigned)atoi(argv[2]) : 0;
    void *p = mmap(NULL, mib << 20, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if (p == MAP_FAILED) {
        printf("mmap: %s\n", strerror(errno));
        return 1;
    }
    if (hold)
        sleep(hold);
    printf("ok\n");
    return 0;
}
