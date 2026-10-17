/* Test helper: fork N short-lived children and count the outcomes. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 100, i, ok = 0, eagain = 0, other = 0;

    for (i = 0; i < n; i++) {
        pid_t pid = fork();

        if (pid == 0)
            _exit(0);
        if (pid > 0) {
            ok++;
            waitpid(pid, NULL, 0);
        } else if (errno == EAGAIN) {
            eagain++;
        } else {
            other++;
        }
    }
    printf("ok=%d eagain=%d other=%d\n", ok, eagain, other);
    return other ? 1 : 0;
}
