/* Test helper: create and join 8 threads; exits 0 only if all were created. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>

static void *work(void *arg)
{
    return arg;
}

int main(void)
{
    pthread_t t[8];
    int i, created = 0;

    for (i = 0; i < 8; i++)
        if (pthread_create(&t[created], NULL, work, NULL) == 0)
            created++;
    for (i = 0; i < created; i++)
        pthread_join(t[i], NULL);
    printf("threads=%d\n", created);
    return created == 8 ? 0 : 1;
}
