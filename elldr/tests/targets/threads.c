#include <pthread.h>
#include <stdio.h>

__thread int tls_counter = 100;

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < 3; i++) {
        tls_counter += 1;
    }
    printf("worker %ld: tls_counter=%d\n", id, tls_counter);
    return (void *)(long)tls_counter;
}

int main(void) {
    pthread_t t1, t2;
    void *r1, *r2;

    tls_counter = 1;
    if (pthread_create(&t1, NULL, worker, (void *)1L) != 0) {
        printf("create failed\n");
        return 1;
    }
    if (pthread_create(&t2, NULL, worker, (void *)2L) != 0) {
        printf("create failed\n");
        return 1;
    }
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    printf("main: tls_counter=%d r1=%ld r2=%ld\n", tls_counter, (long)r1, (long)r2);
    return 0;
}
