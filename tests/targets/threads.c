#include <pthread.h>
#include <stdio.h>

__thread int tls_counter = 100;

static void *worker(void *arg) {
    long id = (long)arg;
    tls_counter += (int)id;
    return (void *)(long)tls_counter;
}

int main(void) {
    pthread_t t1, t2;
    void *r1, *r2;
    pthread_create(&t1, NULL, worker, (void *)1);
    pthread_create(&t2, NULL, worker, (void *)2);
    pthread_join(t1, &r1);
    pthread_join(t2, &r2);
    tls_counter += 5;
    printf("main=%d w1=%ld w2=%ld\n", tls_counter, (long)r1, (long)r2);
    return 0;
}
