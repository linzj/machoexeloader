#include <stdio.h>
#include <stdlib.h>

static void ctor_before(void) __attribute__((constructor(101)));
static void ctor_after(void) __attribute__((constructor(102)));
static void dtor_fn(void) __attribute__((destructor));

static void atexit_fn(void) {
    printf("atexit\n");
}

static void ctor_before(void) {
    printf("ctor 101\n");
}

static void ctor_after(void) {
    printf("ctor 102\n");
}

static void dtor_fn(void) {
    printf("dtor\n");
}

int main(void) {
    atexit(atexit_fn);
    printf("main\n");
    return 0;
}
