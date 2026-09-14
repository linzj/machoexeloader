#include <stdio.h>
#include <string.h>

// Two implementations selected by an ifunc resolver (R_X86_64_IRELATIVE).
static int add_generic(int a, int b) {
    return a + b;
}

static int add_special(int a, int b) {
    return a + b + 1000;
}

static int (*resolve_add(void))(int, int) {
    // Pick based on a runtime condition; must not crash.
    volatile int pick = 0;
    return pick ? add_special : add_generic;
}

static int add(int, int) __attribute__((ifunc("resolve_add")));

int main(void) {
    printf("add(2,3)=%d\n", add(2, 3));
    // exercise host libc ifuncs too
    char buf[8];
    memcpy(buf, "abcdef", 7);
    printf("memcpy=%s\n", buf);
    return 0;
}
