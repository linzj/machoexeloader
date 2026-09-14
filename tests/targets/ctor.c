#include <stdio.h>

__attribute__((constructor)) static void first_ctor(void) {
    printf("ctor ran\n");
}

int main(void) {
    printf("main ran\n");
    return 0;
}
