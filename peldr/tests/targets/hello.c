#include <stdio.h>

int main(int argc, char **argv) {
    printf("hello from target\n");
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]=%s\n", i, argv[i]);
    }
    fflush(stdout);
    return 42;
}
