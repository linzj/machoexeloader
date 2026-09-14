#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        int v = atoi(argv[1]);
        printf("exiting %d\n", v);
        return v;
    }
    printf("no arg\n");
    return 7;
}
