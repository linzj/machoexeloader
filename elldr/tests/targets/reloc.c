#include <stdio.h>

// Absolute-address relocations (R_X86_64_64) into .data function/tables.
int triple(int x) {
    return x * 3;
}

static int (*volatile fn_table[2])(int) = { triple, 0 };

static const char *volatile names[] = {"zero", "one", "two", 0};

int main(void) {
    int total = 0;
    for (int i = 0; i < 2; i++) {
        if (fn_table[i])
            total += fn_table[i](i + 1);
    }
    for (int i = 0; names[i]; i++)
        printf("name[%d]=%s\n", i, names[i]);
    printf("total=%d\n", total);
    return 0;
}
