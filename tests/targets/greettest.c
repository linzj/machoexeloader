#include <stdio.h>

extern const char *greet_message(void);

int main(void) {
    printf("%s\n", greet_message());
    return 0;
}
