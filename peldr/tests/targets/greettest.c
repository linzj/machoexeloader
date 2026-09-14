#include <stdio.h>

__declspec(dllimport) const char *greet_message(void);

int main(void) {
    printf("%s\n", greet_message());
    printf("%s\n", greet_message());
    return 0;
}
