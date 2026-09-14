/* greet.dll is resolved lazily by the image's own delay-load helper, whose
 * LoadLibraryW/GetProcAddress calls run through peldr's IAT shims. */
#include <stdio.h>

__declspec(dllimport) const char *greet_message(void);

int main(void) {
    printf("delayed: %s\n", greet_message());
    return 0;
}
