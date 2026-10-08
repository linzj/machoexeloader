#include <crt_externs.h>
#include <mach-o/dyld.h>
#include <stdio.h>

int main(void) {
    char buf[4096];
    uint32_t n = sizeof(buf);
    if (_NSGetExecutablePath(buf, &n) != 0) {
        printf("execpath: <failed>\n");
        return 1;
    }
    printf("execpath: %s\n", buf);
    printf("argc: %d\n", *_NSGetArgc());
    char **argv = *_NSGetArgv();
    for (int i = 0; argv[i]; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    return 0;
}
