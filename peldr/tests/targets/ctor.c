#include <stdio.h>

static int ctor_first(void) {
    printf("ctor first\n");
    return 0;
}

static int ctor_second(void) {
    printf("ctor second\n");
    return 0;
}

#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) static int(__cdecl *p_first)(void) = ctor_first;
__declspec(allocate(".CRT$XCU")) static int(__cdecl *p_second)(void) = ctor_second;

int main(void) {
    printf("main ran\n");
    return 0;
}
