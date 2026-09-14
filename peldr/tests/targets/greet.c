#include <stdio.h>

__declspec(dllexport) const char *suffix_value(void);

static const char *prefix = "hello, ";
static char buf[64];
static int calls;

__declspec(dllexport) const char *greet_message(void) {
    calls++;
    snprintf(buf, sizeof(buf), "%s%s #%d", prefix, suffix_value(), calls);
    return buf;
}
