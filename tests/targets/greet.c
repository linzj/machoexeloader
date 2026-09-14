extern const char *suffix_value(void);

/* A data pointer into __TEXT, exercised through a rebase fixup. */
static const char *prefix = "hello, ";
static char buf[64];

const char *greet_message(void) {
    int n = 0;
    for (const char *p = prefix; *p; p++) {
        buf[n++] = *p;
    }
    for (const char *p = suffix_value(); *p; p++) {
        buf[n++] = *p;
    }
    buf[n] = 0;
    return buf;
}
