#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <link.h>
#include <unistd.h>

// The target image must be visible to dl_iterate_phdr (Bun's unwinder and
// JSC introspection depend on it): report whether we see ourselves at the
// linked base with our own phdrs.
static int seen_self = 0;

static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (info->dlpi_addr == 0) {
        // ET_EXEC main object: phdrs carry absolute vaddrs.
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
            if (ph->p_type == PT_LOAD && ph->p_vaddr <= (ElfW(Addr))&seen_self &&
                (ElfW(Addr))&seen_self < ph->p_vaddr + ph->p_memsz) {
                seen_self = 1;
                printf("self object: name=%s phnum=%d\n",
                       info->dlpi_name ? info->dlpi_name : "", info->dlpi_phnum);
            }
        }
    }
    return 0;
}

int main(void) {
    dl_iterate_phdr(cb, NULL);
    printf("seen_self=%d\n", seen_self);

    // readlink(/proc/self/exe) must resolve to the target path
    char path[4096];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n > 0) {
        path[n] = 0;
        const char *base = strrchr(path, '/');
        printf("exe=%s\n", base ? base + 1 : path);
    } else {
        printf("readlink failed\n");
    }
    return 0;
}
