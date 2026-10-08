#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

// Identity shims: /proc/self/exe must resolve to the target through every
// interposed path (libc readlink/readlinkat, the Zig-style syscall()
// wrapper, open) and program_invocation_* must name the target. Claude
// Code's Bash-tool wrappers re-exec the captured execPath (bfs/ugrep
// multicall), so a wrong answer here breaks grep/find inside sessions.
static void print_link(const char *tag, const char *path) {
    char buf[4096];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        printf("%s=%s\n", tag, buf);
    } else {
        printf("%s=FAIL\n", tag);
    }
}

int main(int argc, char **argv) {
    (void)argc;
    const char *base = strrchr(argv[0], '/');
    printf("argv0=%s\n", base ? base + 1 : argv[0]);

    print_link("readlink", "/proc/self/exe");

    char pidpath[64];
    snprintf(pidpath, sizeof(pidpath), "/proc/%d/exe", getpid());
    print_link("readlink-pid", pidpath);

    char buf[4096];
    ssize_t n = syscall(SYS_readlinkat, AT_FDCWD, "/proc/self/exe", buf,
                        sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        printf("syscall-readlinkat=%s\n", buf);
    } else {
        printf("syscall-readlinkat=FAIL\n");
    }

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            printf("open-size=%lld\n", (long long)st.st_size);
        } else {
            printf("open-size=FAIL\n");
        }
        close(fd);
    } else {
        printf("open-size=FAIL\n");
    }

    // glibc sets program_invocation_name to the verbatim argv[0] natively,
    // while elldr reports the canonical target path; compare basenames.
    const char *pin = program_invocation_name;
    base = strrchr(pin, '/');
    printf("pin=%s\n", base ? base + 1 : pin);
    printf("pisn=%s\n", program_invocation_short_name);
    return 0;
}
