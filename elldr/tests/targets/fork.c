#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    printf("before fork\n");
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        // child: exec a system binary and exit with its code
        execl("/bin/sh", "sh", "-c", "echo child-hello", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
