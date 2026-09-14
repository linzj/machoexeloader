#include <stdio.h>

__thread int tls_var = 42;
__thread char tls_buf[16] = "hello";

int main(void) {
    tls_var += 1;
    printf("%d %s\n", tls_var, tls_buf);
    return 0;
}
