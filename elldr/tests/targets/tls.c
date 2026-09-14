#include <stdio.h>
#include <string.h>

__thread int tls_init = 42;
__thread char tls_buf[16];
__thread long tls_bss;

int main(void) {
    printf("tls_init=%d\n", tls_init);
    printf("tls_bss=%ld\n", tls_bss);
    tls_init += 1;
    strcpy(tls_buf, "hello-tls");
    tls_bss = 1234567;
    printf("tls_init=%d tls_buf=%s tls_bss=%ld\n", tls_init, tls_buf, tls_bss);
    return 0;
}
