#include <stdio.h>

__declspec(thread) int tls_int = 42;
__declspec(thread) char tls_buf[16] = "hello";
__declspec(thread) long long tls_zero;

int main(void) {
    printf("tls_int=%d tls_buf=%s tls_zero=%lld\n", tls_int, tls_buf, tls_zero);
    tls_int += 8;
    tls_buf[0] = 'H';
    tls_zero++;
    printf("after=%d %s %lld\n", tls_int, tls_buf, tls_zero);
    return tls_int == 50 && tls_buf[0] == 'H' && tls_zero == 1 ? 0 : 1;
}
