/* Threads that end by calling ntdll!RtlExitUserThread directly (the way
 * Bun's runtime does) must also get their TLS array restored under peldr,
 * otherwise ntdll's thread teardown corrupts the heap. */
#include <windows.h>
#include <stdio.h>

extern void __stdcall RtlExitUserThread(unsigned long status);

__declspec(thread) int tls_rx = 700;

static DWORD WINAPI direct_exit(LPVOID p) {
    int id = (int)(INT_PTR)p;
    tls_rx += id;
    printf("thread %d tls=%d\n", id, tls_rx);
    RtlExitUserThread(0); /* no return */
    return 0;
}

int main(void) {
    HANDLE h1 = CreateThread(NULL, 0, direct_exit, (LPVOID)(INT_PTR)1, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, direct_exit, (LPVOID)(INT_PTR)2, 0, NULL);
    WaitForSingleObject(h1, 5000);
    WaitForSingleObject(h2, 5000);
    CloseHandle(h1);
    CloseHandle(h2);
    /* touch the heap a bit: corruption shows up as fail-fast here */
    for (int i = 0; i < 1000; i++) {
        void *p = malloc(64 + i % 200);
        free(p);
    }
    printf("main tls=%d\n", tls_rx);
    return tls_rx == 700 ? 0 : 1;
}
