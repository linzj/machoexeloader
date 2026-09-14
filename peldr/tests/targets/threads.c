#include <windows.h>
#include <process.h>
#include <stdio.h>

__declspec(thread) int tls_counter = 100;

static DWORD WINAPI worker(LPVOID p) {
    int id = (int)(INT_PTR)p;
    tls_counter += id;
    Sleep(10);
    return (DWORD)tls_counter;
}

static unsigned __stdcall worker2(void *p) {
    int id = (int)(INT_PTR)p;
    tls_counter += id * 10;
    return (unsigned)tls_counter;
}

int main(void) {
    HANDLE h1 = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)1, 0, NULL);
    HANDLE h2 = (HANDLE)_beginthreadex(NULL, 0, worker2, (void *)(INT_PTR)2, 0, NULL);
    DWORD c1 = 0, c2 = 0;
    WaitForSingleObject(h1, INFINITE);
    WaitForSingleObject(h2, INFINITE);
    GetExitCodeThread(h1, &c1);
    GetExitCodeThread(h2, &c2);
    CloseHandle(h1);
    CloseHandle(h2);
    tls_counter += 5;
    printf("t1=%lu t2=%lu main=%d\n", c1, c2, tls_counter);
    return c1 == 101 && c2 == 120 && tls_counter == 105 ? 0 : 1;
}
