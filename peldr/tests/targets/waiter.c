/* RegisterWaitForSingleObject callbacks run on ntdll thread-pool threads,
 * not on threads created through CreateThread; thread-local access inside
 * the callback must still work under peldr. */
#include <windows.h>
#include <stdio.h>

__declspec(thread) int tls_in_pool = 500;

static HANDLE done_evt;

static void CALLBACK on_wait(PVOID ctx, BOOLEAN fired) {
    (void)ctx;
    tls_in_pool += 1;
    printf("pool-callback tls=%d fired=%d\n", tls_in_pool, (int)fired);
    SetEvent(done_evt);
}

int main(void) {
    done_evt = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE timer = CreateWaitableTimerW(NULL, TRUE, NULL);
    LARGE_INTEGER due;
    due.QuadPart = -500000; /* 50ms */
    if (!SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE)) {
        printf("SetWaitableTimer failed\n");
        return 2;
    }
    HANDLE wait_h = NULL;
    if (!RegisterWaitForSingleObject(&wait_h, timer, on_wait, NULL, INFINITE, WT_EXECUTEONLYONCE)) {
        printf("RegisterWaitForSingleObject failed\n");
        return 3;
    }
    WaitForSingleObject(done_evt, 5000);
    UnregisterWaitEx(wait_h, INVALID_HANDLE_VALUE);
    CloseHandle(timer);
    CloseHandle(done_evt);
    printf("main tls=%d\n", tls_in_pool);
    return tls_in_pool == 500 ? 0 : 1;
}
