// LoadLibrary("tlsdll.dll") at runtime, then use its exports from the main
// thread and from a CreateThread thread. The DLL's TLS callback bumps a
// process-wide counter on DLL_PROCESS_ATTACH (+100 in get()), while tval is
// per-thread (7 on the fresh worker thread, 42 on the main thread after set).
#include <windows.h>
#include <stdio.h>

typedef int (*get_fn)(void);
typedef void (*set_fn)(int);

static DWORD WINAPI worker(LPVOID p) {
    get_fn get = *(get_fn *)p;
    printf("thread initial %d\n", get());
    return 0;
}

int main(void) {
    HMODULE h = LoadLibraryA("tlsdll.dll");
    if (!h) {
        printf("loadfail\n");
        return 1;
    }
    get_fn get = (get_fn)GetProcAddress(h, "get");
    set_fn set = (set_fn)GetProcAddress(h, "set");
    if (!get || !set) {
        printf("gpafail\n");
        return 2;
    }
    printf("initial %d\n", get());
    set(42);
    printf("after set %d\n", get());
    HANDLE t = CreateThread(NULL, 0, worker, &get, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    printf("final %d\n", get());
    return 0;
}
