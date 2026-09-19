// Runtime-loaded DLL carrying module TLS: a __declspec(thread) variable and a
// TLS callback. tlsdlltest LoadLibrary()s it at runtime, exercising peldr's
// runtime self-map + runtime TLS registration (slot assignment, per-thread
// blocks, callbacks) instead of the load-time path.
#include <windows.h>

__declspec(thread) int tval = 7;
static int cb_count = 0;

static void NTAPI tls_cb(PVOID dll, DWORD reason, PVOID reserved) {
    (void)dll;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        cb_count++;
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_cb_entry = tls_cb;

__declspec(dllexport) int get(void) { return tval + cb_count * 100; }
__declspec(dllexport) void set(int v) { tval = v; }
