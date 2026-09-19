// Probe target: a DLL with module TLS and an instrumented TLS callback.
// The probe (ntdll-only) hand-maps this DLL and registers it with
// LdrpHandleTlsData; these exports report what ntdll then does natively.
#include <windows.h>

__declspec(thread) int tval = 42;
static volatile int cb; // +100 per DLL_PROCESS_ATTACH, +1 per DLL_THREAD_ATTACH
static volatile unsigned long long cb_handle; // DllHandle arg of the last callback

static void NTAPI tls_cb(PVOID dll, DWORD reason, PVOID reserved) {
    (void)dll;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        cb += 100;
        cb_handle = (unsigned long long)dll;
    } else if (reason == DLL_THREAD_ATTACH) {
        cb += 1;
        cb_handle = (unsigned long long)dll;
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_cb_entry = tls_cb;

__declspec(dllexport) int tls_read(void) { return tval; }
__declspec(dllexport) void tls_write(int v) { tval = v; }
__declspec(dllexport) int cb_count(void) { return cb; }
__declspec(dllexport) unsigned long long cb_handle_value(void) { return cb_handle; }
