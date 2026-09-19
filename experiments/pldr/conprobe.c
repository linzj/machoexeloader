// conprobe v7: QUWI dispatch probe (120s).
#include <windows.h>
#include <stdio.h>

static volatile LONG wrk = 0;

static void logln(const char *fmt, ...) {
    char buf[256], path[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    snprintf(path, sizeof path, "C:\\Users\\manji\\conprobe_%lu.log", GetCurrentProcessId());
    FILE *lf = fopen(path, "a");
    fputs(buf, lf);
    fputc('\n', lf);
    fclose(lf);
}

static DWORD WINAPI work_cb(PVOID p) { InterlockedIncrement(&wrk); return 0; }

int main(void) {
    logln("start pid=%lu", GetCurrentProcessId());
    for (int i = 0; i < 120; i++) {
        SetLastError(0);
        BOOL rc = QueueUserWorkItem(work_cb, 0, 0);
        DWORD err = GetLastError();
        logln("tick %d rc=%d err=%lu wrk=%ld", i, rc, err, wrk);
        Sleep(1000);
    }
    logln("exit wrk=%ld", wrk);
    return 0;
}
