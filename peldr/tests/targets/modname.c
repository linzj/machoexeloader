#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    WCHAR path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    const WCHAR *base = path;
    for (DWORD i = 0; i < n; i++) {
        if (path[i] == L'\\' || path[i] == L'/') {
            base = path + i + 1;
        }
    }
    printf("module-name=%ls\n", base);
    HMODULE h = GetModuleHandleW(NULL);
    printf("module-handle-nonnull=%d\n", h != NULL ? 1 : 0);
    for (int i = 0; i < argc; i++) {
        printf("argv[%d]=%s\n", i, argv[i]);
    }
    return 0;
}
